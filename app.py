"""A local-first AI use-case management tool built with Flask.

The application is designed as a weekend-friendly coding exercise: it keeps
infrastructure light (SQLite by default) while offering an opinionated feature
set for managing a catalogue of AI projects.  It supports Python 3.13.7 and
provides an admin-ready web interface for curating records, importing Excel
spreadsheets and browsing data with filters and full text search.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime
from pathlib import Path

import click
import pandas as pd
from flask import (
    Flask,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
    has_app_context,
)
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField, FileRequired
from sqlalchemy import func, or_, text
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from wtforms import PasswordField, SelectField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, Optional

# ---------------------------------------------------------------------------
# Application factory and extensions
# ---------------------------------------------------------------------------

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "login"

CONFIG_PATH = Path(__file__).with_name("use_case_config.json")
COLOR_OVERRIDE_PATH = Path(__file__).with_name("visualization_color_overrides.json")


def create_app() -> Flask:
    """Create and configure the Flask application instance."""

    app = Flask(__name__, instance_relative_config=True)
    default_db_path = Path(app.instance_path) / "use_cases.db"
    app.config.from_mapping(
        SECRET_KEY=os.getenv("SECRET_KEY", "dev-secret-key"),
        SQLALCHEMY_DATABASE_URI=os.getenv(
            "DATABASE_URI", f"sqlite:///{default_db_path}"
        ),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        UPLOAD_FOLDER=os.getenv(
            "UPLOAD_FOLDER", os.path.join(app.instance_path, "uploads")
        ),
        MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16 MB upload cap
    )

    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    config_path = Path(os.getenv("USE_CASE_CONFIG_PATH", CONFIG_PATH))
    app.config["USE_CASE_CONFIG"] = _load_use_case_config(config_path)

    db.init_app(app)
    login_manager.init_app(app)

    # Ensure the database schema is present even if new tables were added
    # after an existing database file had been created. ``create_all`` is
    # idempotent and will only create the missing tables, which prevents
    # runtime ``OperationalError`` exceptions when accessing relationships.
    with app.app_context():
        db.create_all()
        _ensure_database_schema()

    register_cli_commands(app)
    register_routes(app)

    @app.context_processor
    def inject_globals():  # pragma: no cover - simple convenience
        return {
            "app_title": "AI Use Case Library",
            "now": datetime.utcnow(),
            "can_view_field": _can_current_user_view_field,
            "can_view_visualizations": _current_user_can_access_visualizations(),
        }

    return app


# ---------------------------------------------------------------------------
# Database models
# ---------------------------------------------------------------------------


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="reader")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    owned_use_cases = db.relationship(
        "UseCase",
        secondary="use_case_owner",
        back_populates="owners",
        lazy="dynamic",
    )

    def set_password(self, raw_password: str) -> None:
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return check_password_hash(self.password_hash, raw_password)

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return f"<User {self.username}>"


class UseCase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    industry = db.Column(db.String(120))
    summary = db.Column(db.Text)
    problem = db.Column(db.Text)
    solution = db.Column(db.Text)
    impact = db.Column(db.Text)
    data_source = db.Column(db.String(200))
    tags = db.Column(db.String(200))
    synergy = db.Column(db.Text)
    status_color = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    owners = db.relationship(
        "User",
        secondary="use_case_owner",
        back_populates="owned_use_cases",
        order_by="User.username",
        lazy="selectin",
    )

    def tag_list(self) -> list[str]:
        return [tag.strip() for tag in (self.tags or "").split(",") if tag.strip()]

    def is_owned_by(self, user: User | None) -> bool:
        if user is None or not getattr(user, "is_authenticated", False):
            return False
        return any(owner.id == user.id for owner in self.owners)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<UseCase {self.title}>"


class UseCaseOwner(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    use_case_id = db.Column(db.Integer, db.ForeignKey("use_case.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint("use_case_id", "user_id", name="uq_use_case_owner"),
    )


# ---------------------------------------------------------------------------
# Database maintenance helpers
# ---------------------------------------------------------------------------


def _ensure_database_schema() -> None:
    """Make sure the live database includes columns added in newer releases."""

    # ``db.create_all`` will happily create missing tables but it does not add
    # new columns to an existing table, which is a common stumbling block when
    # developing locally with SQLite.  We run a lightweight migration step to
    # keep the ``use_case`` table in sync with the SQLAlchemy model definition.
    inspector = db.session.execute(text("PRAGMA table_info(use_case)")).all()
    existing_columns = {row[1] for row in inspector}

    if "status_color" not in existing_columns:
        db.session.execute(
            text("ALTER TABLE use_case ADD COLUMN status_color VARCHAR(50)")
        )
        db.session.commit()

    if "synergy" not in existing_columns:
        db.session.execute(
            text("ALTER TABLE use_case ADD COLUMN synergy TEXT")
        )
        db.session.commit()


# ---------------------------------------------------------------------------
# Forms
# ---------------------------------------------------------------------------


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=80)])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign in")


class UseCaseForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired(), Length(max=200)])
    industry = StringField("Industry", validators=[Optional(), Length(max=120)])
    summary = TextAreaField("Summary", validators=[Optional()])
    synergy = TextAreaField("Synergy", validators=[Optional()])
    problem = TextAreaField("Problem", validators=[Optional()])
    solution = TextAreaField("Solution", validators=[Optional()])
    impact = TextAreaField("Impact", validators=[Optional()])
    data_source = TextAreaField("Data source", validators=[Optional()])
    tags = StringField(
        "Tags", validators=[Optional(), Length(max=200)],
        description="Comma-separated labels such as industries or technologies."
    )
    status_color = StringField(
        "Status color", validators=[Optional(), Length(max=50)]
    )
    submit = SubmitField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not has_app_context():
            return
        config = current_app.config.get("USE_CASE_CONFIG", {})
        labels = _field_labels_from_config(config)
        for field_name, label in labels.items():
            field = getattr(self, field_name, None)
            if field is not None:
                field.label.text = label


class UploadForm(FlaskForm):
    file = FileField(
        "Excel file",
        validators=[
            FileRequired(message="Choose an Excel file to import."),
            FileAllowed({"xls", "xlsx"}, "Only .xls or .xlsx files are supported."),
        ],
    )
    import_mode = SelectField(
        "Import mode",
        choices=[
            ("append", "Append to existing records"),
            ("replace", "Replace existing records"),
        ],
        default="append",
    )
    submit = SubmitField("Upload")


class UseCaseOwnerForm(FlaskForm):
    user_id = SelectField("Add owner", coerce=int, validators=[DataRequired()])
    submit = SubmitField("Add owner")


# ---------------------------------------------------------------------------
# Authentication utilities
# ---------------------------------------------------------------------------


@login_manager.user_loader
def load_user(user_id: str):
    return User.query.get(int(user_id))


def require_admin() -> None:
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(403)


def can_manage_use_case(user: User, use_case: UseCase) -> bool:
    return user.is_authenticated and (user.is_admin or use_case.is_owned_by(user))


def require_use_case_manager(use_case: UseCase) -> None:
    if not can_manage_use_case(current_user, use_case):
        abort(403)


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------


def register_cli_commands(app: Flask) -> None:
    """Expose helper commands for bootstrapping the application."""

    @app.cli.command("init-db")
    def init_db_command() -> None:
        """Create database tables."""
        with app.app_context():
            db.create_all()
        click.echo("Database initialised.")

    @app.cli.command("create-admin")
    @click.argument("username")
    @click.option(
        "--password",
        prompt=True,
        hide_input=True,
        confirmation_prompt=True,
        help="Password for the administrator account.",
    )
    def create_admin_command(username: str, password: str) -> None:
        """Create or update an administrator account."""
        with app.app_context():
            _upsert_user(username=username, password=password, role="admin")
        click.echo(f"Admin user '{username}' is ready to log in.")

    @app.cli.command("create-user")
    @click.argument("username")
    @click.option(
        "--role",
        type=click.Choice(["reader", "admin"], case_sensitive=False),
        default="reader",
        show_default=True,
        help="Role to assign to the account.",
    )
    @click.option(
        "--password",
        prompt=True,
        hide_input=True,
        confirmation_prompt=True,
        help="Password for the user account.",
    )
    def create_user_command(username: str, role: str, password: str) -> None:
        """Create or update an account with the desired role."""
        with app.app_context():
            normalised_role = role.lower()
            _upsert_user(username=username, password=password, role=normalised_role)
        click.echo(
            f"User '{username}' with role '{normalised_role}' is ready to log in."
        )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


def register_routes(app: Flask) -> None:
    @app.errorhandler(403)
    def forbidden(_error):  # pragma: no cover - presentation only
        flash("You need administrator rights to access that action.", "warning")
        return redirect(url_for("dashboard"))

    @app.route("/")
    @login_required
    def dashboard():
        search = request.args.get("q", "").strip()
        industry = request.args.get("industry", "").strip()

        config = current_app.config.get("USE_CASE_CONFIG", {})
        labels = _field_labels_from_config(config)
        industry_label = labels.get("industry", _humanize_field_name("industry"))
        all_industry_label = _all_option_label(industry_label)

        query = UseCase.query
        if search:
            like = f"%{search.lower()}%"
            query = query.filter(
                or_(
                    func.lower(UseCase.title).like(like),
                    func.lower(UseCase.summary).like(like),
                    func.lower(UseCase.problem).like(like),
                    func.lower(UseCase.solution).like(like),
                    func.lower(UseCase.impact).like(like),
                    func.lower(UseCase.data_source).like(like),
                    func.lower(UseCase.tags).like(like),
                    func.lower(UseCase.synergy).like(like),
                    func.lower(UseCase.status_color).like(like),
                )
            )
        if industry:
            query = query.filter(UseCase.industry == industry)

        use_cases = query.order_by(UseCase.updated_at.desc()).all()
        industries = [
            value
            for (value,) in db.session.query(UseCase.industry)
            .filter(UseCase.industry.isnot(None))
            .distinct()
            .order_by(UseCase.industry)
        ]
        total_records = UseCase.query.count()

        return render_template(
            "index.html",
            use_cases=use_cases,
            search=search,
            industries=industries,
            selected_industry=industry,
            total_records=total_records,
            industry_label=industry_label,
            all_industry_label=all_industry_label,
            field_labels=labels,
        )

    @app.route("/visualizations")
    @login_required
    def visualizations():
        filters, filtered_use_cases = _prepare_visualization_filters(
            current_user, request.args
        )
        graphs = _visualization_payload_for_user(current_user, filtered_use_cases)
        active_filters = sum(1 for item in filters if item.get("is_active"))
        return render_template(
            "visualizations.html",
            graphs=graphs,
            filters=filters,
            active_filters=active_filters,
        )

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user and user.check_password(form.password.data):
                login_user(user)
                return redirect(url_for("dashboard"))
            flash("Invalid credentials", "danger")
        return render_template("login.html", form=form)

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        flash("Signed out successfully.", "info")
        return redirect(url_for("login"))

    @app.route("/use-cases/new", methods=["GET", "POST"])
    @login_required
    def create_use_case():
        require_admin()
        form = UseCaseForm()
        form.submit.label.text = "Create use case"
        if form.validate_on_submit():
            use_case = UseCase(
                title=form.title.data,
                industry=form.industry.data or None,
                summary=form.summary.data or None,
                synergy=form.synergy.data or None,
                problem=form.problem.data or None,
                solution=form.solution.data or None,
                impact=form.impact.data or None,
                data_source=form.data_source.data or None,
                tags=form.tags.data or None,
                status_color=form.status_color.data or None,
            )
            db.session.add(use_case)
            db.session.commit()
            flash("Use case created.", "success")
            return redirect(url_for("dashboard"))
        return render_template(
            "use_case_form.html", form=form, heading="New use case"
        )

    @app.route("/use-cases/<int:use_case_id>/edit", methods=["GET", "POST"])
    @login_required
    def edit_use_case(use_case_id: int):
        use_case = UseCase.query.get_or_404(use_case_id)
        require_use_case_manager(use_case)
        form = UseCaseForm(obj=use_case)
        form.submit.label.text = "Save changes"
        if form.validate_on_submit():
            form.populate_obj(use_case)
            db.session.commit()
            flash("Use case updated.", "success")
            return redirect(url_for("dashboard"))
        return render_template(
            "use_case_form.html",
            form=form,
            heading=f"Edit: {use_case.title}",
            use_case=use_case,
        )

    @app.route("/use-cases/<int:use_case_id>")
    @login_required
    def use_case_detail(use_case_id: int):
        use_case = UseCase.query.get_or_404(use_case_id)
        owners = list(use_case.owners)
        can_manage = can_manage_use_case(current_user, use_case)
        owner_form = None
        if can_manage:
            owner_form = UseCaseOwnerForm()
            owner_form.user_id.choices = _available_owner_choices(use_case)
        config = current_app.config.get("USE_CASE_CONFIG", {})
        field_labels = _field_labels_from_config(config)
        return render_template(
            "use_case_detail.html",
            use_case=use_case,
            owners=owners,
            owner_form=owner_form,
            can_manage_use_case=can_manage,
            field_labels=field_labels,
        )

    @app.route("/use-cases/<int:use_case_id>/delete", methods=["POST"])
    @login_required
    def delete_use_case(use_case_id: int):
        use_case = UseCase.query.get_or_404(use_case_id)
        require_use_case_manager(use_case)
        db.session.delete(use_case)
        db.session.commit()
        flash("Use case deleted.", "info")
        return redirect(url_for("dashboard"))

    @app.route("/use-cases/<int:use_case_id>/owners", methods=["POST"])
    @login_required
    def add_use_case_owner(use_case_id: int):
        use_case = UseCase.query.get_or_404(use_case_id)
        require_use_case_manager(use_case)
        form = UseCaseOwnerForm()
        form.user_id.choices = _available_owner_choices(use_case)
        if not form.user_id.choices:
            flash("All users are already owners of this use case.", "info")
            return redirect(url_for("use_case_detail", use_case_id=use_case_id))
        if form.validate_on_submit():
            new_owner = User.query.get(form.user_id.data)
            if new_owner is None:
                flash("Selected user could not be found.", "danger")
            elif use_case.is_owned_by(new_owner):
                flash(f"{new_owner.username} is already an owner.", "info")
            else:
                use_case.owners.append(new_owner)
                db.session.commit()
                flash(f"{new_owner.username} added as an owner.", "success")
        else:
            flash("Please choose a user to add as an owner.", "warning")
        return redirect(url_for("use_case_detail", use_case_id=use_case_id))

    @app.route("/import", methods=["GET", "POST"])
    @login_required
    def import_excel():
        require_admin()
        config = current_app.config.get("USE_CASE_CONFIG", {})
        import_config = config.get("import", {})
        field_mappings = _field_mappings_from_config(config)
        form = UploadForm()
        upload_columns = list(_field_columns_from_config(config).values())
        upload_columns_text = _format_columns_list(upload_columns)
        if form.validate_on_submit():
            uploaded_file = form.file.data
            filename = secure_filename(uploaded_file.filename)
            saved_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            uploaded_file.save(saved_path)

            try:
                dataframe = pd.read_excel(saved_path)
            except Exception as exc:  # pragma: no cover - user feedback only
                flash(f"Could not read the spreadsheet: {exc}", "danger")
                return redirect(request.url)

            default_missing_value = import_config.get(
                "default_missing_value", "Undefined"
            )

            if not field_mappings:
                flash("No import field mappings are configured.", "danger")
                return redirect(request.url)

            configured_columns = {
                details.get("column")
                for details in field_mappings.values()
                if details.get("column")
            }
            present_columns = set(dataframe.columns)
            missing_columns = sorted(configured_columns - present_columns)
            if missing_columns:
                placeholder = default_missing_value if default_missing_value is not None else ""
                flash(
                    "Missing columns were set to"
                    f" '{placeholder or 'blank'}': "
                    + ", ".join(missing_columns),
                    "info",
                )

            if form.import_mode.data == "replace":
                UseCase.query.delete()

            column_absent = {
                field: details.get("column") not in dataframe.columns
                if details.get("column")
                else True
                for field, details in field_mappings.items()
            }

            created = 0
            for _, row in dataframe.iterrows():
                use_case_data = {}
                for field, details in field_mappings.items():
                    column_name = details.get("column")
                    default_value = details.get("default", default_missing_value)
                    value = None
                    if column_name and not column_absent.get(field, True):
                        value = _clean_cell(row.get(column_name))
                    if value is None and column_absent.get(field, True):
                        value = default_value

                    if field == "title" and not value:
                        value = default_value or default_missing_value or "Untitled use case"

                    use_case_data[field] = value

                if not use_case_data.get("title"):
                    continue

                use_case = UseCase(**use_case_data)
                db.session.add(use_case)
                created += 1

            db.session.commit()

            flash(f"Imported {created} records from {filename}.", "success")
            return redirect(url_for("dashboard"))
        return render_template(
            "upload.html",
            form=form,
            upload_columns=upload_columns,
            upload_columns_text=upload_columns_text,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_use_case_config(path: Path) -> dict:
    try:
        with path.open("r", encoding="utf-8") as config_file:
            return json.load(config_file)
    except FileNotFoundError:  # pragma: no cover - configuration safeguard
        return {
            "import": {"default_missing_value": "Undefined", "fields": {}},
            "access_control": {},
        }


def _configured_use_case_fields() -> set[str]:
    config = current_app.config.get("USE_CASE_CONFIG", {})
    return set(config.get("import", {}).get("fields", {}).keys())


def _field_mappings_from_config(config: dict) -> dict[str, dict]:
    fields = config.get("import", {}).get("fields", {})
    return fields if isinstance(fields, dict) else {}


def _field_columns_from_config(config: dict) -> dict[str, str]:
    mappings = {}
    for field, details in _field_mappings_from_config(config).items():
        if isinstance(details, dict):
            column = details.get("column")
            if column:
                mappings[field] = column
    return mappings


def _format_columns_list(columns: list[str]) -> str:
    cleaned = [column for column in columns if column]
    if not cleaned:
        return ""
    if len(cleaned) == 1:
        return cleaned[0]
    if len(cleaned) == 2:
        return " and ".join(cleaned)
    return ", ".join(cleaned[:-1]) + f" and {cleaned[-1]}"


def _field_labels_from_config(config: dict) -> dict[str, str]:
    labels: dict[str, str] = {}
    for field, details in _field_mappings_from_config(config).items():
        if not isinstance(details, dict):
            continue
        label = details.get("label") or details.get("column")
        if not label:
            label = _humanize_field_name(field)
        labels[field] = label
    return labels


def _humanize_field_name(name: str) -> str:
    if not name:
        return ""
    parts = [part for part in name.replace("-", "_").split("_") if part]
    return " ".join(part.capitalize() for part in parts) if parts else name


def _all_option_label(label: str) -> str:
    if not label:
        return "All"
    return f"All {_pluralize_label(label)}"


def _pluralize_label(label: str) -> str:
    word = label.strip()
    if not word:
        return ""
    lower = word.lower()
    if lower.endswith("y") and len(lower) > 1 and lower[-2] not in "aeiou":
        return lower[:-1] + "ies"
    if lower.endswith("s"):
        return lower
    return lower + "s"


def _visible_fields_for_user(user: User | None, use_case: UseCase | None = None) -> set[str]:
    config = current_app.config.get("USE_CASE_CONFIG", {})
    all_fields = _configured_use_case_fields()
    access_control = config.get("access_control", {})
    roles = access_control.get("roles", {})
    role_name = getattr(user, "role", None) or "reader"
    role_fields = set(roles.get(role_name, {}).get("visible_fields", []))

    if "*" in role_fields:
        visible = set(all_fields)
    else:
        visible = role_fields & all_fields

    ownership_cfg = access_control.get("ownership", {})
    if use_case is not None and user is not None and use_case.is_owned_by(user):
        if ownership_cfg.get("full_access"):
            visible = set(all_fields)
        else:
            visible |= set(ownership_cfg.get("additional_fields", [])) & all_fields

    return visible


def user_can_view_field(user: User | None, use_case: UseCase | None, field: str) -> bool:
    if field not in _configured_use_case_fields():
        return False
    return field in _visible_fields_for_user(user, use_case)


def _can_current_user_view_field(use_case: UseCase | None, field: str) -> bool:
    return user_can_view_field(current_user, use_case, field)


def _clean_cell(value) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


DEFAULT_CHART_COLOR_PALETTE = [
    "#a09f97",
    "#b5b4a9",
    "#8a8a84",
    "#c4cac5",
    "#074c3c",
    "#536a69",
    "#031e2d",
    "#0a5c8e",
    "#73325d",
    "#39122b",
]


def _chart_color_palette() -> list[str]:
    palette = _visualization_config().get("color_palette")
    if isinstance(palette, list):
        cleaned = []
        for color in palette:
            if color is None:
                continue
            text = str(color).strip()
            if text:
                cleaned.append(text)
        if cleaned:
            return cleaned
    return DEFAULT_CHART_COLOR_PALETTE


def _load_visualization_color_overrides() -> dict[str, str]:
    path = COLOR_OVERRIDE_PATH
    if has_app_context():
        override_path = current_app.config.get(
            "VISUALIZATION_COLOR_OVERRIDE_PATH", path
        )
        path = Path(override_path)
        if not path.is_absolute():
            path = Path(current_app.root_path) / path

    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return {}

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}

    if not isinstance(data, dict):
        return {}

    overrides: dict[str, str] = {}
    for key, value in data.items():
        if value is None:
            continue
        text = str(value).strip()
        if text:
            overrides[str(key)] = text

    return overrides


def _visualization_config() -> dict:
    config = current_app.config.get("USE_CASE_CONFIG", {})
    return config.get("visualizations", {})


def _visualization_filters_config() -> list[dict]:
    visuals = _visualization_config()
    return visuals.get("filters", [])


def _graphs_for_role(role: str | None) -> list[dict]:
    role = (role or "reader").lower()
    visuals = _visualization_config()
    graphs = visuals.get("graphs", [])
    accessible = []
    for graph in graphs:
        allowed_roles = graph.get("allowed_roles")
        if allowed_roles:
            if isinstance(allowed_roles, str):
                allowed = {allowed_roles.lower()}
            else:
                allowed = {str(item).lower() for item in allowed_roles}
            if role not in allowed:
                continue
        accessible.append(graph)
    return accessible


def _current_user_can_access_visualizations() -> bool:
    return bool(_graphs_for_role(getattr(current_user, "role", None)))


def _filters_for_role(role: str | None) -> list[dict]:
    role = (role or "reader").lower()
    filters = _visualization_filters_config()
    accessible = []
    for filter_config in filters:
        allowed_roles = filter_config.get("allowed_roles")
        if allowed_roles:
            if isinstance(allowed_roles, str):
                allowed = {allowed_roles.lower()}
            else:
                allowed = {str(item).lower() for item in allowed_roles}
            if role not in allowed:
                continue
        accessible.append(filter_config)
    return accessible


def _visualization_payload_for_user(
    user: User | None, use_cases: list[UseCase] | None = None
) -> list[dict]:
    configs = _graphs_for_role(getattr(user, "role", None))
    if not configs:
        return []

    if use_cases is None:
        use_cases = UseCase.query.all()

    used_ids: set[str] = set()
    prepared: list[dict] = []
    aggregations: list[tuple[int, dict, dict]] = []

    for index, config in enumerate(configs, start=1):
        aggregation = _aggregate_graph_values(config, use_cases)
        if aggregation is None:
            continue
        aggregations.append((index, config, aggregation))

    color_map = _assign_global_category_colors(aggregations)

    for index, config, aggregation in aggregations:
        prepared.append(
            _build_visualization_graph(
                config, aggregation, used_ids, index, color_map
            )
        )

    return prepared


def _prepare_visualization_filters(
    user: User | None, query_args
) -> tuple[list[dict], list[UseCase]]:
    accessible = _filters_for_role(getattr(user, "role", None))
    if not accessible:
        return [], UseCase.query.all()

    all_use_cases = UseCase.query.all()
    filtered_use_cases = list(all_use_cases)
    prepared_filters: list[dict] = []

    for config in accessible:
        field = config.get("field")
        if not field:
            continue

        filter_id = config.get("id") or field
        slug = _slugify_chart_id(str(filter_id))
        label = config.get("label") or field.replace("_", " ").title()
        filter_type = (config.get("type") or "select").lower()

        if filter_type == "select":
            param_name = f"filter_{slug}"
            raw_values = query_args.getlist(param_name)
            selected_values = [value for value in raw_values if value != ""]
            options = _build_select_filter_options(all_use_cases, field, config)
            if selected_values:
                filtered_use_cases = [
                    use_case
                    for use_case in filtered_use_cases
                    if _value_matches_select_filter(
                        getattr(use_case, field, None), selected_values, config
                    )
                ]
            selected_labels = [
                next(
                    (
                        option["label"]
                        for option in options
                        if option["value"] == value
                    ),
                    value,
                )
                for value in selected_values
            ]
            summary_text = _summarise_filter_selection(
                selected_labels, config.get("empty_label") or "All"
            )
            prepared_filters.append(
                {
                    "id": slug,
                    "label": label,
                    "type": "select",
                    "param": param_name,
                    "values": selected_values,
                    "options": options,
                    "empty_label": config.get("empty_label") or "All",
                    "is_active": bool(selected_values),
                    "size": config.get("size")
                    or max(3, min(len(options), 8)),
                    "help_text": config.get("help_text")
                    or "Leave unselected to include all values.",
                    "summary": summary_text,
                    "selected_labels": selected_labels,
                }
            )
        elif filter_type == "range":
            param_min = f"filter_{slug}_min"
            param_max = f"filter_{slug}_max"
            current_min = _parse_filter_number(query_args.get(param_min))
            current_max = _parse_filter_number(query_args.get(param_max))
            numeric_values = [
                value
                for value in (
                    _parse_filter_number(getattr(use_case, field, None))
                    for use_case in all_use_cases
                )
                if value is not None
            ]
            dataset_min = min(numeric_values) if numeric_values else None
            dataset_max = max(numeric_values) if numeric_values else None

            if current_min is not None:
                filtered_use_cases = [
                    use_case
                    for use_case in filtered_use_cases
                    if (
                        (value := _parse_filter_number(getattr(use_case, field, None)))
                        is not None
                        and value >= current_min
                    )
                ]
            if current_max is not None:
                filtered_use_cases = [
                    use_case
                    for use_case in filtered_use_cases
                    if (
                        (value := _parse_filter_number(getattr(use_case, field, None)))
                        is not None
                        and value <= current_max
                    )
                ]

            prepared_filters.append(
                {
                    "id": slug,
                    "label": label,
                    "type": "range",
                    "min_param": param_min,
                    "max_param": param_max,
                    "current_min": current_min,
                    "current_max": current_max,
                    "dataset_min": dataset_min,
                    "dataset_max": dataset_max,
                    "step": config.get("step"),
                    "unit": config.get("unit"),
                    "placeholder_min": config.get("placeholder_min") or "Min",
                    "placeholder_max": config.get("placeholder_max") or "Max",
                    "is_active": current_min is not None or current_max is not None,
                }
            )

    return prepared_filters, filtered_use_cases


def _build_visualization_graph(
    config: dict,
    aggregation: dict,
    used_ids: set[str],
    index: int,
    color_map: dict[str, str],
) -> dict:
    labels = aggregation["labels"]
    values = aggregation["values"]
    chart_type = _normalise_chart_type(config.get("type"))
    colors = [_resolve_category_color(label, color_map) for label in labels]
    dataset = {
        "label": aggregation["dataset_label"],
        "data": values,
        "backgroundColor": colors,
    }

    if chart_type == "bar":
        dataset["borderRadius"] = 6
        dataset["maxBarThickness"] = 48
    else:
        dataset["borderColor"] = "#ffffff"
        dataset["borderWidth"] = 1
        dataset["hoverOffset"] = 8

    return {
        "element_id": _unique_chart_element_id(config.get("id"), index, used_ids),
        "title": config.get("title") or "Untitled graph",
        "description": config.get("description"),
        "chart_type": chart_type,
        "labels": labels,
        "dataset": dataset,
        "options": config.get("chart_options") or {},
    }


def _build_select_filter_options(
    use_cases: list[UseCase], field: str, config: dict
) -> list[dict[str, str]]:
    seen: dict[str, str] = {}
    for use_case in use_cases:
        raw_value = getattr(use_case, field, None)
        for value in _split_filter_values(raw_value, config):
            key = _filter_option_key(value)
            label = _filter_option_label(value, config)
            if key not in seen:
                seen[key] = label
    options = [
        {"value": value, "label": label}
        for value, label in sorted(
            seen.items(), key=lambda item: item[1].lower() if item[1] else ""
        )
    ]
    return options


def _summarise_filter_selection(
    labels: list[str], default_label: str
) -> str:
    if not labels:
        return default_label
    if len(labels) == 1:
        return labels[0]
    if len(labels) == 2:
        return ", ".join(labels)
    return f"{labels[0]}, {labels[1]} +{len(labels) - 2} more"


def _filter_option_key(value) -> str:
    if value is None:
        return "__none__"
    if isinstance(value, str):
        text = value.strip()
        return text if text else "__empty__"
    return str(value)


def _filter_option_label(value, config: dict) -> str:
    missing_label = config.get("missing_label") or "Not specified"
    if value is None:
        return missing_label
    if isinstance(value, str):
        text = value.strip()
        return text or missing_label
    return str(value)


def _split_filter_values(value, config: dict) -> list:
    separator = config.get("value_separator")
    if separator and isinstance(value, str):
        parts = [part.strip() for part in value.split(separator)]
        parts = [part for part in parts if part]
        if parts:
            return parts
        return [""]
    return [value]


def _value_matches_select_filter(value, selected: list[str], config: dict) -> bool:
    if not selected:
        return True
    return any(
        _filter_option_key(candidate) in selected
        for candidate in _split_filter_values(value, config)
    )


def _parse_filter_number(value) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if not text:
        return None
    normalised = re.sub(r"[^0-9.+-]", "", text.replace(",", ""))
    if not normalised:
        return None
    try:
        return float(normalised)
    except ValueError:
        return None


def _aggregate_graph_values(
    config: dict, use_cases: list[UseCase]
) -> dict[str, list] | None:
    group_by = config.get("group_by")
    if not group_by:
        return None

    metric = config.get("metric") or {}
    operation = (metric.get("operation") or "count").lower()
    field = metric.get("field")
    default_label = config.get("missing_label", "Undefined")
    row_filters = config.get("row_filters") or []

    totals: dict[str, float] = {}
    for use_case in use_cases:
        if not _row_passes_filters(use_case, row_filters):
            continue
        raw_label = getattr(use_case, group_by, None)
        labels = _extract_group_labels(raw_label, default_label, config)

        if operation == "sum":
            if not field:
                return None
            value = _coerce_to_number(getattr(use_case, field, None))
        else:
            value = 1

        for label in labels:
            totals[label] = totals.get(label, 0) + value

    labels = list(totals.keys())
    values = list(totals.values())
    if operation != "sum":
        values = [int(value) for value in values]

    dataset_label = metric.get("label")
    if not dataset_label:
        dataset_label = (
            "Use case count"
            if operation == "count"
            else f"Sum of {field or ''}".strip()
        )

    return {"labels": labels, "values": values, "dataset_label": dataset_label}


def _assign_global_category_colors(
    graphs: list[tuple[int, dict, dict]]
) -> dict[str, str]:
    palette = _chart_color_palette()
    if not palette:
        palette = list(DEFAULT_CHART_COLOR_PALETTE)

    if not palette:
        palette = ["#808080"]

    overrides = _load_visualization_color_overrides()

    frequency: dict[str, int] = {}
    first_seen: dict[str, int] = {}
    order = 0

    for _, _, aggregation in graphs:
        for label in aggregation.get("labels", []):
            frequency[label] = frequency.get(label, 0) + 1
            if label not in first_seen:
                first_seen[label] = order
                order += 1

    if not frequency:
        return {}

    sorted_labels = sorted(
        frequency,
        key=lambda label: (-frequency[label], first_seen[label]),
    )

    color_map: dict[str, str] = {}
    palette_size = len(palette)
    if palette_size == 0:
        palette = ["#808080"]
        palette_size = 1

    palette_index = 0
    for label in sorted_labels:
        override_color = overrides.get(label)
        if override_color:
            color_map[label] = override_color
            continue

        color_map[label] = palette[palette_index % palette_size]
        palette_index += 1

    return color_map


def _resolve_category_color(label: str, color_map: dict[str, str]) -> str:
    color = color_map.get(label)
    if color:
        return color

    palette = _chart_color_palette()
    if not palette:
        return "#808080"

    fallback_index = abs(hash(label)) % len(palette)
    return palette[fallback_index]


def _normalise_chart_type(chart_type: str | None) -> str:
    mapping = {
        "donut": "doughnut",
        "doughnut": "doughnut",
        "pie": "pie",
        "bar": "bar",
    }
    if not chart_type:
        return "bar"
    return mapping.get(chart_type.lower(), "bar")


def _unique_chart_element_id(
    raw_id: str | None, index: int, used_ids: set[str]
) -> str:
    base = _slugify_chart_id(str(raw_id) if raw_id else f"graph-{index}")
    candidate = base
    suffix = 1
    while candidate in used_ids:
        suffix += 1
        candidate = f"{base}-{suffix}"
    used_ids.add(candidate)
    return f"chart-{candidate}"


def _slugify_chart_id(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", value).strip("-").lower()
    return slug or "graph"


def _coerce_to_number(value) -> float:
    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if not text:
        return 0.0
    normalised = re.sub(r"[^0-9.+-]", "", text.replace(",", ""))
    try:
        return float(normalised)
    except ValueError:
        return 0.0


def _row_passes_filters(use_case: UseCase, filters: list[dict]) -> bool:
    if not filters:
        return True

    for filter_config in filters:
        field = filter_config.get("field")
        if not field:
            continue

        operator = (filter_config.get("operator") or "equals").lower()
        raw_value = getattr(use_case, field, None)

        if operator == "not_empty":
            if raw_value is None:
                return False
            if isinstance(raw_value, str) and not raw_value.strip():
                return False
        elif operator == "equals":
            if raw_value != filter_config.get("value"):
                return False
        elif operator == "not_equals":
            if raw_value == filter_config.get("value"):
                return False
        elif operator == "in":
            values = filter_config.get("values")
            if values is None:
                return False
            normalised_values = {_normalise_filter_candidate(value) for value in values}
            if _normalise_filter_candidate(raw_value) not in normalised_values:
                return False
        elif operator == "not_in":
            values = filter_config.get("values")
            if values is None:
                continue
            normalised_values = {_normalise_filter_candidate(value) for value in values}
            if _normalise_filter_candidate(raw_value) in normalised_values:
                return False
        else:
            expected = filter_config.get("value")
            if expected is not None and raw_value != expected:
                return False

    return True


def _extract_group_labels(raw_value, default_label: str, config: dict) -> list[str]:
    separator = config.get("group_value_separator")

    if separator and isinstance(raw_value, str):
        parts = [part.strip() for part in raw_value.split(separator)]
        cleaned = [part for part in parts if part]
        if cleaned:
            return [str(part) for part in cleaned]
        return [default_label]

    if isinstance(raw_value, str):
        text = raw_value.strip()
        if text:
            return [text]
        return [default_label]

    if raw_value is None:
        return [default_label]

    return [str(raw_value)]


def _normalise_filter_candidate(value) -> str:
    if value is None:
        return "__none__"
    if isinstance(value, str):
        text = value.strip()
        return text or "__empty__"
    return str(value)


def _available_owner_choices(use_case: UseCase) -> list[tuple[int, str]]:
    owner_ids = {owner.id for owner in use_case.owners}
    return [
        (user.id, user.username)
        for user in User.query.order_by(User.username).all()
        if user.id not in owner_ids
    ]


def _upsert_user(*, username: str, password: str, role: str) -> None:
    """Create or update a user with the given credentials and role."""

    role = role.lower()
    if role not in {"admin", "reader"}:
        raise ValueError("Role must be either 'admin' or 'reader'.")

    user = User.query.filter_by(username=username).first()
    if user is None:
        user = User(username=username)
        db.session.add(user)

    user.role = role
    user.set_password(password)
    db.session.commit()


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
