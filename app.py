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
from sqlalchemy import func, or_
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
    problem = TextAreaField("Problem", validators=[Optional()])
    solution = TextAreaField("Solution", validators=[Optional()])
    impact = TextAreaField("Impact", validators=[Optional()])
    data_source = StringField("Data source", validators=[Optional(), Length(max=200)])
    tags = StringField(
        "Tags", validators=[Optional(), Length(max=200)],
        description="Comma-separated labels such as industries or technologies."
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
                    func.lower(UseCase.tags).like(like),
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
        )

    @app.route("/visualizations")
    @login_required
    def visualizations():
        graphs = _visualization_payload_for_user(current_user)
        return render_template("visualizations.html", graphs=graphs)

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
                problem=form.problem.data or None,
                solution=form.solution.data or None,
                impact=form.impact.data or None,
                data_source=form.data_source.data or None,
                tags=form.tags.data or None,
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
        return render_template(
            "use_case_detail.html",
            use_case=use_case,
            owners=owners,
            owner_form=owner_form,
            can_manage_use_case=can_manage,
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


CHART_COLOR_PALETTE = [
    "#4F46E5",
    "#F97316",
    "#22D3EE",
    "#10B981",
    "#EC4899",
    "#6366F1",
    "#EAB308",
    "#0EA5E9",
    "#F43F5E",
    "#14B8A6",
]


def _visualization_config() -> dict:
    config = current_app.config.get("USE_CASE_CONFIG", {})
    return config.get("visualizations", {})


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


def _visualization_payload_for_user(user: User | None) -> list[dict]:
    configs = _graphs_for_role(getattr(user, "role", None))
    if not configs:
        return []

    use_cases = UseCase.query.all()
    used_ids: set[str] = set()
    prepared: list[dict] = []
    for index, config in enumerate(configs, start=1):
        payload = _build_visualization_graph(config, use_cases, used_ids, index)
        if payload is not None:
            prepared.append(payload)
    return prepared


def _build_visualization_graph(
    config: dict, use_cases: list[UseCase], used_ids: set[str], index: int
) -> dict | None:
    aggregation = _aggregate_graph_values(config, use_cases)
    if aggregation is None:
        return None

    labels = aggregation["labels"]
    values = aggregation["values"]
    chart_type = _normalise_chart_type(config.get("type"))
    colors = _chart_colors(len(labels))
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

    totals: dict[str, float] = {}
    for use_case in use_cases:
        raw_label = getattr(use_case, group_by, None)
        if isinstance(raw_label, str):
            raw_label = raw_label.strip()
        label = str(raw_label) if raw_label else default_label

        if operation == "sum":
            if not field:
                return None
            value = _coerce_to_number(getattr(use_case, field, None))
        else:
            value = 1

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


def _chart_colors(count: int) -> list[str]:
    if count <= 0:
        return []
    palette = []
    for index in range(count):
        palette.append(CHART_COLOR_PALETTE[index % len(CHART_COLOR_PALETTE)])
    return palette


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
    normalised = text.replace(",", "")
    try:
        return float(normalised)
    except ValueError:
        return 0.0


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
