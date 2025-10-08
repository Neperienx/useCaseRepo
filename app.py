"""
A simple Flask web application that demonstrates how to
upload an Excel file, store its contents in a PostgreSQL
database and implement very basic role‑based permissions.

This proof‑of‑concept uses Flask, Flask‑SQLAlchemy and
Flask‑Login.  It defines two roles — `reader` and `admin` —
to restrict who can upload data or modify it.  Records are
stored in a single table with a JSON column so that the
application can cope with arbitrary Excel layouts.

To run this app locally:

1.  Ensure you have a running PostgreSQL database.  You
    can adjust the database connection string by setting
    the `DATABASE_URI` environment variable.  The default
    points at `postgresql://user:password@localhost:5432/mydb`.
2.  Install dependencies from `requirements.txt`:

        pip install -r requirements.txt

3.  Initialise the database tables by running the script
    once with the `initdb` argument:

        python app.py initdb

    This creates the tables and, if no users exist, also
    creates a default administrator account with username
    `admin` and password `admin`.  Change the password in
    production!
4.  Start the development server with:

        python app.py run

5.  Visit http://localhost:5000 in your browser, log in
    and start uploading Excel files.

This code is intentionally minimal.  It leaves many
concerns (such as password resets, CSRF protection on
forms, and input validation) to future iterations.  The
goal is to provide a working baseline that you can extend
over the course of a weekend.
"""

import os
import sys
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    send_from_directory,
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    login_user,
    login_required,
    logout_user,
    current_user,
    UserMixin,
)
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

app = Flask(__name__)

# In a production setting you should set the secret key and database
# connection via environment variables.  Here we provide sensible
# defaults for a local proof of concept.
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')

# Use the DATABASE_URI environment variable if provided; otherwise use
# a local Postgres database.  The URI format is documented in the
# SQLAlchemy docs.  See https://vsupalov.com/flask-sqlalchemy-postgres/
# for details on constructing the URI【649052990375149†L85-L90】.
default_db = 'postgresql://user:password@localhost:5432/mydb'
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', default_db)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class User(db.Model, UserMixin):
    """Simple user model with role field.

    The `role` column stores either 'admin' or 'reader'.  In a real
    application you might use a many‑to‑many relationship to support
    more complex role hierarchies【174427130110899†L105-L116】.  For this POC
    we keep it simple.
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='reader')

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def is_admin(self) -> bool:
        return self.role == 'admin'


class Record(db.Model):
    """Data imported from Excel.

    Each record stores a single row of the uploaded spreadsheet in
    JSON format.  Using JSON allows the table to accommodate any
    column names without altering the schema.  See the pandas
    integration example for reading Excel files【954885212002298†L189-L225】.
    """
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.JSON, nullable=False)


# ---------------------------------------------------------------------------
# User loader for Flask‑Login
# ---------------------------------------------------------------------------

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ---------------------------------------------------------------------------
# Command‑line helpers
# ---------------------------------------------------------------------------

def init_db() -> None:
    """Initialise database tables and create a default admin user."""
    with app.app_context():
        db.create_all()
        # If no users exist, create a default admin account
        if User.query.count() == 0:
            admin = User(username='admin', role='admin')
            admin.set_password('admin')
            db.session.add(admin)
            db.session.commit()
            print(
                'Initialized the database and created default admin user ' \
                'with username="admin" and password="admin".  Change the password!'
            )
        else:
            print('Database already initialised.')


def run_server() -> None:
    """Run the Flask development server."""
    app.run(debug=True)


# ---------------------------------------------------------------------------
# Views / Routes
# ---------------------------------------------------------------------------

@app.route('/')
@login_required
def index():
    """List records and provide navigation based on role."""
    records = Record.query.all()
    return render_template('index.html', records=records)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Log in an existing user."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    """Allow admins to upload an Excel file and import its rows."""
    # Enforce admin role
    if not current_user.is_admin():
        flash('You do not have permission to upload files.')
        return redirect(url_for('index'))

    if request.method == 'POST':
        # Ensure a file was submitted
        file = request.files.get('file')
        if not file or file.filename == '':
            flash('Please select a file to upload.')
            return redirect(request.url)

        try:
            # Save file to a temporary location (optional) and parse
            # using pandas.  The GeeksforGeeks example demonstrates
            # reading Excel from request.files and converting to a
            # DataFrame【954885212002298†L189-L225】.
            df = pd.read_excel(file)
        except Exception as exc:
            flash(f'Error reading Excel file: {exc}')
            return redirect(request.url)

        # Convert rows into JSON records and insert into database
        for _, row in df.iterrows():
            record = Record(data=row.to_dict())
            db.session.add(record)
        db.session.commit()
        flash(f'Successfully imported {len(df)} rows.')
        return redirect(url_for('index'))

    return render_template('upload.html')


@app.route('/record/<int:record_id>/delete', methods=['POST'])
@login_required
def delete_record(record_id: int):
    """Delete a record.  Only admins may perform this action."""
    if not current_user.is_admin():
        flash('You do not have permission to delete records.')
        return redirect(url_for('index'))

    record = Record.query.get_or_404(record_id)
    db.session.delete(record)
    db.session.commit()
    flash('Record deleted.')
    return redirect(url_for('index'))


@app.route('/record/<int:record_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_record(record_id: int):
    """Edit a record's JSON data.  Only admins may edit."""
    if not current_user.is_admin():
        flash('You do not have permission to edit records.')
        return redirect(url_for('index'))

    record = Record.query.get_or_404(record_id)
    if request.method == 'POST':
        # We expect a JSON string in the form field named 'data'
        # which should contain a valid Python dictionary literal.
        try:
            new_data = request.form['data']
            # Evaluate user input carefully.  For a real app you
            # should validate and parse JSON safely.  Here we use
            # eval() for brevity — DO NOT use eval() in production.
            record.data = eval(new_data)
            db.session.commit()
            flash('Record updated.')
            return redirect(url_for('index'))
        except Exception as exc:
            flash(f'Invalid data: {exc}')
            return redirect(request.url)
    return render_template('edit_record.html', record=record)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == 'initdb':
            init_db()
        elif cmd == 'run':
            run_server()
        else:
            print('Unknown command.  Use "initdb" or "run".')
    else:
        # Default behaviour: run the development server
        run_server()