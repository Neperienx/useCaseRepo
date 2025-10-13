# AI Use Case Library

A local-first data management tool built with Flask for curating a catalogue of
AI use cases.  The project targets **Python 3.13.7** and uses SQLite by default
so you can run everything on your laptop.  A password-protected admin interface
lets you add, edit, delete and bulk-import records from Excel spreadsheets.

Inspired by [casebase.ai](https://casebase.ai/en/ai-use-case-collection/), the
app focuses on a clean browsing experience with filters for search and
industries.

---

## ✨ Features

- Modern Flask 3 application with SQLAlchemy 2 models
- Local SQLite database stored in the `instance/` folder
- Password-protected login using Flask-Login
- Role-based permissions (`admin` vs `reader` with restricted Impact visibility)
- Create, edit and delete AI use case entries from the web UI
- Detail pages with structured sections (summary, problem, solution, impact)
- Excel importer supporting append or replace modes
- Responsive dashboard with search and industry filters

---

## 🚀 Getting started

### 1. Prerequisites

- **Python 3.13.7** installed and available on your `PATH`.
- (Optional) [pipx](https://pypa.github.io/pipx/) or a similar tool if you
  prefer managing virtual environments automatically.

You can confirm the interpreter version with:

```bash
python --version
```

If you have multiple Python installations, explicitly call `python3.13` (Unix)
or `py -3.13` (Windows).

### 2. Create and activate a virtual environment

```bash
# macOS / Linux
python3.13 -m venv .venv
source .venv/bin/activate

# Windows (PowerShell)
py -3.13 -m venv .venv
.venv\Scripts\Activate.ps1
```

When the environment is active, your prompt shows `(.venv)`.

### 3. Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

If the `flask` command is not found afterwards, use `python -m flask` (Unix) or
`py -m flask` (Windows) as a drop-in replacement in the steps below.

### 4. Initialise the database

```bash
flask --app app init-db
```

This creates `instance/use_cases.db`. The folder is generated automatically, so
no manual directory setup is required.

### 5. Create user accounts

Two roles are available:

- **admin** users can create, edit, delete and import use cases.
- **reader** users can browse every record but the *Impact* section remains
  hidden from them on detail pages.

Create an administrator account (or update an existing one) with:

```bash
flask --app app create-admin your_admin_username
# You will be prompted for a password twice
```

Create a reader account with:

```bash
flask --app app create-user your_reader_username --role reader
# You will be prompted for a password twice
```

You can rerun either command to reset the password or adjust the role assigned
to a username (for example `flask --app app create-user analyst --role admin`).

### 6. Start the development server

```bash
flask --app app run --debug
```

By default the app listens on http://127.0.0.1:5000. Sign in with the admin
credentials you created in the previous step.

> ℹ️ To point the app at a different database, set the `DATABASE_URI`
> environment variable before running the commands above. Any SQLAlchemy-
> compatible URI will work (for example, PostgreSQL when you outgrow SQLite).

### 7. Deactivate the environment when finished

```bash
deactivate
```

Run `.venv\Scripts\Activate.ps1` (PowerShell) or `source .venv/bin/activate`
again the next time you work on the project.

---

## 📄 Spreadsheet format

When importing from Excel the following columns are recognised:

| Column name | Purpose |
| ----------- | ------- |
| `Title` | Required. Becomes the record title. |
| `Summary` | Short description shown in the dashboard cards. |
| `Industry` | Optional label rendered as a pill. |
| `Problem`, `Solution`, `Impact` | Rendered on the detail page. |
| `Tags` | Comma separated list of tags for quick filtering. |
| `Data Source` | Track where the information came from. |

Additional columns are ignored but preserved in the uploaded file stored inside
`instance/uploads/` for reference.

### Customising the importer

The spreadsheet importer is configuration-driven. All column mappings live in
[`use_case_config.json`](./use_case_config.json) under the top-level
`"import"` key. Each entry maps a model field (for example `industry`) to the
expected spreadsheet column header via a `"column"` value and optionally
declares a fallback `"default"` when the column is missing.【F:use_case_config.json†L1-L34】

#### Changing a column header (e.g. `Industry` → `Domain`)

1. Update the spreadsheet header from **Industry** to **Domain**.
2. Edit the `industry` mapping in `use_case_config.json` so the `"column"`
   attribute reads `"Domain"` instead of `"Industry"`.
3. (Optional) Rename any user-facing labels in the UI to keep them consistent:
   - Form field label in `app.py` (`UseCaseForm.industry`).【F:app.py†L188-L200】
   - Dashboard filter label in `templates/index.html`.
   - Helper text on the upload page in `templates/upload.html`.

The database column remains `industry`, so no schema changes are required.

#### Adding a new column (e.g. `Type of benefits`)

1. Add a new field to the `UseCase` model in `app.py` (for example
   `benefit_type = db.Column(db.String(120))`).【F:app.py†L150-L210】
   Recreate the SQLite database with `flask --app app init-db` if you are not
   using migrations.
2. Expose the field in `UseCaseForm` so it can be edited through the UI and
   display it where appropriate in the templates.
3. Extend `use_case_config.json` with a new mapping. For instance:

   ```json
   "benefit_type": {
     "column": "Type of benefits",
     "default": "Undefined"
   }
   ```

4. Add the new column to your spreadsheet and populate the values before
   importing.

The importer automatically picks up any fields defined in the configuration
file, so no changes to the import logic are necessary once the mapping exists.

---

## 🛠️ Useful commands

```bash
# Delete and rebuild the SQLite database
rm -f instance/use_cases.db
flask --app app init-db

# Run the app with a custom secret key
SECRET_KEY="change-me" flask --app app run

# Windows PowerShell equivalents
Remove-Item instance/use_cases.db -ErrorAction Ignore
flask --app app init-db
${env:SECRET_KEY} = "change-me"; flask --app app run
```

> 💡 Troubleshooting tips
> - `ModuleNotFoundError`: double-check your virtual environment is activated
>   before running `flask` commands.
> - `sqlite3.OperationalError: unable to open database file`: ensure you have
>   write permissions inside the project folder. Running `flask --app app
>   init-db` creates the `instance/` directory automatically.
> - To inspect the generated database, use a GUI such as
>   [SQLite Browser](https://sqlitebrowser.org/) and open `instance/use_cases.db`.

---

## 🧩 Project structure

```
useCaseRepo/
├── app.py              # Flask application, models, routes and CLI helpers
├── requirements.txt    # Python dependencies compatible with 3.13.7
├── templates/          # Jinja2 templates for pages and components
└── static/css/         # Styling for the dashboard
```

---

## ✅ Next ideas

- Enable CSV ingestion alongside Excel
- Add analytics widgets (e.g. counts per industry)
- Integrate a markdown editor for richer descriptions
- Connect to an LLM to recommend related use cases automatically

Enjoy exploring and extending your AI use case library!
