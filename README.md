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

By default the importer expects the columns defined in
[`use_case_config.json`](./use_case_config.json).【F:use_case_config.json†L1-L70】
The table below summarises the stock configuration:

| Model field | Spreadsheet column | Purpose |
| ----------- | ------------------ | ------- |
| `title` | `Use Case Name` | Required. Displayed as the card and detail page title. |
| `industry` | `Business Sector` | Optional business domain badge. |
| `summary` | `Description` | Short teaser for the dashboard cards. |
| `synergy` | `Synergy` | Captures collaboration or alignment notes introduced in this update. |
| `problem` | `ProblemStatement` | Challenge the use case aims to solve. |
| `solution` | `SolutionDescription` | Approach or technology used. |
| `impact` | `Business Value Estimate (Numerical)` | Numeric or textual impact statement. |
| `data_source` | `Source Stage` | Where the information originated. |
| `status_color` | `New Type of Business Benefit` | Used for status chips in the UI. |
| `tags` | `New Domain Mapping for G Level` | Comma-separated tags for filtering. |

Columns not referenced in the configuration are ignored during import, but the
uploaded spreadsheet is preserved under `instance/uploads/` for auditing.

### Customising the importer and field metadata

The `use_case_config.json` file controls both the importer and the labels you
see in the UI. Its top-level `"import"` section contains two important keys:

- `"default_missing_value"`: the fallback used when a column is missing and no
  field-specific default is supplied.
- `"fields"`: a dictionary keyed by model attribute (`title`, `synergy`, …)
  that configures how each attribute is handled.

Each field entry can define the following properties:

| Property | Meaning |
| -------- | ------- |
| `column` | Name of the spreadsheet header to read. Leave it out to skip import for that field. |
| `required` | When `true`, rows missing a value will fall back to the global or field default to keep imports consistent. |
| `default` | Value used if the column is absent or the cell is empty. Overrides `default_missing_value` for that field. |
| `label` | Friendly name reused for form labels, table headings and filters. |

Because the configuration drives the UI, changes here update the application
without modifying templates. For example, renaming the `synergy` label will
automatically update the form field and detail view headings.

### Customising dashboard visualisations

Charts and filters on the **Data visualisations** page are defined in the
`"visualizations"` section of [`use_case_config.json`](./use_case_config.json).
It contains three parts:

- `color_palette`: optional hex colours reused by charts (falls back to a
  built-in palette when omitted).
- `filters`: controls the dropdowns and range inputs rendered above the charts.
- `graphs`: the list of visualisations available to users. Each entry becomes a
  Chart.js configuration at runtime.

#### Adding a new chart

1. Decide which model attribute should drive the grouping. For example, the
   built-in *Synergy coverage by sector* donut counts `synergy` entries per
   `industry` value.
2. Create a new object inside the `"graphs"` array with at least these keys:
   - `id`: unique identifier used to generate the `<canvas>` element ID.
   - `title`/`description`: text displayed above and below the chart.
   - `type`: one of `"bar"`, `"donut"`/`"doughnut"`, or `"pie"`.
   - `group_by`: the model field whose values become the chart labels.
   - `metric`: controls how values are calculated. Use `{"operation": "count"}`
     to count records, or `{"operation": "sum", "field": "impact"}` to sum a
     numeric column. The optional `label` customises the dataset legend.
   - `allowed_roles`: restricts visibility to the listed roles.
   - `missing_label`: fallback label for empty or `NULL` values.
3. (Optional) Add `chart_options` to pass additional Chart.js settings such as
   axis tweaks for bar charts.
4. Save the file and refresh the browser. The Flask app hot-reloads the
   configuration without requiring a restart.

#### Filtering and splitting grouped values

- `row_filters`: array of conditions applied before aggregating data. Each
  filter requires a `field` and an `operator`. Supported operators are
  `not_empty`, `equals`, `not_equals`, `in`, and `not_in`. For example, the
  synergy charts filter out records where the `synergy` column is blank so the
  donut only counts meaningful entries.
- `group_value_separator`: when set (for example to `","`), string values in
  the `group_by` field are split into multiple labels. This is handy for comma-
  separated tags—each tag receives its own slice while the chart still honours
  the configured metric.

#### Changing an existing mapping

1. Update your spreadsheet header to the new name.
2. Edit the corresponding entry under `"fields"` so its `"column"` value matches
   the new header. Adjust `"label"` if you want the UI text to change as well.

No database changes are required because the underlying SQL column keeps the
same name.

#### Removing a field from imports

Delete the field entry from the `"fields"` dictionary. The importer will stop
looking for that column and will no longer populate the associated model
attribute. If you also want the field gone from the UI, remove or hide the
corresponding form field and template snippets in `app.py` and `templates/`.

#### Adding a new field

1. Create a new column on the `UseCase` model in `app.py` (for example,
   `benefit_type = db.Column(db.String(120))`).【F:app.py†L140-L211】
   Run `flask --app app init-db` to rebuild the SQLite database when working
   locally without migrations.
2. Add matching inputs to `UseCaseForm` and render them where appropriate in the
   templates so the field is editable.
3. Extend the configuration with a new mapping, including a `column` that matches
   your spreadsheet header, an optional `default`, and a `label` for the UI.
4. Populate the new column in your spreadsheet and import it—the importer will
   pick up the field automatically once it appears in the configuration.

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
