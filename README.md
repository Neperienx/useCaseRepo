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
- Role-based permissions (`admin` vs `reader`)
- Create, edit and delete AI use case entries from the web UI
- Detail pages with structured sections (summary, problem, solution, impact)
- Excel importer supporting append or replace modes
- Responsive dashboard with search and industry filters

---

## 🚀 Getting started

1. **Install dependencies (Python 3.13.7):**

   ```bash
   python3.13 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Initialise the database:**

   ```bash
   flask --app app init-db
   ```

3. **Create an administrator account:**

   ```bash
   flask --app app create-admin your_username
   # You will be prompted for a password
   ```

4. **Run the development server:**

   ```bash
   flask --app app run --debug
   ```

5. **Visit the dashboard:** Open http://127.0.0.1:5000 and sign in with the
   credentials you created above.

> ℹ️ To point the app at a different database, set the `DATABASE_URI`
> environment variable before running the commands above.  Any SQLAlchemy
> compatible URI will work (for example, PostgreSQL when you outgrow SQLite).

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

---

## 🛠️ Useful commands

```bash
# Delete and rebuild the SQLite database
rm -f instance/use_cases.db
flask --app app init-db

# Run the app with a custom secret key
SECRET_KEY="change-me" flask --app app run
```

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
