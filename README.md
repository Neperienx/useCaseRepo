# Flask Excel CRUD App

A minimal Flask-based web application that allows internal users to upload Excel files and store the contents in a PostgreSQL database. It supports user authentication with role-based access (admin and reader), and provides basic Create, Read, Update, Delete (CRUD) operations via a web interface.

---

## ✅ Implemented Features

### 🧱 Core Functionality
- Upload Excel file (`.xlsx` or `.xls`) via web interface
- Parse Excel into a DataFrame using `pandas`
- Store each row in a PostgreSQL table as a JSON record
- Display a table of all stored records on the index page

### 👤 User Authentication
- Simple login form
- User session managed via `Flask-Login`
- Two user roles:
  - `admin`: full CRUD access and upload permissions
  - `reader`: view-only access

### 🔐 Role-Based Access Control
- Admins can:
  - Upload Excel files
  - Edit or delete individual records
- Readers can:
  - View the list of records
  - View login-protected pages, but not perform writes

### 🖥️ Frontend
- HTML templates using Jinja2
- Clean layout with navigation
- Pages:
  - `/login` – Login page
  - `/logout` – Logout action
  - `/` – List records
  - `/upload` – Upload Excel
  - `/edit/<id>` – Edit individual record (admins only)

### 💾 Tech Stack
- Python 3.11+
- Flask 3.0+
- Flask-SQLAlchemy
- Flask-Login
- PostgreSQL
- Pandas + OpenPyXL

---

## 🔧 Setup Instructions

```bash
# 1. Clone the repo and install dependencies
pip install -r requirements.txt

# 2. Export a DATABASE_URL environment variable
export DATABASE_URL=postgresql://username:password@localhost:5432/mydb

# 3. Run initial DB setup
python app.py initdb

# 4. Start the Flask app
python app.py run
