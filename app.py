
import os
import sqlite3
import hashlib
import secrets
import mimetypes
from functools import wraps
from pathlib import Path

from flask import (
    Flask, request, redirect, url_for, session,
    flash, render_template_string, send_from_directory,
    abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "trustvault.db"
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("TRUSTVAULT_SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user'
                    CHECK(role IN ('user', 'admin')),
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                stored_name TEXT NOT NULL UNIQUE,
                file_hash TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(owner_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS shares (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_id INTEGER NOT NULL,
                shared_with INTEGER NOT NULL,
                permission TEXT NOT NULL DEFAULT 'view'
                    CHECK(permission IN ('view', 'download')),
                UNIQUE(document_id, shared_with),
                FOREIGN KEY(document_id) REFERENCES documents(id),
                FOREIGN KEY(shared_with) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                details TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
                    ON DELETE SET NULL
            );
        """)


def log_action(action, details=""):
    with get_db() as db:
        db.execute(
            "INSERT INTO audit_logs(user_id, action, details) VALUES (?, ?, ?)",
            (session.get("user_id"), action, details[:500])
        )


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "error")
            return redirect(url_for("home"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "error")
            return redirect(url_for("home"))
        if session.get("role") != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


PAGE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TrustVault | Secure Document Sharing</title>
<style>
*{box-sizing:border-box}
body{margin:0;font-family:Arial,sans-serif;background:#f3f6fc;color:#172033}
nav{background:#101b35;color:white;padding:18px 6%;display:flex;
justify-content:space-between;align-items:center;gap:15px;flex-wrap:wrap}
.brand{font-size:23px;font-weight:bold}
nav a{color:white;text-decoration:none;margin-left:15px}
.container{max-width:1050px;margin:35px auto;padding:0 18px}
.hero,.panel{background:white;padding:28px;border-radius:14px;
box-shadow:0 5px 22px #18284812;margin-bottom:22px}
h1{font-size:35px;margin-bottom:10px}
h2{margin-top:0}
p{line-height:1.6;color:#596579}
button,.btn{border:0;border-radius:7px;padding:11px 17px;
background:#345de0;color:white;cursor:pointer;font-weight:bold;text-decoration:none;
display:inline-block}
button:hover,.btn:hover{background:#2346bd}
.secondary{background:#e7edff;color:#2448b8}
.danger{background:#b42332}
input,select{width:100%;padding:12px;margin:7px 0 15px;
border:1px solid #cdd5e1;border-radius:7px}
label{font-weight:bold;font-size:14px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px}
.stat{background:#eef2ff;padding:18px;border-radius:10px}
table{width:100%;border-collapse:collapse;background:white}
th,td{text-align:left;padding:12px;border-bottom:1px solid #e7eaf0}
th{background:#eef2ff}
.table-wrap{overflow-x:auto}
.muted{font-size:13px;color:#697586}
.modal{display:none;position:fixed;inset:0;background:#091326bb;
z-index:10;align-items:center;justify-content:center;padding:18px}
.modal.show{display:flex}
.modal-box{position:relative;background:white;width:100%;max-width:440px;
padding:28px;border-radius:14px;max-height:90vh;overflow:auto}
.close{position:absolute;right:15px;top:12px;background:#e8edf5;color:#172033}
.notice{padding:12px 15px;border-radius:8px;margin:12px 0;background:#e8f7ee}
.notice.error{background:#fff0f0}
.actions{display:flex;gap:10px;flex-wrap:wrap}
footer{text-align:center;padding:25px;color:#758096}
</style>
</head>
<body>
<nav>
 <div class="brand">🔐 TrustVault</div>
 <div>
 {% if user %}
   <span>{{ user.name }}</span>
   {% if user.role == 'admin' %}
     <a href="{{ url_for('admin_dashboard') }}">Admin</a>
     <a href="{{ url_for('audit_logs') }}">Audit Logs</a>
   {% endif %}
   <a href="{{ url_for('home') }}">Dashboard</a>
   <a href="{{ url_for('logout') }}">Logout</a>
 {% else %}
   <a href="{{ url_for('home') }}">Home</a>
   <button onclick="openModal('loginModal')">Login</button>
   <button class="secondary" onclick="openModal('registerModal')">Create Account</button>
 {% endif %}
 </div>
</nav>

<main class="container">
{% for category, message in get_flashed_messages(with_categories=true) %}
  <div class="notice {{ 'error' if category == 'error' else '' }}">{{ message }}</div>
{% endfor %}

{% if not user %}
<section class="hero">
 <h1>Share documents. Stay in control.</h1>
 <p>TrustVault helps teams manage confidential documents with account-based access,
 sharing permissions, document integrity checks and an audit trail.</p>
 <div class="actions">
  <button onclick="openModal('registerModal')">Create Account</button>
  <button class="secondary" onclick="openModal('loginModal')">Login</button>
 </div>
 <p class="muted">Register an account to access the document dashboard.</p>
</section>
<section class="grid">
 <div class="panel"><h2>🔒 Secure access</h2><p>Login-based access to your documents.</p></div>
 <div class="panel"><h2>👥 Sharing controls</h2><p>Grant access to registered users.</p></div>
 <div class="panel"><h2>🧾 Audit trail</h2><p>Administrators can review recorded actions.</p></div>
</section>
{% else %}
<section class="hero">
 <h1>Hello, {{ user.name }}!</h1>
 <p>Welcome to your TrustVault dashboard.</p>
 <div class="grid">
  <div class="stat"><b>Account</b><p>{{ user.email }}</p></div>
  <div class="stat"><b>Role</b><p>{{ user.role|title }}</p></div>
  <div class="stat"><b>Accessible documents</b><p>{{ documents|length }}</p></div>
 </div>
</section>

<section class="panel">
 <h2>Upload a document</h2>
 <p>Maximum file size: 10 MB. Upload only files you are authorized to store.</p>
 <form action="{{ url_for('upload_document') }}" method="post" enctype="multipart/form-data">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <label>Select document</label>
  <input type="file" name="document" required>
  <button type="submit">Upload Document</button>
 </form>
</section>

<section class="panel">
 <h2>Your accessible documents</h2>
 {% if documents %}
 <div class="table-wrap"><table>
 <tr><th>Document</th><th>Owner</th><th>SHA-256</th><th>Actions</th></tr>
 {% for doc in documents %}
 <tr>
  <td>{{ doc.filename }}</td><td>{{ doc.owner_name }}</td>
  <td><span title="{{ doc.file_hash }}">{{ doc.file_hash[:12] }}...</span></td>
  <td>
   <div class="actions">
   <a class="btn"
   href="{{ url_for('view_document', document_id=doc.id) }}"
   target="_blank"
   rel="noopener">
    View
</a>
    <a class="btn" href="{{ url_for('download_document', document_id=doc.id) }}">Download</a>
    {% if doc.owner_id == user.id %}
    <button class="secondary"
onclick="document.getElementById('shareDocumentId').value='{{ doc.id }}'; document.getElementById('shareFilename').textContent='Document: {{ doc.filename|e }}'; document.getElementById('shareModal').classList.add('show');">
Share
</button>
    {% endif %}
   </div>
  </td>
 </tr>
 {% endfor %}
 </table></div>
 {% else %}
 <p>No documents available yet. Upload your first document above.</p>
 {% endif %}
</section>
{% endif %}
</main>

{% if not user %}
<div class="modal" id="loginModal" role="dialog" aria-modal="true" aria-labelledby="loginTitle">
 <div class="modal-box">
  <button class="close" onclick="closeModal('loginModal')">✕</button>
  <h2 id="loginTitle">Login to TrustVault</h2>
  <form method="post" action="{{ url_for('login') }}">
   <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
   <label>Email address</label><input type="email" name="email" required>
   <label>Password</label><input type="password" name="password" required>
   <button type="submit">Login</button>
  </form>
  <p>New user? <a href="#" onclick="switchModal('loginModal','registerModal');return false">Create an account</a></p>
 </div>
</div>

<div class="modal" id="registerModal" role="dialog" aria-modal="true" aria-labelledby="registerTitle">
 <div class="modal-box">
  <button class="close" onclick="closeModal('registerModal')">✕</button>
  <h2 id="registerTitle">Create your account</h2>
  <form method="post" action="{{ url_for('register') }}">
   <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
   <label>Full name</label><input type="text" name="name" maxlength="100" required>
   <label>Email address</label><input type="email" name="email" maxlength="254" required>
   <label>Password (minimum 8 characters)</label><input type="password" name="password" minlength="8" required>
   <button type="submit">Create Account</button>
  </form>
  <p>Already registered? <a href="#" onclick="switchModal('registerModal','loginModal');return false">Login</a></p>
 </div>
</div>
{% endif %}

{% if user %}
<div class="modal" id="shareModal" role="dialog" aria-modal="true">
 <div class="modal-box">
  <button class="close" onclick="closeModal('shareModal')">✕</button>
  <h2>Share document</h2><p id="shareFilename"></p>
  <form method="post" action="{{ url_for('share_document') }}">
   <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
   <input type="hidden" name="document_id" id="shareDocumentId">
   <label>Registered user's email</label><input type="email" name="email" required>
   <label>Permission</label>
   <select name="permission"><option value="view">View only</option>
   <option value="download">View and download</option></select>
   <button type="submit">Share Document</button>
  </form>
 </div>
</div>
{% endif %}

<footer>TrustVault · Secure Document Sharing with a Real Audit Trail</footer>
<script>
function openModal(id){const m=document.getElementById(id);if(m)m.classList.add('show')}
function closeModal(id){const m=document.getElementById(id);if(m)m.classList.remove('show')}
function switchModal(oldId,newId){closeModal(oldId);openModal(newId)}
function openShare(id, name) {
    const modal = document.getElementById('shareModal');
    const documentId = document.getElementById('shareDocumentId');
    const filename = document.getElementById('shareFilename');

    if (!modal || !documentId || !filename) {
        alert('Share form not found. Please refresh the page.');
        return;
    }

    documentId.value = id;
    filename.textContent = 'Document: ' + name;
    modal.classList.add('show');
}
document.querySelectorAll('.modal').forEach(m=>{
 m.addEventListener('click',e=>{if(e.target===m)m.classList.remove('show')});
});
document.addEventListener('keydown',e=>{
 if(e.key==='Escape')document.querySelectorAll('.modal.show').forEach(m=>m.classList.remove('show'));
});
{% if open_modal %}
openModal({{ open_modal|tojson }});
{% endif %}
</script>
</body>
</html>
"""


def render_page(documents=None, open_modal=None, status=200):
    with get_db() as db:
        user = db.execute(
            "SELECT id, name, email, role FROM users WHERE id = ?",
            (session.get("user_id"),)
        ).fetchone() if session.get("user_id") else None

    if documents is None:
        documents = []
        if user:
            with get_db() as db:
                documents = db.execute("""
                    SELECT DISTINCT d.*, u.name AS owner_name
                    FROM documents d
                    JOIN users u ON u.id = d.owner_id
                    LEFT JOIN shares s ON s.document_id = d.id
                    WHERE d.owner_id = ? OR s.shared_with = ?
                    ORDER BY d.id DESC
                """, (user["id"], user["id"])).fetchall()

    return render_template_string(
        PAGE,
        user=user,
        documents=documents,
        open_modal=open_modal,
        csrf_token=session.setdefault("csrf_token", secrets.token_urlsafe(32))
    ), status


def check_csrf():
    token = request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    if not expected or not secrets.compare_digest(token, expected):
        abort(400, description="Invalid form token. Refresh the page and try again.")


@app.route("/")
def home():
    return render_page()


@app.route("/register", methods=["POST"])
def register():
    check_csrf()
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if not name or len(name) > 100 or not email or len(email) > 254:
        flash("Please enter a valid name and email.", "error")
        return render_page(open_modal="registerModal", status=400)

    if len(password) < 8:
        flash("Password must contain at least 8 characters.", "error")
        return render_page(open_modal="registerModal", status=400)

    try:
        with get_db() as db:
            db.execute(
                "INSERT INTO users(name, email, password, role) VALUES (?, ?, ?, 'user')",
                (name, email, generate_password_hash(password))
            )
            user_id = db.execute(
                "SELECT id FROM users WHERE email = ?", (email,)
            ).fetchone()["id"]
            db.execute(
                "INSERT INTO audit_logs(user_id, action, details) VALUES (?, ?, ?)",
                (user_id, "REGISTER", "New user registered")
            )
        flash("Account created successfully. Please log in.", "success")
        return render_page(open_modal="loginModal")
    except sqlite3.IntegrityError:
        flash("This email is already registered. Please log in.", "error")
        return render_page(open_modal="registerModal", status=409)


@app.route("/login", methods=["POST"])
def login():
    check_csrf()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    with get_db() as db:
        user = db.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()

    
    
    if not user or not check_password_hash(user["password"], password):
     return """
    <script>
        alert("Invalid email or password. Please try again.");
        window.history.back();
    </script>
    """, 401

    session.clear()
    session["user_id"] = user["id"]
    session["role"] = user["role"]
    session["csrf_token"] = secrets.token_urlsafe(32)

    with get_db() as db:
        db.execute(
            "INSERT INTO audit_logs(user_id, action, details) VALUES (?, ?, ?)",
            (user["id"], "LOGIN", "Successful login")
        )

    flash("Login successful!", "success")
    return redirect(url_for("admin_dashboard" if user["role"] == "admin" else "home"))


@app.route("/logout")
@login_required
def logout():
    log_action("LOGOUT", "User logged out")
    session.clear()
    flash("You have logged out.", "success")
    return redirect(url_for("home"))


@app.route("/upload", methods=["POST"])
@login_required
def upload_document():
    check_csrf()
    file = request.files.get("document")

    if not file or not file.filename:
        flash("Please select a file.", "error")
        return redirect(url_for("home"))

    original_name = secure_filename(file.filename)
    if not original_name:
        flash("Invalid filename.", "error")
        return redirect(url_for("home"))

    stored_name = secrets.token_hex(16) + "_" + original_name
    path = UPLOAD_DIR / stored_name
    digest = hashlib.sha256()
    size = 0

    try:
        with open(path, "wb") as out:
            while True:
                chunk = file.stream.read(64 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > app.config["MAX_CONTENT_LENGTH"]:
                    raise ValueError("File exceeds the 10 MB limit.")
                digest.update(chunk)
                out.write(chunk)

        with get_db() as db:
            db.execute("""
                INSERT INTO documents(owner_id, filename, stored_name, file_hash)
                VALUES (?, ?, ?, ?)
            """, (session["user_id"], original_name, stored_name, digest.hexdigest()))

        log_action("UPLOAD", "Uploaded document: " + original_name)
        flash("Document uploaded successfully.", "success")
    except Exception as exc:
        path.unlink(missing_ok=True)
        if isinstance(exc, ValueError):
            flash(str(exc), "error")
        else:
            app.logger.exception("Document upload failed")
            flash("Upload failed. Please try again.", "error")

    return redirect(url_for("home"))


def get_accessible_document(document_id):
    with get_db() as db:
        doc = db.execute("""
            SELECT d.*, u.name AS owner_name
            FROM documents d JOIN users u ON u.id = d.owner_id
            WHERE d.id = ? AND (
                d.owner_id = ? OR EXISTS (
                    SELECT 1 FROM shares s
                    WHERE s.document_id = d.id AND s.shared_with = ?
                )
            )
        """, (document_id, session["user_id"], session["user_id"])).fetchone()

        share = db.execute("""
            SELECT permission FROM shares
            WHERE document_id = ? AND shared_with = ?
        """, (document_id, session["user_id"])).fetchone()

    return doc, share


@app.route("/download/<int:document_id>")
@login_required
def download_document(document_id):
    doc, share = get_accessible_document(document_id)
    if not doc:
        abort(404)

    # Shared users need the explicit download permission.
    if doc["owner_id"] != session["user_id"] and (
           not share or share["permission"] != "download"
    ):
        return """
    <script>
        alert("Admin has not granted download permission for this document.");
        window.history.back();
    </script>
    """, 403
    
    path = UPLOAD_DIR / doc["stored_name"]
    if not path.is_file():
        abort(404, description="Document file is missing from storage.")

    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(64 * 1024), b""):
            digest.update(chunk)

    if not secrets.compare_digest(digest.hexdigest(), doc["file_hash"]):
        log_action("INTEGRITY_FAILURE", "Hash mismatch for document ID " + str(document_id))
        abort(409, description="Document integrity check failed.")

    log_action("DOWNLOAD", "Downloaded document: " + doc["filename"])
    return send_from_directory(
        str(UPLOAD_DIR), doc["stored_name"],
        as_attachment=True, download_name=doc["filename"]
    )
@app.route("/view/<int:document_id>")
@login_required
def view_document(document_id):
    doc, share = get_accessible_document(document_id)

    if not doc:
        abort(403)

    # View permission unna users kuda document choodavachu
    # Download permission unna users kuda choodavachu
    if doc["owner_id"] != session["user_id"] and (
        not share or share["permission"] not in ("view", "download")
    ):
        abort(403)

    file_path = UPLOAD_DIR / doc["stored_name"]

    if not file_path.exists():
        abort(404, description="Document file not found.")

    # Check file integrity
    import hashlib

    sha256 = hashlib.sha256()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(8192), b""):
            sha256.update(chunk)

    if sha256.hexdigest() != doc["file_hash"]:
        abort(409, description="Document integrity check failed.")

    # Allow browser preview for PDF files only
    mime_type, _ = mimetypes.guess_type(doc["filename"])

    if mime_type != "application/pdf":
        abort(415, description="Browser preview is available for PDF files only.")

    return send_from_directory(
        str(UPLOAD_DIR),
        doc["stored_name"],
        mimetype="application/pdf",
        as_attachment=False,
        download_name=doc["filename"]
    )


@app.route("/share", methods=["POST"])
@login_required
def share_document():
    check_csrf()
    try:
        document_id = int(request.form.get("document_id", ""))
    except ValueError:
        abort(400)

    email = request.form.get("email", "").strip().lower()
    permission = request.form.get("permission", "view")

    if permission not in ("view", "download"):
        abort(400)

    with get_db() as db:
        doc = db.execute(
            "SELECT * FROM documents WHERE id = ? AND owner_id = ?",
            (document_id, session["user_id"])
        ).fetchone()
        target = db.execute(
            "SELECT id FROM users WHERE email = ?", (email,)
        ).fetchone()

        if not doc:
            abort(403, description="Only the document owner can share it.")
        if not target:
            flash("That email is not registered in TrustVault.", "error")
            return redirect(url_for("home"))
        if target["id"] == session["user_id"]:
            flash("You already own this document.", "error")
            return redirect(url_for("home"))

        db.execute("""
            INSERT INTO shares(document_id, shared_with, permission)
            VALUES (?, ?, ?)
            ON CONFLICT(document_id, shared_with)
            DO UPDATE SET permission = excluded.permission
        """, (document_id, target["id"], permission))

    log_action("SHARE", "Shared document ID " + str(document_id) + " with " + email)
    flash("Document sharing permission saved.", "success")
    return redirect(url_for("home"))


@app.route("/admin")
@admin_required
def admin_dashboard():
    with get_db() as db:
        stats = {
            "users": db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
            "documents": db.execute("SELECT COUNT(*) FROM documents").fetchone()[0],
            "shares": db.execute("SELECT COUNT(*) FROM shares").fetchone()[0],
        }
    page, status = render_page()
    # Admin statistics and audit links are available from /admin.
    return page.replace(
        '<h1>Hello, ', '<h1>Admin Dashboard — Hello, ', 1
    ).replace(
        '<div class="stat"><b>Account</b>',
        '<div class="stat"><b>Total users: ' + str(stats["users"]) +
        '</b><p>Total documents: ' + str(stats["documents"]) +
        '<br>Shared permissions: ' + str(stats["shares"]) +
        '</p></div><div class="stat"><b>Account</b>', 1
    ), status



@app.route("/admin/audit-logs")
@admin_required
def audit_logs():
    with get_db() as db:
        logs = db.execute("""
            SELECT a.id, a.action, a.details, a.created_at,
                   COALESCE(u.email, 'Deleted user') AS email
            FROM audit_logs a
            LEFT JOIN users u ON u.id = a.user_id
            ORDER BY a.id DESC
            LIMIT 500
        """).fetchall()

        user = db.execute(
            "SELECT id, name, email, role FROM users WHERE id = ?",
            (session["user_id"],)
        ).fetchone()

    return render_template_string("""
    <!doctype html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>TrustVault Audit Logs</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background: #f3f6fc;
                margin: 30px;
                color: #172033;
            }
            .wrap {
                background: white;
                padding: 22px;
                border-radius: 12px;
                overflow-x: auto;
            }
            table {
                border-collapse: collapse;
                width: 100%;
            }
            th, td {
                padding: 12px;
                border-bottom: 1px solid #ddd;
                text-align: left;
            }
            th { background: #eef2ff; }
            a { color: #345de0; }
        </style>
    </head>
    <body>
      <div class="wrap">
        <h1>🔐 TrustVault — Admin Audit Logs</h1>
        <p>Signed in as {{ user.email }}.
        Only administrators can access this page.</p>

        <p>
          <a href="{{ url_for('admin_dashboard') }}">Admin dashboard</a> |
          <a href="{{ url_for('home') }}">Documents</a>
        </p>

        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Date</th>
              <th>User</th>
              <th>Action</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {% for log in logs %}
            <tr>
              <td>{{ log.id }}</td>
              <td>{{ log.created_at }}</td>
              <td>{{ log.email }}</td>
              <td>{{ log.action }}</td>
              <td>{{ log.details or '' }}</td>
            </tr>
            {% else %}
            <tr>
              <td colspan="5">No audit logs found.</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>

        <p>Showing up to 500 records.</p>
      </div>
    </body>
    </html>
    """, user=user, logs=logs)


@app.errorhandler(403)
def forbidden(error):
    return (
        "<h2>403 - Access denied</h2><p>You do not have permission to access this resource.</p>"
        '<p><a href="/">Return to TrustVault</a></p>',
        403
    )


@app.errorhandler(404)
def not_found(error):
    return (
        "<h2>404 - Not found</h2><p>The requested resource was not found.</p>"
        '<p><a href="/">Return to TrustVault</a></p>',
        404
    )


init_db()

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
