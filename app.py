"""
Task 4 - Secure Login System (Flask)
------------------------------------
Security features
  * Passwords hashed with bcrypt (falls back to scrypt from Werkzeug if bcrypt isn't installed)
  * SQL injection protection: ONLY parameterised queries (? placeholders) - never string formatting
  * Input validation: username / email / password policy checked server side
  * Session management: server-side signed session, HttpOnly + SameSite cookies,
    session timeout, session cleared on logout, session id reset on login
  * CSRF protection on every POST form (random token per session)
  * Brute-force protection: account lock for 5 minutes after 5 failed logins
  * Security headers (CSP, X-Frame-Options, nosniff, Referrer-Policy)
  * Optional 2FA: TOTP (RFC 6238) compatible with Google Authenticator / Authy
  * Generic error message on login failure (no user enumeration)

Run
  pip install -r requirements.txt
  python app.py        ->  http://127.0.0.1:5000
"""
import base64
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import struct
import time
from datetime import timedelta
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for)

try:
    import bcrypt
    HAVE_BCRYPT = True
except ImportError:  # keeps the project runnable on machines without bcrypt
    from werkzeug.security import check_password_hash, generate_password_hash
    HAVE_BCRYPT = False

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(HERE, "users.db")
MAX_ATTEMPTS = 5
LOCK_SECONDS = 300

app = Flask(__name__)
# In production set SECRET_KEY as an environment variable. Random key = sessions reset on restart.
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("HTTPS", "0") == "1",  # set HTTPS=1 behind TLS
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=20),
)


# ---------------- database ----------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config.get("DB_PATH", DB_PATH))
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    db = sqlite3.connect(app.config.get("DB_PATH", DB_PATH))
    db.execute("""CREATE TABLE IF NOT EXISTS users(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    pw_hash TEXT NOT NULL,
                    failed_attempts INTEGER DEFAULT 0,
                    locked_until REAL DEFAULT 0,
                    totp_secret TEXT,
                    totp_enabled INTEGER DEFAULT 0)""")
    db.commit()
    db.close()


# ---------------- password hashing ----------------
def hash_password(pw):
    if HAVE_BCRYPT:
        return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=12)).decode()
    return generate_password_hash(pw)  # scrypt + salt


def verify_password(pw, stored):
    if HAVE_BCRYPT and stored.startswith("$2"):
        return bcrypt.checkpw(pw.encode(), stored.encode())
    if not HAVE_BCRYPT:
        return check_password_hash(stored, pw)
    return False


# ---------------- TOTP (RFC 6238) ----------------
def totp_now(secret_b32, t=None, step=30, digits=6):
    key = base64.b32decode(secret_b32, casefold=True)
    counter = int((t if t is not None else time.time()) // step)
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp_verify(secret_b32, code, window=1):
    code = (code or "").strip()
    now = time.time()
    return any(hmac.compare_digest(totp_now(secret_b32, now + 30 * w), code)
               for w in range(-window, window + 1))


# ---------------- validation ----------------
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")


def validate_registration(username, email, password, confirm):
    errors = []
    if not USERNAME_RE.fullmatch(username):
        errors.append("Username: 3-20 characters, letters/numbers/underscore only.")
    if not EMAIL_RE.fullmatch(email) or len(email) > 120:
        errors.append("Enter a valid email address.")
    if len(password) < 10:
        errors.append("Password must be at least 10 characters.")
    if not (re.search(r"[a-z]", password) and re.search(r"[A-Z]", password)
            and re.search(r"\d", password) and re.search(r"[^A-Za-z0-9]", password)):
        errors.append("Password needs upper, lower, digit and symbol.")
    if username and username.lower() in password.lower():
        errors.append("Password must not contain your username.")
    if password != confirm:
        errors.append("Passwords do not match.")
    return errors


# ---------------- CSRF + auth helpers ----------------
def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def csrf_protect():
    if request.method == "POST":
        sent = request.form.get("_csrf", "")
        if not sent or not hmac.compare_digest(sent, session.get("_csrf", "")):
            abort(400, "Invalid CSRF token")


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if "user_id" not in session:
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        return view(*a, **kw)
    return wrapped


def start_session(user_id, username):
    session.clear()                # new session -> prevents session fixation
    session.permanent = True
    session["user_id"] = user_id
    session["username"] = username


# ---------------- routes ----------------
@app.route("/")
def index():
    return redirect(url_for("dashboard" if "user_id" in session else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        errors = validate_registration(username, email, password, confirm)
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("register.html"), 400
        try:
            # parameterised query -> SQL injection safe
            get_db().execute("INSERT INTO users(username,email,pw_hash) VALUES(?,?,?)",
                             (username, email, hash_password(password)))
            get_db().commit()
        except sqlite3.IntegrityError:
            flash("Username or email already registered.", "error")
            return render_template("register.html"), 400
        flash("Account created. Please log in.", "ok")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        generic = "Invalid username or password."
        if not USERNAME_RE.fullmatch(username):
            flash(generic, "error")
            return render_template("login.html"), 401

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and user["locked_until"] > time.time():
            wait = int(user["locked_until"] - time.time())
            flash(f"Account locked. Try again in {wait} seconds.", "error")
            return render_template("login.html"), 429

        if user and verify_password(password, user["pw_hash"]):
            db.execute("UPDATE users SET failed_attempts=0, locked_until=0 WHERE id=?", (user["id"],))
            db.commit()
            if user["totp_enabled"]:
                session.clear()
                session["pending_2fa"] = user["id"]
                session["pending_name"] = user["username"]
                return redirect(url_for("verify_2fa"))
            start_session(user["id"], user["username"])
            return redirect(url_for("dashboard"))

        if user:
            attempts = user["failed_attempts"] + 1
            locked = time.time() + LOCK_SECONDS if attempts >= MAX_ATTEMPTS else 0
            db.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
                       (0 if locked else attempts, locked, user["id"]))
            db.commit()
        else:
            hash_password(password)  # dummy work: similar timing for unknown users
        flash(generic, "error")
        return render_template("login.html"), 401
    return render_template("login.html")


@app.route("/2fa/verify", methods=["GET", "POST"])
def verify_2fa():
    uid = session.get("pending_2fa")
    if not uid:
        return redirect(url_for("login"))
    if request.method == "POST":
        user = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        if user and totp_verify(user["totp_secret"], request.form.get("code", "")):
            start_session(user["id"], user["username"])
            return redirect(url_for("dashboard"))
        flash("Invalid authentication code.", "error")
        return render_template("verify_2fa.html"), 401
    return render_template("verify_2fa.html")


@app.route("/dashboard")
@login_required
def dashboard():
    user = get_db().execute("SELECT username,email,totp_enabled FROM users WHERE id=?",
                            (session["user_id"],)).fetchone()
    return render_template("dashboard.html", user=user)


@app.route("/2fa/setup", methods=["GET", "POST"])
@login_required
def setup_2fa():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    if request.method == "POST":
        secret = session.get("new_totp")
        if secret and totp_verify(secret, request.form.get("code", "")):
            db.execute("UPDATE users SET totp_secret=?, totp_enabled=1 WHERE id=?", (secret, user["id"]))
            db.commit()
            session.pop("new_totp", None)
            flash("Two-factor authentication enabled.", "ok")
            return redirect(url_for("dashboard"))
        flash("Wrong code, try again.", "error")
    secret = session.setdefault("new_totp", base64.b32encode(os.urandom(10)).decode())
    uri = f"otpauth://totp/SecureLogin:{user['username']}?secret={secret}&issuer=SecureLogin"
    return render_template("setup_2fa.html", secret=secret, uri=uri)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("Logged out successfully.", "ok")
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
