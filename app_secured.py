"""Club portal - SECURED version.

Same features as app_vulnerable.py. Each FIX comment points at the
vulnerability it closes (numbers match REPORT.md).
"""
import os
import secrets
import sqlite3
import time
from functools import wraps

from flask import Flask, abort, g, redirect, render_template_string, request, session
from werkzeug.security import check_password_hash, generate_password_hash

from common import init_db

MAX_FAILS = 5        # failed logins allowed...
LOCK_WINDOW = 300    # ...inside this many seconds
DUMMY_HASH = generate_password_hash("not-a-real-password")

# Templates are fixed strings. User data only ever goes in through {{ }},
# which Jinja HTML-escapes. (FIX 3)
BASE = """<!doctype html>
<title>Club Portal</title>
<nav><a href="/">Home</a> | <a href="/events">Events</a> |
<a href="/my-registrations">My registrations</a>
{% if g.user and g.user.role == 'admin' %} | <a href="/admin">Admin</a>{% endif %}
{% if g.user %} | <a href="/profile/{{ g.user.id }}">My profile</a>{% endif %}</nav>
{% if g.user %}
<form method="post" action="/logout">
<input type="hidden" name="csrf" value="{{ csrf_token() }}">
<button>Logout ({{ g.user.username }})</button></form>
{% endif %}
<hr>
%%BODY%%"""

LOGIN_BODY = """<h2>Login</h2>
{% if error %}<p><strong>{{ error }}</strong></p>{% endif %}
<form method="post" action="/login">
<input type="hidden" name="csrf" value="{{ csrf_token() }}">
Username: <input name="username" maxlength="50"><br>
Password: <input name="password" type="password" maxlength="200"><br>
<button>Login</button></form>"""


def create_app(db_path="database_sec.db"):
    app = Flask(__name__)
    app.config.update(
        # FIX 5: secret comes from the environment, random if not set
        SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        # needs HTTPS, so it is opt-in for local http testing: COOKIE_SECURE=1
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",
        PERMANENT_SESSION_LIFETIME=1800,
    )
    init_db(db_path, hashed=True)
    failures = {}  # "ip|username" -> list of failed-attempt timestamps

    def db():
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def csrf_token():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)
        return session["csrf"]

    app.jinja_env.globals["csrf_token"] = csrf_token

    def render(body, **ctx):
        return render_template_string(BASE.replace("%%BODY%%", body), **ctx)

    @app.before_request
    def load_user_and_check_csrf():
        # FIX 4: identity and role always come from the database, using the
        # id in the signed session. Nothing the client sends is trusted.
        g.user = None
        uid = session.get("user_id")
        if uid is not None:
            conn = db()
            g.user = conn.execute(
                "SELECT id, username, role, full_name FROM users WHERE id = ?", (uid,)
            ).fetchone()
            conn.close()
        if request.method == "POST":
            sent = request.form.get("csrf", "").encode()
            expected = session.get("csrf", "").encode()
            if not expected or not secrets.compare_digest(sent, expected):
                abort(400)

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; frame-ancestors 'none'; form-action 'self'"
        )
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    def login_required(f):
        @wraps(f)
        def wrapper(*a, **k):
            if g.user is None:
                return redirect("/login")
            return f(*a, **k)
        return wrapper

    def admin_required(f):
        @wraps(f)
        def wrapper(*a, **k):
            if g.user is None:
                return redirect("/login")
            if g.user["role"] != "admin":
                abort(403)
            return f(*a, **k)
        return wrapper

    @app.errorhandler(400)
    def bad_request(e):
        return render("<h2>400</h2><p>Bad request (missing or invalid form token).</p>"), 400

    @app.errorhandler(403)
    def forbidden(e):
        return render("<h2>403</h2><p>You are not allowed to do that.</p>"), 403

    @app.errorhandler(404)
    def not_found(e):
        return render("<h2>404</h2><p>Not found.</p>"), 404

    @app.route("/")
    def index():
        return render(
            "<h2>Club Portal</h2>"
            "{% if g.user %}<p>Logged in as <b>{{ g.user.username }}</b> "
            "({{ g.user.role }})</p>{% else %}<p><a href='/login'>Login</a> to continue.</p>{% endif %}"
        )

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return render(LOGIN_BODY, error=None)

        username = request.form.get("username", "").strip()[:50]
        password = request.form.get("password", "")[:200]

        # FIX 6: lockout after repeated failures
        key = f"{request.remote_addr}|{username.lower()}"
        now = time.time()
        recent = [t for t in failures.get(key, []) if now - t < LOCK_WINDOW]
        failures[key] = recent
        if len(recent) >= MAX_FAILS:
            return render(LOGIN_BODY, error="Too many failed attempts. Try again in a few minutes."), 429

        # FIX 1: parameterized query, the input is data and never SQL
        conn = db()
        row = conn.execute(
            "SELECT id, password FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()

        # hash is checked even for unknown users so timing does not reveal valid names
        ok = check_password_hash(row["password"] if row else DUMMY_HASH, password)
        if row and ok:
            failures.pop(key, None)
            session.clear()  # fresh session on login (no session fixation)
            session["user_id"] = row["id"]
            session.permanent = True
            return redirect("/")

        recent.append(now)
        # same message whether the user exists or not
        return render(LOGIN_BODY, error="Invalid username or password."), 401

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect("/")

    @app.route("/profile/<int:uid>")
    @login_required
    def profile(uid):
        # FIX 2: owner or admin only. Same 403 whether or not the id exists.
        if uid != g.user["id"] and g.user["role"] != "admin":
            abort(403)
        conn = db()
        u = conn.execute(
            "SELECT username, full_name, email, role, bio FROM users WHERE id = ?", (uid,)
        ).fetchone()
        conn.close()
        if not u:
            abort(404)
        return render(
            "<h2>Profile: {{ u.username }}</h2><p>Name: {{ u.full_name }}</p>"
            "<p>Email: {{ u.email }}</p><p>Role: {{ u.role }}</p><p>Bio: {{ u.bio }}</p>",
            u=u,
        )

    @app.route("/events")
    @login_required
    def events():
        conn = db()
        rows = conn.execute(
            "SELECT e.id, e.title, e.event_date, "
            "(SELECT COUNT(*) FROM registrations r WHERE r.event_id = e.id) AS n "
            "FROM events e"
        ).fetchall()
        conn.close()
        return render(
            "<h2>Events</h2>{% for e in events %}"
            "<h3>{{ e.title }} ({{ e.event_date }}) - {{ e.n }} registered</h3>"
            '<form method="post" action="/events/{{ e.id }}/register">'
            '<input type="hidden" name="csrf" value="{{ csrf_token() }}">'
            'Note: <input name="note" maxlength="200"> <button>Register</button></form>'
            "{% endfor %}",
            events=rows,
        )

    @app.route("/events/<int:eid>/register", methods=["POST"])
    @login_required
    def register(eid):
        note = request.form.get("note", "").strip()
        if len(note) > 200:  # basic input validation
            abort(400)
        conn = db()
        if not conn.execute("SELECT 1 FROM events WHERE id = ?", (eid,)).fetchone():
            conn.close()
            abort(404)
        conn.execute(
            "INSERT INTO registrations (user_id, event_id, note) VALUES (?,?,?)",
            (g.user["id"], eid, note),
        )
        conn.commit()
        conn.close()
        return redirect("/my-registrations")

    @app.route("/my-registrations")
    @login_required
    def my_registrations():
        conn = db()
        rows = conn.execute(
            "SELECT r.id, e.title, r.note FROM registrations r "
            "JOIN events e ON e.id = r.event_id WHERE r.user_id = ?",
            (g.user["id"],),
        ).fetchall()
        conn.close()
        return render(
            "<h2>My registrations</h2><ul>{% for r in rows %}"
            '<li><a href="/registrations/{{ r.id }}">#{{ r.id }}</a> {{ r.title }}: {{ r.note }}</li>'
            "{% endfor %}</ul>",
            rows=rows,
        )

    @app.route("/registrations/<int:rid>")
    @login_required
    def registration(rid):
        conn = db()
        r = conn.execute(
            "SELECT r.id, r.user_id, u.username, e.title, r.note FROM registrations r "
            "JOIN users u ON u.id = r.user_id JOIN events e ON e.id = r.event_id "
            "WHERE r.id = ?",
            (rid,),
        ).fetchone()
        conn.close()
        # FIX 2: ownership check; unknown ids and other people's ids look the same
        if not r or (r["user_id"] != g.user["id"] and g.user["role"] != "admin"):
            abort(403)
        return render(
            "<h2>Registration #{{ r.id }}</h2><p>{{ r.username }} -> {{ r.title }}</p><p>{{ r.note }}</p>",
            r=r,
        )

    @app.route("/admin")
    @admin_required
    def admin():
        conn = db()
        users = conn.execute("SELECT id, username, role, email FROM users").fetchall()
        regs = conn.execute(
            "SELECT r.id, u.username, e.title, r.note FROM registrations r "
            "JOIN users u ON u.id = r.user_id JOIN events e ON e.id = r.event_id"
        ).fetchall()
        conn.close()
        return render(
            "<h2>Admin panel</h2><h3>Users</h3><ul>{% for u in users %}"
            "<li>{{ u.id }} - {{ u.username }} ({{ u.role }}) {{ u.email }}</li>{% endfor %}</ul>"
            "<h3>All registrations</h3><ul>{% for r in regs %}"
            "<li>#{{ r.id }} {{ r.username }} / {{ r.title }}: {{ r.note }}</li>{% endfor %}</ul>",
            users=users,
            regs=regs,
        )

    return app


if __name__ == "__main__":
    # debug is off on purpose: the Werkzeug debugger allows code execution
    create_app().run(port=5001, debug=False)
