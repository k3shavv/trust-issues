"""Club portal - INTENTIONALLY VULNERABLE version.

Run this only on localhost. Every bug here is deliberate and marked
with a VULN comment so it is easy to find while writing the report.
"""
import sqlite3

from flask import Flask, make_response, redirect, request, session

from common import init_db

PAGE = """<!doctype html>
<title>Club Portal (VULNERABLE)</title>
<nav><a href="/">Home</a> | <a href="/events">Events</a> |
<a href="/my-registrations">My registrations</a> | <a href="/admin">Admin</a> |
<a href="/logout">Logout</a></nav><hr>
{body}"""

LOGIN_FORM = """<h2>Login</h2>
<form method="post" action="/login">
Username: <input name="username"><br>
Password: <input name="password" type="password"><br>
<button>Login</button></form>"""


def page(body):
    return PAGE.format(body=body)


def create_app(db_path="database_vuln.db"):
    app = Flask(__name__)
    # VULN 5: weak, hardcoded secret key. Anyone who guesses it can forge sessions.
    app.secret_key = "club123"
    init_db(db_path, hashed=False)

    def db():
        return sqlite3.connect(db_path)

    @app.route("/")
    def index():
        if "user_id" in session:
            who = f"Logged in as <b>{session['username']}</b>"
        else:
            who = '<a href="/login">Login</a> to continue.'
        return page(f"<h2>Club Portal</h2><p>{who}</p>")

    # VULN 1: SQL injection. User input is pasted straight into the query.
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            u = request.form.get("username", "")
            p = request.form.get("password", "")
            sql = (
                "SELECT id, username, role FROM users "
                f"WHERE username = '{u}' AND password = '{p}'"
            )
            conn = db()
            try:
                row = conn.execute(sql).fetchone()
            except sqlite3.Error as e:
                conn.close()
                # also leaks the query + error to the attacker
                return page(f"<p>Database error: {e}</p><pre>{sql}</pre>"), 500
            conn.close()
            if row:
                session["user_id"] = row[0]
                session["username"] = row[1]
                resp = make_response(redirect("/"))
                # VULN 4: role is handed to the browser in a plain cookie...
                resp.set_cookie("role", row[2])
                return resp
            return page("<p>Invalid credentials.</p>" + LOGIN_FORM), 401
        return page(LOGIN_FORM)

    @app.route("/logout")
    def logout():
        session.clear()
        resp = make_response(redirect("/"))
        resp.delete_cookie("role")
        return resp

    # VULN 2: IDOR. Only checks "is somebody logged in", never "is this MY profile".
    @app.route("/profile/<int:uid>")
    def profile(uid):
        if "user_id" not in session:
            return redirect("/login")
        conn = db()
        u = conn.execute(
            "SELECT username, full_name, email, role, bio FROM users WHERE id = ?",
            (uid,),
        ).fetchone()
        conn.close()
        if not u:
            return page("User not found."), 404
        return page(
            f"<h2>Profile: {u[0]}</h2><p>Name: {u[1]}</p><p>Email: {u[2]}</p>"
            f"<p>Role: {u[3]}</p><p>Bio: {u[4]}</p>"
        )

    # VULN 3: stored XSS. Notes are dropped into the HTML without escaping.
    @app.route("/events")
    def events():
        if "user_id" not in session:
            return redirect("/login")
        conn = db()
        out = "<h2>Events</h2>"
        for eid, title, date in conn.execute("SELECT id, title, event_date FROM events"):
            out += f"<h3>{title} ({date})</h3><ul>"
            rows = conn.execute(
                "SELECT u.username, r.note FROM registrations r "
                "JOIN users u ON u.id = r.user_id WHERE r.event_id = ?",
                (eid,),
            )
            for name, note in rows:
                out += f"<li><b>{name}</b>: {note}</li>"
            out += (
                f'</ul><form method="post" action="/events/{eid}/register">'
                'Note: <input name="note"> <button>Register</button></form>'
            )
        conn.close()
        return page(out)

    @app.route("/events/<int:eid>/register", methods=["POST"])
    def register(eid):
        if "user_id" not in session:
            return redirect("/login")
        note = request.form.get("note", "")
        conn = db()
        conn.execute(
            "INSERT INTO registrations (user_id, event_id, note) VALUES (?,?,?)",
            (session["user_id"], eid, note),
        )
        conn.commit()
        conn.close()
        return redirect("/events")

    @app.route("/my-registrations")
    def my_registrations():
        if "user_id" not in session:
            return redirect("/login")
        conn = db()
        rows = conn.execute(
            "SELECT r.id, e.title, r.note FROM registrations r "
            "JOIN events e ON e.id = r.event_id WHERE r.user_id = ?",
            (session["user_id"],),
        ).fetchall()
        conn.close()
        items = "".join(
            f'<li><a href="/registrations/{rid}">#{rid}</a> {title}: {note}</li>'
            for rid, title, note in rows
        )
        return page(f"<h2>My registrations</h2><ul>{items}</ul>")

    # VULN 2 again: another IDOR, sequential ids and no ownership check.
    @app.route("/registrations/<int:rid>")
    def registration(rid):
        if "user_id" not in session:
            return redirect("/login")
        conn = db()
        r = conn.execute(
            "SELECT r.id, u.username, e.title, r.note FROM registrations r "
            "JOIN users u ON u.id = r.user_id JOIN events e ON e.id = r.event_id "
            "WHERE r.id = ?",
            (rid,),
        ).fetchone()
        conn.close()
        if not r:
            return page("Not found."), 404
        return page(f"<h2>Registration #{r[0]}</h2><p>{r[1]} -> {r[2]}</p><p>{r[3]}</p>")

    # VULN 4: broken access control. The server believes whatever the "role"
    # cookie says, and the user controls that cookie.
    @app.route("/admin")
    def admin():
        if request.cookies.get("role") != "admin":
            return page("Admins only."), 403
        conn = db()
        users = conn.execute(
            "SELECT id, username, password, role, email FROM users"
        ).fetchall()
        regs = conn.execute("SELECT id, user_id, event_id, note FROM registrations").fetchall()
        conn.close()
        out = "<h2>Admin panel</h2><h3>Users</h3><ul>"
        out += "".join(f"<li>{u}</li>" for u in users)
        out += "</ul><h3>All registrations</h3><ul>"
        out += "".join(f"<li>{r}</li>" for r in regs)
        return page(out + "</ul>")

    return app


if __name__ == "__main__":
    create_app().run(port=5000, debug=True)
