"""Security regression tests.

The test_vuln_* tests prove each attack WORKS on the vulnerable app.
The test_secure_* tests prove the same attack FAILS on the secured app.
If someone reintroduces a bug in app_secured.py, a test_secure_* test fails.
"""
import re
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app_secured  # noqa: E402
import app_vulnerable  # noqa: E402

XSS = "<script>alert(1)</script>"


@pytest.fixture
def vuln(tmp_path):
    return app_vulnerable.create_app(str(tmp_path / "v.db")).test_client()


@pytest.fixture
def secure(tmp_path):
    return app_secured.create_app(str(tmp_path / "s.db")).test_client()


def token(client):
    html = client.get("/login").get_data(as_text=True)
    return re.search(r'name="csrf" value="([0-9a-f]+)"', html).group(1)


def vuln_login(client, user, pw):
    return client.post("/login", data={"username": user, "password": pw})


def secure_login(client, user, pw):
    return client.post("/login", data={"username": user, "password": pw, "csrf": token(client)})


def secure_post(client, url, **data):
    # grab a fresh token from any page that renders a form
    html = client.get("/events").get_data(as_text=True)
    t = re.search(r'name="csrf" value="([0-9a-f]+)"', html).group(1)
    return client.post(url, data={**data, "csrf": t})


# ---------- 1. SQL injection ----------

def test_vuln_sqli_login_bypass(vuln):
    r = vuln_login(vuln, "admin'--", "wrong-password")
    assert r.status_code == 302
    assert "admin" in vuln.get("/").get_data(as_text=True)


def test_secure_sqli_login_bypass_fails(secure):
    r = secure_login(secure, "admin'--", "wrong-password")
    assert r.status_code == 401
    assert secure.get("/admin").status_code == 302  # still not logged in


def test_secure_normal_login_still_works(secure):
    assert secure_login(secure, "alice", "alice123").status_code == 302
    assert "alice" in secure.get("/").get_data(as_text=True)


# ---------- 2. IDOR ----------

def test_vuln_idor_profile(vuln):
    vuln_login(vuln, "alice", "alice123")
    body = vuln.get("/profile/2").get_data(as_text=True)
    assert "98765 43210" in body  # Bob's private phone number


def test_vuln_idor_registration(vuln):
    vuln_login(vuln, "alice", "alice123")
    assert "Peanut allergy" in vuln.get("/registrations/2").get_data(as_text=True)


def test_secure_idor_profile_blocked(secure):
    secure_login(secure, "alice", "alice123")
    assert secure.get("/profile/2").status_code == 403
    assert secure.get("/profile/999").status_code == 403  # no id enumeration
    assert secure.get("/profile/1").status_code == 200


def test_secure_idor_registration_blocked(secure):
    secure_login(secure, "alice", "alice123")
    assert secure.get("/registrations/2").status_code == 403
    assert secure.get("/registrations/1").status_code == 200


def test_secure_admin_can_view_any_profile(secure):
    secure_login(secure, "admin", "admin@123")
    assert secure.get("/profile/2").status_code == 200


# ---------- 3. Stored XSS ----------

def test_vuln_stored_xss(vuln):
    vuln_login(vuln, "alice", "alice123")
    vuln.post("/events/1/register", data={"note": XSS})
    assert XSS in vuln.get("/events").get_data(as_text=True)  # raw script tag


def test_secure_stored_xss_escaped(secure):
    secure_login(secure, "alice", "alice123")
    secure_post(secure, "/events/1/register", note=XSS)
    page = secure.get("/my-registrations").get_data(as_text=True)
    assert XSS not in page
    assert "&lt;script&gt;" in page
    # and the admin, who sees every note, gets it escaped too
    admin = app_secured.create_app  # noqa: F841 (just to show intent)
    secure.post("/logout", data={"csrf": token(secure)})
    secure_login(secure, "admin", "admin@123")
    assert XSS not in secure.get("/admin").get_data(as_text=True)


# ---------- 4. Trusting the client (role cookie) ----------

def test_vuln_forged_role_cookie(vuln):
    vuln.set_cookie("role", "admin")
    r = vuln.get("/admin")  # not even logged in
    assert r.status_code == 200
    assert "admin@123" in r.get_data(as_text=True)  # plaintext passwords leak


def test_secure_forged_role_cookie_ignored(secure):
    secure_login(secure, "alice", "alice123")
    secure.set_cookie("role", "admin")
    assert secure.get("/admin").status_code == 403


def test_secure_admin_page_for_real_admin(secure):
    secure_login(secure, "admin", "admin@123")
    body = secure.get("/admin").get_data(as_text=True)
    assert "admin@123" not in body  # no passwords on the page


# ---------- extras in the secured version ----------

def test_secure_csrf_token_required(secure):
    secure_login(secure, "alice", "alice123")
    r = secure.post("/events/1/register", data={"note": "hi"})  # no token
    assert r.status_code == 400


def test_secure_lockout_after_five_failures(secure):
    for _ in range(5):
        assert secure_login(secure, "alice", "nope").status_code == 401
    # even the correct password is refused while locked
    assert secure_login(secure, "alice", "alice123").status_code == 429


def test_secure_headers_and_cookie_flags(secure):
    r = secure.get("/login")
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    cookie = r.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie


def test_secure_passwords_are_hashed(tmp_path):
    path = str(tmp_path / "h.db")
    app_secured.create_app(path)
    pw = sqlite3.connect(path).execute(
        "SELECT password FROM users WHERE username='admin'"
    ).fetchone()[0]
    assert pw != "admin@123" and pw.startswith(("scrypt:", "pbkdf2:"))
