# Trust Issues: a club portal with holes in it (and the fixes)

A small Flask + SQLite portal : members log in, register for
events and view profiles, and admins get a panel with everything in it.
The idea of the task is that "you have to log in" does not mean "it's secure",
so I built the portal twice:

| File | What it is | Port |
|---|---|---|
| `app_vulnerable.py` | the portal with deliberate bugs, each marked `VULN` in the code | 5000 |
| `app_secured.py` | same features, bugs fixed, each fix marked `FIX` | 5001 |
| `common.py` | database schema and demo data shared by both | |
| `tests/test_security.py` | pytest suite: attacks must work on the vulnerable app and fail on the secured one | |
| `poc/` | curl scripts that run each attack against both versions | |
| `REPORT.md` | the security assessment (root causes, impact, fixes, threat model, limitations) | |

**Only run this on your own machine.** The vulnerable version is meant to be
attacked, so don't expose it to a network.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Run it

```bash
python app_vulnerable.py        # http://127.0.0.1:5000
python app_secured.py           # http://127.0.0.1:5001  
```

Demo accounts (both versions): `alice / alice123` (member),
`bob / bob123` (member), `admin / admin@123` (admin).
The database is recreated from scratch every time an app starts.

## Test it


```bash
pytest -q
```

Manual proof-of-concept with curl, with both apps running:

```bash
bash poc/poc_vulnerable.sh      # every attack should succeed
bash poc/poc_secured.sh         # every attack should be refused
```

You can also try them by hand in a browser or Burp/ZAP against port 5000:

1. Login with username `admin'--` and any password.
2. Login as alice, then open `/profile/2` and `/registrations/2`.
3. As alice, register for an event with the note `<script>alert(1)</script>`, then open `/events`.
4. In dev tools, set a cookie `role=admin` and open `/admin`.

## What's in the secured version

To patch these flaws without breaking the portal features, `app_secured.py` implements:
- **Database & Query Safety:** Parameterized queries for all lookups and hashed passwords using `werkzeug.security`.
- **Access Control:** Session-bound user IDs with owner/admin permission checks on every route.
- **Frontend & Headers:** Jinja auto-escaping, Content-Security-Policy (CSP), CSRF tokens on POST forms, and SameSite/HttpOnly cookies.
- **Brute-Force Protection:** In-memory lockout (max 5 failed attempts per IP/username in 5 minutes).

Full technical details and design trade-offs are documented in `REPORT.md`.

## CI

`.github/workflows/ci.yml` runs the pytest suite and a `bandit` scan of the
secured code on every push, so a reintroduced bug fails the build.
