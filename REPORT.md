# Security Assessment: Club Portal

Tested locally against my own instance. The vulnerable version (app_vulnerable.py, port 5000) demonstrates five practical web security flaws, while the secured version (app_secured.py, port 5001) implements the corresponding fixes.

## Summary

The portal requires authentication, but trusts client input too heavily—specifically cookies, URL parameters, and unescaped form inputs.
I found and demonstrated five problems in the vulnerable version.

| # | Issue | Severity | Result of the attack |
|---|---|---|---|
| 1 | SQL injection in login | Critical | log in as anyone, including admin, with no password |
| 2 | IDOR / missing ownership checks | High | any member reads other members' profiles and registrations |
| 3 | Stored XSS in event notes | High | script runs in other users' browsers (including the admin's) |
| 4 | Role taken from a client cookie | Critical | anyone, even logged out, opens the admin panel |
| 5 | Weak/hardcoded secret key and plaintext passwords | Medium | forged sessions; one leak exposes every password |

Vulnerability Details & Fixes
1. SQL Injection (Login)

app_vulnerable.py constructs SQL queries using raw string formatting (WHERE username = '{u}' AND password = '{p}'). Entering admin'-- comments out the password logic entirely, allowing instant access to the admin account.

    Fix: app_secured.py uses parameterized queries (WHERE username = ?) and hashes passwords with werkzeug.security. Database errors return generic response messages. Verified via test_secure_sqli_login_bypass_fails and poc_secured.sh.

2. IDOR (Insecure Direct Object Reference)

The /profile/<id> and /registrations/<id> endpoints check if a user is logged in, but never verify whether the requested record belongs to them. An attacker logged in as alice can change the URL ID to /profile/2 to view bob's private details.

    Fix: Every handler explicitly checks session['user_id'] == requested_id or is_admin. Unauthorized requests return a uniform 403 status code to prevent account probing.

3. Stored Cross-Site Scripting (XSS)

Event notes are concatenated directly into HTML strings without escaping. Submitting <script>alert(document.cookie)</script> executes JavaScript for anyone viewing the /events page, creating an account takeover risk if an admin views the page.

    Fix: Output is rendered through Jinja2 auto-escaping templates ({{ }}). The app also enforces a Content-Security-Policy header, sets HttpOnly on session cookies, and restricts input length.

4. Client-Controlled Role Cookie

The vulnerable app checks request.cookies.get("role") to restrict access to /admin. Anyone can send curl -H "Cookie: role=admin" to access the admin panel without logging in.

    Fix: Client-side role cookies are completely ignored. User roles are loaded directly from the database using the server-signed session ID via an @admin_required decorator.

5. Hardcoded Secret Key & Plaintext Passwords

The vulnerable app uses a hardcoded SECRET_KEY = "club123" and stores passwords in cleartext, meaning a single database leak compromises every user account.

    Fix: The secret key is loaded from the SECRET_KEY environment variable, passwords are stored as salted hashes, and credentials are removed from the admin dashboard views.

Additional Defenses

    CSRF Protection: Anti-CSRF tokens added to all POST forms; logout changed to POST-only.

    Brute-Force Rate Limiting: 5 failed login attempts per IP/username triggers a 5-minute lockout (429 Too Many Requests).

    Hardened HTTP Headers: Added CSP, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, and strict cache control.

    Session Hygiene: Active sessions clear on login, expire after 30 minutes, and use HttpOnly + SameSite=Lax flags.

Threat Model & Limitations

Threat Matrix:

    External Visitors: Blocked from SQLi, authentication bypass, and cookie forgery via parameterized queries and server-side role checks.

    Malicious Members: Blocked from IDOR data harvesting and XSS injection via ownership validation and Jinja2 escaping.

Remaining Limitations:

    In-Memory Lockout: Lockout counters live in process memory, meaning they reset if the server restarts. A production deployment should use Redis.

    Account Locking DoS: Rate limiting per username allows malicious actors to intentionally lock out legitimate users.

    Testing Scope: Validated using the 17-test pytest suite and local curl PoC scripts; automated scanners like OWASP ZAP were not run against the code.