#!/usr/bin/env bash
# Same attacks against the SECURED app (localhost:5001 only).
# Start it first:  python app_secured.py
B=http://127.0.0.1:5001
J=$(mktemp -d)
strip() { sed -e 's/<[^>]*>/ /g' | tr -s ' \n' | head -c 300; echo; }
# fetch a page, remember the session cookie, print the CSRF token
tok() { curl -s -c $1 -b $1 $B/${2:-login} | sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' | head -1; }

echo "=== 1. SQL injection ==="
T=$(tok $J/x.jar)
curl -s -c $J/x.jar -b $J/x.jar -o /dev/null -w "login status: %{http_code} (expect 401)\n" \
  --data-urlencode "username=admin'--" --data-urlencode "password=anything" --data-urlencode "csrf=$T" $B/login
curl -s -b $J/x.jar -o /dev/null -w "/admin status: %{http_code} (expect 302 redirect to login)\n" $B/admin

echo; echo "=== 2. IDOR (alice logs in properly first) ==="
T=$(tok $J/alice.jar)
curl -s -c $J/alice.jar -b $J/alice.jar -o /dev/null \
  --data-urlencode "username=alice" --data-urlencode "password=alice123" --data-urlencode "csrf=$T" $B/login
curl -s -b $J/alice.jar -o /dev/null -w "/profile/2 status: %{http_code} (expect 403)\n" $B/profile/2
curl -s -b $J/alice.jar -o /dev/null -w "/registrations/2 status: %{http_code} (expect 403)\n" $B/registrations/2
curl -s -b $J/alice.jar -o /dev/null -w "/profile/1 (her own) status: %{http_code} (expect 200)\n" $B/profile/1

echo; echo "=== 3. Stored XSS ==="
T=$(tok $J/alice.jar events)
curl -s -b $J/alice.jar -o /dev/null --data-urlencode "note=<script>alert(1)</script>" \
  --data-urlencode "csrf=$T" $B/events/1/register
echo "note as stored in the page:"
curl -s -b $J/alice.jar $B/my-registrations | grep -o "&lt;script&gt;[^<]*"
echo "CSP header:"; curl -sI $B/login | grep -i content-security-policy

echo; echo "=== 4. Forged role cookie ==="
curl -s -H "Cookie: role=admin" -o /dev/null -w "/admin status: %{http_code} (expect 302)\n" $B/admin
S=$(awk '$6=="session"{print $7}' $J/alice.jar)   # alice's real session cookie
curl -s -H "Cookie: session=$S; role=admin" -o /dev/null -w "logged in as alice + fake cookie: %{http_code} (expect 403)\n" $B/admin

echo; echo "=== 5. Brute force: 6 wrong passwords ==="
for i in 1 2 3 4 5 6; do
  T=$(tok $J/b.jar)
  curl -s -c $J/b.jar -b $J/b.jar -o /dev/null -w "attempt $i: %{http_code}\n" \
    --data-urlencode "username=bob" --data-urlencode "password=wrong$i" --data-urlencode "csrf=$T" $B/login
done
