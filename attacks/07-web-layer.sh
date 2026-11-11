#!/usr/bin/env bash
# Checklist section 7 — CSRF, CORS, security headers, output encoding.  Target: m07-web-layer (8087)
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
PORT=8087
banner "07 · browser-facing controls (port ${PORT})"
up "${PORT}" m07-web-layer

# -----------------------------------------------------------------------------------------------
title "1. CSRF: a state change that the browser authorises with its own cookie"
note "The attacker page is the fragment printed in docs/07-web-layer.md; a browser that has the"
note "session cookie sends it automatically. curl reproduces it exactly: no token, no warning."
req POST "${PORT}" "/vuln7/subscriptions/SUB-1001/cancel"
note "The same operation on /safe7 requires a token that is bound to the session:"
printf '  POST /safe7 without token -> '; status_of "${PORT}" "/safe7/subscriptions/SUB-1001/cancel" -X POST
printf '\n  GET  /safe7/csrf         -> '; body_of "${PORT}" "/safe7/csrf" | head -c 160; echo
note "With the token from /safe7/csrf in the header below, the same call succeeds:"
CSRF_JSON=$(body_of "${PORT}" "/safe7/csrf")
CSRF_TOKEN=$(echo "${CSRF_JSON}" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
printf '  POST /safe7 with X-XSRF-TOKEN -> '
curl -sS -m 8 -o /dev/null -w '%{http_code}\n' -X POST \
  -H "X-XSRF-TOKEN: ${CSRF_TOKEN}" -H "Cookie: XSRF-TOKEN=${CSRF_TOKEN}" \
  "$(BASE_FOR_PORT ${PORT})/safe7/subscriptions/SUB-1001/cancel"

# -----------------------------------------------------------------------------------------------
title "2. CORS: any origin plus credentials"
note "Preflight from a hostile origin:"
req_with_headers OPTIONS "${PORT}" "/vuln7/profile" \
  -H 'Origin: http://evil.example.invalid' \
  -H 'Access-Control-Request-Method: GET' \
  -H 'Access-Control-Request-Headers: x-custom'
note "Actual request: the response echoes the hostile origin and allows credentials, so any"
note "website can read a logged-in user's profile with fetch(..., {credentials:'include'})."
req_with_headers GET "${PORT}" "/vuln7/profile" -H 'Origin: http://evil.example.invalid'
note "Reference configuration allows only the allow-listed origin:"
req_with_headers GET "${PORT}" "/safe7/profile" -H 'Origin: http://evil.example.invalid'
req_with_headers GET "${PORT}" "/safe7/profile" -H 'Origin: http://localhost:4200'

# -----------------------------------------------------------------------------------------------
title "3. Security headers: absent on /vuln7, present on /safe7"
note "/vuln7 response headers (those that exist at all):"
curl -sS -m 5 -D - -o /dev/null "$(BASE_FOR_PORT ${PORT})/vuln7/page" 2>/dev/null | sed 's/^/    /' | head -12
note "/safe7 response headers:"
curl -sS -m 5 -D - -o /dev/null "$(BASE_FOR_PORT ${PORT})/safe7/page" 2>/dev/null | sed 's/^/    /' | head -20
note "Self-report endpoint used by CI:"
req GET "${PORT}" "/safe7/headers-selftest"

# -----------------------------------------------------------------------------------------------
title "4. Reflected XSS via th:utext"
PAYLOAD='<img src=x onerror=alert(document.cookie)>'
echo "  GET /vuln7/page?name=<payload>"
curl -sS -m 5 --get --data-urlencode "name=${PAYLOAD}" "$(BASE_FOR_PORT ${PORT})/vuln7/page" \
  | grep -n "operator\|<img" | head -3 | sed 's/^/    /'
note "The value is emitted as markup. In a browser this executes in the application's origin."
note "Reference template uses th:text, so the same payload is rendered as visible text:"
curl -sS -m 5 --get --data-urlencode "name=${PAYLOAD}" "$(BASE_FOR_PORT ${PORT})/safe7/page" \
  | grep -n "&lt;img\|<img" | head -3 | sed 's/^/    /'

# -----------------------------------------------------------------------------------------------
title "5. Stored XSS: the payload is persisted and re-rendered for every visitor"
req POST "${PORT}" "/vuln7/notes" "note <script>fetch('/vuln7/profile')</script>" text/plain
curl -sS -m 5 "$(BASE_FOR_PORT ${PORT})/vuln7/page" | grep -n "script" | head -3 | sed 's/^/    /'

# -----------------------------------------------------------------------------------------------
title "6. Clickjacking: the page can be framed (no X-Frame-Options, no frame-ancestors)"
curl -sS -m 5 "$(BASE_FOR_PORT ${PORT})/vuln7/clickjacking" | head -6 | sed 's/^/    /'
note "An attacker page loads it in a transparent iframe and overlays a button; the user clicks"
note "'Keep tariff' and cancels the subscription. /safe7 sends frame-ancestors 'none'."

# -----------------------------------------------------------------------------------------------
title "7. Missing nosniff: a user-controlled body served as an upload preview"
req GET "${PORT}" "/vuln7/upload-preview?body=%3Cscript%3Ealert(1)%3C/script%3E"
echo
banner "done · details and fixes: docs/07-web-layer.md"
