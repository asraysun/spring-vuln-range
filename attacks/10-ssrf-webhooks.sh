#!/usr/bin/env bash
# Checklist section 10 — outbound calls, SSRF, webhooks.  Target: m10-ssrf-webhooks (8090)
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
PORT=8090
banner "10 · SSRF and unsigned webhooks (port ${PORT})"
up "${PORT}" m10-ssrf-webhooks

# -----------------------------------------------------------------------------------------------
title "1. SSRF to an internal admin surface on the same host"
note "The caller cannot reach /vuln10/internal-admin/users from outside; the server can."
printf '  direct call from this shell (expected to work here because it is loopback): '
status_of "${PORT}" "/vuln10/internal-admin/users"; echo
req POST "${PORT}" "/vuln10/fetch" "{\"url\":\"http://127.0.0.1:${PORT}/vuln10/internal-admin/users\"}"

# -----------------------------------------------------------------------------------------------
title "2. SSRF to the simulated instance-metadata service"
note "In a real cloud this response carries temporary IAM credentials. The range simulates it"
note "locally so nothing leaves the machine and no real credential exists."
req POST "${PORT}" "/vuln10/fetch" "{\"url\":\"http://127.0.0.1:${PORT}/vuln10/imds/latest/meta-data/iam/security-credentials\"}"

# -----------------------------------------------------------------------------------------------
title "3. Redirect-following defeats a naive allow-list"
note "A URL that looks internal, whose redirect target is not: the client follows it silently."
req POST "${PORT}" "/vuln10/fetch" "{\"url\":\"http://127.0.0.1:${PORT}/vuln10/redirect-to-internal\"}"
note "Reference implementation disables redirects and re-validates everything:"
req POST "${PORT}" "/safe10/fetch" "{\"url\":\"http://127.0.0.1:${PORT}/vuln10/redirect-to-internal\"}"

# -----------------------------------------------------------------------------------------------
title "4. Fetch-and-store: SSRF plus an unbounded write"
req POST "${PORT}" "/vuln10/avatar" "{\"url\":\"http://127.0.0.1:${PORT}/vuln10/imds/latest/meta-data/iam/security-credentials\"}"
note "Attacker-chosen bytes are now a file on the server, with no type or size check."

# -----------------------------------------------------------------------------------------------
title "5. No timeouts: one slow upstream occupies a request thread"
printf '  /vuln10/slow blocks for 8 s before answering: '
start=$(date +%s)
status_of "${PORT}" "/vuln10/slow" >/dev/null
end=$(date +%s)
echo "$((end - start)) s (in a real service, a few of these exhaust the pool)"
note "Reference client sets connect 2 s / read 4 s and caps the response at 256 KB."

# -----------------------------------------------------------------------------------------------
title "6. Unsigned, replayable payment webhook"
req POST "${PORT}" "/vuln10/webhook/payment" \
  '{"subscriptionId":"SUB-2001","status":"PAID","amount":"0.00","days":3650}'
note "No signature, no timestamp, no idempotency key: anyone can mark anything paid."
note "Reference implementation rejects a request without signature headers:"
req POST "${PORT}" "/safe10/webhook/payment" '{"subscriptionId":"SUB-2001","status":"PAID"}'
note "…and accepts a correctly signed one exactly once:"
TS=$(date +%s)
BODY='{"subscriptionId":"SUB-2001","status":"PAID","eventId":"evt-0001"}'
SIG=$(python3 - "$TS" "$BODY" <<'PY'
import base64, hashlib, hmac, sys
ts, body = sys.argv[1], sys.argv[2]
secret = "local-demo-webhook-secret-not-a-real-credential"
print(base64.b64encode(hmac.new(secret.encode(), f"{ts}.{body}".encode(), hashlib.sha256).digest()).decode())
PY
)
echo "  signed POST /safe10/webhook/payment (timestamp ${TS})"
curl -sS -m 8 -X POST -H 'Content-Type: application/json' \
  -H "X-Webhook-Timestamp: ${TS}" -H "X-Webhook-Signature: ${SIG}" -H "X-Webhook-Event-Id: evt-0001" \
  --data-binary "${BODY}" -w '\n<status:%{http_code}>\n' \
  "$(BASE_FOR_PORT ${PORT})/safe10/webhook/payment" | sed 's/^/    /' | head -10
note "Replay the exact same message: the idempotency key turns it into a no-op."
curl -sS -m 8 -X POST -H 'Content-Type: application/json' \
  -H "X-Webhook-Timestamp: ${TS}" -H "X-Webhook-Signature: ${SIG}" -H "X-Webhook-Event-Id: evt-0001" \
  --data-binary "${BODY}" -w '\n<status:%{http_code}>\n' \
  "$(BASE_FOR_PORT ${PORT})/safe10/webhook/payment" | sed 's/^/    /' | head -10

# -----------------------------------------------------------------------------------------------
title "7. Reference policy, stated in code"
req GET "${PORT}" "/safe10/egress-policy"
echo
banner "done · details and fixes: docs/10-ssrf-webhooks.md"
