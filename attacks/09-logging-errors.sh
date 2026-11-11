#!/usr/bin/env bash
# Checklist section 9 — error handling, logging, security events.  Target: m09-logging-errors (8089)
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
PORT=8089
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
banner "09 · error handling, logging, audit events (port ${PORT})"
up "${PORT}" m09-logging-errors

# -----------------------------------------------------------------------------------------------
title "1. A stack trace in the HTTP response"
req GET "${PORT}" "/vuln9/boom"
note "Class names, line numbers, framework versions: the map an attacker uses to pick a technique."

# -----------------------------------------------------------------------------------------------
title "2. SQL text and internal details returned with the error"
req GET "${PORT}" "/vuln9/report?id=SUB-1001'"
note "The statement text leaks table and column names even when the query itself is parameterised."

# -----------------------------------------------------------------------------------------------
title "3. User enumeration through error messages and timing"
for candidate in alice nobody; do
  printf '  user=%-6s -> ' "${candidate}"
  start=$(date +%s%N 2>/dev/null || date +%s)
  post_body_of "${PORT}" "/vuln9/login" "{\"username\":\"${candidate}\",\"password\":\"x\"}" | tr -d '\n'
  end=$(date +%s%N 2>/dev/null || date +%s)
  echo
done
note "'no such user' vs 'bad password for existing user': account existence is public."
note "Reference implementation answers the same body for both and does the same work:"
post_body_of "${PORT}" "/safe9/login" '{"username":"alice","password":"x"}'; echo
post_body_of "${PORT}" "/safe9/login" '{"username":"nobody","password":"x"}'; echo

# -----------------------------------------------------------------------------------------------
title "4. Validation messages that echo stored state"
req POST "${PORT}" "/vuln9/register" '{"username":"a","email":"not-an-email"}'
note "Reference implementation describes the violated rule, not the value:"
req POST "${PORT}" "/safe9/register" '{"username":"a","email":"not-an-email"}'

# -----------------------------------------------------------------------------------------------
title "5. PII and the caller's token written to the log"
req POST "${PORT}" "/vuln9/audit/checkout" \
  '{"cardNumber":"4111111111111111","email":"alice@example.invalid","amount":"990.00"}'
sleep 1
if [ -f "${ROOT}/logs/m09-logging-errors.log" ]; then
  echo "  matches in logs/m09-logging-errors.log:"
  grep -n "4111111111111111" "${ROOT}/logs/m09-logging-errors.log" | head -2 | sed 's/^/    /' \
    || echo "    (not found; run scripts/run-all.sh so logs are captured)"
else
  echo "  logs/m09-logging-errors.log not present; start the range with scripts/run-all.sh"
fi
note "Now the card number is in the log file, the shipper, the index, and a backup someone sold."
note "Reference implementation logs presence, masked identity and no token:"
req POST "${PORT}" "/safe9/audit/checkout" \
  '{"cardNumber":"4111111111111111","email":"alice@example.invalid","amount":"990.00"}'

# -----------------------------------------------------------------------------------------------
title "6. CRLF log forging"
req POST "${PORT}" "/vuln9/audit/message?message=ok%0A2026-10-30%20WARN%20%20payment%20failed%20for%20alice" \
  "" application/x-www-form-urlencoded
req POST "${PORT}" "/safe9/audit/message" '{"message":"ok\n2026-10-30 WARN payment failed for alice"}'
note "Compare the two log lines: one request, two entries in the first case."

# -----------------------------------------------------------------------------------------------
title "7. Nothing is recorded: a brute-force run leaves no trace"
req GET "${PORT}" "/vuln9/audit/trail"
note "Reference implementation keeps the events an incident responder needs:"
for i in 1 2 3; do
  post_body_of "${PORT}" "/safe9/login" '{"username":"alice","password":"wrong"}' >/dev/null
done
req GET "${PORT}" "/safe9/audit/trail"

# -----------------------------------------------------------------------------------------------
title "8. Runtime and topology disclosure"
req GET "${PORT}" "/vuln9/debug/info"
note "OS, JVM version, working directory, internal hostnames: reconnaissance without a single exploit."

# -----------------------------------------------------------------------------------------------
title "9. Uniform failure, correlation id, incident reference"
curl -sS -m 8 -D - "$(BASE_FOR_PORT ${PORT})/safe9/error" -o /tmp/vulnrange-m09-error.json 2>/dev/null \
  | grep -i "HTTP/\|x-correlation-id" | sed 's/^/    /'
echo "  body:"; sed 's/^/    /' /tmp/vulnrange-m09-error.json | head -8
note "The caller gets a reference, the responder gets the stack trace - in the log only."
echo
banner "done · details and fixes: docs/09-logging-errors.md"
