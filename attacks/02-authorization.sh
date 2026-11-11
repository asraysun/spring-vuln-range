#!/usr/bin/env bash
# Checklist section 2 — authorization / access control.  Target: m02-authorization (8082)
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
PORT=8082
banner "02 · authorization: IDOR, tenants, permitAll leftovers, bypass matchers (port ${PORT})"
up "${PORT}" m02-authorization

ALICE="-u alice:alice-pass"
BOB="-u bob:bob-pass"
ANON=""

# -----------------------------------------------------------------------------------------------
title "1. IDOR / BOLA: bob reads alice's subscription by changing the id"
note "bob is perfectly authenticated; the row simply is not his."
req GET "${PORT}" "/vuln2/subscriptions/SUB-1001" "" application/json ${BOB}
note "Same call on /safe2 returns 404 for a foreign row:"
req GET "${PORT}" "/safe2/subscriptions/SUB-1001" "" application/json ${BOB}
note "And it works for the real owner:"
req GET "${PORT}" "/safe2/subscriptions/SUB-1001" "" application/json ${ALICE}

# -----------------------------------------------------------------------------------------------
title "2. Sequential ids make enumeration trivial (walk the id space)"
for id in SUB-1001 SUB-1002 SUB-2001 SUB-3001; do
  printf '  %s -> ' "${id}"
  curl -sS -m "${CURL_TIMEOUT}" -u bob:bob-pass "$(BASE_FOR_PORT ${PORT})/vuln2/subscriptions/${id}" | tr -d '\n' | cut -c1-120
  echo
done
note "Authenticated once, all tenants' data is one loop away. Use non-sequential ids AND ownership checks."

# -----------------------------------------------------------------------------------------------
title "3. State change behind a 'public read' matcher"
req POST "${PORT}" "/vuln2/subscriptions/SUB-1001/cancel" "" application/json   # blocked: POST is not matched by the GET rule
req GET  "${PORT}" "/vuln2/subscriptions/SUB-1001/cancel"                       # accepted: the GET matcher allows it, and it mutates

# -----------------------------------------------------------------------------------------------
title "4. permitAll() leftovers: full data dump with PII, no authentication"
req GET "${PORT}" "/vuln2/admin/subscriptions"
req GET "${PORT}" "/vuln2/internal/metrics"

# -----------------------------------------------------------------------------------------------
title "5. WebSecurityCustomizer ignoring(): no filter chain at all"
req GET "${PORT}" "/vuln2/bypass/whoami"
note "No 401, no CSRF check, no security headers: the request never met a filter."

# -----------------------------------------------------------------------------------------------
title "6. Cross-tenant read: the tenant id is a request parameter"
req GET "${PORT}" "/vuln2/tenant/subscriptions?tenantId=T-200" "" application/json ${ALICE}
note "alice (T-100) receives tenant T-200 data because the boundary came from the query string."
note "Reference implementation derives the tenant from the principal:"
req GET "${PORT}" "/safe2/tenant/subscriptions" "" application/json ${ALICE}

# -----------------------------------------------------------------------------------------------
title "7. Vacuous method security: @PreAuthorize(\"isAuthenticated()\")"
req GET "${PORT}" "/vuln2/profile/bob" "" application/json ${ALICE}
note "'isAuthenticated()' answers who you are, never whether this object is yours."

# -----------------------------------------------------------------------------------------------
title "8. Privilege escalation through self-service authority assignment"
note "Registration trusts a client-supplied authority list (a very real pattern in admin UIs)."
req POST "${PORT}" "/vuln2/register?username=attacker&authorities=ROLE_ADMIN"
note "mallory was seeded with ROLE_ADMIN through exactly that path, so the admin report is open:"
req GET "${PORT}" "/vuln2/admin/report" "" application/json -u mallory:mallory-pass
note "and the hardened chain (/safe2/admin/**) denies alice:"
req GET "${PORT}" "/safe2/admin/report" "" application/json ${ALICE}
note "…while allowing the real admin:"
req GET "${PORT}" "/safe2/admin/report" "" application/json -u mallory:mallory-pass

# -----------------------------------------------------------------------------------------------
title "9. Denial answers to compare"
printf '  /vuln2 without credentials  -> '; status_of "${PORT}" "/vuln2/subscriptions/SUB-1001"
printf '\n  /safe2 without credentials  -> '; status_of "${PORT}" "/safe2/subscriptions/SUB-1001"
printf '\n  unknown path (default deny) -> '; status_of "${PORT}" "/whatever"
echo
banner "done · details and fixes: docs/02-authorization.md"
