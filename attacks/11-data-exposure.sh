#!/usr/bin/env bash
# Checklist section 11 — data exposure and privacy.  Target: m11-data-exposure (8091)
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
PORT=8091
banner "11 · over-exposure of data (port ${PORT})"
up "${PORT}" m11-data-exposure

# -----------------------------------------------------------------------------------------------
title "1. The JPA entity is the API response"
req GET "${PORT}" "/vuln11/subscribers/USR-0001"
note "passwordHash, refreshToken, internalRiskScore, INN, SNILS, espdTokenHash - none of it asked for,"
note "all of it now in a client, a proxy log, a browser cache and a screenshot in a chat."
note "Reference implementation answers with an explicit projection:"
req GET "${PORT}" "/safe11/subscribers/USR-0001"
note "Its contract, stated for CI:"
req GET "${PORT}" "/safe11/selftest"

# -----------------------------------------------------------------------------------------------
title "2. Whole table, no pagination"
req GET "${PORT}" "/vuln11/subscribers"
note "Every subscriber with every column in one response: the cheapest way to exfiltrate a base."
req GET "${PORT}" "/safe11/subscribers?page=0&size=1"

# -----------------------------------------------------------------------------------------------
title "3. PII in the query string"
req GET "${PORT}" "/vuln11/subscribers/search?email=alice@example.invalid"
note "Access logs, referrer headers, browser history and shared links now contain the address."
note "Reference implementation takes the same value in a POST body:"
req POST "${PORT}" "/safe11/subscribers/search" '{"email":"alice@example.invalid"}'

# -----------------------------------------------------------------------------------------------
title "4. Access token as a query parameter"
req GET "${PORT}" "/vuln11/reports/REP-1?accessToken=placeholder-token-0001"
note "Every proxy, load balancer and access log between client and server has now seen the token."
req_with_headers GET "${PORT}" "/safe11/reports/REP-1" -H 'Authorization: Bearer placeholder-token-0001'

# -----------------------------------------------------------------------------------------------
title "5. Field selection without an allow-list"
req GET "${PORT}" "/vuln11/subscribers/USR-0001/export?fields=passwordHash,refreshToken"
note "Reference implementation rejects the field names and exports the allow-listed ones:"
req GET "${PORT}" "/safe11/subscribers/USR-0001/export?fields=passwordHash"
req GET "${PORT}" "/safe11/subscribers/USR-0001/export?fields=username,primaryPlan"

# -----------------------------------------------------------------------------------------------
title "6. Client-controlled page size"
printf '  /vuln11/subscribers/page?size=1000000 -> '
status_of "${PORT}" "/vuln11/subscribers/page?size=1000000"; echo
printf '  /safe11/subscribers?size=1000000      -> '
status_of "${PORT}" "/safe11/subscribers?size=1000000"; echo
req GET "${PORT}" "/safe11/subscribers?size=1000000"
note "The safe endpoint caps the page size at its own maximum and reports it back."
echo
banner "done · details and fixes: docs/11-data-exposure.md"
