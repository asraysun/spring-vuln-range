#!/usr/bin/env bash
# Checklist section 4 — input validation and data binding.  Target: m04-validation-binding (8084)
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
PORT=8084

# Detect OS and set temp directory for file staging.
if uname -s | grep -qi microsoft; then
  # Windows (Git Bash / WSL): use %TEMP% or %TMP%
  TMP_DIR="${TMP:-${TEMP:-/tmp}}"
else
  TMP_DIR="/tmp"
fi

banner "04 · input validation and data binding (port ${PORT})"
up "${PORT}" m04-validation-binding

# -----------------------------------------------------------------------------------------------
title "1. Mass assignment through form binding (CWE-915)"
note "The form fields map onto the persistence entity, so 'role' and 'priceOverride' are inputs."
req POST "${PORT}" "/vuln4/users" "username=attacker&email=a@example.invalid&role=ADMIN&monthlyLimit=999999&priceOverride=0" \
  application/x-www-form-urlencoded
note "Same request against /safe4: the DTO has no such fields, and unknown JSON fields are rejected."
req POST "${PORT}" "/safe4/users" '{"username":"attacker","email":"a@example.invalid","role":"ADMIN","monthlyLimit":999999}'
printf '  (note: /safe4/users expects JSON; the form call above is the contrast case)'

# -----------------------------------------------------------------------------------------------
title "2. Mass assignment through JSON"
req POST "${PORT}" "/vuln4/users/json" '{"username":"m1","email":"m1@example.invalid","role":"ADMIN","priceOverride":-1}'

# -----------------------------------------------------------------------------------------------
title "3. No bounds on input: absurd lengths and shapes are accepted"
LONG=$(printf 'A%.0s' $(seq 1 400))
req POST "${PORT}" "/vuln4/notes" "{\"body\":\"${LONG}\"}"
note "A length/format rule at the boundary removes a whole class of downstream problems."
req POST "${PORT}" "/safe4/search" "{\"query\":\"${LONG:0:80}\",\"input\":\"x\"}"

# -----------------------------------------------------------------------------------------------
title "4. ORDER BY taken from the request (identifiers cannot be parameterised)"
req GET "${PORT}" "/vuln4/subscriptions?sort=monthly_price&direction=desc&plan=ESPD-BASIC"
note "Blind extraction through a CASE expression, with no quotes needed:"
req GET "${PORT}" "/vuln4/subscriptions?sort=(CASE%20WHEN%20(1=1)%20THEN%20id%20ELSE%20plan%20END)&direction=asc&plan=ESPD-BASIC"
note "Reference implementation resolves both sort and direction from an allow-list:"
req GET "${PORT}" "/safe4/subscriptions?sort=monthly_price&direction=desc&plan=ESPD-BASIC"
req GET "${PORT}" "/safe4/subscriptions?sort=password_hash&direction=desc&plan=ESPD-BASIC"

# -----------------------------------------------------------------------------------------------
title "5. Path traversal in a file read (CWE-22)"
# Stage a file inside the service upload directory through the unvalidated upload endpoint itself,
# then read it back by name. No assumptions about where java.io.tmpdir points on this OS.
mkdir -p "${TMP_DIR}"
printf 'staged-by-the-upload-endpoint' > "${TMP_DIR}/vulnrange-probe.txt"
req POST "${PORT}" "/vuln4/upload" "" multipart/form-data -F "file=@${TMP_DIR}/vulnrange-probe.txt;filename=probe.txt"
req GET "${PORT}" "/vuln4/files/probe.txt"
note "Directory-climbing attempt: Spring's default HttpFirewall rejects %2F/%5C and %2e sequences,"
note "so the encoded variant is refused by the firewall. That is one of the few defaults that saves"
note "you - it is not the application checking anything, which is why /safe4 normalises and checks too."
req GET "${PORT}" "/vuln4/files/%2e%2e%2f%2e%2e%2fetc%2fhosts"
note "Reference implementation normalises and checks containment:"
req GET "${PORT}" "/safe4/files/%2e%2e%2f%2e%2e%2fetc%2fhosts"

# -----------------------------------------------------------------------------------------------
title "6. Upload with no size, type or filename checks"
mkdir -p "${TMP_DIR}/vulnrange-m04-uploads"
printf 'not-a-text-file-but-the-server-does-not-care' > "${TMP_DIR}/vulnrange-upload-probe.txt"
req POST "${PORT}" "/vuln4/upload" "" multipart/form-data \
  -F "file=@${TMP_DIR}/vulnrange-upload-probe.txt;filename=../../../../tmp/vulnrange-escapes-upload-root.txt"
echo "  did it escape the upload directory?"
[ -f "${TMP_DIR}/vulnrange-escapes-upload-root.txt" ] && echo "    yes: ${TMP_DIR}/vulnrange-escapes-upload-root.txt was written" \
  || echo "    no (container refused or normalised the name)"
note "Reference implementation: size cap, extension allow-list, magic bytes, generated filename."
req POST "${PORT}" "/safe4/upload" "" multipart/form-data -F "file=@${TMP_DIR}/vulnrange-upload-probe.txt;filename=report.txt"
printf 'evil' > "${TMP_DIR}/vulnrange-upload-probe.txt.exe"
req POST "${PORT}" "/safe4/upload" "" multipart/form-data -F "file=@${TMP_DIR}/vulnrange-upload-probe.txt.exe;filename=report.exe"

# -----------------------------------------------------------------------------------------------
title "7. Binder exposure (the Spring4Shell shape)"
note "On a patched Spring the class-resolver chain is dead; the DTO boundary is the actual fix."
req POST "${PORT}" "/vuln4/binder-probe" 'role=ADMIN&probe=class.classLoader.name' application/x-www-form-urlencoded
req POST "${PORT}" "/vuln4/binder-probe" 'class.module.classLoader=default' application/x-www-form-urlencoded

# -----------------------------------------------------------------------------------------------
title "8. ReDoS through a user-supplied regular expression"
req POST "${PORT}" "/vuln4/search/regex" '{"pattern":"(a+)+$","input":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaab"}'
note "Same intent, bounded engine:"
req POST "${PORT}" "/safe4/search" '{"query":"aaa","input":"aaab"}'

# -----------------------------------------------------------------------------------------------
title "9. Open redirect and unbounded export"
req GET "${PORT}" "/vuln4/redirect?url=http://evil.example.invalid/phishing"
req GET "${PORT}" "/safe4/redirect?url=http://evil.example.invalid/phishing"
req GET "${PORT}" "/safe4/redirect?url=subscriptions"
req GET "${PORT}" "/vuln4/export?size=2000000"
req GET "${PORT}" "/safe4/export?size=2000000"
echo
banner "done · details and fixes: docs/04-validation-binding.md"
