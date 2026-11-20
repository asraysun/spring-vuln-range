#!/usr/bin/env bash
# Checklist section 17 — Spring4Shell (CVE-2022-22965).  Target: m17-spring4shell (8097)
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
PORT=8097
banner "17 · Spring4Shell RCE via Spring Data Binding (port ${PORT})"
up "${PORT}" m17-spring4shell

# -----------------------------------------------------------------------------------------------
title "1. Normal form submission (expected to work)"
req POST "${PORT}" "/vuln17/profile" "name=alice&email=alice@example.com&age=30"
note "Normal form submission works as expected."

# -----------------------------------------------------------------------------------------------
title "2. Exploit attempt 1: class.module.classLoader parameter"
req POST "${PORT}" "/vuln17/exploit" "class.module.classLoader=@java.lang.Runtime@getRuntime()"
note "The server detects and logs the exploit attempt."

# -----------------------------------------------------------------------------------------------
title "3. Exploit attempt 2: Mixed with normal parameters"
req POST "${PORT}" "/vuln17/exploit" "name=test&email=test@example.com&age=30&class.module.classLoader=@java.lang.Runtime@getRuntime()"
note "Even with normal parameters mixed in, the exploit is detected."

# -----------------------------------------------------------------------------------------------
title "4. Safe endpoint rejects exploit"
req POST "${PORT}" "/safe17/profile" "class.module.classLoader=@java.lang.Runtime@getRuntime()"
note "The safe endpoint uses setDisallowedFields(\"class.*\") to block the exploit."

# -----------------------------------------------------------------------------------------------
title "5. Safe endpoint still accepts normal form"
req POST "${PORT}" "/safe17/profile" "name=bob&email=bob@example.com&age=25"
note "Normal form submission works on the safe endpoint."

# -----------------------------------------------------------------------------------------------
title "6. Mitigations summary"
note "1. Upgrade to Spring Framework 5.3.18+ or 6.0.3+"
note "2. Add @InitBinder with setDisallowedFields(\"class.*\")"
note "3. Use setAllowedFields() to whitelist properties"
note "4. Use @Valid with validation annotations"
note "5. Use Spring Boot 2.6.7+ or 2.5.13+"
echo
banner "done · details and fixes: docs/17-spring4shell.md"
