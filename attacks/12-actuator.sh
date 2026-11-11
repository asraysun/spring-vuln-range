#!/usr/bin/env bash
# Checklist section 12 — actuator, API description, debug surfaces.  Target: m12-actuator (8092)
#
# Note: the /safe12 paths here do not exist as controllers on purpose. The hardening of this module
# lives in configuration (application-safe.yml + the security chain), so the "safe" half of the
# demonstration is a second run of the same jar with the safe profile.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
PORT=8092
MANAGEMENT_PORT=8192
banner "12 · management endpoints and API description (port ${PORT})"
up "${PORT}" m12-actuator

# -----------------------------------------------------------------------------------------------
title "1. Endpoint inventory: what an anonymous caller can enumerate"
for endpoint in /actuator /actuator/health /actuator/info /actuator/env /actuator/configprops \
                /actuator/loggers /actuator/threaddump /actuator/heapdump /actuator/shutdown; do
  printf '  %-28s -> ' "${endpoint}"
  status_of "${PORT}" "${endpoint}" -X GET
  echo
done
note "/actuator/env lists property sources (credentials included when show-values=always)."
note "/actuator/heapdump is a one-request dump of everything in memory: tokens, keys, PII."

# -----------------------------------------------------------------------------------------------
title "2. Health details: database, disk, internal component names"
req GET "${PORT}" "/actuator/health"

# -----------------------------------------------------------------------------------------------
title "3. API description served unauthenticated: the complete route map"
req GET "${PORT}" "/api-docs/openapi.json"

# -----------------------------------------------------------------------------------------------
title "4. Runtime log levels are remotely settable"
req POST "${PORT}" "/actuator/loggers/ROOT" '{"configuredLevel":"DEBUG"}'
req GET  "${PORT}" "/actuator/loggers/ROOT"

# -----------------------------------------------------------------------------------------------
title "5. Thread dump: application state on demand"
curl -sS -m 8 "$(BASE_FOR_PORT ${PORT})/actuator/threaddump" 2>/dev/null \
  | head -12 | sed 's/^/    /'
note "Stack frames name your internal classes, libraries and connection pools."

# -----------------------------------------------------------------------------------------------
title "6. The same application hardened by configuration (second run)"
note "Stop this module and start it again with the safe profile:"
note "  scripts/stop-all.sh && java -jar m12-actuator/target/m12-actuator-1.0.0.jar --spring.profiles.active=safe"
note "Then expect:"
note "  http://127.0.0.1:${PORT}/actuator/health  -> 200, 'show-details: never' (no component data)"
note "  http://127.0.0.1:${PORT}/actuator/env     -> 404 (not exposed on the public port)"
note "  http://127.0.0.1:${MANAGEMENT_PORT}/actuator/health -> 200 on the separate management port"
note "  http://127.0.0.1:${MANAGEMENT_PORT}/actuator/heapdump -> 401 for anonymous callers"
req GET "${PORT}" "/actuator/health"
req GET "${PORT}" "/actuator/env"
req GET "${MANAGEMENT_PORT}" "/actuator/health"
req GET "${MANAGEMENT_PORT}" "/actuator/heapdump"
note "The difference is configuration, which is exactly why it belongs in review."
echo
banner "done · details and fixes: docs/12-actuator.md"
