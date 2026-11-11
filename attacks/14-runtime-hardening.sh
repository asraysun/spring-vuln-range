#!/usr/bin/env bash
# Checklist section 14 — runtime, container and platform hardening.  Target: m14-runtime-hardening (8094)
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
PORT=8094
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
banner "14 · post-exploitation view of the runtime (port ${PORT})"
up "${PORT}" m14-runtime-hardening

# -----------------------------------------------------------------------------------------------
title "1. Identity, mounts and credential layout in one anonymous call"
note "Nothing here is a bug by itself. It is the answer to 'what do I do next?' once any request-level"
note "primitive exists (an SSRF, one path traversal, one leaked ingress rule)."
req GET "${PORT}" "/vuln14/context"

# -----------------------------------------------------------------------------------------------
title "2. Credential-shaped variables, with values"
note "Requires demo credentials in the environment before starting the service:"
note "  export DEMO_DB_PASSWORD=supersecret123 DEMO_API_TOKEN=tok_live_abc123 DEMO_SECRET_KEY=sk_demo_456 DEMO_AUTH_KEY=auth_key_789"
note "Without these variables the endpoint returns {} (no secrets present in env)."
req GET "${PORT}" "/vuln14/config-check"
note "A root container with secrets in env means /proc/self/environ is a credential store."

# -----------------------------------------------------------------------------------------------
title "3. Writable filesystem: a request-level write becomes persistence"
req POST "${PORT}" "/vuln14/write" "{\"path\":\"/tmp/vulnrange-m14-written.txt\",\"content\":\"persisted\"}"
printf '  file present on disk -> '
if [ -f /tmp/vulnrange-m14-written.txt ]; then echo "yes"; else echo "no"; fi
note "On a hardened pod (readOnlyRootFilesystem: true, tmpfs for /tmp only) the same call fails."

# -----------------------------------------------------------------------------------------------
title "4. What a hardened runtime would report instead"
req GET "${PORT}" "/safe14/hardening"
req POST "${PORT}" "/safe14/write" "{\"path\":\"/etc/evil.conf\",\"content\":\"x\"}"
req GET "${PORT}" "/safe14/egress-and-integrity"

# -----------------------------------------------------------------------------------------------
title "5. The manifests, and the audit that runs in CI"
note "Diff the two manifests; the diff is most of this checklist section:"
note "  ${ROOT}/m14-runtime-hardening/deploy/k8s/vulnerable-deployment.yaml"
note "  ${ROOT}/m14-runtime-hardening/deploy/k8s/hardened-deployment.yaml"
echo "  running the manifest audit:"
"${ROOT}/scripts/check_k8s_manifests.sh" 2>&1 | tail -25 | sed 's/^/    /'
note "Exit code 0 means the hardened manifest contains every control the script checks."
note "Add these controls to a Pod Security Standards profile (restricted) and to an admission policy,"
note "so a non-compliant pod cannot be scheduled at all."
echo
banner "done · details and fixes: docs/14-runtime-hardening.md"
