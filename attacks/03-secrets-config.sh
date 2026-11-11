#!/usr/bin/env bash
# Checklist section 3 — secrets and configuration.  Target: m03-secrets-config (8083)
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
PORT=8083
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
banner "03 · secrets and configuration (port ${PORT})"
up "${PORT}" m03-secrets-config

# -----------------------------------------------------------------------------------------------
title "1. Secrets returned by an ordinary API call"
req GET "${PORT}" "/vuln3/config"
note "This is a 'config inspector' support endpoint. Anyone who can call it holds the credentials."

# -----------------------------------------------------------------------------------------------
title "2. The service hands out its own integration credential instead of using it"
req GET "${PORT}" "/vuln3/integration/token"
note "Compare: /safe3 signs the request with the key and shows only a fingerprint."
req POST "${PORT}" "/safe3/integration/call" '{"requestId":"req-0001"}'

# -----------------------------------------------------------------------------------------------
title "3. Environment dump: every credential-shaped variable with its value"
req GET "${PORT}" "/vuln3/env-dump"
note "Run the app with a Vault-injected variable and watch it appear here:"
note "  RANGE_M03_ESPD_API_KEY=secret-from-vault scripts/run-module.sh m03-secrets-config"

# -----------------------------------------------------------------------------------------------
title "4. Credential written into the application log (and from there into the SIEM)"
MARKER="CARD-$(date +%s)"
req POST "${PORT}" "/vuln3/integration/check" "{\"dbUser\":\"espd_app\",\"dbPassword\":\"${MARKER}\"}"
sleep 1
if [ -f "${ROOT}/logs/m03-secrets-config.log" ]; then
  echo "  grep of logs/m03-secrets-config.log:"
  grep -n "${MARKER}" "${ROOT}/logs/m03-secrets-config.log" | head -3 | sed 's/^/    /' \
    || echo "    (log line not found - start the module with scripts/run-all.sh so logs are captured)"
else
  echo "  logs/m03-secrets-config.log not present; start with scripts/run-all.sh, then rerun this step"
fi
note "Now imagine the field is a real password: it is in a file, in the log shipper, in the index, in a backup."

# -----------------------------------------------------------------------------------------------
title "5. Development tooling enabled in a production-shaped configuration"
req GET "${PORT}" "/vuln3/diagnostics"
printf '  /h2-console/ answers -> '; status_of "${PORT}" "/h2-console/"
echo
note "An in-process SQL console reachable over HTTP is a complete database takeover: the JDBC URL"
note "is in the config dump above, and the console does not care which schema you point it at."

# -----------------------------------------------------------------------------------------------
title "6. One credential for every environment"
req GET "${PORT}" "/vuln3/per-env-credentials"
note "A dev-only leak (a screenshot, a trainee's laptop, a shared CI variable) is therefore a prod breach."

# -----------------------------------------------------------------------------------------------
title "7. The repository is the leak: scan the history, not only HEAD"
cd "${ROOT}" || exit 1
if git rev-parse --git-dir >/dev/null 2>&1; then
  echo "  git log -p …/application.yml | grep password:"
  git log -p -- m03-secrets-config/src/main/resources/application.yml 2>/dev/null \
    | grep -niE "password|api-key" | head -5 | sed 's/^/    /'
else
  echo "  (this checkout is not a git repository; on a real one run:"
  echo "     git log -p -- '**/application*.yml' | grep -inE 'password|secret|token'"
  echo "     ./scripts/run_secret_scan.sh )"
fi
echo "  grep over the working tree instead:"
grep -rnE "espd-api-key|db-password|encryption-key" m03-secrets-config/src/main/resources/*.yml | sed 's/^/    /'

# -----------------------------------------------------------------------------------------------
title "8. The reference shape: presence without material"
req GET "${PORT}" "/safe3/config-summary"
req POST "${PORT}" "/safe3/integration/call" '{"requestId":"req-0002"}'
req POST "${PORT}" "/safe3/echo" '{"token":"echo-me-and-watch-the-mask"}'
echo
banner "done · details and fixes: docs/03-secrets-config.md"
