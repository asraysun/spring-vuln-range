#!/usr/bin/env bash
# Checklist section 16 — process and verification.  Target: m16-verification (8096)
#
# This is the module that asks the uncomfortable question: would your tooling actually catch the
# other fifteen? It contains SAST fixtures (must be flagged) and an authorization matrix (must pass
# on /safe16 and must not be "fixed" by weakening the assertion).
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
PORT=8096
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
banner "16 · verification: does the pipeline see what is in front of it? (port ${PORT})"
up "${PORT}" m16-verification

# -----------------------------------------------------------------------------------------------
title "1. Authorization matrix, live"
note "In the test matrix alice owns DOC-0001 and bob owns DOC-0002; the live service has no"
note "authentication filter, so both callers arrive anonymous and see the same status."
printf '  /safe16/documents/DOC-0001 (anonymous) -> '; status_of "${PORT}" "/safe16/documents/DOC-0001"; echo
printf '  /safe16/documents/DOC-0002 (anonymous) -> '; status_of "${PORT}" "/safe16/documents/DOC-0002"; echo
note "The real matrix runs as a test (see below), where a principal can be set."
req GET "${PORT}" "/safe16/policy"
req GET "${PORT}" "/vuln16/documents/DOC-0002"

# -----------------------------------------------------------------------------------------------
title "2. The matrix as a test, where a principal actually exists"
echo "  ./mvnw -pl m16-verification test"
note "  SafeOwnershipMatrixTest      - owner 200, other user 404, other tenant 404"
note "  VulnerableEndpointRegressionTest - asserts the leak exists, so the contrast is visible"

# -----------------------------------------------------------------------------------------------
title "3. SAST fixtures: every pattern below must appear in the scanner report"
for fixture in sql-injection path-traversal weak-hash open-redirect hardcoded-secret jdbc-url; do
  printf '  GET  /vuln16/fixture/%-18s -> ' "${fixture}"
  status_of "${PORT}" "/vuln16/fixture/${fixture}"
  echo
done
for fixture in log-injection xxe; do
  printf '  POST /vuln16/fixture/%-18s -> ' "${fixture}"
  status_of "${PORT}" "/vuln16/fixture/${fixture}" -X POST
  echo
done
note "A clean report on these eight is proof the SAST stage is not looking."
note "  ./mvnw -Psast -pl m16-verification verify    (SpotBugs + Find Security Bugs)"
note "  semgrep --config tools/semgrep/spring-security-rules.yml ."

# -----------------------------------------------------------------------------------------------
title "4. The whole gate chain, calibrated against this repository"
for script in verify_range.sh run_secret_scan.sh run_sast.sh run_sca.sh; do
  if [ -x "${ROOT}/scripts/${script}" ]; then
    echo "  available: scripts/${script}"
  fi
done
note "Expected outcomes here:"
note "  scripts/run_secret_scan.sh  -> finds the documented placeholder literals (not silent)"
note "  scripts/run_sast.sh         -> finds the m16 fixtures"
note "  scripts/run_sca.sh          -> FAILS on m13 (that failure is the acceptance test)"
note "  scripts/verify_range.sh     -> checks the range is self-consistent"

# -----------------------------------------------------------------------------------------------
title "5. Definition of Done, security part (copy into your own ticket template)"
cat <<'TXT'
  [ ] threat model updated for the feature (data, actors, trust boundaries, abuse cases)
  [ ] negative authorization matrix row added for every new endpoint
  [ ] new inputs bounded and validated at the trust boundary (DTO, allow-list, size)
  [ ] no new permitAll / ignoring() / csrf().disable() without a written justification
  [ ] new outbound call has an allow-list, timeouts and a response-size cap
  [ ] secrets resolved at runtime (mounted file / env from Vault), never a repository default
  [ ] logs carry the correlation id and no PII, tokens or credentials
  [ ] repository methods used by the API returns a projection, not an entity
  [ ] actuator/docs endpoints unchanged or explicitly reviewed in the same MR
  [ ] dependency diff reviewed; SCA, SAST, secret-scan gates green or suppression dated
  [ ] security events added: what should alert when it happens
  [ ] rollback plan covers the migration / key change introduced here
TXT
echo
banner "done · details and fixes: docs/16-verification.md"
