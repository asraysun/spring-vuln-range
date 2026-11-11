#!/usr/bin/env bash
# Supply-chain gate: SCA over the Maven reactor (+ Trivy when available).
#
# Expected result against THIS repository: FAIL on m13-supply-chain
# (commons-collections 3.2.1, fastjson 1.2.24). That failure is the acceptance test for the gate.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"
mkdir -p sast-results/dependency-check

echo "== 1/3 Maven dependency tree (what you actually ship) =="
./mvnw -q dependency:tree -DoutputDirectory=sast-results 2>/dev/null \
  || echo "   dependency:tree unavailable offline; continuing"

echo
echo "== 2/3 OWASP dependency-check (needs the NVD feed, so it needs network) =="
if ./mvnw -B -pl m13-supply-chain org.owasp:dependency-check-maven:check \
      -DfailBuildOnCVSS=7 \
      -DsuppressionFile=tools/owasp/suppressions.xml; then
  echo "   UNEXPECTED: the gate passed although m13 ships known-vulnerable libraries."
  echo "   Check that the NVD database was downloaded (a stale DB silently reports nothing)."
  GATE=1
else
  echo "   gate failed as expected -> m13 findings are real. Report: sast-results/dependency-check/"
  GATE=0
fi

echo
echo "== 3/3 Trivy (filesystem + image) =="
if command -v trivy >/dev/null 2>&1; then
  trivy fs --severity CRITICAL,HIGH --exit-code 1 . || echo "   trivy reported findings"
else
  echo "   trivy not installed; in CI use aquasecurity/trivy-action (see .github/workflows/security.yml)"
fi

echo
echo "== What to check in your own pipeline =="
cat <<'TXT'
 1. Does the scanner see TRANSITIVE dependencies (not just the declared ones)?
 2. Is the vulnerability database fresh, and is a stale DB a build failure?
 3. Is there a threshold (CVSS/reachable) that actually fails the build?
 4. Are suppressions dated and owned, and does an expired one fail?
 5. Are build plugins and container images scanned too, not only the jar?
 6. Is there a nightly rescan, so a new CVE in an old dependency resurfaces?
TXT

exit "${GATE}"
