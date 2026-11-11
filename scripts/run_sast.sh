#!/usr/bin/env bash
# Static analysis gate.
#
# Expected result against THIS repository: findings in m01-m16 (fixtures). A run with zero findings
# means the toolchain is not looking at the code, and no "clean" report from it should be trusted.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"
mkdir -p sast-results

echo "== 1/3 Semgrep with tools/semgrep/spring-security-rules.yml =="
if command -v semgrep >/dev/null 2>&1; then
  semgrep scan --config tools/semgrep/spring-security-rules.yml --metrics=off \
    --text --output sast-results/semgrep-report.txt . || echo "   semgrep reported findings (expected)"
else
  echo "   semgrep not installed: pip install semgrep   (or run the container: returntocorp/semgrep)"
  echo "   fallback grep -l scan of the same patterns:"
  grep -rlnE "csrf\(\)\.disable|headers\(\)\.disable|ignoring\(\)|MessageDigest\.getInstance\(\"MD5\"\)|Cipher\.getInstance\(\"AES/ECB|activateDefaultTyping|setAutoTypeSupport\(true\)|include-stacktrace: always" \
    --include='*.java' --include='*.yml' . | sed 's/^/     hit: /' | head -40
fi

echo
echo "== 2/3 SpotBugs + Find Security Bugs (m16 fixtures) =="
if ./mvnw -q -Psast -pl m16-verification verify; then
  echo "   spotbugs finished; see sast-results/spotbugs (findings expected in FlaggableSastFixtures)"
else
  echo "   spotbugs run failed or reported issues; inspect sast-results/spotbugs"
fi

echo
echo "== 3/3 Manual review shortcuts that catch what tools miss =="
cat <<'TXT'
  * New endpoint? grep for ownership: does the query include the principal or tenant?
      grep -rn "@GetMapping\|@PostMapping\|@PutMapping\|@DeleteMapping" src/main/java | wc -l
      grep -rn "@PreAuthorize" src/main/java | wc -l
  * Any permitAll added in this diff?       git diff -U0 -- '*.java' | grep -n 'permitAll\|ignoring()'
  * Any new outbound call?                  git diff -U0 -- '*.java' | grep -n 'RestTemplate\|WebClient\|HttpClient'
  * Any new @Query?                         git diff -U0 -- '*.java' | grep -n '@Query\|createNativeQuery'
  * Any new dependency?                     git diff -U0 -- 'pom.xml' | grep -n '^+.*<artifactId>'
TXT
