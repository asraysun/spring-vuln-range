#!/usr/bin/env bash
# Static consistency checks for the range, so that "it builds" is not the first time anyone finds
# out that a path changed, a port collides or a module is missing from the reactor.
#
#   usage: scripts/verify_range.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"
STATUS=0

echo "== 1/5 structure, ports, loopback binding, PoC endpoint references =="
python3 scripts/_verify_structure.py || STATUS=1

echo
echo "== 2/5 Java references, imports and known compile traps =="
python3 scripts/_verify_java.py || STATUS=1

echo
echo "== 3/5 YAML syntax =="
python3 scripts/_yamlcheck.py \
  $(find . -path ./target -prune -o -name '*.yml' -print | grep -v '/target/') || STATUS=1

echo
echo "== 4/5 scanner configuration syntax =="
python3 scripts/_tomlcheck.py tools/gitleaks/.gitleaks.toml || STATUS=1

echo
echo "== 5/5 shell scripts (bash -n) and Kubernetes manifest controls =="
for script in scripts/*.sh attacks/*.sh mvnw; do
  bash -n "${script}" || { echo "  FAIL  ${script}"; STATUS=1; }
done
./scripts/check_k8s_manifests.sh > /tmp/vulnrange-k8s-audit.txt 2>&1 || STATUS=1
tail -3 /tmp/vulnrange-k8s-audit.txt | sed 's/^/  /'

echo
if [ "${STATUS}" -eq 0 ]; then
  echo "RESULT: all static checks passed"
else
  echo "RESULT: some static checks failed (see above)"
fi
exit "${STATUS}"
