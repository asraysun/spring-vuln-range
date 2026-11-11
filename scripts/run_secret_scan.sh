#!/usr/bin/env bash
# Secret scanning over the working tree AND the git history (secrets live in old commits).
#
# Expected result against THIS repository: findings for the placeholder literals in
# m03-secrets-config and m16-verification. Zero findings = the scanner is misconfigured.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"
mkdir -p sast-results

if command -v gitleaks >/dev/null 2>&1; then
  echo "== gitleaks over git history =="
  if git rev-parse --git-dir >/dev/null 2>&1; then
    gitleaks detect --source . --config tools/gitleaks/.gitleaks.toml --redact \
      --report-format json --report-path sast-results/gitleaks-report.json || \
      echo "   gitleaks reported findings (expected against this repository)"
  else
    echo "   no git repository here; scanning the working tree instead"
    gitleaks detect --no-git --source . --config tools/gitleaks/.gitleaks.toml --redact || \
      echo "   gitleaks reported findings (expected against this repository)"
  fi
else
  echo "gitleaks not installed (brew install gitleaks). Falling back to a grep-shaped scan:"
fi

echo
echo "== grep-shaped fallback (catches the classic shapes) =="
grep -rnEi --include='*.java' --include='*.yml' --include='*.yaml' --include='*.properties' --include='*.xml' \
  '(password|secret|api[_-]?key|access[_-]?token|private[_-]?key)[[:space:]]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9/+=._-]{10,}' \
  . | grep -v '/sast-results/' | head -30 | sed 's/^/  hit: /'

echo
echo "== files that must never be tracked =="
for pattern in '.env' '*.pem' '*.p12' '*.jks' '*.keystore' 'id_rsa'; do
  matches=$(git ls-files 2>/dev/null | grep -E "${pattern}" || true)
  if [ -n "${matches}" ]; then
    echo "  TRACKED (fix now): ${matches}"
  fi
done
grep -qxF '.env' .gitignore && echo "  ok: .env is ignored" || echo "  WARN: .env is not in .gitignore"
grep -qE 'keystore|\.p12|\.pem' .gitignore && echo "  ok: key material is ignored" || echo "  WARN: key material not ignored"

echo
echo "Remember: deleting a secret from HEAD does not remove it from history."
echo "Rotate it, then rewrite history or decommission the credential entirely."
