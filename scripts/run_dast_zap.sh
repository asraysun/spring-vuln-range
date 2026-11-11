#!/usr/bin/env bash
# DAST smoke run against the locally started range. Loopback only, by construction.
#
#   usage: scripts/run_dast_zap.sh [base-url]        (default http://127.0.0.1:8081)
#
# Needs ZAP. Without it the script still runs the passive checks that curl can do (headers, exposed
# endpoints, cookie flags), which is enough to see why a DAST stage earns its place in the pipeline.
set -uo pipefail

BASE="${1:-http://127.0.0.1:8081}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

case "${BASE}" in
  http://127.0.0.1:*|http://localhost:*) ;;
  *)
    echo "refusing to scan ${BASE}: this range is loopback-only by design." >&2
    echo "Point a real DAST engagement at your own staging environment, with authorisation." >&2
    exit 2 ;;
esac

mkdir -p sast-results

if command -v zap.sh >/dev/null 2>&1; then
  echo "== ZAP baseline scan (passive) =="
  zap.sh -cmd -quickurl "${BASE}" -quickout sast-results/zap-baseline.html || true
elif command -v docker >/dev/null 2>&1; then
  echo "== ZAP baseline via container =="
  docker run --rm --network host -v "${ROOT}/sast-results:/zap/wrk:rw" \
    ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t "${BASE}" -r zap-baseline.html || true
else
  echo "ZAP is not installed; running the curl-only equivalent checks instead."
fi

echo
echo "== passive checks that need nothing but curl =="
check() {
  local url="$1" expect="$2" description="$3"
  local headers
  headers="$(curl -sS -m 5 -D - -o /dev/null "${url}" 2>/dev/null || true)"
  if echo "${headers}" | grep -qiE "${expect}"; then
    echo "  present: ${description}  <- ${url}"
  else
    echo "  MISSING: ${description}  <- ${url}"
  fi
}

check "${BASE}/" "content-security-policy" "Content-Security-Policy"
check "${BASE}/" "x-content-type-options:\s*nosniff" "X-Content-Type-Options: nosniff"
check "${BASE}/" "x-frame-options|frame-ancestors" "clickjacking protection"
check "${BASE}/" "strict-transport-security" "HSTS"
check "${BASE}/" "referrer-policy" "Referrer-Policy"

echo
echo "== exposed management endpoints across the range =="
for port in 8081 8082 8083 8084 8085 8086 8087 8088 8089 8090 8091 8092 8093 8094 8095 8096; do
  for endpoint in /actuator /actuator/env /actuator/heapdump /api-docs/openapi.json; do
    code="$(curl -s -o /dev/null -w '%{http_code}' -m 3 "http://127.0.0.1:${port}${endpoint}" 2>/dev/null || echo 000)"
    if [ "${code}" = "200" ]; then
      echo "  OPEN     :${port}${endpoint}"
    fi
  done
done

echo
echo "In a real pipeline run the full active scan against an isolated staging environment only."
