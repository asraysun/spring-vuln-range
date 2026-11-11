#!/usr/bin/env bash
# Build everything, then start all 16 modules in the background (loopback only).
# Logs: logs/<module>.log   Pids: logs/<module>.pid   Stop: scripts/stop-all.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"
mkdir -p logs

MODULES="m01-authentication m02-authorization m03-secrets-config m04-validation-binding \
m05-injection m06-deserialization m07-web-layer m08-crypto-tls m09-logging-errors \
m10-ssrf-webhooks m11-data-exposure m12-actuator m13-supply-chain m14-runtime-hardening \
m15-business-logic m16-verification"

# m13 carries intentionally vulnerable dependencies (supply-chain demo). Skip it with SKIP_M13=1.
if [ "${SKIP_M13:-0}" = "1" ]; then
  MODULES="${MODULES/m13-supply-chain/}"
  echo "[run-all] m13-supply-chain skipped (SKIP_M13=1)"
fi

echo "[run-all] building reactor (this also proves the range compiles)"
./mvnw -q -DskipTests package || { echo "[run-all] build failed"; exit 1; }

for m in ${MODULES}; do
  if [ -f "logs/${m}.pid" ] && kill -0 "$(cat "logs/${m}.pid")" 2>/dev/null; then
    echo "[run-all] ${m} already running (pid $(cat "logs/${m}.pid"))"
    continue
  fi
  JAR="$(find "${m}/target" -maxdepth 1 -name '*.jar' ! -name '*-sources.jar' 2>/dev/null | head -1)"
  if [ -z "${JAR}" ]; then
    echo "[run-all] ${m}: no jar, skipped" >&2
    continue
  fi
  nohup java -Dserver.address=127.0.0.1 -jar "${JAR}" > "logs/${m}.log" 2>&1 &
  echo $! > "logs/${m}.pid"
  echo "[run-all] ${m} started pid $! -> logs/${m}.log"
done

echo
echo "[run-all] waiting for loopback listeners"
sleep 8
"${ROOT}/scripts/status.sh" || true
echo
echo "[run-all] stop everything with: scripts/stop-all.sh"
