#!/usr/bin/env bash
# Stop every module started by scripts/run-all.sh.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

if [ ! -d logs ]; then
  echo "[stop-all] nothing to stop (no logs directory)"
  exit 0
fi

for pidfile in logs/*.pid; do
  [ -e "${pidfile}" ] || continue
  pid="$(cat "${pidfile}")"
  name="$(basename "${pidfile}" .pid)"
  if kill -0 "${pid}" 2>/dev/null; then
    kill "${pid}" 2>/dev/null || true
    echo "[stop-all] ${name} pid ${pid} terminated"
  else
    echo "[stop-all] ${name} pid ${pid} not running"
  fi
  rm -f "${pidfile}"
done
