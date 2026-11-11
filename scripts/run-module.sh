#!/usr/bin/env bash
# Start a single vulnerable module in the foreground.
#   usage: scripts/run-module.sh m05-injection
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODULE="${1:-}"
if [ -z "${MODULE}" ]; then
  echo "usage: $0 <module-dir>   (e.g. $0 m05-injection)" >&2
  exit 2
fi

JAR="$(find "${ROOT}/${MODULE}/target" -maxdepth 1 -name '*.jar' ! -name '*-sources.jar' 2>/dev/null | head -1)"
if [ -z "${JAR}" ]; then
  echo "[run-module] no jar for ${MODULE}, building it first" >&2
  "${ROOT}/mvnw" -q -pl "${MODULE}" -am -DskipTests package || exit 1
  JAR="$(find "${ROOT}/${MODULE}/target" -maxdepth 1 -name '*.jar' ! -name '*-sources.jar' 2>/dev/null | head -1)"
fi

# Every module binds to 127.0.0.1 via its own application.yml. server.address is passed
# again here so that a copy-pasted external config cannot silently widen the binding.
exec java -Dserver.address=127.0.0.1 -jar "${JAR}" "${@:2}"
