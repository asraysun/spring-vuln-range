#!/usr/bin/env bash
# Which modules are up? Uses a loopback TCP probe only (no external traffic).
set -uo pipefail

PORTS="8081 8082 8083 8084 8085 8086 8087 8088 8089 8090 8091 8092 8093 8094 8095 8096"
NAMES="m01-authentication m02-authorization m03-secrets-config m04-validation-binding \
m05-injection m06-deserialization m07-web-layer m08-crypto-tls m09-logging-errors \
m10-ssrf-webhooks m11-data-exposure m12-actuator m13-supply-chain m14-runtime-hardening \
m15-business-logic m16-verification"

i=1
for p in ${PORTS}; do
  name="$(echo "${NAMES}" | tr ' ' '\n' | sed -n "${i}p")"
  if (exec 3<>"/dev/tcp/127.0.0.1/${p}") 2>/dev/null; then
    echo "  ${p}  UP    ${name}"
  else
    echo "  ${p}  down  ${name}"
  fi
  i=$((i + 1))
done
