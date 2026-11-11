#!/usr/bin/env bash
# Shared helpers for the PoC scripts.
#
# Two hard rules, both deliberate:
#   1. every request must go to the loopback interface - the guard below refuses anything else,
#      so a stray RANGE_HOST/typo cannot turn this into traffic against somebody else's system;
#   2. the scripts only demonstrate the checklist items of this range; they contain no payload
#      that targets a third-party host, service or person.
set -uo pipefail

RANGE_HOST="${RANGE_HOST:-127.0.0.1}"
CURL_TIMEOUT="${CURL_TIMEOUT:-8}"

_guard() {
  case "$1" in
    "http://${RANGE_HOST}:"*|"http://localhost:"*) return 0 ;;
    *)
      echo "REFUSING ${1}: this range is loopback-only by design." >&2
      echo "Attack your own staging environment with written authorisation, not with this script." >&2
      exit 2 ;;
  esac
}

BASE_FOR_PORT() { echo "http://${RANGE_HOST}:$1"; }

title() {
  echo
  echo "-------------------------------------------------------------------------------"
  echo "  $*"
  echo "-------------------------------------------------------------------------------"
}

note() { echo "  >> $*"; }

# req METHOD PORT PATH [BODY] [CONTENT_TYPE] [EXTRA CURL ARGS...]
req() {
  local method="$1" port="$2" path="$3" body="${4:-}" ctype="${5:-application/json}"
  if [ "$#" -ge 5 ]; then shift 5; else shift "$#"; fi
  local url; url="$(BASE_FOR_PORT "${port}")${path}"
  _guard "${url}"

  local args=(-sS -m "${CURL_TIMEOUT}" -X "${method}" -H "Content-Type: ${ctype}" -w '\n<status:%{http_code}>' "${url}")
  if [ -n "${body}" ]; then
    args+=(--data-binary "${body}")
  fi
  if [ "$#" -gt 0 ]; then
    args+=("$@")
  fi

  echo
  echo "  ${method} ${path}"
  if [ -n "${body}" ]; then
    echo "  body: ${body:0:220}$([ ${#body} -gt 220 ] && echo ' …')"
  fi
  curl "${args[@]}" 2>/dev/null | sed -e 's/^/    /' | head -40
}

# raw: same as req but keeps headers, for header/Cookie/CORS assertions
req_with_headers() {
  local method="$1" port="$2" path="$3"; shift 3
  local url; url="$(BASE_FOR_PORT "${port}")${path}"
  _guard "${url}"
  echo
  echo "  ${method} ${path} (with response headers)"
  curl -sS -m "${CURL_TIMEOUT}" -X "${method}" -D - -o /dev/null "$@" "${url}" 2>/dev/null | sed -e 's/^/    /' | head -40
}

# body_of PORT PATH -> response body only (for value extraction in a PoC)
body_of() {
  local url; url="$(BASE_FOR_PORT "$1")$2"
  _guard "${url}"
  curl -sS -m "${CURL_TIMEOUT}" "${url}" 2>/dev/null
}

post_body_of() {
  local url; url="$(BASE_FOR_PORT "$1")$2"
  _guard "${url}"
  curl -sS -m "${CURL_TIMEOUT}" -X POST -H "Content-Type: ${4:-application/json}" --data-binary "$3" "${url}" 2>/dev/null
}

status_of() {
  local url; url="$(BASE_FOR_PORT "$1")$2"
  _guard "${url}"
  curl -sS -m "${CURL_TIMEOUT}" -o /dev/null -w '%{http_code}' "${@:3}" "${url}" 2>/dev/null
}

up() {
  if ! status_of "$1" "/" >/dev/null 2>&1 || [ "$(status_of "$1" "/")" = "000" ]; then
    echo
    echo "Module on port $1 is not answering."
    echo "Start it with:  scripts/run-module.sh $2     (or scripts/run-all.sh)"
    exit 3
  fi
}

banner() {
  echo "==============================================================================="
  echo " $*"
  echo "==============================================================================="
  echo " target: ${RANGE_HOST} (loopback) - educational range, intentionally vulnerable"
}
