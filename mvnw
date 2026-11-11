#!/bin/sh
# ---------------------------------------------------------------------------------------
# Maven bootstrap for spring-vuln-range.
#
# This is NOT the official maven-wrapper script: it is a deliberately tiny, auditable
# bootstrap that downloads a pinned Apache Maven distribution into .mvn/maven-distro
# (inside this project, nothing is installed system-wide) and then delegates to it.
#
# If you prefer the real wrapper, run once with any Maven on PATH:  mvn wrapper:wrapper
# ---------------------------------------------------------------------------------------
set -eu

MAVEN_VERSION="${MAVEN_VERSION:-3.9.9}"
# Internal mirrors: override with  MVN_BASE_URL=https://nexus.example.org/maven2  ./mvnw ...
BASE_URL="${MVN_BASE_URL:-https://repo.maven.apache.org/maven2}"
# Internal repo settings.xml (Vault-backed credentials) are picked up automatically
# from ~/.m2/settings.xml by Maven itself; nothing sensitive is stored here.
MVN_REPO_URL="${MVN_REPO_URL:-${BASE_URL}}"

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
DIST_DIR="${SCRIPT_DIR}/.mvn/maven-distro"
MVN_BIN="${DIST_DIR}/apache-maven-${MAVEN_VERSION}/bin/mvn"
TARBALL_URL="${MVN_REPO_URL}/org/apache/maven/apache-maven/${MAVEN_VERSION}/apache-maven-${MAVEN_VERSION}-bin.tar.gz"

if [ ! -x "${MVN_BIN}" ]; then
  echo "[mvnw] Apache Maven ${MAVEN_VERSION} not present, downloading into ${DIST_DIR}" >&2
  mkdir -p "${DIST_DIR}"
  TMP_TGZ="${DIST_DIR}/apache-maven-${MAVEN_VERSION}-bin.tar.gz.part"
  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 3 -o "${TMP_TGZ}" "${TARBALL_URL}"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "${TMP_TGZ}" "${TARBALL_URL}"
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c "import sys,urllib.request;urllib.request.urlretrieve(sys.argv[1],sys.argv[2])" \
      "${TARBALL_URL}" "${TMP_TGZ}"
  else
    echo "[mvnw] ERROR: no curl/wget/python3 available to download Maven. Install Maven instead." >&2
    exit 1
  fi
  tar -xzf "${TMP_TGZ}" -C "${DIST_DIR}"
  rm -f "${TMP_TGZ}"
  chmod +x "${MVN_BIN}"
fi

# Never let the range reach outside ~/.m2 for caches, and keep builds reproducible.
export MAVEN_PROJECTBASEDIR="${SCRIPT_DIR}"
exec "${MVN_BIN}" -f "${SCRIPT_DIR}/pom.xml" "$@"
