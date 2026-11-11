#!/usr/bin/env bash
# Audit the range's own Kubernetes manifests for checklist section 14.
# This is a grep-based gate: it needs no cluster and no kubectl, so it can run in any CI job.
# It FAILS against deploy/k8s/vulnerable-deployment.yaml on purpose (that is the negative test).
#
#   usage: scripts/check_k8s_manifests.sh [path-to-manifests]
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-${ROOT}/m14-runtime-hardening/deploy/k8s}"
FAILURES=0

check_absent() {
  local file="$1" pattern="$2" description="$3"
  if grep -Eq "${pattern}" "${file}"; then
    echo "  FAIL  $(basename "${file}"): ${description}"
    FAILURES=$((FAILURES + 1))
  else
    echo "  ok    $(basename "${file}"): ${description}"
  fi
}

check_present() {
  local file="$1" pattern="$2" description="$3"
  if grep -Eq "${pattern}" "${file}"; then
    echo "  ok    $(basename "${file}"): ${description}"
  else
    echo "  FAIL  $(basename "${file}"): ${description}"
    FAILURES=$((FAILURES + 1))
  fi
}

HARDENED="${TARGET}/hardened-deployment.yaml"
VULNERABLE="${TARGET}/vulnerable-deployment.yaml"

if [ ! -f "${HARDENED}" ]; then
  echo "usage: $0 [dir containing hardened-deployment.yaml]" >&2
  exit 2
fi

echo "== hardened manifest must contain =="
check_present "${HARDENED}" "runAsNonRoot: true"            "non-root container"
check_present "${HARDENED}" "allowPrivilegeEscalation: false" "no privilege escalation"
check_present "${HARDENED}" "readOnlyRootFilesystem: true"  "read-only root filesystem"
check_present "${HARDENED}" "drop: \[\"ALL\"\]"             "capabilities dropped"
check_present "${HARDENED}" "type: RuntimeDefault"          "seccomp runtime default"
check_present "${HARDENED}" "automountServiceAccountToken: false" "no API token mounted"
check_present "${HARDENED}" "limits:"                        "resource limits"
check_present "${HARDENED}" "requests:"                      "resource requests"
check_present "${HARDENED}" "kind: PodDisruptionBudget"      "disruption budget"
check_present "${HARDENED}" "kind: NetworkPolicy"            "network policy"
check_present "${HARDENED}" "policyTypes"                    "network policy types"
check_present "${HARDENED}" "@sha256:"                       "image pinned by digest"
check_present "${HARDENED}" "readOnly: true"                 "read-only config mount"
check_present "${HARDENED}" "readinessProbe"                 "readiness probe"
check_present "${HARDENED}" "preStop"                        "graceful drain hook"

echo
echo "== hardened manifest must not contain =="
check_absent "${HARDENED}" "image: .*:latest"        "no mutable image tag"
check_absent "${HARDENED}" "privileged: true"        "no privileged containers"
check_absent "${HARDENED}" "hostPath:"               "no hostPath mounts"
check_absent "${HARDENED}" "hostNetwork: true"       "no host network"
check_absent "${HARDENED}" "_PASSWORD|_TOKEN|_SECRET" "no credential material in env"

if [ -f "${VULNERABLE}" ]; then
  echo
  echo "== vulnerable manifest (expected to fail these checks) =="
  for pattern in "runAsNonRoot: true" "readOnlyRootFilesystem: true" "kind: NetworkPolicy"; do
    if grep -Eq "${pattern}" "${VULNERABLE}"; then
      echo "  unexpected pass: vulnerable manifest contains '${pattern}'"
    else
      echo "  as expected, vulnerable manifest lacks: ${pattern}"
    fi
  done
fi

echo
if [ "${FAILURES}" -gt 0 ]; then
  echo "RESULT: ${FAILURES} hardening control(s) missing in ${HARDENED}"
  exit 1
fi
echo "RESULT: hardened manifest satisfies all checked controls"
