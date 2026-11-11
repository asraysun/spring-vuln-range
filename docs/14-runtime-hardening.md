# 14 · Runtime, container and Kubernetes hardening

Checklist section: **§14 Runtime, container and platform hardening** · Module: `m14-runtime-hardening` · Port: **8094**
PoC: [`attacks/14-runtime-hardening.sh`](../attacks/14-runtime-hardening.sh) · Run: `scripts/run-module.sh m14-runtime-hardening`

Nothing in `/vuln14` is a remote-code bug. The endpoints answer the question that follows every other
module: **once an attacker has any request-level primitive inside this pod, what do they get?** The
other half of the demonstration is the pair of manifests under `deploy/k8s/` — the diff between
`vulnerable-deployment.yaml` and `hardened-deployment.yaml` is most of checklist section 14 — and the
audit in `scripts/check_k8s_manifests.sh`.

## What this module demonstrates

| # | Vulnerability | CWE | Insecure | Hardened |
|---|---------------|-----|----------|----------|
| 1 | Identity, runtime and coordinates disclosed anonymously | CWE-200 | `GET /vuln14/context` (`user`, `uid`, `env`, `commandLine`) | `GET /safe14/hardening` (booleans and counts only) |
| 2 | Namespaces and service account layout disclosed | CWE-200, CWE-497 | `GET /vuln14/context` (`serviceAccountNamespace`, `serviceAccountTokenMounted`) | `serviceAccountTokenMounted` as a boolean; `automountServiceAccountToken: false` in `hardened-deployment.yaml` |
| 3 | Credential-shaped variables returned with their values | CWE-526, CWE-312 | `GET /vuln14/config-check` (`DB_PASSWORD` from `vulnerable-deployment.yaml`) | `credentialValuesReturned: 0`; secret mounted read-only from `espd-m14-config` |
| 4 | Any writable path is a persistence primitive | CWE-732 | `POST /vuln14/write` (`path`, `content`) | `POST /safe14/write` scoped to the `vulnrange-m14` scratch dir; `readOnlyRootFilesystem: true` + tmpfs |
| 5 | Runs as root | CWE-250 | `vulnerable-deployment.yaml` (`securityContext: {}`), `Dockerfile.vulnerable` (`FROM eclipse-temurin:21-jdk`) | pod `runAsNonRoot: true`, `runAsUser: 10001`; `Dockerfile` (`USER 10001:10001`) |
| 6 | Privileged sidecar with the host root mounted | CWE-250, CWE-269 | `vulnerable-deployment.yaml` (`sidecar-debug`, `privileged: true`, `hostPath: /`) | `allowPrivilegeEscalation: false`, `privileged: false`, `capabilities.drop: ["ALL"]`; audit rejects `privileged: true` and `hostPath:` |
| 7 | Mutable image tag | CWE-1104 | `image: ...:latest` with `imagePullPolicy: Always` | image pinned by digest (`@sha256:`) |
| 8 | No workload limits or disruption budget | CWE-770 | `vulnerable-deployment.yaml` (no `resources`, no `PodDisruptionBudget`) | `requests`/`limits`, `kind: PodDisruptionBudget`, `replicas: 2` |
| 9 | Every pod can reach every pod | CWE-923 | no `NetworkPolicy` in `vulnerable-deployment.yaml`; API token mounted for every pod | `espd-m14-default-deny` plus `espd-m14-allowed-edges` |
| 10 | Seccomp not restricted, no probe-driven rollout | CWE-693 | no `seccompProfile`, no probes, no drain hook | `type: RuntimeDefault`, `startupProbe`/`readinessProbe`/`livenessProbe`, `preStop` |
| 11 | No manifest gate in CI | CWE-1104 | the vulnerable manifest is committable | `scripts/check_k8s_manifests.sh` (exit 1 on a missing control), called by `scripts/verify_range.sh` |

## Reproduce

```bash
attacks/14-runtime-hardening.sh

# identity, mounts and credential layout in one anonymous call
curl -s http://127.0.0.1:8094/vuln14/context

# credential-shaped variables, with values
curl -s http://127.0.0.1:8094/vuln14/config-check

# a request-level write that lands on disk
curl -s -X POST -H 'Content-Type: application/json' \
     -d '{"path":"/tmp/vulnrange-m14-written.txt","content":"persisted"}' \
     http://127.0.0.1:8094/vuln14/write
ls -l /tmp/vulnrange-m14-written.txt

# the hardened shape answers the same questions without material
curl -s http://127.0.0.1:8094/safe14/hardening
curl -s -i -X POST -H 'Content-Type: application/json' -d '{"path":"/etc/evil.conf","content":"x"}' \
     http://127.0.0.1:8094/safe14/write | head -12
curl -s http://127.0.0.1:8094/safe14/egress-and-integrity
```

`GET /vuln14/config-check` filters the process environment, so the value it returns is whatever the pod
was started with. Run the module the way the vulnerable manifest does and the disclosure is real:

```bash
DB_PASSWORD=placeholder-not-a-real-credential scripts/run-module.sh m14-runtime-hardening
curl -s http://127.0.0.1:8094/vuln14/config-check
```

The manifests and the gate:

```bash
diff -u m14-runtime-hardening/deploy/k8s/vulnerable-deployment.yaml \
        m14-runtime-hardening/deploy/k8s/hardened-deployment.yaml

scripts/check_k8s_manifests.sh            # exit 0: hardened manifest holds every checked control
scripts/check_k8s_manifests.sh m14-runtime-hardening/deploy/k8s   # same, explicit path
```

The images, where the container shape is set:

```bash
DOCKER_BUILDKIT=1 docker build -f m14-runtime-hardening/deploy/docker/Dockerfile \
    -t registry.example.org/espd/m14-runtime-hardening:1.0.0 .
docker run --rm -p 127.0.0.1:8094:8094 --read-only --tmpfs /tmp \
    registry.example.org/espd/m14-runtime-hardening:1.0.0
# then repeat POST /vuln14/write: read-only root filesystem, write refused or confined to /tmp
```

`Dockerfile.vulnerable` is the shape the bad manifest describes: `eclipse-temurin:21-jdk` as root, a
shell, a package manager, `ENV DB_PASSWORD=...` in a layer, no health probe.

## Fix, in the order that matters

1. **Run as non-root, without escalation.** `runAsNonRoot: true`, `runAsUser: 10001`,
   `allowPrivilegeEscalation: false`, `capabilities.drop: ["ALL"]`, `seccompProfile: RuntimeDefault` at
   pod level, not per container where someone remembered. In the image: a dedicated `USER 10001:10001`.
2. **Read-only root filesystem.** `readOnlyRootFilesystem: true`, tmpfs only where the service writes
   (`/tmp`, `sizeLimit: 256Mi`), and an application allow-list for the paths it writes to
   (`SafeRuntimeController.WRITABLE_ALLOW_LIST`) so a request-level write cannot become persistence.
3. **No credentials in the pod spec or the image.** The manifest carries no secret material (the audit
   rejects `_PASSWORD|_TOKEN|_SECRET` in env); values are mounted read-only from the secret provider
   (Vault Agent injector) at `/mnt/config`, `defaultMode: 0440`. `Dockerfile.vulnerable`'s
   `ENV DB_PASSWORD` is a layer that no `rm` in a later `RUN` removes.
4. **Immutable images.** Pin by digest (`@sha256:`), minimal base (`21-jre-alpine`, distroless where the
   registry has it), no shell, no compiler, no package manager, multi-stage build so the toolchain never
   reaches the runtime layer, SBOM and digest recorded in the deployment record.
5. **No token unless the API is needed.** `automountServiceAccountToken: false`; the reference pod talks
   to no API server. Where it does, the token is a bound, audience-restricted one and RBAC is per
   resource, not `cluster-admin` because "the sidecar needed it".
6. **Default-deny network, then the edges.** `espd-m14-default-deny` for ingress and egress, then
   `espd-m14-allowed-edges` admitting the gateway namespace and DNS, and one named internal service.
   What is not there matters as much as what is: no metadata service, no arbitrary outbound 443.
7. **Probes, drain and limits.** Separate startup/readiness/liveness probes, `preStop` sleep with
   `terminationGracePeriodSeconds` so a rollout drains, `requests`/`limits`, `PodDisruptionBudget`,
   `topologySpreadConstraints`, `-XX:MaxRAMPercentage` and `-XX:+ExitOnOutOfMemoryError` instead of an
   `-Xmx` guess.
8. **Report the shape, not the contents.** `GET /safe14/hardening` returns booleans and counts — whether
   the pod is non-root, whether a token is mounted, how many credential-shaped variables were seen — never
   values, never the manifest an attacker can use as a target map.
9. **Enforce at admission.** The script is the review-time check; a Pod Security Standards profile
   (`restricted`) plus an admission policy is what prevents a non-compliant pod from being scheduled at
   all, so the manifest cannot regress quietly.

## Detection

`scripts/check_k8s_manifests.sh` is a grep-based gate (no cluster, no `kubectl`) with named controls.
The hardened manifest must contain: *non-root container* (`runAsNonRoot: true`), *no privilege
escalation*, *read-only root filesystem*, *capabilities dropped*, *seccomp runtime default*, *no API
token mounted*, *resource limits*, *resource requests*, *disruption budget*, *network policy*, *network
policy types*, *image pinned by digest*, *read-only config mount*, *readiness probe*, *graceful drain
hook*. It must not contain: *no mutable image tag*, *no privileged containers*, *no hostPath mounts*,
*no host network*, *no credential material in env*. It then asserts the vulnerable manifest lacks
`runAsNonRoot: true`, `readOnlyRootFilesystem: true` and `kind: NetworkPolicy`, and exits `1` with the
count of missing controls. It is identical in shape to the runtime's own self-report in
`GET /safe14/hardening` (`expectedPlatformControls`), so code and policy cannot drift apart silently.

* `scripts/verify_range.sh` step 5/5 runs the audit and fails the overall check if it fails.
* Semgrep rules in `tools/semgrep/spring-security-rules.yml` cover the code-side complements:
  `path-resolution-from-request-without-containment` (`Path.of`/`Paths.get` without `normalize()` +
  `startsWith`) would flag an unguarded write path, and `hardcoded-credential-literal` reports the
  `ENV DB_PASSWORD=...` style credential wherever it appears in source or config.
* `scripts/run_secret_scan.sh` (`tools/gitleaks/.gitleaks.toml`, `useDefault = true` plus
  `spring-property-credential`) is what catches a credential copied out of a manifest or a Dockerfile
  into a file that gets committed.
* `scripts/run_dast_zap.sh` sweeps ports 8081-8096 including 8094 for management paths, and
  `attacks/14-runtime-hardening.sh` prints the audit output, so a runtime change that re-exposes a
  self-inspection endpoint shows up in the same run.
* In a real cluster, `kubectl -n <ns> get pod <pod> -o yaml` and reviewing the effective
  `securityContext` after every admission policy change; a manifest in git is an intention, the
  running object is the control.

## Where this appears in real reviews

`securityContext: {}` copied from a quick-start guide, a `privileged: true` debug sidecar that made it
to production because the incident was closed before the rollback, `DB_PASSWORD` as a plain `env`
value "temporarily" so the job would start, an image on `:latest` so nobody can answer which build is
running, a "container inspector" or `/safe14`-style diagnostics endpoint left anonymous because it "only
returns booleans" (it did not), no `NetworkPolicy` so every pod can reach the metadata service, and a
`/config` `emptyDir` that makes a config-poisoning primitive out of any file write. All of them pass
`kubectl apply` without a warning, and all of them are caught by the manifest diff — which is why the
manifest belongs in the same review as the code.
