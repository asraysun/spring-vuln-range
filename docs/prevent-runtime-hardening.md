# Spring Security: How to Prevent Runtime, Container & Kubernetes Hardening Vulnerabilities

A practical guide to securing Spring Boot against post-exploitation lateral movement, container escapes, privilege escalation, and platform misconfiguration — covering 11 CWEs found in real Spring applications.

---

## Table of Contents

1. [Identity & Topology Disclosure](#1-identity--topology-disclosure)
2. [System Architecture Exposure](#2-system-architecture-exposure)
3. [Credential Exposure in Containers](#3-credential-exposure-in-containers)
4. [Cleartext Credentials in Dockerfiles](#4-cleartext-credentials-in-dockerfiles)
5. [Writable Filesystem (Persistence)](#5-writable-filesystem-persistence)
6. [Root & Privileged Containers](#6-root--privileged-containers)
7. [Mutable Image Tags](#7-mutable-image-tags)
8. [Resource Limits & Disruption Budgets](#8-resource-limits--disruption-budgets)
9. [Network Policy (Default-Deny)](#9-network-policy-default-deny)
10. [Seccomp & Health Probes](#10-seccomp--health-probes)
11. [Manifest Gate in CI](#11-manifest-gate-in-ci)

---

## 1. Identity & Topology Disclosure

**CWE-200** — *Information Exposure (Identity, Runtime, Topology Disclosure)*

### The Problem

When an attacker already has a request into the application, exposing identity, runtime environment, process coordinates, and service account layout gives them a complete map of the pod's internals. This enables lateral movement, privilege escalation, and targeted attacks against the Kubernetes infrastructure.

```java
// ❌ VULNERABLE — identity, runtime and coordinates disclosed anonymously
@GetMapping("/context")
public ResponseEntity<?> context() {
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("user", System.getProperty("user.name"));       // root
    info.put("uid", ProcessHandle.current().pid());          // process ID
    info.put("env", System.getenv());                        // ALL environment variables
    info.put("commandLine", ProcessHandle.current().info().commandLine().orElse(""));
    info.put("serviceAccountNamespace", getNamespace());     // Kubernetes namespace
    info.put("serviceAccountTokenMounted", isTokenMounted()); // true
    return ResponseEntity.ok(info);
}
```

`GET /vuln14/context` returns the process user, UID, command line, all environment variables, and Kubernetes namespace.

### The Fix

Return booleans and counts only — never values, never the manifest.

```java
// ✅ SAFE — report the shape, not the contents
@GetMapping("/hardening")
public ResponseEntity<?> hardening() {
    return ResponseEntity.ok(Map.of(
        "runsAsNonRoot", isNonRoot(),           // boolean
        "readOnlyRootFilesystem", isReadOnly(),  // boolean
        "serviceAccountTokenMounted", isTokenMounted(), // boolean
        "credentialShapedVariablesSeen", countCredentialVars(), // count, not values
        "credentialValuesReturned", 0           // never return values
    ));
}
```

**Key rules:**
- Return booleans and counts only
- Never return environment variable values or the manifest
- The attacker can use the manifest as a target map — don't give them one
- Treat any endpoint exposing `ProcessHandle.current()`, `System.getenv()`, or pod metadata as a security review blocker

---

## 2. System Architecture Exposure

**CWE-497** — *Exposure of System Architecture to Unauthorized Actors*

### The Problem

CWE-497 specifically covers exposure of the system's architectural layout — namespaces, service accounts, network topology, and pod relationships. In Kubernetes, this information reveals the multi-tenant structure, service mesh configuration, and inter-pod communication patterns.

```java
// ❌ VULNERABLE — namespace and service account layout disclosed
@GetMapping("/context")
public ResponseEntity<?> context() {
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("serviceAccountNamespace", getNamespace());  // "production"
    info.put("serviceAccountName", getServiceAccountName());  // "espd-service-sa"
    info.put("serviceAccountTokenMounted", isTokenMounted());  // true
    // Attacker learns: namespace, SA name, whether API token is mounted
}
```

### The Fix

Expose only the presence of controls, never the architectural identifiers. Disable automatic service account token mounting.

```java
// ✅ SAFE — boolean only, no names
@GetMapping("/hardening")
public ResponseEntity<?> hardening() {
    return ResponseEntity.ok(Map.of(
        "serviceAccountTokenMounted", isTokenMounted(),  // true/false only
        // No namespace name, no SA name
    ));
}
```

**Kubernetes configuration:**

```yaml
# ✅ SAFE — do not mount token unless needed
spec:
  automountServiceAccountToken: false
  containers:
  - name: app
    # ...
```

**Key rules:**
- `automountServiceAccountToken: false` in the deployment manifest
- Where the API is needed, use a bound, audience-restricted token with per-resource RBAC — not `cluster-admin`
- Never expose namespace names or service account names in runtime diagnostics

---

## 3. Credential Exposure in Containers

**CWE-526** — *Information Exposure Through Environment Variables (Credential Exposure in Container)*

### The Problem

CWE-526 in the container context refers to credentials injected as environment variables into the pod spec. These are visible in the pod YAML, in `kubectl describe pod`, and through any endpoint that reads `System.getenv()`.

```yaml
# ❌ VULNERABLE — credential as plain env in pod spec
spec:
  containers:
  - name: app
    env:
    - name: DB_PASSWORD
      value: "placeholder-not-a-real-credential"  # Visible in kubectl get pod -o yaml
    - name: API_KEY
      value: "AKIAIOSFODNN7EXAMPLE"
```

```java
// ❌ VULNERABLE — endpoint returns all env vars with values
@GetMapping("/config-check")
public ResponseEntity<?> configCheck() {
    Map<String, String> result = new LinkedHashMap<>();
    for (Map.Entry<String, String> entry : System.getenv().entrySet()) {
        result.put(entry.getKey(), entry.getValue());  // DB_PASSWORD, API_KEY, etc.
    }
    return ResponseEntity.ok(result);
}
```

### The Fix

Mount secrets as read-only volumes from the secret provider. Never inject credentials as plain environment variables.

```yaml
# ✅ SAFE — secrets mounted read-only from secret provider
spec:
  containers:
  - name: app
    volumeMounts:
    - name: secret-volume
      mountPath: /mnt/config
      readOnly: true
  volumes:
  - name: secret-volume
    secret:
      secretName: espd-m14-config
      defaultMode: 0440  # read-only
```

```java
// ✅ SAFE — endpoint reports count only, never values
@GetMapping("/config-check")
public ResponseEntity<?> configCheck() {
    long count = System.getenv().keySet().stream()
        .filter(k -> k.matches(".*(_PASSWORD|_TOKEN|_SECRET)$"))
        .count();
    return ResponseEntity.ok(Map.of(
        "credentialShapedVariablesSeen", count,
        "credentialValuesReturned", 0
    ));
}
```

**Key rules:**
- No credential material in the pod spec or the image
- Values mounted read-only from Vault Agent injector at `/mnt/config`
- The audit rejects `_PASSWORD|_TOKEN|_SECRET` in env variables
- Always mask or count credential-shaped environment variables

---

## 4. Cleartext Credentials in Dockerfiles

**CWE-312** — *Cleartext Storage of Sensitive Information (Credential in Container)*

### The Problem

CWE-312 in the container context refers to credentials stored in cleartext in environment variables, Dockerfile layers, or pod specs. A credential in an `ENV` instruction becomes part of the image layer and is visible in `docker history` and `docker inspect`, even if a later layer deletes the file.

```dockerfile
# ❌ VULNERABLE — credential in Dockerfile layer
FROM eclipse-temurin:21-jdk
ENV DB_PASSWORD=super-secret-123  # In image layer, visible in docker history
RUN rm /tmp/secret.txt  # Does NOT remove the ENV from the layer
```

The credential persists in the image layer even after "deletion" — it is visible in `docker history` and `docker inspect`.

### The Fix

Never put credentials in Dockerfiles. Use multi-stage builds and mount secrets as read-only volumes.

```dockerfile
# ✅ SAFE — multi-stage build, no credentials in image
# Stage 1: Build
FROM eclipse-temurin:21-jdk AS build
WORKDIR /build
COPY . .
RUN ./mvnw clean package -DskipTests

# Stage 2: Runtime (minimal, no env vars with secrets)
FROM eclipse-temurin:21-jre-slim
WORKDIR /app
COPY --from=build /build/target/app.jar app.jar
USER 10001:10001
# Secrets mounted via Kubernetes Secret volume, not ENV
EXPOSE 8094
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75.0", "-jar", "app.jar"]
```

**Key rules:**
- **Never put credentials in Dockerfiles** or `ENV` instructions
- Use multi-stage builds so the toolchain never reaches the runtime layer
- Mount secrets as read-only volumes from the secret provider
- Build images with BuildKit and scan for credential leaks (`DOCKER_BUILDKIT=1 docker build`)

---

## 5. Writable Filesystem (Persistence)

**CWE-732** — *Incorrect Permission Assignment for Critical Resource (Writable Filesystem)*

### The Problem

A writable root filesystem in a container means that once an attacker has any file write primitive, they can persist malicious files on the container. This includes shell scripts, JSP shells, SSH keys, cron jobs, or systemd units — turning a temporary write into persistent access.

```java
// ❌ VULNERABLE — any writable path is a persistence primitive
@PostMapping("/write")
public ResponseEntity<?> write(@RequestBody WriteRequest req) {
    Path target = Path.of(req.getPath());  // Attacker chooses any path
    Files.write(target, req.getContent().getBytes());
    // Attacker writes: /etc/cron.d/backdoor, /root/.ssh/authorized_keys, /tmp/shell.jsp
    return ResponseEntity.ok("written");
}
```

### The Fix

Scope writes to a scratch directory. Enforce `readOnlyRootFilesystem: true` at the pod level.

```java
// ✅ SAFE — scoped to scratch directory only
private static final Path WRITABLE_ALLOW_LIST = Path.of("/tmp/vulnrange-m14").toAbsolutePath();

@PostMapping("/write")
public ResponseEntity<?> write(@RequestBody WriteRequest req) {
    Path target = Path.of(req.getPath()).toAbsolutePath().normalize();
    if (!target.startsWith(WRITABLE_ALLOW_LIST)) {
        return ResponseEntity.status(403).body("Path not allowed");
    }
    Files.write(target, req.getContent().getBytes());
    return ResponseEntity.ok("written");
}
```

```yaml
# ✅ SAFE — read-only root filesystem + tmpfs
spec:
  containers:
  - name: app
    securityContext:
      readOnlyRootFilesystem: true
    volumeMounts:
    - name: tmp
      mountPath: /tmp
  volumes:
  - name: tmp
    emptyDir:
      sizeLimit: 256Mi
```

**Key rules:**
- `readOnlyRootFilesystem: true` in the pod security context
- tmpfs only where the service writes (`/tmp`, with `sizeLimit`)
- Application allow-list for paths (`WRITABLE_ALLOW_LIST`) so a request-level write cannot become persistence
- Audit file writes — any path outside the scratch directory is a security incident

---

## 6. Root & Privileged Containers

**CWE-250** — *Running with Unnecessary Privileges (Root Container)*  
**CWE-269** — *Improper Privilege Management (Privileged Container)*

### The Problem

CWE-250 covers two related issues: running the container process as root and running privileged containers. A root process inside a container can escape to the host if the container is privileged, modify system files, install packages, or pivot to other containers on the same node. CWE-269 refers to granting unnecessary privileges (e.g., `privileged: true`, `hostPath` mounts).

```yaml
# ❌ VULNERABLE — runs as root, privileged sidecar
spec:
  containers:
  - name: app
    securityContext: {}  # Runs as root by default
  - name: sidecar-debug
    securityContext:
      privileged: true  # Full host access
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /  # Host root filesystem!
```

### The Fix

Run as non-root, drop all capabilities, restrict syscalls, and block privilege escalation.

```yaml
# ✅ SAFE — non-root, no escalation, no privileges
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    runAsGroup: 10001
    fsGroup: 10001
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    securityContext:
      allowPrivilegeEscalation: false
      privileged: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
    # Dockerfile: USER 10001:10001
```

```dockerfile
# ✅ SAFE — non-root user in image
FROM eclipse-temurin:21-jre-slim
USER 10001:10001
# ...
```

**Key rules:**
- `runAsNonRoot: true`, `runAsUser: 10001` at pod level
- `allowPrivilegeEscalation: false`, `privileged: false`, `capabilities.drop: ["ALL"]`
- `seccompProfile: RuntimeDefault` blocks dangerous syscalls (`mount`, `reboot`, `kexec_load`)
- In the image: `USER 10001:10001`
- No privileged sidecars, no `hostPath` mounts
- The audit script rejects `privileged: true` and `hostPath:` in manifests

---

## 7. Mutable Image Tags

**CWE-1104** — *Use of Unmaintained or Vulnerable Third-Party Component (Mutable Image Tag)*

### The Problem

CWE-1104 in the container context refers to using mutable image tags (`:latest`) in deployments. A `:latest` tag is not a fixed version — it changes whenever a new image is pushed to the registry. This means the deployment can silently pull a new build with new dependencies, new CVEs, or even malicious code. There is no way to answer which build is running.

```yaml
# ❌ VULNERABLE — mutable image tag
spec:
  containers:
  - name: app
    image: registry.example.org/espd/m14:latest  # Changes on every deploy
    imagePullPolicy: Always  # Always pulls the latest
```

### The Fix

Pin by digest. Use minimal base images. Multi-stage builds.

```yaml
# ✅ SAFE — image pinned by digest
spec:
  containers:
  - name: app
    image: registry.example.org/espd/m14@sha256:abc123def456...  # Immutable
```

```dockerfile
# ✅ SAFE — minimal base, multi-stage, no toolchain
FROM eclipse-temurin:21-jre-slim AS build
# ... build steps ...
FROM eclipse-temurin:21-jre-slim
COPY --from=build /app.jar app.jar
USER 10001:10001
# No shell, no compiler, no package manager in the runtime image
```

**Key rules:**
- **Pin by digest** (`@sha256:`) — never use `:latest` or mutable tags in production
- Minimal base image (`21-jre-alpine`, distroless where available)
- No shell, no compiler, no package manager in the runtime image
- Multi-stage build so the toolchain never reaches the runtime layer
- SBOM and digest recorded in the deployment record

---

## 8. Resource Limits & Disruption Budgets

**CWE-770** — *Allocation of Resources Without Limits (No Workload Limits)*

### The Problem

Without resource requests/limits, a single pod can consume all node resources (CPU, memory), causing other pods to starve. Without a PodDisruptionBudget, voluntary disruptions can take down all replicas simultaneously.

```yaml
# ❌ VULNERABLE — no workload limits
spec:
  replicas: 1  # Single replica, no PDB
  containers:
  - name: app
    # No resources.requests or resources.limits
    # A memory leak → OOM → node fills up → other pods die
```

### The Fix

Set requests/limits, PodDisruptionBudget, and JVM flags.

```yaml
# ✅ SAFE — resource limits + PDB
spec:
  replicas: 2
  containers:
  - name: app
    resources:
      requests:
        cpu: "250m"
        memory: "512Mi"
      limits:
        cpu: "500m"
        memory: "1Gi"
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: espd-pdb
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app: espd
```

```bash
# JVM flags (in Dockerfile or k8s args)
-javaagent:/app/jmx-exporter.jar=8080:/app/config.yml \
-XX:MaxRAMPercentage=75.0 \
-XX:+ExitOnOutOfMemoryError
```

**Key rules:**
- `requests`/`limits` for CPU and memory
- `PodDisruptionBudget` with `minAvailable: 1` (or `maxUnavailable: 0`)
- `-XX:MaxRAMPercentage` and `-XX:+ExitOnOutOfMemoryError` for JVM
- Use `topologySpreadConstraints` for even distribution across nodes

---

## 9. Network Policy (Default-Deny)

**CWE-923** — *Improper Control of Communication Path Components (No Network Policy)*

### The Problem

CWE-923 in the Kubernetes context refers to the absence of NetworkPolicy, which means every pod can reach every other pod. Without network segmentation, a compromised pod can reach the database, the metadata service, internal admin panels, and any other service on the cluster.

```yaml
# ❌ VULNERABLE — no NetworkPolicy
# Every pod can reach every pod
# Compromised pod can reach:
# - Database (port 5432)
# - Metadata service (169.254.169.254)
# - Internal admin panels
```

### The Fix

Default-deny all traffic, then explicitly allow only required edges.

```yaml
# ✅ SAFE — default-deny + explicit edges
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: app-egress-policy
spec:
  podSelector:
    matchLabels:
      app: espd
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: gateway
    ports:
    - port: 8094
      protocol: TCP
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: database
    ports:
    - port: 5432
      protocol: TCP
  - to:
    - namespaceSelector: {}
    ports:
    - port: 53
      protocol: UDP  # DNS only
  - to:
    - ipBlock:
        cidr: 169.254.169.254/32
    ports: []  # Block metadata service explicitly
```

**Key rules:**
- `default-deny-all` for ingress and egress
- Explicit egress rules: gateway namespace, DNS (port 53), internal services
- **Block metadata service** (`169.254.169.254`) explicitly
- No arbitrary outbound 443 — allow only required external endpoints

---

## 10. Seccomp & Health Probes

**CWE-693** — *Missing Defense in Depth (No Seccomp, No Probes)*

### The Problem

CWE-693 in the container context refers to missing security controls that provide defense-in-depth. Without a seccomp profile, the container can use all Linux syscalls — including dangerous ones like `mount`, `reboot`, `kexec_load`. Without health probes, the orchestrator cannot detect when a pod is unhealthy.

```yaml
# ❌ VULNERABLE — no seccomp, no probes, no drain hook
spec:
  containers:
  - name: app
    # No seccompProfile → can use any syscall
    # No startupProbe → pod marked ready before Spring context loads
    # No readinessProbe → traffic sent to unready pod
    # No livenessProbe → dead pod keeps receiving traffic
    # No preStop → rolling update kills pod immediately, no drain
```

### The Fix

Add seccomp, separate probes, and a drain hook.

```yaml
# ✅ SAFE — seccomp + probes + drain
spec:
  seccompProfile:
    type: RuntimeDefault
  containers:
  - name: app
    startupProbe:
      httpGet:
        path: /actuator/health/liveness
        port: 8094
      failureThreshold: 30
      periodSeconds: 10
    readinessProbe:
      httpGet:
        path: /actuator/health/readiness
        port: 8094
    livenessProbe:
      httpGet:
        path: /actuator/health/liveness
        port: 8094
    lifecycle:
      preStop:
        exec:
          command: ["sleep", "10"]  # Graceful drain
  terminationGracePeriodSeconds: 30
```

**Key rules:**
- `seccompProfile: RuntimeDefault` blocks dangerous syscalls
- Separate `startupProbe`, `readinessProbe`, and `livenessProbe`
- `preStop` sleep with `terminationGracePeriodSeconds` so a rollout drains
- Use `/actuator/health/liveness` and `/actuator/health/readiness` for Spring Boot compatibility

---

## 11. Manifest Gate in CI

**CWE-1104** — *No Manifest Gate in CI (Mutable Image Tag / Missing Controls)*

### The Problem

CWE-1104 in the CI/CD context refers to the absence of a manifest gate that enforces security controls at commit time. Without a gate, any developer can commit a vulnerable manifest and it passes CI. The gate is what prevents manifest regression.

```yaml
# ❌ VULNERABLE — no manifest gate, vulnerable manifest is committable
# vulnerable-deployment.yaml contains:
#   - securityContext: {}  (runs as root)
#   - privileged: true
#   - hostPath: /
#   - image: ...:latest
# All of these pass kubectl apply without a warning
```

### The Fix

Run a grep-based manifest gate in CI before deployment.

```bash
# ✅ SAFE — manifest gate in CI
# scripts/check_k8s_manifests.sh
# Must contain: runAsNonRoot: true, allowPrivilegeEscalation: false,
#   readOnlyRootFilesystem: true, capabilities dropped, seccomp RuntimeDefault,
#   no API token mounted, resource limits, resource requests, PDB,
#   NetworkPolicy, image pinned by digest, readiness probe, drain hook
# Must NOT contain: mutable image tag, privileged containers, hostPath mounts,
#   host network, credential material in env
# Exits 1 on a missing control
```

**Script outline:**

```bash
#!/bin/bash
# scripts/check_k8s_manifests.sh
MANIFEST_DIR="${1:-.}"
FAIL_COUNT=0

check_required() {
    local file="$1"
    local pattern="$2"
    if ! grep -q "$pattern" "$file"; then
        echo "FAIL: $file missing control: $pattern"
        ((FAIL_COUNT++))
    fi
}

check_forbidden() {
    local file="$1"
    local pattern="$2"
    if grep -q "$pattern" "$file"; then
        echo "FAIL: $file contains forbidden control: $pattern"
        ((FAIL_COUNT++))
    fi
}

for f in "$MANIFEST_DIR"/*.yaml; do
    check_required "$f" "runAsNonRoot: true"
    check_required "$f" "allowPrivilegeEscalation: false"
    check_required "$f" "readOnlyRootFilesystem: true"
    check_required "$f" "drop:"
    check_required "$f" "seccompProfile:"
    check_forbidden "$f" ":latest"
    check_forbidden "$f" "privileged: true"
    check_forbidden "$f" "hostPath:"
    check_forbidden "$f" "_PASSWORD:"
done

echo "Manifest check: $FAIL_COUNT failures"
exit "$FAIL_COUNT"
```

**Key rules:**
- `scripts/check_k8s_manifests.sh` is a grep-based gate (no cluster, no `kubectl`)
- Called by `scripts/verify_range.sh` — fails the overall check if it fails
- A Pod Security Standards profile (`restricted`) plus an admission policy prevents non-compliant pods from being scheduled at all
- The manifest belongs in the same review as the code
- CI must fail if any manifest control is missing or forbidden

---

## Summary Checklist

| # | Control | CWE | Priority |
|---|---------|-----|----------|
| 1 | Return booleans/counts only, no env values | CWE-200 | CRITICAL |
| 2 | `automountServiceAccountToken: false` | CWE-497 | HIGH |
| 3 | Secrets as read-only volumes, never env vars | CWE-526, CWE-312 | CRITICAL |
| 4 | `readOnlyRootFilesystem: true` + path allow-list | CWE-732 | HIGH |
| 5 | `runAsNonRoot`, `drop: ALL`, no `hostPath` | CWE-250, CWE-269 | CRITICAL |
| 6 | `@sha256:` digest pin, minimal base image | CWE-1104 | HIGH |
| 7 | Resource requests/limits + PDB | CWE-770 | HIGH |
| 8 | Default-deny NetworkPolicy + explicit edges | CWE-923 | CRITICAL |
| 9 | `seccompProfile: RuntimeDefault` + probes + drain | CWE-693 | HIGH |
| 10 | Manifest gate in CI (`check_k8s_manifests.sh`) | CWE-1104 | CRITICAL |

---

## Detection & Review Heuristics

| Check | Command / Pattern |
|-------|-------------------|
| Root containers | `grep -r 'runAsNonRoot:\s*false\|securityContext:\s*{}' deploy/` → should be `true` |
| Privileged pods | `grep -r 'privileged:\s*true\|hostPath:' deploy/` → should not exist |
| Mutable tags | `grep -r ':latest' deploy/` → should be `@sha256:` |
| Env credentials | `grep -r '_PASSWORD:\|_TOKEN:\|_SECRET:' deploy/` → should not exist |
| No NetworkPolicy | `grep -r 'kind:\s*NetworkPolicy' deploy/` → must exist |
| No PDB | `grep -r 'kind:\s*PodDisruptionBudget' deploy/` → must exist |
| No resource limits | `grep -r 'resources:\s*$' deploy/` → must have `requests` and `limits` |
| No seccomp | `grep -r 'seccompProfile:' deploy/` → must exist |
| Manifest gate | `scripts/check_k8s_manifests.sh` → must exit 0 |

---

## References

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [OWASP Kubernetes Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html)
- [CNCF Container Security Best Practices](https://github.com/cncf/tag-security/blob/main/security-whitepaper/v2/README.md)
- [Spring Boot Actuator Health Probes](https://docs.spring.io/spring-boot/reference/actuator/endpoints.html)
- [Container Hardening with Docker](https://docs.docker.com/develop/security-best-practices/)
- [RuntimeDefault seccomp profile](https://man7.org/linux/man-pages/man2/seccomp.2.html)
