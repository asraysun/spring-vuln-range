# How to use this range

This is the hands-on guide: how to build it, how to start it, how to reproduce each vulnerability, and
how to use it for reviews, training and tool calibration. It does not repeat the security analysis —
that lives in [`docs/`](docs/) (one file per checklist section) and
[`SECURITY_CHECKLIST.md`](SECURITY_CHECKLIST.md).

Read the safety rules in [`README.md`](README.md) first. The short version: **127.0.0.1 only, fake data
only, self-contained targets only.**

---

## 0. The idea in one picture

```
            ┌──────────────────────────────────────────────────────────────────┐
            │ 16 modules, one per checklist section, ports 8081–8096            │
            │                                                                  │
  you  ───▶ │  /vulnN/**   broken on purpose   ──▶ attack script shows it      │
            │  /safeN/**   reference fix       ──▶ same request, no effect     │
            │                                                                  │
            │ docs/NN-*.md      why + CWE + fix                                 │
            │ SECURITY_CHECKLIST.md   §N.M items, insecure vs hardened          │
            └──────────────────────────────────────────────────────────────────┘
```

Every exercise follows the same four steps:

1. **Observe** — call `/vulnN/...`, see the flaw.
2. **Exploit** — the attack script turns the observation into a repeatable attack.
3. **Fix** — call the same thing on `/safeN/...`, and read the class that makes the difference.
4. **Detect** — run the scanner/rule that would have flagged it in review.

---

## 1. Prerequisites

| Need | Why | Check |
|------|-----|-------|
| JDK 21 | the range targets Java 21 | `java -version` |
| network on first build | Maven Central, and the Maven distribution itself | — |
| `curl`, `bash`, `python3` | PoC scripts | `bash --version`, `python3 --version` |
| optional: `semgrep`, `gitleaks`, `trivy`, `docker` | tool-calibration exercises | `semgrep --version`, … |

Docker is **not** required to run the range: H2 in-memory databases, a throw-away keystore generated at
startup, and simulated internal services replace everything external.

`./mvnw` is a small bootstrap script that downloads a pinned Maven into `.mvn/maven-distro/` (project-local,
never system-wide). Behind a corporate mirror:

```bash
MVN_REPO_URL=https://<your-nexus>/repository/maven-public ./mvnw -DskipTests package
```

or just rely on `~/.m2/settings.xml`.

---

## 2. Build

```bash
cd spring-vuln-range
./mvnw -DskipTests package
```

This produces `mNN-*/target/mNN-*.jar`. It is also the first real compile of the range: if something is
broken, it breaks here.

Build one module only (faster inner loop, still resolves the parent):

```bash
./mvnw -DskipTests -pl m05-injection -am package
```

Useful profiles:

| Command | What it does |
|---------|--------------|
| `./mvnw -DskipTests package` | normal build, no scanners — this is what you run locally |
| `./mvnw -pl m16-verification test` | the authorization matrix and the vulnerable-regression tests |
| `./mvnw -Psast -pl m16-verification verify` | SpotBugs + Find Security Bugs over the flaggable fixtures |
| `./mvnw -Psca -pl m13-supply-chain verify` | OWASP dependency-check gate; **fails on purpose** |
| `./mvnw -Pbaseline-upgrades -pl m13-supply-chain package` | the "upgraded" dependency set (see `docs/13`) |

The `sca` gate is opt-in so a plain build never downloads the NVD database or fails because of it.

---

## 3. Start and stop

### Everything at once

```bash
scripts/run-all.sh          # builds, then starts 8081–8096 in the background
scripts/status.sh           # which modules answer on loopback
scripts/stop-all.sh         # stop what run-all.sh started
```

`run-all.sh` writes `logs/<module>.log` and `logs/<module>.pid`. Watch one module:

```bash
tail -f logs/m01-authentication.log
```

Skip the supply-chain module if you do not want its dependency set on the classpath:

```bash
SKIP_M13=1 scripts/run-all.sh
```

### One module, in the foreground

```bash
scripts/run-module.sh m05-injection
```

The script builds the jar if it is missing, then runs it with `-Dserver.address=127.0.0.1`. Ctrl-C stops it.
Extra arguments are passed to Spring Boot, which is how you switch profiles:

```bash
# m12 hardened configuration: actuator only on 8192, health/info only
scripts/run-module.sh m12-actuator --spring.profiles.active=safe

# m03 production-shaped configuration (fails fast unless the env vars are set — that is the point)
RANGE_M03_DB_URL=jdbc:h2:mem:m03 RANGE_M03_DB_USER=sa RANGE_M03_DB_PASSWORD=placeholder \
  scripts/run-module.sh m03-secrets-config --spring.profiles.active=prod
```

### Two optional switches (m05 only)

Two sinks are sandboxed by default so the range cannot become a weapon:

```bash
VULNRANGE_ALLOW_SPEL_TYPES=true scripts/run-module.sh m05-injection   # unsandboxed StandardEvaluationContext
VULNRANGE_ALLOW_EXEC=true      scripts/run-module.sh m05-injection   # real OS command execution
```

Without them `/vuln5/report` runs with a property-only `SimpleEvaluationContext` and
`/vuln5/tools/ping` returns an explanatory refusal instead of running a command. The vulnerability and its
fix are still visible — you just do not get a live shell out of a demo.

### Ports

| Port | Module | Port | Module |
|------|--------|------|--------|
| 8081 | `m01-authentication` | 8089 | `m09-logging-errors` |
| 8082 | `m02-authorization` | 8090 | `m10-ssrf-webhooks` |
| 8083 | `m03-secrets-config` | 8091 | `m11-data-exposure` |
| 8084 | `m04-validation-binding` | 8092 | `m12-actuator` (8192 in the `safe` profile) |
| 8085 | `m05-injection` | 8093 | `m13-supply-chain` |
| 8086 | `m06-deserialization` | 8094 | `m14-runtime-hardening` |
| 8087 | `m07-web-layer` | 8095 | `m15-business-logic` |
| 8088 | `m08-crypto-tls` (+ HTTPS 8443) | 8096 | `m16-verification` |

---

## 4. Reproduce a vulnerability

Each section has a script in `attacks/`. Run it with the module up:

```bash
scripts/run-module.sh m01-authentication   # terminal 1
attacks/01-authentication.sh               # terminal 2
```

The script refuses to run against anything but loopback (`attacks/lib.sh` guard), prints each request with
its status code, and ends with the path of the matching writeup. Read the writeup with the output next to it:
the **Insecure** column is what you just saw, the **Hardened** column is what `/safeN` does instead.

### Manual reproduction

When you want to poke at a single thing, the raw requests are all `curl` against `127.0.0.1`.

**§1 Authentication** — MD5 hashes readable without a login:

```bash
curl -s http://127.0.0.1:8081/vuln1/debug/users
```

**§2 Authorization** — bob reads alice's subscription (IDOR / BOLA):

```bash
curl -s -u bob:bob-pass      http://127.0.0.1:8082/vuln2/subscriptions/SUB-1001   # 200, someone else's data
curl -s -u bob:bob-pass      http://127.0.0.1:8082/safe2/subscriptions/SUB-1001   # 404
curl -s -u alice:alice-pass  http://127.0.0.1:8082/safe2/subscriptions/SUB-1001   # 200, the owner
```

**§5 Injection** — SQL injection, then the same request against the prepared statement:

```bash
curl -s -G --data-urlencode "email=x' OR '1'='1" http://127.0.0.1:8085/vuln5/subscriptions
curl -s -G --data-urlencode "email=x' OR '1'='1" http://127.0.0.1:8085/safe5/subscriptions
```

**§7 Web layer** — reflected XSS, and the escaping template:

```bash
curl -s -G --data-urlencode "name=<img src=x onerror=alert(document.cookie)>" http://127.0.0.1:8087/vuln7/page
curl -s -G --data-urlencode "name=<img src=x onerror=alert(document.cookie)>" http://127.0.0.1:8087/safe7/page
```

`/vuln7/page` needs a browser to prove the script runs; `curl` only shows that the markup is emitted
unescaped.

**§10 SSRF** — the server fetches its own internal admin surface:

```bash
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"url":"http://127.0.0.1:8090/vuln10/internal-admin/users"}' \
  http://127.0.0.1:8090/vuln10/fetch
# same call through the reference client: allow-list (host/port/path) → refused
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"url":"http://127.0.0.1:8090/vuln10/internal-admin/users"}' \
  http://127.0.0.1:8090/safe10/fetch
```

**§12 Actuator** — everything, unauthenticated, on the application port:

```bash
curl -s http://127.0.0.1:8092/actuator/env | head -40
curl -s http://127.0.0.1:8092/actuator/heapdump -o /tmp/m12.hprof   # do not share this file
```

Then start the same module with `--spring.profiles.active=safe` and repeat: only `health` and `info` on
8192, no values, no dump.

**§15 Business logic** — the client decides the price:

```bash
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"subscriptionId":"SUB-EVIL-1","plan":"ESPD-PRO","price":"1.00","currency":"RUB"}' \
  http://127.0.0.1:8095/vuln15/orders
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"subscriptionId":"SUB-OK-1","plan":"ESPD-PRO","price":"1.00","currency":"RUB"}' \
  http://127.0.0.1:8095/safe15/orders
```

`/safe15/orders` keeps the `price` field in the DTO for compatibility and ignores it: the order is priced
from `/vuln15/catalog`, with only server-owned discount rules applied.

Every other request in the range is listed in the corresponding `attacks/NN-*.sh` (each `req` line is a
copy-pasteable call) and in `docs/NN-*.md` under **Reproduce**.

---

## 5. Read the code, not only the output

The paired packages are the point:

```
m02-authorization/src/main/java/com/example/vulnrange/m02/
├── vuln/      ← broken on purpose, every flaw marked "// VULNERABLE (intentional)"
└── safe/      ← the reference implementation you can lift into a real service
```

Diff a pair to see the fix as a minimal change:

```bash
diff -ru m02-authorization/src/main/java/com/example/vulnrange/m02/vuln \
        m02-authorization/src/main/java/com/example/vulnrange/m02/safe
```

The `vuln/` packages are not meant to survive a merge: they exist to be deleted from a real branch.

---

## 6. Turn the vulnerability into a review comment

For any finding in your own code, this range gives you the reference shape:

1. Find the checklist item in [`SECURITY_CHECKLIST.md`](SECURITY_CHECKLIST.md) — e.g. §2.1 "IDOR".
2. Open the module writeup, read the **Insecure** and **Hardened** cells for that row.
3. Copy the shape of the `/safeN` class, not the patch: the fix is usually a query that includes the
   principal, a DTO without the privileged field, or an allow-list instead of a string.
4. If the finding is contested ("nobody would exploit that"), run the matching `attacks/NN-*.sh` to show
   what the request looks like.

For issues the checklist does not cover yet: add an item to `SECURITY_CHECKLIST.md`, a fixture to
`m16-verification` (`FlaggableSastFixtures`) and a Semgrep rule to `tools/semgrep/spring-security-rules.yml`.
That is the maintenance loop that keeps the checklist from decaying into a document nobody reads.

---

## 7. Calibrate your security tooling

The range is built so that a **clean report is a failure signal**: the tooling must find something.

```bash
scripts/run_sast.sh          # Semgrep + SpotBugs/Find Security Bugs over the fixtures
scripts/run_secret_scan.sh   # gitleaks (git history) + fallback greps
scripts/run_sca.sh           # dependency tree + dependency-check; FAILS on m13 (expected)
scripts/run_dast_zap.sh      # ZAP baseline when available, curl-only passive checks otherwise
scripts/check_k8s_manifests.sh   # 20 controls across the bad and hardened manifests
scripts/verify_range.sh      # the range itself: ports, loopback, PoC paths, docs, YAML
```

| Script | Expected output here | What it proves |
|--------|----------------------|----------------|
| `run_sast.sh` | findings in `FlaggableSastFixtures` (m16) | the SAST job is wired to the code |
| `run_secret_scan.sh` | the documented placeholder literals | the secret scan is not misconfigured |
| `run_sca.sh` | **exit 1**, m13 findings | the threshold, not just the scanner, works |
| `run_dast_zap.sh` | missing CSP/HSTS/frame-options, open `/actuator/env` | DAST reaches the deployed surface |
| `check_k8s_manifests.sh` | vulnerable manifest fails, hardened passes | policy checks are meaningful |

Missing tools degrade to a fallback (grep, curl, `bash -n`) with a clear message — the exercise still works,
it just proves less. Run the tools against your own repository afterwards and compare the shapes.

The authorization matrix is a test, not a script: `./mvnw -pl m16-verification test` runs
`SafeOwnershipMatrixTest` (must pass) and `VulnerableEndpointRegressionTest` (asserts the leak still exists,
so the contrast does not silently disappear).

---

## 8. A suggested session plan

Roughly 4 hours for a team, in this order — it moves from "easy to see" to "easy to miss":

| Block | Modules | Focus |
|-------|---------|-------|
| 1 | m01, m02, m03 | authentication, authorization, secrets — the highest-yield review comments |
| 2 | m04, m05 | validation, binding and injection — where the input actually comes from |
| 3 | m07, m09, m10 | browser surface, error/log hygiene, outbound calls |
| 4 | m11, m12 | what the API and the management plane leak |
| 5 | m13, m14, m15 | dependencies, runtime/Kubernetes, revenue logic — the "not code" classes |
| 6 | m06, m08, m16 | deserialization, crypto/TLS, and the process that keeps the rest honest |

Per module: run the script (5 min), read the writeup (10 min), diff `vuln/` vs `safe/` (10 min), then
look at your own code for the same shape (15 min). The last step is the only one that matters.

---

## 9. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Module on port 8081 is not answering` | module not started or still booting | `scripts/status.sh`, then `tail logs/m01-authentication.log` |
| `build failed` in `run-all.sh` | compile error, offline Maven, or a mirror problem | run `./mvnw -DskipTests package` directly to see the full error |
| `Address already in use` | a previous run left a JVM, or something else owns 8081–8096 | `scripts/stop-all.sh`, then `lsof -iTCP:8081-8096 -sTCP:LISTEN` |
| attack script exits with `REFUSING ...` | you pointed it at a non-loopback host | remove `RANGE_HOST=` or set it to `127.0.0.1`; the guard is deliberate |
| `/vuln5/tools/ping` says "disabled" | `VULNRANGE_ALLOW_EXEC` is not set | see §3; the safe endpoint demonstrates the fix without it |
| `/safe10/fetch` returns 403 for your URL | outbound calls are restricted to `127.0.0.1:8090` paths under `/safe10/public/` | intended; see `docs/10-ssrf-webhooks.md` |
| `/vuln14/config-check` returns `{}` | no credential-shaped variable in the process environment | `DB_PASSWORD=demo scripts/run-module.sh m14-runtime-hardening`, then `/vuln14/config-check` |
| HTTPS on 8443 fails with a certificate warning | self-signed keystore generated at startup | expected; use `curl -k` — that is the point of m08 |
| `dependency-check` slow or failing | NVD feed download, network, or a stale database | check the mirror/proxy; a stale DB reporting "clean" is itself the lesson |
| `git rev-parse` fails in `run_secret_scan.sh` | the directory is not a git repository | expected; the script falls back to scanning the working tree |

If a module fails to start, its log names the reason — usually a port conflict or, for m03 with the `prod`
profile, a deliberately missing environment variable.

---

## 10. Where things are

```
spring-vuln-range/
├── README.md                  safety rules, prerequisites, module table
├── USAGE.md                   this file (the hands-on guide)
├── SECURITY_CHECKLIST.md      §1–§16 with every item, insecure vs hardened
├── docs/INDEX.md              checklist item → module matrix, automation table
├── docs/NN-*.md               one writeup per section: table, reproduce, fix, detection
├── attacks/NN-*.sh            executable PoCs (lib.sh holds the loopback guard and curl helpers)
├── scripts/                   build, run, stop, status, sast/sca/secret-scan/dast, k8s audit, verify
├── tools/                     Semgrep rules, gitleaks config, OWASP suppressions
├── .github/ .gitlab-ci.yml    CI wiring: the same gates, ordered
├── mNN-<slug>/                one Maven module per section, `vuln/` + `safe/` packages
└── logs/  sast-results/       created at runtime, git-ignored
```

Next: pick a module, run its script, open its writeup. Start with `docs/INDEX.md` if you want the matrix
instead of the narrative.
