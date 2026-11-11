# Documentation index

Start here. `SECURITY_CHECKLIST.md` is the list of items; this directory is the "why" and "how" for
each of them. Every module is implemented twice — `/vulnN/**` (broken on purpose) and `/safeN/**`
(the reference fix) — so read the two side by side.

| # | Section | Module | Port | Writeup | PoC |
|---|---------|--------|------|---------|-----|
| 1 | Authentication, sessions and tokens | `m01-authentication` | 8081 | [01-authentication.md](01-authentication.md) | [01-authentication.sh](../attacks/01-authentication.sh) |
| 2 | Authorization and access control | `m02-authorization` | 8082 | [02-authorization.md](02-authorization.md) | [02-authorization.sh](../attacks/02-authorization.sh) |
| 3 | Secrets and configuration | `m03-secrets-config` | 8083 | [03-secrets-config.md](03-secrets-config.md) | [03-secrets-config.sh](../attacks/03-secrets-config.sh) |
| 4 | Input validation and data binding | `m04-validation-binding` | 8084 | [04-validation-binding.md](04-validation-binding.md) | [04-validation-binding.sh](../attacks/04-validation-binding.sh) |
| 5 | Injection | `m05-injection` | 8085 | [05-injection.md](05-injection.md) | [05-injection.sh](../attacks/05-injection.sh) |
| 6 | Deserialization, XML, polymorphic JSON | `m06-deserialization` | 8086 | [06-deserialization.md](06-deserialization.md) | [06-deserialization.sh](../attacks/06-deserialization.sh) |
| 7 | CSRF, CORS, headers, output encoding | `m07-web-layer` | 8087 | [07-web-layer.md](07-web-layer.md) | [07-web-layer.sh](../attacks/07-web-layer.sh) |
| 8 | Cryptography and TLS | `m08-crypto-tls` | 8088 (+8443) | [08-crypto-tls.md](08-crypto-tls.md) | [08-crypto-tls.sh](../attacks/08-crypto-tls.sh) |
| 9 | Error handling, logging, security events | `m09-logging-errors` | 8089 | [09-logging-errors.md](09-logging-errors.md) | [09-logging-errors.sh](../attacks/09-logging-errors.sh) |
| 10 | Outbound calls and webhooks | `m10-ssrf-webhooks` | 8090 | [10-ssrf-webhooks.md](10-ssrf-webhooks.md) | [10-ssrf-webhooks.sh](../attacks/10-ssrf-webhooks.sh) |
| 11 | Data exposure and privacy | `m11-data-exposure` | 8091 | [11-data-exposure.md](11-data-exposure.md) | [11-data-exposure.sh](../attacks/11-data-exposure.sh) |
| 12 | Management endpoints, API docs, debug surfaces | `m12-actuator` | 8092 (8192 in `safe`) | [12-actuator.md](12-actuator.md) | [12-actuator.sh](../attacks/12-actuator.sh) |
| 13 | Dependencies and supply chain | `m13-supply-chain` | 8093 | [13-supply-chain.md](13-supply-chain.md) | [13-supply-chain.sh](../attacks/13-supply-chain.sh) |
| 14 | Runtime, container, Kubernetes hardening | `m14-runtime-hardening` | 8094 | [14-runtime-hardening.md](14-runtime-hardening.md) | [14-runtime-hardening.sh](../attacks/14-runtime-hardening.sh) |
| 15 | Business logic (subscription / ESPD) | `m15-business-logic` | 8095 | [15-business-logic.md](15-business-logic.md) | [15-business-logic.sh](../attacks/15-business-logic.sh) |
| 16 | Process and verification | `m16-verification` | 8096 | [16-verification.md](16-verification.md) | [16-verification.sh](../attacks/16-verification.sh) |

## Checklist item → module matrix

Items are numbered `§N.M` as in [`SECURITY_CHECKLIST.md`](../SECURITY_CHECKLIST.md).

| Section | Items | Insecure | Hardened | PoC blocks | Detection |
|---------|-------|----------|----------|-----------|-----------|
| §1 | 1.1 – 1.10 | `/vuln1/**` | `/safe1/**` | 10 | token/cookie assertions in `m16` |
| §2 | 2.1 – 2.9 | `/vuln2/**` | `/safe2/**` | 9 | `SafeOwnershipMatrixTest` (m16), Semgrep authz rules |
| §3 | 3.1 – 3.7 | `/vuln3/**`, `application-prod.yml` | `/safe3/**` | 8 | `scripts/run_secret_scan.sh`, `gitleaks` |
| §4 | 4.1 – 4.9 | `/vuln4/**` | `/safe4/**` | 9 | Semgrep binding/path rules |
| §5 | 5.1 – 5.8 | `/vuln5/**` | `/safe5/**` | 7 | Semgrep injection rules, DAST (`run_dast_zap.sh`) |
| §6 | 6.1 – 6.5 | `/vuln6/**` | `/safe6/**` | 4 | Semgrep deserialization rules |
| §7 | 7.1 – 7.6 | `/vuln7/**`, templates | `/safe7/**` | 7 | Semgrep CSRF/CORS/header rules |
| §8 | 8.1 – 8.9 | `/vuln8/**`, HTTPS 8443 | `/safe8/**` | 8 | Semgrep crypto rules, TLS inspection |
| §9 | 9.1 – 9.9 | `/vuln9/**` | `/safe9/**` | 9 | log-hygiene test, Semgrep `verbose-error-responses-enabled` |
| §10 | 10.1 – 10.8 | `/vuln10/**` | `/safe10/**` | 7 | Semgrep `ssrf-url-from-request` |
| §11 | 11.1 – 11.7 | `/vuln11/**` | `/safe11/**` | 6 | projection/entity greps, `/safe11/selftest` |
| §12 | 12.1 – 12.12 | default profile | `application-safe.yml` | 6 | YAML review, `/safe12` profile diff in CI |
| §13 | 13.1 – 13.7 | parent `pom.xml` versions | `-Psca` gate, `baseline-upgrades` | 5 | `scripts/run_sca.sh`, Semgrep `fastjson-autotype-enabled` |
| §14 | 14.1 – 14.11 | `deploy/docker/Dockerfile.vulnerable`, bad manifest | hardened `Dockerfile`, hardened manifest | 5 | `scripts/check_k8s_manifests.sh` (20 controls) |
| §15 | 15.1 – 15.10 | `/vuln15/**` | `/safe15/**` | 7 | rule assertions in `m16`, DAST on 8081–8096 |
| §16 | 16.1 – 16.12 | `FlaggableSastFixtures` | `SafeOwnershipMatrixTest`, `VulnerableEndpointRegressionTest` | 5 | the module *is* the detection |

## Automation

| Script | What it does | Needs |
|--------|--------------|-------|
| `scripts/verify_range.sh` | static self-consistency: ports, loopback binding, PoC paths, docs, YAML, manifests | `python3`, `bash` |
| `scripts/run_sast.sh` | Semgrep with `tools/semgrep/spring-security-rules.yml` | `semgrep` (fails with a clear message otherwise) |
| `scripts/run_sca.sh` | dependency-check via `-Psca`; **expected to fail on m13** | Maven, internet for the NVD database |
| `scripts/run_secret_scan.sh` | `gitleaks` with `tools/gitleaks/.gitleaks.toml` | `gitleaks` |
| `scripts/run_dast_zap.sh` | ZAP baseline against loopback modules | Docker |
| `scripts/check_k8s_manifests.sh` | 20 controls on the pair of manifests | `python3` |
| `scripts/run-all.sh` | build + start 8081–8096 (`SKIP_M13=1` supported) | JDK 21 |

## Reading order for a review

1. The checklist item you are reviewing in `SECURITY_CHECKLIST.md`.
2. The matching row in the module writeup — **Insecure** column first, then **Hardened**.
3. `/safeN/**` source for that row; copy its shape into your service.
4. Run the PoC script if the "it cannot happen here" claim needs testing.
5. If a rule is missing for the item you just found, add it to `tools/semgrep/spring-security-rules.yml`
   and a fixture to `m16-verification` — that is what keeps the checklist from decaying into a document.
