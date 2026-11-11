# spring-vuln-range — deliberately vulnerable Spring Boot microservices

A security test range that implements **every item of [`SECURITY_CHECKLIST.md`](SECURITY_CHECKLIST.md)** as a running
Spring Boot service: one microservice per checklist section (16 services). Each service exposes

* `/vulnN/**` — the **insecure** implementation (so you can reproduce the attack end to end), and
* `/safeN/**` — the **hardened** implementation of the same functionality (so you can confirm the fix works),

plus a shell/`curl` PoC in [`attacks/`](attacks/) and a writeup in [`docs/`](docs/) with CWE, reproduction steps,
detection rule and the exact code diff that fixes it.

Start at [`docs/INDEX.md`](docs/INDEX.md) for the checklist-item → module matrix and the automation table;
[`SECURITY_CHECKLIST.md`](SECURITY_CHECKLIST.md) is the per-item list of insecure vs hardened artefacts.
**[`USAGE.md`](USAGE.md)** is the hands-on guide: build, start/stop, profiles, reproduce a vulnerability by
hand, calibrate scanners, troubleshooting, suggested session plan.

---

## ⚠️ Read this before you run anything

1. **Intentionally insecure by design.** These services contain SQL injection, XXE, path traversal, SSRF,
   unsafe deserialization, disabled CSRF/CORS, hardcoded demo credentials and exposed actuator endpoints.
   That is the entire point of the project.
2. **Loopback only.** Every module ships `server.address: 127.0.0.1`. Do not remove it, do not put these
   services behind an ingress/gateway, do not deploy them to dev/stage/prod, and do not open the ports in a
   shared network namespace. Attack scripts refuse to run against a non-loopback host.
3. **Fake data only.** Users, subscriptions, ESPD documents, tokens and "secrets" are synthetic placeholders
   (e.g. the AWS-style key `AKIAIOSFODNN7EXAMPLE` from AWS documentation). No real credential, PII or
   customer data is present, and none should be added.
4. **Self-contained targets only.** SSRF/XXE/external-entity demos point at endpoints *inside this range*.
   No attack script contacts a third-party host, and the range contains no working remote-code-execution
   chain against another system. Chains that require an attacker-controlled infrastructure (LDAP/RMI
   `ObjectFactory`, DNS rebinding, cloud IMDS credentials) are documented and detected, but deliberately not
   weaponised here.
5. **Intended use**: reviewing your own code, calibrating SAST/SCA/DAST gates, writing negative authorization
   tests, training developers and QA, and validating that your review checklist actually finds real bugs.

Use it only on systems you own or are explicitly authorised to test.

---

## Prerequisites

* JDK 21 (`java -version`) — the only hard requirement.
* Internet access to Maven Central (or an internal mirror) on first build.
* `curl` and `python3` for the PoC scripts. Docker is **not** required — the range uses H2 in-memory
  databases, runtime-generated throw-away keystores and mock internal services.

`./mvnw` is a small auditable bootstrap: it downloads a pinned Apache Maven into `.mvn/maven-distro/`
(project-local, never system-wide) and delegates to it. For an internal Nexus/Artifactory, run
`MVN_REPO_URL=https://<your-mirror> ./mvnw -DskipTests package` or just keep using your `~/.m2/settings.xml`.

## Quick start

```bash
cd spring-vuln-range
./mvnw -DskipTests package          # build all 16 modules (this is also the compile-time proof)
scripts/run-all.sh                  # start everything on 127.0.0.1:8081-8096
scripts/status.sh                   # who is up
attacks/01-authentication.sh        # reproduce the authn/token attacks
docs/01-authentication.md           # read what just happened and how to fix it
scripts/stop-all.sh                 # stop everything
```

Single module, foreground (fastest inner loop):

```bash
scripts/run-module.sh m05-injection
attacks/05-injection.sh
```

## Modules

| Port | Module | Checklist section | What you can reproduce |
|------|--------|-------------------|------------------------|
| 8081 | `m01-authentication` | §1 Authentication, sessions, tokens | MD5 password dump, `alg:none` + brute-forced HMAC token forgery, session fixation, cookie flags, login brute force/enumeration, static remember-me key |
| 8082 | `m02-authorization` | §2 Authorization | IDOR/BOLA on `/subscriptions/{id}`, cross-tenant read, `permitAll` leftovers, `WebSecurityCustomizer` bypass, missing `@PreAuthorize`, role vs authority confusion |
| 8083 | `m03-secrets-config` | §3 Secrets and configuration | Secret in code/config, secret leaked through API + env dump, dev profile/H2 console in prod config, per-env credential reuse |
| 8084 | `m04-validation-binding` | §4 Input validation and data binding | Mass assignment of `isAdmin`, unbounded DTO fields, `Sort`/direction injection, path traversal in file name, upload abuse, Spring4Shell-style binder probe |
| 8085 | `m05-injection` | §5 Injection | SQLi in JDBC and JPQL/native query, `LIKE` wildcard abuse, ORDER BY injection, SpEL injection, command injection, log forging (CRLF) — each with a parameterised/allow-list fix |
| 8086 | `m06-deserialization` | §6 Serialization, XML, remoting | Java `readObject` on untrusted bytes, XStream with no type permissions, XXE (file read + external entity), Jackson polymorphic typing, `ObjectInputFilter` fix |
| 8087 | `m07-web-layer` | §7 CSRF, CORS, headers, XSS | CSRF state change without token, credentialed wildcard CORS, missing CSP/HSTS/nosniff, stored XSS via `th:utext` and raw JSON HTML |
| 8088 | `m08-crypto-tls` | §8 Cryptography and TLS | Unauthenticated CBC/ECB oracle-ish padding, static IV, MD5 hashing, `java.util.Random` tokens, hardcoded key, trust-all `TrustManager` + hostname verifier bypass against the module's own HTTPS listener |
| 8089 | `m09-logging-errors` | §9 Error handling, logging, monitoring | Stack traces/SQL in 500 responses, constraint-message user enumeration, PII + token in logs, CRLF log forging, missing audit events, and the hardened equivalents |
| 8090 | `m10-ssrf-webhooks` | §10 Outbound calls and webhooks | SSRF to an "internal admin" endpoint, redirect-following SSRF, metadata-endpoint pattern, unsigned + replayed payment webhook, timeout-less client |
| 8091 | `m11-data-exposure` | §11 Data exposure and privacy | JPA entity leaked with `passwordHash`/roles, over-fetching, unbounded `?size=`, PII in query params/URLs, missing column-level protection |
| 8092 | `m12-actuator` | §12 Actuator, API docs, debug endpoints | Unauthenticated `/env`, `/heapdump`, `/configprops`, `/loggers`, `/threaddump`, OpenAPI in prod, health details disclosure |
| 8093 | `m13-supply-chain` | §13 Dependencies and supply chain | Dependency inventory that SCA must flag (`commons-collections 3.2.1` gadget classes, `fastjson 1.2.24`), `@type`/gadget-style instantiation demo, `ObjectInputFilter` mitigation, `-Psca` dependency gate |
| 8094 | `m14-runtime-hardening` | §14 Runtime / container / Kubernetes | Bad vs hardened manifests (root, privileges, no limits, secrets in env), endpoints that dump env/mounts/uid to show why "non-root + readOnlyRootFilesystem" matters, manifest audit script |
| 8095 | `m15-business-logic` | §15 Business logic (subscription/ESPD) | Client-controlled price/tariff, state-machine bypass, double activation via replay (no idempotency), entitlement bypass, quota/DoS abuse, tampered consent/scope |
| 8096 | `m16-verification` | §16 Process and verification | SAST/SCA/secret-scan/DAST wiring, negative authorization matrix tests that must fail against `/vulnN` and pass against `/safeN`, deliberately flaggable code sample |

Section numbers match `SECURITY_CHECKLIST.md`; module numbers match `docs/NN-*.md` and `attacks/NN-*.sh`.

## Conventions

* **`/vulnN/**` is broken on purpose.** Class and method names carry `// VULNERABLE (intentional)` comments
  explaining the flaw and pointing at the fix. Never merge these packages into a product branch — delete them.
* **`/safeN/**` is the reference implementation** you can lift into a real service.
* Each module is independently runnable (`scripts/run-module.sh mNN-*`) and shares nothing but the parent POM,
  so a reviewer can diff one section without noise from the others.
* No module writes outside its own `target/` dir and the OS temp directory; all databases are in-memory H2.

## What is intentionally *not* here

* No working RCE against anything but the range itself, no credential-stealing malware, no exfiltration to
  external hosts, no weaponised Log4Shell JNDI listener, no container-escape exploit.
* No real secrets, tokens, certificates or customer data.

Those limits are enough to demonstrate and detect every checklist item; they are not needed to learn the fix.
