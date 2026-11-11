# Security review checklist — the target this range reproduces

Every item below is implemented twice in `spring-vuln-range`: once as an insecure variant under
`/vulnN/**` and once as the reference fix under `/safeN/**`. The module column links to the writeup,
the PoC script is the executable form of "how would an attacker use this".

Legend: **Insecure / Hardened** columns give the concrete artefact in the repository, so a review
comment can be backed by a running counter-example instead of an opinion.

| Section | Module | Port | PoC | Doc |
|---------|--------|------|-----|-----|
| §1 Authentication, sessions and tokens | `m01-authentication` | 8081 | [`attacks/01-authentication.sh`](attacks/01-authentication.sh) | [`docs/01-authentication.md`](docs/01-authentication.md) |
| §2 Authorization and access control | `m02-authorization` | 8082 | [`attacks/02-authorization.sh`](attacks/02-authorization.sh) | [`docs/02-authorization.md`](docs/02-authorization.md) |
| §3 Secrets and configuration | `m03-secrets-config` | 8083 | [`attacks/03-secrets-config.sh`](attacks/03-secrets-config.sh) | [`docs/03-secrets-config.md`](docs/03-secrets-config.md) |
| §4 Input validation and data binding | `m04-validation-binding` | 8084 | [`attacks/04-validation-binding.sh`](attacks/04-validation-binding.sh) | [`docs/04-validation-binding.md`](docs/04-validation-binding.md) |
| §5 Injection | `m05-injection` | 8085 | [`attacks/05-injection.sh`](attacks/05-injection.sh) | [`docs/05-injection.md`](docs/05-injection.md) |
| §6 Deserialization, XML, polymorphic JSON | `m06-deserialization` | 8086 | [`attacks/06-deserialization.sh`](attacks/06-deserialization.sh) | [`docs/06-deserialization.md`](docs/06-deserialization.md) |
| §7 CSRF, CORS, headers, output encoding | `m07-web-layer` | 8087 | [`attacks/07-web-layer.sh`](attacks/07-web-layer.sh) | [`docs/07-web-layer.md`](docs/07-web-layer.md) |
| §8 Cryptography and TLS | `m08-crypto-tls` | 8088 (+8443 HTTPS) | [`attacks/08-crypto-tls.sh`](attacks/08-crypto-tls.sh) | [`docs/08-crypto-tls.md`](docs/08-crypto-tls.md) |
| §9 Error handling, logging, monitoring | `m09-logging-errors` | 8089 | [`attacks/09-logging-errors.sh`](attacks/09-logging-errors.sh) | [`docs/09-logging-errors.md`](docs/09-logging-errors.md) |
| §10 Outbound calls and webhooks | `m10-ssrf-webhooks` | 8090 | [`attacks/10-ssrf-webhooks.sh`](attacks/10-ssrf-webhooks.sh) | [`docs/10-ssrf-webhooks.md`](docs/10-ssrf-webhooks.md) |
| §11 Data exposure and privacy | `m11-data-exposure` | 8091 | [`attacks/11-data-exposure.sh`](attacks/11-data-exposure.sh) | [`docs/11-data-exposure.md`](docs/11-data-exposure.md) |
| §12 Management endpoints, API docs, debug surfaces | `m12-actuator` | 8092 | [`attacks/12-actuator.sh`](attacks/12-actuator.sh) | [`docs/12-actuator.md`](docs/12-actuator.md) |
| §13 Dependencies and supply chain | `m13-supply-chain` | 8093 | [`attacks/13-supply-chain.sh`](attacks/13-supply-chain.sh) | [`docs/13-supply-chain.md`](docs/13-supply-chain.md) |
| §14 Runtime, container, Kubernetes hardening | `m14-runtime-hardening` | 8094 | [`attacks/14-runtime-hardening.sh`](attacks/14-runtime-hardening.sh) | [`docs/14-runtime-hardening.md`](docs/14-runtime-hardening.md) |
| §15 Business logic (subscription / ESPD) | `m15-business-logic` | 8095 | [`attacks/15-business-logic.sh`](attacks/15-business-logic.sh) | [`docs/15-business-logic.md`](docs/15-business-logic.md) |
| §16 Process and verification | `m16-verification` | 8096 | [`attacks/16-verification.sh`](attacks/16-verification.sh) | [`docs/16-verification.md`](docs/16-verification.md) |

---

## §1 Authentication, sessions and tokens

| # | Item | Insecure | Hardened |
|---|------|----------|----------|
| 1.1 | Password storage uses a fast, salted-but-useless hash | MD5 digest, dumpable via `/vuln1/users` | `Argon2PasswordEncoder` |
| 1.2 | Login response reveals whether the account exists | distinct messages | identical body and timing |
| 1.3 | No throttling or lockout on login | unlimited attempts | attempt counter + delay |
| 1.4 | Session id is not rotated after login | session fixation works | `changeSessionId()` |
| 1.5 | Cookie without `Secure` / `HttpOnly` / `SameSite` | `/vuln1/set-cookie` | safe cookie writer |
| 1.6 | JWT `alg:none` accepted | forged token accepted | algorithm pinned on verification |
| 1.7 | JWT HMAC key is guessable/static | dictionary brute force recovers it | key from configuration, ≥ 256-bit |
| 1.8 | Password-reset code is predictable | sequential code | CSPRNG code, single use, short TTL |
| 1.9 | Static remember-me key | forged cookie | key rotation |
| 1.10 | Logout does not invalidate the credential | token survives logout | server-side revocation |

## §2 Authorization and access control

| # | Item | Insecure | Hardened |
|---|------|----------|----------|
| 2.1 | IDOR / BOLA on `/subscriptions/{id}` | any authenticated user reads any id | ownership check returns 404 for foreign ids |
| 2.2 | Sequential ids allow enumeration | `/vuln2/subscriptions` listing | no listing, opaque ids |
| 2.3 | State change on `GET` | `GET /vuln2/subscriptions/{id}/cancel` | `POST` + CSRF token |
| 2.4 | Leftover `permitAll()` on a business route | anonymous dump | explicit matcher list |
| 2.5 | `WebSecurityCustomizer.ignoring()` bypass | filters skipped entirely | all requests through the chain |
| 2.6 | Cross-tenant read | tenant id taken from the request | tenant id taken from the principal |
| 2.7 | `@PreAuthorize` present but vacuous | `hasAnyRole()` on a missing role | decision asserted in a test |
| 2.8 | Self-granted `ROLE_ADMIN` | mass-assigned authorities | authorities never bound from input |
| 2.9 | No method-level denial path exercised | — | negative matrix in `m16` |

## §3 Secrets and configuration

| # | Item | Insecure | Hardened |
|---|------|----------|----------|
| 3.1 | Credential literal in a configuration file | `application.yml` | runtime resolution, no default |
| 3.2 | Secret returned by an API endpoint | `/vuln3/config` | `/safe3/config` returns key names only |
| 3.3 | Secret visible in the environment dump | `/vuln3/env` | removed |
| 3.4 | Secret printed to the log | log grep finds it | masked logging |
| 3.5 | Dev console enabled in a shared config | H2 console | disabled outside `dev` |
| 3.6 | Same credential reused per environment | one password everywhere | per-environment credentials |
| 3.7 | Secret committed to the repository | git/log scan finds the literal | `gitleaks` gate, history rewrite |

## §4 Input validation and data binding

| # | Item | Insecure | Hardened |
|---|------|----------|----------|
| 4.1 | Mass assignment of a privileged field | `isAdmin` from the form/JSON | DTO without the field |
| 4.2 | Unbounded input accepted | any length | `@Size`/`@Max` at the boundary |
| 4.3 | `Sort` direction / `ORDER BY` injection | `direction=asc;DROP…` | allow-list of sortable columns |
| 4.4 | Path traversal in a file name | `../../` reads outside the root | name sanitisation + containment check |
| 4.5 | Upload escapes the upload directory | traversal in the stored name | fixed name, type/size check |
| 4.6 | Unsafe binder configuration | Spring4Shell-style probe | `disallowedFields` / no `BeanWrapper` |
| 4.7 | ReDoS-able validation pattern | catastrophic backtracking | bounded pattern |
| 4.8 | Open redirect | `Location` from a parameter | relative-only redirects |
| 4.9 | Export with no limit | unbounded export | capped export |

## §5 Injection

| # | Item | Insecure | Hardened |
|---|------|----------|----------|
| 5.1 | SQL injection in JDBC | concatenated `WHERE` | `PreparedStatement` |
| 5.2 | JPQL / native query injection | concatenated query | bound parameters |
| 5.3 | `LIKE` wildcard abuse | `%` from input not escaped | escaped pattern |
| 5.4 | `ORDER BY` injection | column from input | allow-list |
| 5.5 | SpEL injection | expression from input | no expression from input (gated by `VULNRANGE_ALLOW_SPEL_TYPES`) |
| 5.6 | Command injection | argument from input | gated by `VULNRANGE_ALLOW_EXEC`, `ProcessBuilder` with a fixed argv |
| 5.7 | CRLF log forging | raw value in the log | sanitised value |
| 5.8 | Stack/SQL detail in an error | — | generic error, detail server-side |

## §6 Deserialization, XML and polymorphic JSON

| # | Item | Insecure | Hardened |
|---|------|----------|----------|
| 6.1 | `ObjectInputStream.readObject` on request bytes | gadget chain on the classpath | allow-listed `ObjectInputFilter` |
| 6.2 | XStream with no type permissions | `AnyTypePermission`-style config | allow-list + `AnyTypePermission` removed |
| 6.3 | XXE with a plain JDK parser | local file read, external entity | `disallow-doctype-decl`, entities off |
| 6.4 | Jackson polymorphic typing enabled by default | class named in JSON | `PolymorphicTypeValidator` allow-list |
| 6.5 | Unbounded deserialization | deep/large payload accepted | depth and size limits |

## §7 CSRF, CORS, security headers and output encoding

| # | Item | Insecure | Hardened |
|---|------|----------|----------|
| 7.1 | CSRF disabled, state change via POST | no token needed | `CookieCsrfTokenRepository` + double submit |
| 7.2 | Credentialed wildcard CORS | `*` with credentials | fixed origin list |
| 7.3 | Missing CSP / HSTS / `nosniff` | no headers | `SecurityHeaders` |
| 7.4 | Stored XSS via `th:utext` | script runs | `th:text` |
| 7.5 | HTML injection in a JSON-envelope page | raw string interpolated | escaped |
| 7.6 | Framing allowed | clickjacking | `X-Frame-Options: DENY` / `frame-ancestors 'none'` |

## §8 Cryptography and TLS

| # | Item | Insecure | Hardened |
|---|------|----------|----------|
| 8.1 | ECB / static IV | identical ciphertext blocks | AES-GCM |
| 8.2 | MD5 for integrity | collision-prone | SHA-256 |
| 8.3 | `java.util.Random` for tokens | predictable | `SecureRandom` |
| 8.4 | Hardcoded symmetric key | key in the jar | key from configuration |
| 8.5 | Trust-all `TrustManager` | any certificate accepted | default trust store |
| 8.6 | Hostname verifier bypass | `return true` | default verifier |
| 8.7 | Weak TLS protocol/cipher | TLS 1.0/1.1, RC4 | TLS 1.2+ |
| 8.8 | Timing-unsafe comparison | `equals` on a digest | `MessageDigest.isEqual` |
| 8.9 | Signature not verified | JWT MAC-only | full verification |

## §9 Error handling, logging and security events

| # | Item | Insecure | Hardened |
|---|------|----------|----------|
| 9.1 | Stack trace in the response | `include-stacktrace: always` | never |
| 9.2 | SQL text and internals in the error body | — | generic problem detail + `incidentId` |
| 9.3 | User enumeration by message and timing | — | identical body, identical work |
| 9.4 | Validation errors echo stored state | — | rule-based violations only |
| 9.5 | PII and token in the log | — | masked |
| 9.6 | CRLF log forging | — | sanitised |
| 9.7 | No security events | — | event stream |
| 9.8 | Runtime/topology disclosure | — | removed |
| 9.9 | No correlation id | — | `CorrelationIdFilter` |

## §10 Outbound calls and webhooks

| # | Item | Insecure | Hardened |
|---|------|----------|----------|
| 10.1 | SSRF to an internal admin surface | `/vuln10/fetch` | allow-list + containment |
| 10.2 | SSRF to the metadata endpoint | simulated IMDS | host allow-list denies it |
| 10.3 | Redirect-following defeats the allow-list | redirect target unvalidated | redirects disabled, target re-validated |
| 10.4 | Fetch-and-store with no type/size limit | attacker-chosen bytes stored | no store route, 256 KB cap |
| 10.5 | No timeouts | request thread pinned | connect 2 s / read 4 s |
| 10.6 | Unsigned webhook | anyone marks a payment `PAID` | HMAC signature + timestamp |
| 10.7 | Replayable webhook | replays accepted | idempotency key |
| 10.8 | No egress policy stated | — | `/safe10/egress-policy` |

## §11 Data exposure and privacy

| # | Item | Insecure | Hardened |
|---|------|----------|----------|
| 11.1 | JPA entity serialised with `passwordHash` and roles | — | projection (`SubscriberView`) |
| 11.2 | Over-fetching | full entity | explicit columns |
| 11.3 | Unbounded `?size=` | 1 000 000 accepted | clamped |
| 11.4 | PII in query strings and URLs | logs/Referer leak | PII in the body only |
| 11.5 | No column-level protection | raw values | masking at the boundary |
| 11.6 | Sensitive values in error/log output | — | masked |
| 11.7 | No "never exposed" contract statement | — | `/safe11/selftest` |

## §12 Management endpoints, API documentation and debug surfaces

| # | Item | Insecure | Hardened |
|---|------|----------|----------|
| 12.1 | Every actuator endpoint exposed on the public port | `exposure.include: '*'` | `health`, `info` only |
| 12.2 | `/actuator/env` with values | `show-values: always` | disabled |
| 12.3 | `/actuator/configprops` with values | — | disabled |
| 12.4 | `/actuator/heapdump` | downloadable heap | removed |
| 12.5 | `/actuator/loggers` writable | runtime level change | fixed levels |
| 12.6 | `/actuator/threaddump` | internals | removed |
| 12.7 | Health shows component details | `show-details: always` | `show-details: never` |
| 12.8 | Remote `shutdown` | `POST /actuator/shutdown` | disabled |
| 12.9 | OpenAPI published in production | full route map, including debug routes | not served |
| 12.10 | Debug route reachable without authorization | `/vuln12/debug/reset-cache` | route absent from production builds |
| 12.11 | H2 console in the shipped configuration | `/h2-console` | disabled |
| 12.12 | Management surface on the application port | 8092 | separate loopback port (8192) with authentication |

## §13 Dependencies and supply chain

| # | Item | Insecure | Hardened |
|---|------|----------|----------|
| 13.1 | Vulnerable library on the classpath, never flagged | `fastjson` 1.2.24 | replaced, SCA gate green |
| 13.2 | Deserialization gadget reachable | `commons-collections` (CVE-2015-6420 class of issue) | `commons-collections4` 4.4 |
| 13.3 | Polymorphic parser callable from the API | `autoType` enabled | no parser that names classes |
| 13.4 | Live gadget chain | one-step instantiation only | `ObjectInputFilter` |
| 13.5 | No dependency gate in the build | none | `dependency-check` under `-Psca` |
| 13.6 | No inventory | `/vuln13/dependency-inventory` | SBOM + gate |
| 13.7 | No suppression discipline | — | dated suppressions |

## §14 Runtime, container and Kubernetes hardening

| # | Item | Insecure | Hardened |
|---|------|----------|----------|
| 14.1 | Runs as root | `Dockerfile.vulnerable` | `USER 10001` |
| 14.2 | Full OS with shell and package manager | `eclipse-temurin:21-jdk` | JRE-Alpine / distroless |
| 14.3 | Mutable image tag | `latest` | digest-pinned |
| 14.4 | Secrets baked into the image layer | `ENV DB_PASSWORD` | mounted secret |
| 14.5 | No resource limits | none | requests/limits |
| 14.6 | Privileged pod / no security context | — | `runAsNonRoot`, `readOnlyRootFilesystem`, drop `ALL` |
| 14.7 | No network policy | — | `NetworkPolicy` |
| 14.8 | No probes | — | liveness/readiness |
| 14.9 | No PDB | — | `PodDisruptionBudget` |
| 14.10 | Environment and mounts disclosed by the app | `/vuln14/context` | `/safe14/hardening` states the controls |
| 14.11 | Unbounded write to the filesystem | `/vuln14/write` | containment + quota |

## §15 Business logic: subscription, ESPD and revenue integrity

| # | Item | Insecure | Hardened |
|---|------|----------|----------|
| 15.1 | Client-controlled price | `amount` from the request | price from the tariff catalogue |
| 15.2 | State-machine bypass | `PENDING → ACTIVE` directly | legal transitions only |
| 15.3 | Double activation by replay | no idempotency key | idempotent callback |
| 15.4 | Entitlement bypass | feature flag from the request | entitlement from the subscription |
| 15.5 | Quota/DoS abuse | unlimited document generation | daily quota |
| 15.6 | Tampered consent/scope | scope from the client | scope from the grant |
| 15.7 | Missing audit trail | — | abuse log |
| 15.8 | Time-window logic from creation time | not a calendar day | calendar-day window |
| 15.9 | Recoverable partial failure | — | compensation on rollback |
| 15.10 | No negative tests for the rules | — | rule assertions + regression tests |

## §16 Process and verification

| # | Item | Insecure | Hardened |
|---|------|----------|----------|
| 16.1 | SAST not calibrated | eight flaggable fixtures, a clean report is the failure | fixtures in the acceptance test |
| 16.2 | SQL injection not caught | fixture | Semgrep + Find Security Bugs |
| 16.3 | Path traversal not caught | fixture | Semgrep `path-resolution-from-request-without-containment` |
| 16.4 | Weak hash not caught | fixture | rule + SBOM policy |
| 16.5 | Open redirect not caught | fixture | Semgrep `unvalidated-redirect` |
| 16.6 | Hardcoded secret not caught | fixture | Semgrep + `gitleaks` |
| 16.7 | Log injection not caught | fixture | sanitisation rule |
| 16.8 | XXE not caught | fixture | parser configuration rule |
| 16.9 | Credentials in a JDBC URL not caught | fixture | `gitleaks` |
| 16.10 | Authorization matrix not written | — | `SafeOwnershipMatrixTest` |
| 16.11 | Vulnerability regressions not pinned | — | `VulnerableEndpointRegressionTest` |
| 16.12 | No Definition of Done | — | listing in `attacks/16-verification.sh` |

---

How to use this in a review: quote the section number, point at `/safeN/**` for the expected shape, and
run `attacks/NN-*.sh` when someone claims the flaw is only theoretical.
