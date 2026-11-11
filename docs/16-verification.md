# 16 · Process and verification: turning the checklist into executable checks

Checklist section: **§16 Process and verification** · Module: `m16-verification` · Port: **8096**
PoC: [`attacks/16-verification.sh`](../attacks/16-verification.sh) · Run: `scripts/run-module.sh m16-verification`

The other fifteen modules are findings. This one is the question that decides whether they would have
been found in a pipeline instead of by a pentester: **does the tooling see what is in front of it?**
It answers in two mechanisms that are deliberately falsifiable. `FlaggableSastFixtures` is a short list
of textbook insecure patterns that SpotBugs+FindSecBugs and Semgrep **must** report — a clean report on
these eight is proof that the SAST stage is decorative. `src/test/java` is a negative authorization
matrix that must **pass** on `/safe16` and that `VulnerableEndpointRegressionTest` shows would **fail**
if the ownership rule were missing, which is what makes it worth copying into a real project.

The module is also the calibration point for the gates: `.github/workflows/security.yml` and
`.gitlab-ci.yml` both run `./mvnw -B -pl m16-verification test` in the build stage and
`./mvnw -B -Psast -pl m16-verification verify` in the SAST stage, and `scripts/run_sast.sh` step 2/3 runs
the same SpotBugs goal.

## What this module demonstrates

| # | Vulnerability | CWE | Insecure | Hardened |
|---|---------------|-----|----------|----------|
| 1 | Authenticated treated as authorised: any caller reads any document | CWE-639, CWE-863 | `GET /vuln16/documents/{id}` (`VulnerableDocumentController`, principal ignored) | `GET /safe16/documents/{id}` (owner from `Principal`, foreign row answered 404) |
| 2 | Anonymous caller reaches the same document | CWE-306, CWE-862 | `GET /vuln16/documents/{id}` without a principal → 200 | 401 when `Principal` is null |
| 3 | Foreign row and missing row are distinguishable | CWE-203 | `GET /vuln16/documents/{id}` — 200 or 404 discloses existence | foreign row and `DOC-9999` both 404 |
| 4 | SQL built by concatenating request data | CWE-89 | `GET /vuln16/fixture/sql-injection?plan=` (`JdbcTemplate.queryForList`) | Semgrep `spring-sql-string-concatenation`; Fixture 1 must be reported |
| 5 | Path built from request data without containment | CWE-22 | `GET /vuln16/fixture/path-traversal?name=` (`Path.of("/tmp", name)`) | FindSecBugs `PATH_TRAVERSAL_IN`; Semgrep `path-resolution-from-request-without-containment` does not match this shape (see Detection) |
| 6 | MD5 used as a security digest | CWE-327, CWE-328 | `GET /vuln16/fixture/weak-hash?value=` | FindSecBugs `WEAK_MESSAGE_DIGEST_MD5`; Semgrep `weak-message-digest-for-security` |
| 7 | Redirect target from a request parameter | CWE-601 | `GET /vuln16/fixture/open-redirect?url=` (`"redirect:" + url`) | FindSecBugs `REDIRECT_HEADER_PARAMETER_DISCLOSURE`; Semgrep `unvalidated-redirect` |
| 8 | Credential-shaped literal in source | CWE-798 | `GET /vuln16/fixture/hardcoded-secret` (`AKIAIOSFODNN7EXAMPLE`, placeholder) | Semgrep `hardcoded-credential-literal`; `scripts/run_secret_scan.sh` must report it |
| 9 | Log forged from request data | CWE-117 | `POST /vuln16/fixture/log-injection` (`message` written to the log unsanitised) | FindSecBugs `CRLF_INJECTION_LOGS`; `m09` has the server-side control |
| 10 | XML parser with external entities enabled | CWE-611 | `POST /vuln16/fixture/xxe` (`DocumentBuilderFactory.newInstance()`, default features) | Semgrep `xxe-parser-without-hardening`; FindSecBugs `XML_DECODER`, `XXE_*` |
| 11 | JDBC URL assembled from a request parameter | CWE-89, CWE-918 | `GET /vuln16/fixture/jdbc-url?host=` (`DriverManager.getConnection`) | FindSecBugs `SQL_INJECTION_JDBC`; the sink is also an SSRF/JNDI pattern |
| 12 | No test that asserts the refusal | CWE-657 | a suite that only proves the owner can read | `SafeOwnershipMatrixTest` (`(endpoint, caller, ownership, expected status)`) + `VulnerableEndpointRegressionTest` as the counter-test |

## Reproduce

The endpoints are compiled, not exercised: the fixtures are read by the scanners, and the attack script
only shows which ones answer, so that "the fixtures exist" is one command away.

```bash
attacks/16-verification.sh

# the leak, live: no principal, no ownership check
curl -s -i http://127.0.0.1:8096/vuln16/documents/DOC-0002 | head -12

# the policy, stated where a test can assert on it
curl -s http://127.0.0.1:8096/safe16/policy
```

The live service has no authentication filter, so both `/safe16` and `/vuln16` requests arrive as
anonymous: `/safe16/documents/DOC-0001` answers 401 here (`attacks/16-verification.sh` prints the status
codes). The real matrix needs a principal, so it runs as a test:

```bash
./mvnw -pl m16-verification test
```

which executes:

* `SafeOwnershipMatrixTest` — `ownerCanRead` (alice → `DOC-0001` → 200), `otherUserCannotRead`
  (bob → `DOC-0001` → 404), `otherTenantCannotRead` (alice → `DOC-0002`, owned by bob's tenant → 404),
  `missingAndForeignAreTheSame` (`DOC-9999` → 404), `policyIsMachineReadable` (`/safe16/policy`).
* `VulnerableEndpointRegressionTest` — `crossUserReadIsAccepted` (mallory → `DOC-0001` → 200) and
  `anonymousReadIsAccepted` (no principal → 200): the finding, written as an assertion so the contrast
  is visible in the same report.

The fixtures, and the gates that must report them:

```bash
for fixture in sql-injection path-traversal weak-hash open-redirect hardcoded-secret \
               log-injection xxe jdbc-url; do
  printf '  /vuln16/fixture/%-18s -> ' "${fixture}"
  curl -s -o /dev/null -w '%{http_code}\n' "http://127.0.0.1:8096/vuln16/fixture/${fixture}"
done

./mvnw -Psast -pl m16-verification verify                  # SpotBugs + Find Security Bugs
semgrep --config tools/semgrep/spring-security-rules.yml . # Semgrep
scripts/run_sast.sh                                        # both, plus the review shortcuts
scripts/run_secret_scan.sh                                 # must find the fixture literal
scripts/verify_range.sh                                    # structure, ports, scripts, manifests
```

The `fixture/log-injection` and `fixture/xxe` endpoints are `POST`; `status_of` in
`attacks/lib.sh` calls them with `-X GET`, so on 8096 they answer 405 both to the script and to a `curl`
without `-X POST`. That is expected — the point of the fixture is the sink the scanner sees in the source,
not the response.

## Fix, in the order that matters

1. **Make the SAST stage falsifiable.** Ship a fixture module that must be flagged. SpotBugs runs with
   `effort` Max and `threshold` Low and `xmlOutput` into `sast-results/spotbugs`; `failOnError` is
   `false` so that the fixtures can live in the build, and the CI job treats "zero findings on
   `FlaggableSastFixtures`" as a failed SAST stage.
2. **Write the refusal, not only the success.** For every protected endpoint: unauthenticated, owner,
   other user, other tenant, missing row. `SafeOwnershipMatrixTest` is the shape — enumerate
   `(endpoint, caller, object-ownership, expected status)` and generate the cases, so a new endpoint
   without coverage is visible as a gap rather than as a pentest finding.
3. **Keep the counter-test.** `VulnerableEndpointRegressionTest` asserts the insecure behaviour of
   `/vuln16`. If it ever passes against the safe controller, the matrix has been weakened; the second way
   to use it is against a staging deployment of a real service, failing the build on any 2xx for a
   non-owner.
4. **Answer 404 for foreign rows, 401 for anonymous.** `SafeDocumentController` maps foreign and missing
   rows to the same response, so authorization does not become an enumeration oracle; identity comes from
   `java.security.Principal`, never from a parameter.
5. **Calibrate every gate against this repository.** `scripts/run_sca.sh` must **fail** on `m13`
   (commons-collections 3.2.1, fastjson 1.2.24); `scripts/run_sast.sh` must find the m16 fixtures;
   `scripts/run_secret_scan.sh` must find the placeholder literal in `FlaggableSastFixtures`. A gate
   that is green here is not looking.
6. **Put the security part of Definition of Done in the ticket template** (step 5 of the attack script):
   threat model updated, authorization matrix row per new endpoint, inputs bounded at the boundary, no
   new `permitAll` / `ignoring()` / `csrf().disable()` without a written justification, egress allow-list
   for new outbound calls, secrets at runtime, correlation id and no PII in logs, projections instead of
   entities, actuator/docs reviewed in the same MR, dependency diff reviewed, security events and a
   rollback plan.
7. **Make the pipeline stop, not report.** `.github/workflows/security.yml` and `.gitlab-ci.yml` run the
   test matrix in the build stage and Semgrep with `--error` in the SAST stage; spurious findings are
   suppressed with a dated, owned, expiring entry, never with a disabled rule.

## Detection

This module *is* the detection section; what it asserts is which real rule catches which fixture.

* **JUnit, `./mvnw -pl m16-verification test`:** `SafeOwnershipMatrixTest` and
  `VulnerableEndpointRegressionTest` (five and two tests) — the first must stay green, the second exists
  to make the contrast readable.
* **Find Security Bugs 1.13.0 via `spotbugs-maven-plugin` 4.8.6.6:** `SQL_INJECTION_JDBC` (fixtures 1 and
  11), `PATH_TRAVERSAL_IN` (2), `WEAK_MESSAGE_DIGEST_MD5` (3), `REDIRECT_HEADER_PARAMETER_DISCLOSURE`
  (4), `CRLF_INJECTION_LOGS` (6), `XML_DECODER` / `XXE_*` (7). The ids are the ones named in
  `FlaggableSastFixtures`; the plugin is pinned in `m16-verification/pom.xml` and invoked by
  `scripts/run_sast.sh` step 2/3.
* **Semgrep, `tools/semgrep/spring-security-rules.yml`:** `spring-sql-string-concatenation` on the
  `JdbcTemplate` concatenation, `weak-message-digest-for-security` on `MessageDigest.getInstance("MD5")`,
  `xxe-parser-without-hardening` on the bare `DocumentBuilderFactory.newInstance()`, and
  `hardcoded-credential-literal` on the fixture's placeholder API key. Note the coverage gap: fixture 2
  uses `Path.of("/tmp", name)`, but `path-resolution-from-request-without-containment` matches only
  `$ROOT.resolve($REQ.get...)` and `Paths.get($A, $B)`, so only FindSecBugs reports it; fixture 4 returns
  a `"redirect:" + url` string from a REST method rather than from a `RedirectView`, so
  `unvalidated-redirect` does not match either. That is the same lesson as the rest of the range: one
  tool is a partial answer.
* **gitleaks, `tools/gitleaks/.gitleaks.toml`:** `scripts/run_secret_scan.sh` is calibrated to report the
  placeholder literals in `m03-secrets-config` and here; zero findings means the scanner is
  misconfigured.
* **DAST:** `scripts/run_dast_zap.sh` sweeps 8081–8096 for management paths and `attacks/16-verification.sh`
  prints the status matrix, so a new endpoint or a re-opened actuator on any port shows up in the same run.
* **`scripts/verify_range.sh`** (five steps: structure/ports, Java references, YAML, gitleaks config,
  `bash -n` over every script plus the manifest audit) is the gate for the range itself — a renamed path
  or a port collision is caught before anyone tries to demonstrate a finding.

## Where this appears in real reviews

A suite of "authorization tests" that only exercises the happy path — every test green, the object-level
bug untouched; a SAST stage that has been green for a year because the ruleset was tuned until the noise
went away, and nobody noticed it no longer flags `queryForList` with a concatenated string; a
suppression file with an `exclude all of org.apache.*` entry and no expiry; a security ticket closed as
"verified" on the strength of one manual retest; a new endpoint added to a controller with a
`@PreAuthorize("isAuthenticated()")` and no ownership check, merged because no matrix row existed to go
red; and a Definition of Done that says "security reviewed" without saying what would have failed if it
had not been. Each of these is the same finding: the pipeline describes the system instead of checking
it. The fixtures and the matrix here are what turn "we have SAST and tests" into a statement that can be
falsified in one `mvnw` run.
