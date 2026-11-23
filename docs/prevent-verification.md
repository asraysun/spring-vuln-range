# Spring Security: How to Verify Security Through Testable Assertions & Falsifiable Gating

A practical guide to building executable security verification in Spring Boot — turning checklists into automated gates that can fail builds — covering 12 CWEs found in real Spring applications.

---

## Table of Contents

1. [Negative Authorization Matrix Tests](#1-negative-authorization-matrix-tests)
2. [Falsifiable SAST Fixture Module](#2-falsifiable-sast-fixture-module)
3. [Counter-Tests for Regression](#3-counter-tests-for-regression)
4. [Calibrate Gates Against Known Findings](#4-calibrate-gates-against-known-findings)
5. [Cover All Verification Angles](#5-cover-all-verification-angles)
6. [Make the Pipeline Stop, Not Report](#6-make-the-pipeline-stop-not-report)
7. [Enforce Security Definition of Done](#7-enforce-security-definition-of-done)

---

## 1. Negative Authorization Matrix Tests

**CWE-639** — *Authorization Bypass Through User-Controlled Key (IDOR / BOLA)*  
**CWE-863** — *Incorrect Authorization (Anonymous Access)*  
**CWE-862** — *Incomplete Authentication (Missing Principal)*  
**CWE-203** — *Observable Response Discrepancy (Enumeration via Distinguishable Responses)*

### The Problem

An endpoint that treats authentication as authorization fails silently in functional tests. When `VulnerableDocumentController` ignores the principal and only checks `isAuthenticated()`, any authenticated user can read any document. Worse, if anonymous callers reach the same endpoint, there is zero authentication enforcement. When foreign rows and missing rows return different HTTP status codes, authorization becomes an enumeration oracle.

```java
// ❌ VULNERABLE — authenticated treated as authorised, anonymous reaches same endpoint
// GET /vuln16/documents/{id} — principal ignored, any caller reads any document
@GetMapping("/documents/{id}")
public ResponseEntity<?> getDocument(@PathVariable String id) {
    // No ownership check, no principal check — alice, bob, mallory all get the same document
    Document doc = documentRepository.findById(id).orElseThrow();
    return ResponseEntity.ok(doc);
}
```

`GET /vuln16/documents/DOC-0002` without credentials → 200. `GET /vuln16/documents/DOC-0001` as bob → 200 (alice's document). Foreign row returns 404, missing row returns 404 — but if the error messages or timing differ, the attacker knows DOC-0002 exists.

### The Fix

Write negative authorization matrix tests that **must fail on insecure endpoints and pass on secure ones**.

```java
// ✅ SAFE — Security filter chain enforces authentication
http.requestMatcher("/safe16/**")
    .authorizeHttpRequests(a -> a
        .anyRequest().authenticated()  // Principal always present
    );

// ✅ SAFE — owner from Principal, foreign row answered 404
@GetMapping("/documents/{id}")
@PreAuthorize("@documentAccess.isOwner(authentication.name, #id)")
public ResponseEntity<?> getDocument(@PathVariable String id) {
    Document doc = documentRepository.findByIdAndOwner(id, authentication.getName())
        .orElseThrow(() -> new NotFoundException());  // Same exception for both cases
    return ResponseEntity.ok(doc);
}
```

**The Authorization Matrix Test:**

```java
// ✅ SAFE — enumerate (endpoint, caller, ownership, expected status)
class SafeOwnershipMatrixTest {

    @Test
    void ownerCanRead() {
        // alice → DOC-0001 → 200
        assertThat(getDoc("alice", "DOC-0001")).statusCode(200);
    }

    @Test
    void otherUserCannotRead() {
        // bob → DOC-0001 → 404 (same as missing)
        assertThat(getDoc("bob", "DOC-0001")).statusCode(404);
    }

    @Test
    void otherTenantCannotRead() {
        // alice → DOC-0002 (bob's tenant) → 404
        assertThat(getDoc("alice", "DOC-0002")).statusCode(404);
    }

    @Test
    void missingAndForeignAreTheSame() {
        // DOC-9999 → 404 (same as foreign)
        assertThat(getDoc("alice", "DOC-9999")).statusCode(404);
    }

    @Test
    void policyIsMachineReadable() {
        // The policy endpoint states every rule
        ResponseEntity<String> policy = RestAssured.given()
            .when().get("/safe16/policy");
        assertThat(policy).statusCode(200);
        assertThat(policy.body().jsonPath().getList("exposedFields")).isNotEmpty();
        assertThat(policy.body().jsonPath().getList("neverExposed")).isNotEmpty();
    }
}

// ✅ SAFE — counter-test that asserts insecure behaviour on /vuln16
class VulnerableEndpointRegressionTest {

    @Test
    void crossUserReadIsAccepted() {
        // mallory → DOC-0001 → 200 (FAILS on safe controller, PASSES on vuln)
        assertThat(getDoc("mallory", "DOC-0001"))
            .on("/vuln16/**").statusCode(200);  // Intentional — proves the gap
        // If this same test passes against /safe16, the matrix has been weakened
    }

    @Test
    void anonymousReadIsAccepted() {
        // no principal → 200 (FAILS on safe controller, PASSES on vuln)
        assertThat(getDoc(null, "DOC-0001"))
            .on("/vuln16/**").statusCode(200);
    }
}
```

**Key rules:**
- For **every protected endpoint**, test: unauthenticated, owner, other user, other tenant, missing row
- Answer **404 for foreign rows** so authorization does not become an enumeration oracle
- **Answer 401 when Principal is null** — identity comes from `java.security.Principal`, never from a parameter
- `SafeOwnershipMatrixTest` enumerates `(endpoint, caller, object-ownership, expected status)`
- `VulnerableEndpointRegressionTest` asserts insecure behaviour — if it ever passes against the safe controller, the matrix has been weakened
- Generate cases from `/safe16/policy` so a new endpoint without coverage is visible as a gap

---

## 2. Falsifiable SAST Fixture Module

**CWE-89** — *SQL Injection (Concatenation)*  
**CWE-22** — *Path Traversal (Request-Built Path Without Containment)*  
**CWE-327** — *Use of a Broken or Risky Cryptographic Algorithm (MD5)*  
**CWE-328** — *Use of Weak Hash Algorithm*  
**CWE-601** — *Open URL Redirection*  
**CWE-798** — *Use of Hard-coded Credentials (Credential-shaped Literal)*  
**CWE-117** — *Improper Neutralization of Log Injection Characters (CRLF)*  
**CWE-611** — *Improper Restriction of XML External Entity Reference (XXE)*  
**CWE-918** — *Server-Side Request Forgery (JDBC URL Assembly)*

### The Problem

A SAST stage that has been green for a year because the ruleset was tuned until the noise went away is not looking — it is decorative. Without a **falsifiable fixture module**, there is no way to verify that the SAST tools are actually reporting what is in front of them. A clean report on textbook insecure patterns is proof that the SAST stage is broken.

### The Fix

Ship a fixture module (`FlaggableSastFixtures`) that SAST tools **must** report. A clean report means the gate is misconfigured.

```java
// ✅ SAFE — fixtures that SAST tools must find
public class FlaggableSastFixtures {

    // Fixture 1: SQL Injection — Semgrep spring-sql-string-concatenation, FindSecBugs SQL_INJECTION_JDBC
    public void sqlInjection(@RequestParam String plan) {
        String sql = "SELECT * FROM documents WHERE plan = '" + plan + "'";
        jdbcTemplate.queryForList(sql);  // MUST FLAG
    }

    // Fixture 2: Path Traversal — FindSecBugs PATH_TRAVERSAL_IN
    public void pathTraversal(@RequestParam String name) {
        Path file = Path.of("/tmp", name);  // no normalize() + startsWith check
        Files.readString(file);  // MUST FLAG
    }

    // Fixture 3: Weak Hash — FindSecBugs WEAK_MESSAGE_DIGEST_MD5, Semgrep weak-message-digest-for-security
    public void weakHash(@RequestParam String value) {
        MessageDigest.getInstance("MD5");  // MUST FLAG
    }

    // Fixture 4: Open Redirect — FindSecBugs REDIRECT_HEADER_PARAMETER_DISCLOSURE
    public String openRedirect(@RequestParam String url) {
        return "redirect:" + url;  // MUST FLAG
    }

    // Fixture 5: Hardcoded Secret — Semgrep hardcoded-credential-literal, gitleaks
    public String hardcodedSecret() {
        String key = "AKIAIOSFODNN7EXAMPLE";  // MUST FLAG
        return key;
    }

    // Fixture 6: Log Injection — FindSecBugs CRLF_INJECTION_LOGS
    public void logInjection(@RequestParam String message) {
        log.info("User message: {}", message);  // MUST FLAG
    }

    // Fixture 7: XXE — Semgrep xxe-parser-without-hardening, FindSecBugs XML_DECODER, XXE_*
    public void xxe(@RequestBody String xml) {
        DocumentBuilderFactory.newInstance();  // bare, default features
        // MUST FLAG
    }

    // Fixture 8: JDBC URL Assembly — FindSecBugs SQL_INJECTION_JDBC
    public void jdbcUrl(@RequestParam String host) {
        String url = "jdbc:postgresql://" + host + ":5432/internal-db";
        DriverManager.getConnection(url, "app", "password");  // MUST FLAG
    }
}
```

**CI must fail on zero findings:**

```bash
# ✅ SAFE — run SAST against fixtures; must find them
./mvnw -Psast -pl m16-verification verify
# SpotBugs + FindSecBugs: 8 fixtures must be flagged

# ✅ SAFE — run Semgrep against fixtures; must find them
semgrep --config tools/semgrep/spring-security-rules.yml .
# Rules: spring-sql-string-concatenation, weak-message-digest-for-security,
#        xxe-parser-without-hardening, hardcoded-credential-literal

# ✅ SAFE — secret scan against fixtures; must find them
scripts/run_secret_scan.sh
# gitleaks must report AKIAIOSFODNN7EXAMPLE in FlaggableSastFixtures
```

**Coverage gaps to document:**

| Fixture | SAST Tool | Rule | Notes |
|---------|-----------|------|-------|
| SQL Injection | Semgrep | `spring-sql-string-concatenation` | Must flag `queryForList` with concatenation |
| Path Traversal | FindSecBugs | `PATH_TRAVERSAL_IN` | Semgrep `path-resolution-from-request-without-containment` does not match `Path.of("/tmp", name)` |
| Weak Hash | FindSecBugs, Semgrep | `WEAK_MESSAGE_DIGEST_MD5`, `weak-message-digest-for-security` | Both must flag |
| Open Redirect | FindSecBugs | `REDIRECT_HEADER_PARAMETER_DISCLOSURE` | Semgrep `unvalidated-redirect` does not match `"redirect:" + url` string return |
| Hardcoded Secret | Semgrep, gitleaks | `hardcoded-credential-literal`, secret scan | Both must flag |
| Log Injection | FindSecBugs | `CRLF_INJECTION_LOGS` | Must flag |
| XXE | Semgrep, FindSecBugs | `xxe-parser-without-hardening`, `XML_DECODER`, `XXE_*` | Both must flag |
| JDBC URL | FindSecBugs | `SQL_INJECTION_JDBC` | Must flag |

**Key rules:**
- **One tool is a partial answer** — document coverage gaps explicitly
- Ship a fixture module that **must** be flagged — a clean report proves the SAST stage is misconfigured
- Run SpotBugs/FindSecBugs with `effort: Max`, `threshold: Low`, `xmlOutput` into `sast-results/spotbugs`
- Run Semgrep with the security ruleset — treat "zero findings on `FlaggableSastFixtures`" as a failed stage
- Run gitleaks with `scripts/run_secret_scan.sh` — zero findings means the scanner is misconfigured
- A gate that is green here is not looking

---

## 3. Counter-Tests for Regression

**CWE-657** — *Violation of Secure Design Principles (No Test Asserting Refusal)*

### The Problem

CWE-657 is the meta-finding: a test suite that only exercises the happy path. When all tests prove the owner can read, but no test proves that other users cannot read, the authorization bug is invisible. A new endpoint added with `@PreAuthorize("isAuthenticated()")` and no ownership check gets merged because no matrix row existed to go red.

```java
// ❌ VULNERABLE — no test that asserts the refusal
// A suite that only proves the owner can read
// SafeOwnershipMatrixTest missing: otherUserCannotRead, otherTenantCannotRead
// VulnerableEndpointRegressionTest missing: crossUserReadIsAccepted, anonymousReadIsAccepted
```

### The Fix

Keep the counter-test (`VulnerableEndpointRegressionTest`) that asserts insecure behaviour.

```java
// ✅ SAFE — counter-test that proves the gap exists on insecure code
class VulnerableEndpointRegressionTest {

    @Test
    void crossUserReadIsAccepted() {
        // mallory → DOC-0001 → 200
        // Intentional: proves the insecure controller accepts cross-user reads
        // If this passes against /safe16, the matrix has been weakened
        assertThat(getDoc("mallory", "DOC-0001"))
            .on("/vuln16/**").statusCode(200);
    }

    @Test
    void anonymousReadIsAccepted() {
        // no principal → 200
        // Intentional: proves the insecure controller accepts anonymous reads
        assertThat(getDoc(null, "DOC-0001"))
            .on("/vuln16/**").statusCode(200);
    }
}
```

**How to use the counter-test:**
1. Against `/vuln16` (insecure controller) — the test **PASSES** (proves the gap)
2. Against `/safe16` (secure controller) — the test **FAILS** (proves the fix works)
3. Against a staging deployment of a real service — if it returns 2xx for a non-owner, the build **fails**

**Key rules:**
- The counter-test exists to make the contrast visible in the same report
- If the counter-test ever passes against the secure controller, the matrix has been weakened
- Use the counter-test against staging to catch regressions before production
- The test is the regression guard — if someone weakens the ownership check, the counter-test catches it

---

## 4. Calibrate Gates Against Known Findings

**CWE-1104** — *Use of Unmaintained or Vulnerable Third-Party Component (from m13)*  
**CWE-502** — *Deserialization of Untrusted Data (from m06/m13)*

### The Problem

Security gates that pass on known vulnerabilities are decorative. If `scripts/run_sca.sh` passes on a module that ships `commons-collections` 3.2.1 and `fastjson` 1.2.24, the scanner is misconfigured. If `scripts/run_sast.sh` passes on the m16 fixture module, the SAST stage is broken. If `scripts/run_secret_scan.sh` passes on hardcoded credentials, the secret scan is failing silently.

### The Fix

Calibrate every gate against a known-failing case. **A gate that passes known findings is misconfigured.**

```bash
# ✅ SAFE — calibrate SCA gate against m13
# m13 ships commons-collections 3.2.1 and fastjson 1.2.24 — the gate MUST fail
scripts/run_sca.sh
# Expected: FAIL (finds CVEs in commons-collections and fastjson)
# If GREEN: the SCA gate is misconfigured

# ✅ SAFE — calibrate SAST gate against m16 fixtures
# m16 ships FlaggableSastFixtures — the gate MUST report all 8 fixtures
scripts/run_sast.sh
# Expected: 8 findings reported
# If 0 findings: the SAST gate is misconfigured

# ✅ SAFE — calibrate secret scan against m03/m16
# m03 and m16 ship credential-shaped literals — the gate MUST find them
scripts/run_secret_scan.sh
# Expected: findings reported
# If 0 findings: the secret scan is misconfigured
```

**Calibration checklist:**

| Gate | Calibration Target | Expected |
|------|-------------------|----------|
| SCA (`run_sca.sh`) | m13 (commons-collections 3.2.1, fastjson 1.2.24) | **FAIL** |
| SAST (`run_sast.sh`) | m16 (`FlaggableSastFixtures`) | **8 findings** |
| Secret Scan (`run_secret_scan.sh`) | m03 + m16 (`AKIAIOSFODNN7EXAMPLE`) | **1+ findings** |
| DAST (`run_dast_zap.sh`) | Management paths on ports 8081-8096 | **Empty report** (if hardened) |

**Key rules:**
- Calibrate **every gate** against a known-failing case in the repository
- A gate that is green here is not looking
- Treat "zero findings on `FlaggableSastFixtures`" as a failed SAST stage
- Document calibration expectations in CI workflows

---

## 5. Cover All Verification Angles

**CWE-89** — *SQL Injection*  
**CWE-22** — *Path Traversal*  
**CWE-327** — *Weak Cryptographic Algorithm*  
**CWE-601** — *Open Redirect*  
**CWE-798** — *Hard-coded Credentials*  
**CWE-117** — *Log Injection*  
**CWE-611** — *XXE*  
**CWE-918** — *SSRF*

### The Problem

One tool is a partial answer. A Semgrep rule `spring-sql-string-concatenation` finds JDBC concatenation but not `PATH_TRAVERSAL_IN` (which FindSecBugs catches but Semgrep misses). A FindSecBugs rule `REDIRECT_HEADER_PARAMETER_DISCLOSURE` catches redirect strings but not `XML_DECODER` (which Semgrep catches but FindSecBugs misses). Relying on a single tool or a single rule leaves gaps.

### The Fix

Use multiple tools, document coverage gaps, and ensure each fixture is caught by at least one tool.

```bash
# ✅ SAFE — run both FindSecBugs and Semgrep
# Step 1: SpotBugs + FindSecBugs (must flag: PATH_TRAVERSAL_IN, WEAK_MESSAGE_DIGEST_MD5, etc.)
./mvnw -Psast -pl m16-verification verify

# Step 2: Semgrep (must flag: spring-sql-string-concatenation, xxe-parser-without-hardening, etc.)
semgrep --config tools/semgrep/spring-security-rules.yml .

# Step 3: gitleaks (must flag: AKIAIOSFODNN7EXAMPLE)
scripts/run_secret_scan.sh

# Step 4: Verify all tools ran
scripts/run_sast.sh
```

**Coverage matrix:**

| Vulnerability | FindSecBugs | Semgrep | gitleaks | DAST |
|---------------|-------------|---------|----------|------|
| SQL Injection | `SQL_INJECTION_JDBC` ✓ | `spring-sql-string-concatenation` ✓ | — | ✓ |
| Path Traversal | `PATH_TRAVERSAL_IN` ✓ | (gap) | — | ✓ |
| Weak Hash | `WEAK_MESSAGE_DIGEST_MD5` ✓ | `weak-message-digest-for-security` ✓ | — | — |
| Open Redirect | `REDIRECT_HEADER_PARAMETER_DISCLOSURE` ✓ | (gap) | — | ✓ |
| Hardcoded Secret | — | `hardcoded-credential-literal` ✓ | ✓ | — |
| Log Injection | `CRLF_INJECTION_LOGS` ✓ | — | — | — |
| XXE | `XML_DECODER`, `XXE_*` ✓ | `xxe-parser-without-hardening` ✓ | — | ✓ |
| SSRF/JDBC | `SQL_INJECTION_JDBC` ✓ | — | — | ✓ |

**Key rules:**
- **Use multiple tools** — no single tool catches everything
- Document coverage gaps explicitly (as in the table above)
- Ensure every fixture is caught by **at least one** tool
- A gap is acceptable only if documented and compensated by another gate (DAST, matrix test)

---

## 6. Make the Pipeline Stop, Not Report

**CWE-657** — *Violation of Secure Design Principles*

### The Problem

A security pipeline that "reports" vulnerabilities but never blocks the build is decorative. Findings are ignored, suppressed with blanket rules, and merged anyway. The pipeline must **stop** on real findings.

### The Fix

Configure CI to fail on security findings. Suppress spurious findings with dated, owned, expiring entries — never with disabled rules.

```yaml
# ✅ SAFE — GitHub Actions: security pipeline stops on findings
# .github/workflows/security.yml
name: Security Pipeline
on:
  pull_request:
  push:
    branches: [main]

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-java@v4
        with:
          java-version: '21'
          distribution: 'temurin'
      - name: Semgrep (fails on error)
        uses: semgrep/semgrep-action@v1
        with:
          config: >-
            p/owasp-top ten
            tools/semgrep/spring-security-rules.yml
          fail-on-severity: high
      - name: SpotBugs + FindSecBugs
        run: ./mvnw -B -Psast verify

  sast-fixtures-calibration:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run SAST calibration
        run: |
          FINDINGS=$(./mvnw -B -Psast -pl m16-verification verify 2>&1 | grep -c "finding")
          if [ "$FINDINGS" -lt 8 ]; then
            echo "FAIL: SAST calibration failed. Expected >= 8 findings, got $FINDINGS"
            exit 1
          fi

  matrix-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run ownership matrix test
        run: ./mvnw -B -pl m16-verification test

  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Gitleaks calibration
        run: |
          FINDINGS=$(scripts/run_secret_scan.sh 2>&1 | grep -c "LEAKED")
          if [ "$FINDINGS" -lt 1 ]; then
            echo "FAIL: Secret scan calibration failed. Expected >= 1 finding"
            exit 1
          fi
```

**Suppression policy:**

```xml
<!-- ❌ NEVER suppress with a blanket rule -->
<suppress>
    <notes>disable all spring-security-rules</notes>
    <packageUrl regex="true">^pkg:maven/org\.springframework\..*</packageUrl>
</suppress>

<!-- ✅ ALWAYS suppress with metadata and expiry -->
<suppression>
    <notes>CVE-202X-XXXX: false positive — library not used</notes>
    <packageUrl regex="true">^pkg:maven/com\.example\.vuln-lib@1\.0\.0</packageUrl>
    <vulnerabilityName>CVE-202X-XXXX</vulnerabilityName>
    <justification>Excluded by scope/test or managed dependency</justification>
    <owner>security-team</owner>
    <expires>2026-06-01</expires>
</suppression>
```

**Key rules:**
- **Pipeline stops, not reports** — `--error` / `fail-on-severity: high` / `failBuildOnCVSS: 7`
- Suppress findings with **dated, owned, expiring entries** — never with disabled rules
- Calibration gates must **fail** on known findings (m13 SCA, m16 SAST, m03/m16 secrets)
- Every merge request must pass: matrix test + SAST calibration + secret scan + SCA gate

---

## 7. Enforce Security Definition of Done

**CWE-657** — *Violation of Secure Design Principles*

### The Problem

A security ticket closed as "verified" on the strength of one manual retest, a new endpoint added with `@PreAuthorize("isAuthenticated()")` and no ownership check, merged because no matrix row existed to go red — each of these is the same finding: the pipeline describes the system instead of checking it.

### The Fix

Put the security part of Definition of Done in the ticket template.

```markdown
## Definition of Done — Security Checklist

When opening a security-critical MR, verify:

- [ ] **Threat model updated** — new endpoints, data flows, trust boundaries
- [ ] **Authorization matrix row per new endpoint** — `(endpoint, caller, ownership, expected status)`
- [ ] **Inputs bounded at the boundary** — `@Valid` + `@Size` + `@Pattern` + `@Min`/`@Max`
- [ ] **No new `permitAll()` / `ignoring()` / `csrf().disable()`** without written justification
- [ ] **Egress allow-list** for new outbound calls (SSRF prevention)
- [ ] **Secrets at runtime** — env vars, Vault, or KMS; no hardcoded defaults
- [ ] **Correlation ID and no PII in logs** — `MaskingFilter` + `MDC.put("correlationId", ...)`
- [ ] **Projections instead of entities** — DTO/View, not `@Entity` as response type
- [ ] **Actuator/docs reviewed in the same MR** — no exposed `/actuator/env`, no OpenAPI in prod
- [ ] **Dependency diff reviewed** — every new `<artifactId>` reviewed as security-relevant
- [ ] **Security events logged** — `login_ok`, `authz_denied`, `transition_rejected`, `quota_exceeded`
- [ ] **Rollback plan** — how to revert if this change introduces a vulnerability
```

**Key rules:**
- Security Definition of Done belongs in the **ticket template**, not the PR description
- Every new endpoint needs an **authorization matrix row**
- Every new `<artifactId>` is a **security-relevant change**, not housekeeping
- A MR without threat model update and matrix row is **not mergeable**

---

## Summary Checklist

| # | Control | CWE | Priority |
|---|---------|-----|----------|
| 1 | Negative authorization matrix test | CWE-639, CWE-863, CWE-862, CWE-203 | CRITICAL |
| 2 | Falsifiable SAST fixture module | CWE-89, CWE-22, CWE-327, CWE-601, CWE-798, CWE-117, CWE-611, CWE-918 | CRITICAL |
| 3 | Counter-test for regression | CWE-657 | CRITICAL |
| 4 | Calibrate gates against known findings | CWE-1104, CWE-502 | CRITICAL |
| 5 | Multiple tools, document coverage gaps | CWE-89, CWE-22, CWE-327, CWE-601, CWE-798, CWE-117, CWE-611, CWE-918 | HIGH |
| 6 | Pipeline stops, not reports | CWE-657 | CRITICAL |
| 7 | Security Definition of Done in ticket template | CWE-657 | HIGH |

---

## Detection & Review Heuristics

| Check | Command / Pattern |
|-------|-------------------|
| SAST fixtures missing | `grep -r 'FlaggableSastFixtures'` → must exist, must be flagged |
| Matrix test missing | `grep -r 'SafeOwnershipMatrixTest' \| 'otherUserCannotRead'` → must exist |
| Counter-test missing | `grep -r 'VulnerableEndpointRegressionTest' \| 'crossUserReadIsAccepted'` → must exist |
| Gate calibration missing | `grep -r 'run_sca.sh\|run_sast.sh\|run_secret_scan.sh' .github/workflows/` → must call calibration |
| No security DoD | `grep -r 'Definition of Done\|security checklist'` → must exist in ticket templates |
| Suppression without expiry | `grep -r 'suppress.*<notes>' tools/owasp/` → must have `owner` and `expires` |
| Happy-path-only tests | `grep -r 'isAuthenticated()' src/test/java` without `otherUserCannotRead` → must add negative tests |

---

## References

- [OWASP Software Verification Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Software_Verification_Cheat_Sheet.html)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [OWASP Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Semgrep Security Rules](https://semgrep.dev/explore)
- [Find Security Bugs](https://find-sec-bugs.github.io/)
- [CWE-657: Violation of Secure Design Principles](https://cwe.mitre.org/data/definitions/657.html)
