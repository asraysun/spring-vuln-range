# CWE Reference — §16 Process and Verification: Turning the Checklist into Executable Checks

CWEs extracted from `docs/16-verification.md` with developer-focused comments.

> **Key premise of this module:** The other fifteen modules are findings. This one is the question that decides whether they would have been found in a pipeline instead of by a pentester: **does the tooling see what is in front of it?** It answers in two mechanisms that are deliberately falsifiable: `FlaggableSastFixtures` (textbook insecure patterns that SAST tools must report) and `SafeOwnershipMatrixTest` (negative authorization matrix that must pass on `/safe16` and fail on `/vuln16`). This module is the calibration point for all security gates.

---

## CWE-639 — Authorization Bypass Through User-Controlled Key (IDOR / BOLA)

**Why it matters:** This is the verification module's primary finding: an endpoint that treats authentication as authorization. When `VulnerableDocumentController` ignores the principal and only checks `isAuthenticated()`, any authenticated user can read any document. The verification module proves this with `VulnerableEndpointRegressionTest` — `mallory → DOC-0001 → 200` is a failing assertion that should never pass.

**Attack vector in Spring:**
```java
// VULNERABLE — authenticated treated as authorised
// GET /vuln16/documents/{id} — principal ignored, any caller reads any document
@GetMapping("/documents/{id}")
public ResponseEntity<?> getDocument(@PathVariable String id) {
    // No ownership check — alice, bob, mallory all get the same document
    Document doc = documentRepository.findById(id).orElseThrow();
    return ResponseEntity.ok(doc);
}
// VulnerableEndpointRegressionTest: crossUserReadIsAccepted → 200 (FAIL)
```
`GET /vuln16/documents/DOC-0002` without credentials → 200. `GET /vuln16/documents/DOC-0001` as bob → 200 (alice's document).

**How to prevent:**
```java
// SAFE — owner from Principal, foreign row answered 404
@GetMapping("/documents/{id}")
@PreAuthorize("@documentAccess.isOwner(authentication.name, #id)")
public ResponseEntity<?> getDocument(@PathVariable String id) {
    Document doc = documentRepository.findByIdAndOwner(id, authentication.getName())
        .orElseThrow(() -> new NotFoundException());
    return ResponseEntity.ok(doc);
}
```
- `SafeOwnershipMatrixTest`: `ownerCanRead` (alice → DOC-0001 → 200), `otherUserCannotRead` (bob → DOC-0001 → 404), `otherTenantCannotRead` (alice → DOC-0002 → 404).
- Answer 404 for foreign rows so authorization does not become an enumeration oracle.

---

## CWE-863 — Incorrect Authorization (Anonymous Access)

**Why it matters:** CWE-863 in the verification context refers to endpoints that are accessible without any authentication. When `VulnerableDocumentController` has no security filter, both `/safe16` and `/vuln16` requests arrive as anonymous. The verification module proves this with `VulnerableEndpointRegressionTest` — `anonymousReadIsAccepted` (no principal → 200) is a failing assertion.

**Attack vector in Spring:**
```java
// VULNERABLE — anonymous caller reaches the same document
// GET /vuln16/documents/{id} without a principal → 200
// No authentication filter on the endpoint
@GetMapping("/documents/{id}")
public ResponseEntity<?> getDocument(@PathVariable String id) {
    // No Principal check — anonymous caller gets the document
    Document doc = documentRepository.findById(id).orElseThrow();
    return ResponseEntity.ok(doc);
}
// VulnerableEndpointRegressionTest: anonymousReadIsAccepted → 200 (FAIL)
```

**How to prevent:**
```java
// SAFE — 401 when Principal is null
@GetMapping("/documents/{id}")
public ResponseEntity<?> getDocument(@PathVariable String id) {
    if (authentication == null || !authentication.isAuthenticated()) {
        return ResponseEntity.status(401).body("Unauthorized");
    }
    // ... ownership check ...
}
```
- Identity comes from `java.security.Principal`, never from a parameter.
- `/safe16/documents/DOC-0001` answers 401 when `Principal` is null.

---

## CWE-862 — Incomplete Authentication (Missing Principal)

**Why it matters:** CWE-862 covers the absence of authentication enforcement. When a security filter chain does not require authentication for a path, the `Principal` is null and the application has no way to identify the caller. This is the root cause of CWE-306 and CWE-863.

**Attack vector in Spring:**
```java
// VULNERABLE — no authentication filter
// Both /safe16 and /vuln16 requests arrive as anonymous
// Security filter chain does not require authentication for /vuln16/**
http.requestMatcher("/vuln16/**")
    .authorizeHttpRequests(a -> a
        .anyRequest().permitAll()  // No authentication required
    );
```

**How to prevent:**
```java
// SAFE — authentication required
http.requestMatcher("/safe16/**")
    .authorizeHttpRequests(a -> a
        .anyRequest().authenticated()  // Principal always present
    );
```

---

## CWE-203 — Observable Response Discrepancy (Enumeration via Distinguishable Responses)

**Why it matters:** When foreign rows and missing rows return different HTTP status codes (200 vs 404), authorization becomes an enumeration oracle. An attacker can distinguish "exists but not mine" from "doesn't exist," leaking the total count of records and enabling targeted attacks.

**Attack vector in Spring:**
```java
// VULNERABLE — foreign row and missing row are distinguishable
@GetMapping("/documents/{id}")
public ResponseEntity<?> getDocument(@PathVariable String id) {
    Document doc = documentRepository.findById(id).orElseThrow(() -> new NotFoundException());
    // Foreign row → 404
    // Missing row → 404
    // But: foreign row triggers ownership check → different error message or timing
    // 200 or 404 discloses existence
    return ResponseEntity.ok(doc);
}
```
`GET /vuln16/documents/DOC-0002` (foreign row) → 404. `GET /vuln16/documents/DOC-9999` (missing row) → 404. If the error messages or timing differ, the attacker knows DOC-0002 exists but they don't own it.

**How to prevent:**
```java
// SAFE — foreign row and missing row both 404, same response
@GetMapping("/documents/{id}")
public ResponseEntity<?> getDocument(@PathVariable String id) {
    Document doc = documentRepository.findByIdAndOwner(id, authentication.getName())
        .orElseThrow(() -> new NotFoundException());  // Same exception for both cases
    return ResponseEntity.ok(doc);
}
```
- Map foreign and missing rows to the same response (404).
- Authorization should not be an enumeration oracle.

---

## CWE-89 — SQL Injection (Concatenation)

**Why it matters:** CWE-89 in the verification module is a fixture that must be reported by SAST tools. The `FlaggableSastFixtures` class contains a `JdbcTemplate.queryForList` with string concatenation — a Semgrep rule `spring-sql-string-concatenation` must flag it. A clean report on these fixtures is proof that the SAST stage is decorative.

**Attack vector in Spring:**
```java
// VULNERABLE — SQL built by concatenating request data
// GET /vuln16/fixture/sql-injection?plan=
// JdbcTemplate.queryForList with string concatenation
@GetMapping("/fixture/sql-injection")
public ResponseEntity<?> sqlInjection(@RequestParam String plan) {
    String sql = "SELECT * FROM documents WHERE plan = '" + plan + "'";
    // Attacker sends: plan='; DROP TABLE documents;--
    return ResponseEntity.ok(jdbcTemplate.queryForList(sql));
}
```

**How to prevent:**
```java
// SAFE — bound parameters
@GetMapping("/safe16/fixture/sql-injection")
public ResponseEntity<?> sqlInjection(@RequestParam String plan) {
    return ResponseEntity.ok(
        jdbcTemplate.queryForList(
            "SELECT * FROM documents WHERE plan = ?",
            String.class, plan
        )
    );
}
```
- Semgrep `spring-sql-string-concatenation` must report this fixture.
- `scripts/run_sast.sh` step 2/3 runs SpotBugs — must find it.

---

## CWE-22 — Path Traversal (Request-Built Path Without Containment)

**Why it matters:** CWE-22 in the verification module is a fixture that FindSecBugs `PATH_TRAVERSAL_IN` must report. The `Path.of("/tmp", name)` shape is not matched by Semgrep's `path-resolution-from-request-without-containment` rule (which matches `$ROOT.resolve($REQ.get...)` and `Paths.get($A, $B)`), so only FindSecBugs reports it. This is the same lesson as the rest of the range: one tool is a partial answer.

**Attack vector in Spring:**
```java
// VULNERABLE — path built from request data without containment
// GET /vuln16/fixture/path-traversal?name=
// Path.of("/tmp", name) — no normalize() + startsWith check
@GetMapping("/fixture/path-traversal")
public ResponseEntity<?> pathTraversal(@RequestParam String name) {
    Path file = Path.of("/tmp", name);  // ../../etc/passwd escapes /tmp
    return ResponseEntity.ok(Files.readString(file));
}
```

**How to prevent:**
```java
// SAFE — normalize + containment check
@GetMapping("/safe16/fixture/path-traversal")
public ResponseEntity<?> pathTraversal(@RequestParam String name) {
    Path baseDir = Path.of("/tmp").toAbsolutePath().normalize();
    Path file = baseDir.resolve(name).toAbsolutePath().normalize();
    if (!file.startsWith(baseDir)) {
        return ResponseEntity.status(403).body("Access denied");
    }
    return ResponseEntity.ok(Files.readString(file));
}
```
- FindSecBugs `PATH_TRAVERSAL_IN` must report this fixture.
- Semgrep does not match this shape — only FindSecBugs catches it.

---

## CWE-327 — Use of a Broken or Risky Cryptographic Algorithm (MD5)

**Why it matters:** CWE-327 in the verification module is a fixture that FindSecBugs `WEAK_MESSAGE_DIGEST_MD5` must report. Using MD5 as a security digest (token verification, password hashing, integrity checks) is a textbook vulnerability that SAST tools should catch.

**Attack vector in Spring:**
```java
// VULNERABLE — MD5 used as a security digest
// GET /vuln16/fixture/weak-hash?value=
// MessageDigest.getInstance("MD5")
@GetMapping("/fixture/weak-hash")
public ResponseEntity<?> weakHash(@RequestParam String value) {
    MessageDigest md = MessageDigest.getInstance("MD5");  // Weak!
    byte[] hash = md.digest(value.getBytes());
    return ResponseEntity.ok(Map.of("hash", bytesToHex(hash)));
}
```

**How to prevent:**
```java
// SAFE — SHA-256 or better for non-password digests
// Argon2id or BCrypt for passwords
@GetMapping("/safe16/fixture/weak-hash")
public ResponseEntity<?> weakHash(@RequestParam String value) {
    MessageDigest md = MessageDigest.getInstance("SHA-256");  // Strong
    byte[] hash = md.digest(value.getBytes());
    return ResponseEntity.ok(Map.of("hash", bytesToHex(hash)));
}
```
- FindSecBugs `WEAK_MESSAGE_DIGEST_MD5` must report this fixture.
- Semgrep `weak-message-digest-for-security` also catches it.

---

## CWE-328 — Use of Weak Hash Algorithm

**Why it matters:** CWE-328 is the broader category for CWE-327. MD5 is cryptographically broken — collisions can be generated in seconds, and pre-image attacks are practical. Using it for any security purpose (token verification, password hashing, integrity checks) provides no security.

**Attack vector in Spring:**
```java
// VULNERABLE — MD5 as security digest
MessageDigest md = MessageDigest.getInstance("MD5");
```

**How to prevent:**
- Same as CWE-327: use SHA-256 or better for non-password digests.
- Use Argon2id or BCrypt for passwords.

---

## CWE-601 — Open URL Redirection

**Why it matters:** CWE-601 in the verification module is a fixture that FindSecBugs `REDIRECT_HEADER_PARAMETER_DISCLOSURE` must report. The `"redirect:" + url` shape is not matched by Semgrep's `unvalidated-redirect` rule (which matches `RedirectView`), so only FindSecBugs catches it. Again: one tool is a partial answer.

**Attack vector in Spring:**
```java
// VULNERABLE — redirect target from a request parameter
// GET /vuln16/fixture/open-redirect?url=
// "redirect:" + url
@GetMapping("/fixture/open-redirect")
public String openRedirect(@RequestParam String url) {
    return "redirect:" + url;  // ?url=http://evil.com
}
```

**How to prevent:**
```java
// SAFE — logical name → allow-listed target
@GetMapping("/safe16/fixture/open-redirect")
public String openRedirect(@RequestParam String destination) {
    Map<String, String> ALLOWED = Map.of("home", "/", "profile", "/profile");
    String target = ALLOWED.get(destination);
    if (target == null) return "redirect:/";
    return "redirect:" + target;
}
```
- FindSecBugs `REDIRECT_HEADER_PARAMETER_DISCLOSURE` must report this fixture.
- Semgrep `unvalidated-redirect` does not match this shape (returns a String, not RedirectView).

---

## CWE-798 — Use of Hard-coded Credentials (Credential-shaped Literal in Source)

**Why it matters:** CWE-798 in the verification module is a fixture that `scripts/run_secret_scan.sh` (gitleaks) must report. A credential-shaped literal like `AKIAIOSFODNN7EXAMPLE` in source code is visible to anyone with repo access. The secret scan must find it — zero findings means the scanner is misconfigured.

**Attack vector in Spring:**
```java
// VULNERABLE — credential-shaped literal in source
// GET /vuln16/fixture/hardcoded-secret
// AKIAIOSFODNN7EXAMPLE (placeholder AWS key)
@GetMapping("/fixture/hardcoded-secret")
public ResponseEntity<?> hardcodedSecret() {
    String key = "AKIAIOSFODNN7EXAMPLE";  // In source code!
    return ResponseEntity.ok(Map.of("key", key));
}
```

**How to prevent:**
```java
// SAFE — key from environment or secret manager
@Value("${AWS_ACCESS_KEY}")
private String accessKey;

@GetMapping("/safe16/fixture/hardcoded-secret")
public ResponseEntity<?> hardcodedSecret() {
    return ResponseEntity.ok(Map.of("keyPresent", !Strings.isNullOrEmpty(accessKey)));
}
```
- Semgrep `hardcoded-credential-literal` must report this fixture.
- `scripts/run_secret_scan.sh` must report it.
- Zero findings means the scanner is misconfigured.

---

## CWE-117 — Improper Neutralization of Log Injection Characters (CRLF)

**Why it matters:** CWE-117 in the verification module is a fixture that FindSecBugs `CRLF_INJECTION_LOGS` must report. User input written to logs without sanitization enables log forging attacks.

**Attack vector in Spring:**
```java
// VULNERABLE — log forged from request data
// POST /vuln16/fixture/log-injection
// message written to the log unsanitised
@PostMapping("/fixture/log-injection")
public ResponseEntity<?> logInjection(@RequestParam String message) {
    log.info("User message: {}", message);  // No sanitization
    // Attacker sends: message=%0d%0a{"level":"INFO","user":"admin"}
    return ResponseEntity.ok("logged");
}
```

**How to prevent:**
```java
// SAFE — sanitize before logging
@PostMapping("/safe16/fixture/log-injection")
public ResponseEntity<?> logInjection(@RequestParam String message) {
    String sanitized = message.replaceAll("[\\r\\n\\x00]", "");
    log.info("User message: {}", sanitized);
    return ResponseEntity.ok("logged");
}
```
- FindSecBugs `CRLF_INJECTION_LOGS` must report this fixture.
- Strip CR, LF, NUL from all log input.

---

## CWE-611 — Improper Restriction of XML External Entity Reference (XXE)

**Why it matters:** CWE-611 in the verification module is a fixture that Semgrep `xxe-parser-without-hardening` and FindSecBugs `XML_DECODER` / `XXE_*` must report. A bare `DocumentBuilderFactory.newInstance()` with default features resolves external entities.

**Attack vector in Spring:**
```java
// VULNERABLE — XML parser with external entities enabled
// POST /vuln16/fixture/xxe
// DocumentBuilderFactory.newInstance(), default features
@PostMapping("/fixture/xxe")
public ResponseEntity<?> xxe(@RequestBody String xml) {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    // No hardening flags — default features resolve external entities
    Document document = factory.newDocumentBuilder()
        .parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    return ResponseEntity.ok(Map.of("text", document.getDocumentElement().getTextContent()));
}
```

**How to prevent:**
```java
// SAFE — hardened parser
@PostMapping("/safe16/fixture/xxe")
public ResponseEntity<?> xxe(@RequestBody String xml) {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    factory.setXIncludeAware(false);
    factory.setExpandEntityReferences(false);
    Document document = factory.newDocumentBuilder()
        .parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    return ResponseEntity.ok(Map.of("text", document.getDocumentElement().getTextContent()));
}
```
- Semgrep `xxe-parser-without-hardening` must report this fixture.
- FindSecBugs `XML_DECODER` / `XXE_*` must report this fixture.

---

## CWE-918 — Server-Side Request Forgery (JDBC URL Assembly)

**Why it matters:** CWE-918 in the verification module is a fixture that FindSecBugs `SQL_INJECTION_JDBC` must report. Assembling a JDBC URL from a request parameter is both SQL injection and SSRF — the attacker controls the host, port, and database name.

**Attack vector in Spring:**
```java
// VULNERABLE — JDBC URL assembled from a request parameter
// GET /vuln16/fixture/jdbc-url?host=
// DriverManager.getConnection
@GetMapping("/fixture/jdbc-url")
public ResponseEntity<?> jdbcUrl(@RequestParam String host) {
    String url = "jdbc:postgresql://" + host + ":5432/internal-db";
    // Attacker sends: host=169.254.169.254:9200
    // Connects to cloud metadata service via JDBC
    Connection conn = DriverManager.getConnection(url, "app", "password");
    return ResponseEntity.ok("connected");
}
```

**How to prevent:**
```java
// SAFE — JDBC URL from configuration, never from request
// DriverManager.getConnection with hardcoded URL
@GetMapping("/safe16/fixture/jdbc-url")
public ResponseEntity<?> jdbcUrl() {
    // URL from application.yml, not from request parameter
    String url = dataSource.getUrl();  // Pre-configured
    Connection conn = DriverManager.getConnection(url, user, password);
    return ResponseEntity.ok("connected");
}
```
- FindSecBugs `SQL_INJECTION_JDBC` must report this fixture.
- The sink is also an SSRF/JNDI pattern.

---

## CWE-657 — Violation of Secure Design Principles (No Test Asserting Refusal)

**Why it matters:** CWE-657 is the meta-finding of this module: a test suite that only exercises the happy path. When all tests prove the owner can read, but no test proves that other users cannot read, the authorization bug is invisible. A SAST stage that has been green for a year because the ruleset was tuned until the noise went away is not looking — it is decorative. The verification module turns "we have SAST and tests" into a statement that can be falsified in one `mvnw` run.

**Attack vector in Spring:**
```java
// VULNERABLE — no test that asserts the refusal
// A suite that only proves the owner can read
// SafeOwnershipMatrixTest missing: otherUserCannotRead, otherTenantCannotRead
// VulnerableEndpointRegressionTest missing: crossUserReadIsAccepted, anonymousReadIsAccepted

// The matrix test:
// SafeOwnershipMatrixTest — ownerCanRead (200), otherUserCannotRead (404),
//   otherTenantCannotRead (404), missingAndForeignAreTheSame (404)
// VulnerableEndpointRegressionTest — crossUserReadIsAccepted (200 = FAIL),
//   anonymousReadIsAccepted (200 = FAIL)
```
A suite of "authorization tests" that only exercises the happy path — every test green, the object-level bug untouched.

**How to prevent:**
```java
// SAFE — write the refusal, not only the success
// SafeOwnershipMatrixTest
@Test
void ownerCanRead() {
    // alice → DOC-0001 → 200
    assertThat(getDoc("alice", "DOC-0001")).is200();
}

@Test
void otherUserCannotRead() {
    // bob → DOC-0001 → 404
    assertThat(getDoc("bob", "DOC-0001")).is404();
}

@Test
void otherTenantCannotRead() {
    // alice → DOC-0002 (bob's tenant) → 404
    assertThat(getDoc("alice", "DOC-0002")).is404();
}

@Test
void missingAndForeignAreTheSame() {
    // DOC-9999 → 404
    assertThat(getDoc("alice", "DOC-9999")).is404();
}

// VulnerableEndpointRegressionTest — the counter-test
@Test
void crossUserReadIsAccepted() {
    // mallory → DOC-0001 → 200 (this SHOULD FAIL on safe controller)
    // If it passes, the matrix has been weakened
    assertThat(getDoc("mallory", "DOC-0001")).is200();  // FAIL on safe
}

@Test
void anonymousReadIsAccepted() {
    // no principal → 200 (this SHOULD FAIL on safe controller)
    assertThat(getDoc(null, "DOC-0001")).is200();  // FAIL on safe
}
```
- For every protected endpoint: unauthenticated, owner, other user, other tenant, missing row.
- `SafeOwnershipMatrixTest` enumerates `(endpoint, caller, object-ownership, expected status)`.
- `VulnerableEndpointRegressionTest` asserts the insecure behaviour — if it ever passes against the safe controller, the matrix has been weakened.
- Calibrate every gate: `scripts/run_sca.sh` must **fail** on m13; `scripts/run_sast.sh` must find the m16 fixtures; `scripts/run_secret_scan.sh` must find the placeholder literal. A gate that is green here is not looking.
