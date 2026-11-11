# CWE Reference — §11 Data Exposure and Privacy

CWEs extracted from `docs/11-data-exposure.md` with developer-focused comments.

---

## CWE-213 — Exposure of Sensitive Information to an Unauthorized Actor

**Why it matters:** This is the core data-exposure vulnerability. When an API returns more fields than the client needs, sensitive data (password hashes, refresh tokens, government IDs like INN/SNILS, internal risk scores) leaks to anyone who can call the endpoint. This happens silently — the endpoint "works correctly" from a functional perspective, but the response contract includes internal fields that should never leave the service. A new entity column automatically becomes API output without any security review.

**Attack vector in Spring:**
```java
// VULNERABLE — JPA entity serialised as the API response
@GetMapping("/subscribers/{id}")
public ResponseEntity<?> getSubscriber(@PathVariable String id) {
    Subscriber sub = subscriberRepository.findById(id).orElseThrow();
    // Returns ALL fields including: passwordHash, refreshToken, internalRiskScore, inn, snils, espdTokenHash
    // spring.jpa.open-in-view is at default → lazy-loaded subscriptions serialises silently
    return ResponseEntity.ok(sub);
}
// Response: {"id":"USR-0001","username":"alice","email":"alice@example.invalid",
//            "passwordHash":"$2a$12$...", "refreshToken":"eyJ...",
//            "inn":"123456789012", "snils":"123-456-789 00",
//            "internalRiskScore":0.7, "espTokenHash":"..."}
```
`GET /vuln11/subscribers/USR-0001` returns the entire entity — every column from the database, including password hashes, refresh tokens, and government IDs.

**How to prevent:**
```java
// SAFE — a response contract (DTO/View), not an entity
@GetMapping("/subscribers/{id}")
@PreAuthorize("@subscriberAccess.isOwner(authentication.name, #id)")
public ResponseEntity<?> getSubscriber(@PathVariable String id) {
    Subscriber sub = subscriberRepository.findById(id).orElseThrow();
    // Only the fields the client needs
    SubscriberView view = new SubscriberView(
        sub.getId(),
        sub.getUsername(),
        maskEmail(sub.getEmail()),
        sub.getPrimaryPlan()
    );
    return ResponseEntity.ok(view);
}

public record SubscriberView(String id, String username, String maskedEmail, String primaryPlan) {}
```
- A response contract is the only shape data leaves the service in.
- A new entity column does NOT become API output by default.
- Use DTOs with explicit fields — not `@Entity` as the response type.

---

## CWE-312 — Cleartext Storage of Sensitive Information (Exposed in Transit)

**Why it matters:** CWE-312 in the context of API exposure refers to sensitive data being transmitted in cleartext over the network, either because TLS is not enforced or because the API returns sensitive fields that should never leave the service. Even over TLS, returning password hashes, refresh tokens, or government IDs in an API response is a data-protection violation (GDPR, CCPA, PCI-DSS).

**Attack vector in Spring:**
```java
// VULNERABLE — sensitive fields returned in every response
@GetMapping("/subscribers/{id}")
public ResponseEntity<?> getSubscriber(@PathVariable String id) {
    Subscriber sub = subscriberRepository.findById(id).orElseThrow();
    // passwordHash, refreshToken, inn, snils sent over the wire
    // Even over TLS, this is a data-protection violation
    return ResponseEntity.ok(sub);
}

// VULNERABLE — access token as query parameter, then echoed
@GetMapping("/reports/{id}")
public ResponseEntity<?> getReport(@PathVariable String id,
                                    @RequestParam String accessToken) {
    // Token is in the URL → logged in access logs, browser history, proxy logs
    // Then echoed in the response body
    return ResponseEntity.ok(Map.of("report", reportService.get(id, accessToken)));
}
```

**How to prevent:**
```java
// SAFE — never echo tokens, never send sensitive data
// Token from Authorization header, not query parameter
@GetMapping("/reports/{id}")
public ResponseEntity<?> getReport(@PathVariable String id,
                                    @RequestHeader("Authorization") String authorization) {
    String token = authorization.substring(7);  // "Bearer "
    // Never echo the token back
    Report report = reportService.get(id, token);
    return ResponseEntity.ok(Map.of("report", report));
}

// Mask PII before serialising
public record SubscriberView(String id, String username, String maskedEmail, String primaryPlan) {
    public SubscriberView(Subscriber sub) {
        this(sub.getId(), sub.getUsername(), maskEmail(sub.getEmail()), sub.getPrimaryPlan());
    }
    
    private static String maskEmail(String email) {
        int at = email.indexOf('@');
        if (at < 2) return "***@***";
        return email.charAt(0) + "***" + email.substring(at - 1);
    }
}
```
- Tokens from `Authorization: Bearer`, not from query parameters.
- Mask PII in the projection, not after serialization.
- Column-level protection in the database: encrypt `inn`/`snils` at rest.

---

## CWE-598 — Use of GET Request Method That Should Return Non-Cacheable Data

**Why it matters:** When PII (emails, tokens, identifiers) is placed in the query string, it is logged in multiple places: browser history, proxy logs, access logs, server logs, referrer headers. This turns a search endpoint into a PII leak that affects not just the caller but every proxy and log aggregator in the request path.

**Attack vector in Spring:**
```java
// VULNERABLE — PII in query string
@GetMapping("/subscribers/search")
public ResponseEntity<?> search(@RequestParam String email) {
    // Email is in the URL → logged in:
    // - Browser history
    // - Proxy logs (nginx, CDN)
    // - Server access logs (127.0.0.1 - - [10/Nov/2025:14:32:00 +0000] "GET /search?email=alice@example.invalid HTTP/1.1" 200)
    // - Referer headers if the page links elsewhere
    List<Subscriber> results = subscriberRepository.findByEmail(email);
    return ResponseEntity.ok(results);
}
```
`GET /vuln11/subscribers/search?email=alice@example.invalid` — the email is in the URL, logged in access logs, visible in browser history, and leaked via Referer headers to any linked third-party pages.

**How to prevent:**
```java
// SAFE — POST with body, validated SearchRequest
@PostMapping("/subscribers/search")
public ResponseEntity<?> search(@Valid @RequestBody SearchRequest req) {
    // Email is in the request body, not the URL
    // Not logged in access logs (body is not in the log line)
    List<Subscriber> results = subscriberRepository.findByEmail(req.email());
    return ResponseEntity.ok(results);
}

public record SearchRequest(
    @Email @Size(max = 254) String email
) {}
```
- Search endpoints that take PII should use POST with a validated request body.
- Never put PII in URLs — it is logged everywhere.

---

## CWE-532 — Information Exposure Through Log Files (Token in URL)

**Why it matters:** CWE-532 in the context of data exposure refers to sensitive data (tokens, credentials, PII) being exposed through log files because it was placed in the URL (query parameters) or logged without masking. Access logs, proxy logs, and CDN logs capture the full request URL — including query parameters with tokens.

**Attack vector in Spring:**
```java
// VULNERABLE — access token as query parameter, then echoed
@GetMapping("/reports/{id}")
public ResponseEntity<?> getReport(@PathVariable String id,
                                    @RequestParam String accessToken) {
    // Token is in the URL → logged in access logs
    // Then echoed in the response body
    return ResponseEntity.ok(Map.of("report", reportService.get(id, accessToken)));
}
// Access log: "GET /vuln11/reports/REP-1?accessToken=placeholder-token-0001 HTTP/1.1" 200
// The token is now in every log aggregator, backup, and proxy log
```

**How to prevent:**
- Same as CWE-598: use `Authorization: Bearer` header, never query parameters.
- Never echo tokens back in the response body.
- Mask any PII that must be logged.

---

## CWE-770 — Allocation of Resources Without Limits (Client-Controlled Page Size)

**Why it matters:** When the client controls the page size or export limit, an attacker can request an arbitrarily large dataset that exhausts server memory or disk. A request with `?size=1000000` can load millions of records into memory, causing an OutOfMemoryError or crashing the JVM. This is a denial-of-service attack through resource exhaustion.

**Attack vector in Spring:**
```java
// VULNERABLE — client-controlled page size
@GetMapping("/subscribers/page")
public ResponseEntity<?> page(@RequestParam(defaultValue = "1000000") int size) {
    // Loads up to 1,000,000 records into memory
    List<Subscriber> all = subscriberRepository.findAll();
    return ResponseEntity.ok(all.subList(0, Math.min(size, all.size())));
}
// Also vulnerable: ?size=1000000 on export endpoint
```
`GET /vuln11/subscribers/page?size=1000000` loads all records into memory — OOM crash. The client decides how much memory the server spends.

**How to prevent:**
```java
// SAFE — server owns the page size
private static final int MAX_PAGE_SIZE = 100;

@GetMapping("/subscribers")
public ResponseEntity<?> page(@RequestParam(defaultValue = "100") int size) {
    int capped = Math.clamp(size, 1, MAX_PAGE_SIZE);  // 1 ≤ size ≤ 100
    Page<Subscriber> result = subscriberRepository.findAll(PageRequest.of(0, capped));
    return ResponseEntity.ok(Map.of(
        "page", result.getNumber(),
        "size", result.getSize(),
        "total", result.getTotalElements(),
        "maxPageSize", MAX_PAGE_SIZE
    ));
}
```
- The server owns the page size, not the client.
- `MAX_PAGE_SIZE` = 100, clamped with `Math.clamp`.
- Report the cap back in the response so the client knows the limit.

---

## CWE-213 — Field Selection Without an Allow-List (Over-Export)

**Why it matters:** When an export endpoint accepts a `fields` parameter without validating it against an allow-list, the caller can request any database column — including password hashes, refresh tokens, and government IDs. This is a dynamic over-fetching vulnerability: the endpoint "works correctly" for legitimate fields but has no boundary on what can be exported.

**Attack vector in Spring:**
```java
// VULNERABLE — field selection without allow-list
@GetMapping("/subscribers/{id}/export")
public ResponseEntity<?> export(@PathVariable String id,
                                 @RequestParam List<String> fields) {
    Subscriber sub = subscriberRepository.findById(id).orElseThrow();
    Map<String, Object> result = new LinkedHashMap<>();
    for (String field : fields) {
        // Attacker sends: fields=passwordHash,refreshToken,inn,snils
        // Returns ALL requested fields, including sensitive ones
        result.put(field, getField(sub, field));
    }
    return ResponseEntity.ok(result);
}
```
`GET /vuln11/subscribers/USR-0001/export?fields=passwordHash,refreshToken` returns the password hash and refresh token. The caller can request any field from the entity.

**How to prevent:**
```java
// SAFE — field selection is a projection allow-list
@GetMapping("/subscribers/{id}/export")
public ResponseEntity<?> export(@PathVariable String id,
                                 @RequestParam List<String> fields) {
    Set<String> ALLOWED = Set.of("id", "username", "primaryPlan", "createdAt");
    
    List<String> rejected = fields.stream()
        .filter(f -> !ALLOWED.contains(f))
        .toList();
    
    if (!rejected.isEmpty()) {
        // Return 400 with the rejected fields — visible in logs, not silently filtered
        return ResponseEntity.status(400).body(Map.of(
            "error", "Rejected fields",
            "rejected", rejected,
            "allowed", new ArrayList<>(ALLOWED)
        ));
    }
    
    Subscriber sub = subscriberRepository.findById(id).orElseThrow();
    Map<String, Object> result = new LinkedHashMap<>();
    for (String field : fields) {
        result.put(field, getSafeField(sub, field));
    }
    return ResponseEntity.ok(result);
}
```
- Field selection checks against a fixed allow-list.
- Return 400 with the rejected fields — the attempt is visible in logs.
- Do not silently filter — that hides the attack from monitoring.

---

## CWE-213 — No Stated Response Contract

**Why it matters:** When an API has no documented or machine-readable response contract, there is no way to verify that the response contains only the fields it should. New entity columns automatically become API output without review. Without a contract test, data exposure regressions are invisible until a security audit or a breach.

**Attack vector in Spring:**
```java
// VULNERABLE — no stated response contract
@GetMapping("/subscribers/{id}")
public ResponseEntity<?> getSubscriber(@PathVariable String id) {
    Subscriber sub = subscriberRepository.findById(id).orElseThrow();
    return ResponseEntity.ok(sub);  // Whatever fields the entity has, goes out
    // If a new column "passwordHash" is added to the entity,
    // it automatically appears in the API response
}
```

**How to prevent:**
```java
// SAFE — selftest endpoint states the contract
@GetMapping("/selftest")
public ResponseEntity<?> selftest() {
    return ResponseEntity.ok(Map.of(
        "exposedFields", List.of("id", "username", "maskedEmail", "primaryPlan"),
        "neverExposed", List.of("passwordHash", "refreshToken", "inn", "snils")
    ));
}

// Contract test asserts that GET /safe11/subscribers/USR-0001 has exactly
// the keys in exposedFields and does NOT contain any key in neverExposed.
// If a new entity column is added, the test fails the build.
```
- `/safe11/selftest` lists `exposedFields` and `neverExposed`.
- A contract test fails the build when the two lists change.
- This is the moment a review should happen — when a new column is added.
