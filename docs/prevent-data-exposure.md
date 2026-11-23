# Spring Security: How to Prevent Data Exposure & Privacy Vulnerabilities

A practical guide to securing Spring Boot against over-fetching, PII leakage, token exposure, and resource exhaustion — covering 6 CWEs found in real Spring applications.

---

## Table of Contents

1. [Response Contracts Over Entities](#1-response-contracts-over-entities)
2. [Client-Controlled Page Size Limits](#2-client-controlled-page-size-limits)
3. [PII in Query Strings](#3-pii-in-query-strings)
4. [Token Exposure via URLs and Echoing](#4-token-exposure-via-urls-and-echoing)
5. [Field Selection Allow-List](#5-field-selection-allow-list)
6. [Stated Response Contracts & CI Testing](#6-stated-response-contracts--ci-testing)

---

## 1. Response Contracts Over Entities

**CWE-213** — *Exposure of Sensitive Information to an Unauthorized Actor*  
**CWE-312** — *Cleartext Storage of Sensitive Information (Exposed in Transit)*

### The Problem

When an API returns more fields than the client needs, sensitive data (password hashes, refresh tokens, government IDs like INN/SNILS, internal risk scores) leaks to anyone who can call the endpoint. This happens silently — the endpoint "works correctly" from a functional perspective, but the response contract includes internal fields that should never leave the service. A new entity column automatically becomes API output without any security review.

```java
// ❌ VULNERABLE — JPA entity serialised as the API response
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

### The Fix

Use a **response contract (DTO/View)** — not an entity — as the only shape data leaves the service in.

```java
// ✅ SAFE — a response contract (DTO/View), not an entity
@GetMapping("/subscribers/{id}")
@PreAuthorize("@subscriberAccess.isOwner(authentication.name, #id)")
public ResponseEntity<?> getSubscriber(@PathVariable String id) {
    Subscriber sub = subscriberRepository.findById(id).orElseThrow();
    
    // Only the fields the client needs, masked where appropriate
    SubscriberView view = new SubscriberView(
        sub.getId(),
        sub.getUsername(),
        maskEmail(sub.getEmail()),
        sub.getPrimaryPlan()
    );
    return ResponseEntity.ok(view);
}

// Response DTO — explicit fields, nothing more
public record SubscriberView(
    String id,
    String username,
    String maskedEmail,
    String primaryPlan
) {
    private static String maskEmail(String email) {
        if (email == null || !email.contains("@")) return "***@***";
        int at = email.indexOf('@');
        return email.charAt(0) + "***" + email.substring(at - 1);
    }
}
```

**Key rules:**
- A **response contract is the only shape data leaves the service** in
- A new entity column does **NOT** become API output by default
- Use DTOs with explicit fields — not `@Entity` as the response type
- Mask PII **in the projection**, not after serialization (Jackson serialisers are easy to forget)
- Keep `spring.jpa.open-in-view` off in production to prevent silent lazy-load serialization

---

## 2. Client-Controlled Page Size Limits

**CWE-770** — *Allocation of Resources Without Limits (Client-Controlled Page Size)*

### The Problem

When the client controls the page size or export limit, an attacker can request an arbitrarily large dataset that exhausts server memory or disk. A request with `?size=1000000` can load millions of records into memory, causing an OutOfMemoryError or crashing the JVM. This is a denial-of-service attack through resource exhaustion.

```java
// ❌ VULNERABLE — client-controlled page size
@GetMapping("/subscribers/page")
public ResponseEntity<?> page(@RequestParam(defaultValue = "1000000") int size) {
    // Loads up to 1,000,000 records into memory
    List<Subscriber> all = subscriberRepository.findAll();
    return ResponseEntity.ok(all.subList(0, Math.min(size, all.size())));
}
// Also vulnerable: ?size=1000000 on export endpoint
```

`GET /vuln11/subscribers/page?size=1000000` loads all records into memory — OOM crash. The client decides how much memory the server spends.

### The Fix

The server owns the page size. Clamp client input to a maximum.

```java
// ✅ SAFE — server owns the page size
private static final int MAX_PAGE_SIZE = 100;

@GetMapping("/subscribers")
public ResponseEntity<?> page(
        @RequestParam(defaultValue = "100") int size) {
    
    // Clamp to server-defined bounds
    int capped = Math.clamp(size, 1, MAX_PAGE_SIZE);
    
    Page<Subscriber> result = subscriberRepository.findAll(PageRequest.of(0, capped));
    
    return ResponseEntity.ok(Map.of(
        "page", result.getNumber(),
        "size", result.getSize(),
        "total", result.getTotalElements(),
        "maxPageSize", MAX_PAGE_SIZE
    ));
}

// ✅ SAFE — validate with annotations
@GetMapping("/subscribers")
public ResponseEntity<?> page(
        @RequestParam(defaultValue = "100") @Min(1) @Max(100) int size) {
    
    Page<Subscriber> result = subscriberRepository.findAll(PageRequest.of(0, size));
    return ResponseEntity.ok(Map.of(
        "page", result.getNumber(),
        "size", result.getSize(),
        "total", result.getTotalElements(),
        "maxPageSize", 100
    ));
}
```

**Key rules:**
- **The server owns the page size**, not the client
- `MAX_PAGE_SIZE` = 100, clamped with `Math.clamp` or `@Max(100)`
- Report the cap back in the response so the client knows the limit
- Use Spring Data `Page`/`Pageable` for database-level pagination, not in-memory `subList`
- For export endpoints, return a streaming response (CSV, NDJSON) with a smaller cap

---

## 3. PII in Query Strings

**CWE-598** — *Use of GET Request Method That Should Return Non-Cacheable Data*  
**CWE-532** — *Information Exposure Through Log Files (Token in URL)*

### The Problem

When PII (emails, tokens, identifiers) is placed in the query string, it is logged in multiple places: browser history, proxy logs, access logs, server logs, referrer headers. This turns a search endpoint into a PII leak that affects not just the caller but every proxy and log aggregator in the request path.

```java
// ❌ VULNERABLE — PII in query string
@GetMapping("/subscribers/search")
public ResponseEntity<?> search(@RequestParam String email) {
    // Email is in the URL → logged in:
    // - Browser history
    // - Proxy logs (nginx, CDN)
    // - Server access logs (127.0.0.1 - - [10/Nov/2025:14:32:00 +0000] 
    //   "GET /search?email=alice@example.invalid HTTP/1.1" 200)
    // - Referer headers if the page links elsewhere
    List<Subscriber> results = subscriberRepository.findByEmail(email);
    return ResponseEntity.ok(results);
}
```

`GET /vuln11/subscribers/search?email=alice@example.invalid` — the email is in the URL, logged in access logs, visible in browser history, and leaked via Referer headers to any linked third-party pages.

### The Fix

Search endpoints that take PII should use POST with a validated request body.

```java
// ✅ SAFE — POST with body, validated SearchRequest
@PostMapping("/subscribers/search")
public ResponseEntity<?> search(@Valid @RequestBody SearchRequest req) {
    // Email is in the request body, not the URL
    // Not logged in access logs (body is not in the log line)
    List<Subscriber> results = subscriberRepository.findByEmail(req.email());
    return ResponseEntity.ok(results);
}

public record SearchRequest(
    @Email(message = "Must be a valid email")
    @Size(max = 254, message = "Email must be ≤ 254 characters")
    String email
) {}
```

**Key rules:**
- Search endpoints that take PII should use **POST with a validated request body**
- Never put PII in URLs — it is logged everywhere (access logs, proxies, browser history, referrers)
- If GET is required for cacheability, use a non-PII identifier (session token, user ID) as the key
- Mask or hash identifiers in URLs to prevent PII leakage through the URL path

---

## 4. Token Exposure via URLs and Echoing

**CWE-598** — *Use of GET Request Method That Should Return Non-Cacheable Data*  
**CWE-532** — *Information Exposure Through Log Files*

### The Problem

When an access token is passed as a query parameter, it is logged in access logs, proxy logs, and browser history. If the API also echoes the token back in the response body, the exposure is doubled. Tokens in URLs are a direct credential leak.

```java
// ❌ VULNERABLE — access token as query parameter, then echoed
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

### The Fix

Use `Authorization: Bearer` header. Never echo tokens back in the response body.

```java
// ✅ SAFE — token from Authorization header, never from query params
@GetMapping("/reports/{id}")
public ResponseEntity<?> getReport(@PathVariable String id,
                                    @RequestHeader("Authorization") String authorization) {
    // Extract token from "Bearer <token>" header
    String token;
    if (authorization != null && authorization.startsWith("Bearer ")) {
        token = authorization.substring(7);
    } else {
        return ResponseEntity.status(401).body(Map.of("error", "Authorization header required"));
    }
    
    // Never echo the token back
    Report report = reportService.get(id, token);
    return ResponseEntity.ok(Map.of("report", report));
}

// ✅ SAFE — if the API needs to reference a token, return a masked version
public record ReportView(String id, String title, String summary) {
    // No token fields in the response
}
```

**Key rules:**
- **Tokens from `Authorization: Bearer` header**, not from query parameters
- **Never echo tokens back** in the response body
- Mask any PII in the projection, not after serialization
- Column-level protection in the database: encrypt sensitive fields at rest

---

## 5. Field Selection Allow-List

**CWE-213** — *Exposure of Sensitive Information to an Unauthorized Actor (Over-Export)*

### The Problem

When an export endpoint accepts a `fields` parameter without validating it against an allow-list, the caller can request any database column — including password hashes, refresh tokens, and government IDs. This is a dynamic over-fetching vulnerability: the endpoint "works correctly" for legitimate fields but has no boundary on what can be exported.

```java
// ❌ VULNERABLE — field selection without allow-list
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

### The Fix

Field selection checks against a **fixed allow-list**. Return 400 with rejected fields — visible in logs, not silently filtered.

```java
// ✅ SAFE — field selection is a projection allow-list
@GetMapping("/subscribers/{id}/export")
public ResponseEntity<?> export(@PathVariable String id,
                                 @RequestParam List<String> fields) {
    Set<String> ALLOWED = Set.of("id", "username", "primaryPlan", "createdAt");

    // Reject disallowed fields — don't silently filter
    List<String> rejected = fields.stream()
        .filter(f -> !ALLOWED.contains(f))
        .toList();

    if (!rejected.isEmpty()) {
        log.warn("Export rejected fields: {} for subscriber {}", rejected, id);
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

private Object getSafeField(Subscriber sub, String field) {
    return switch (field) {
        case "id" -> sub.getId();
        case "username" -> sub.getUsername();
        case "primaryPlan" -> sub.getPrimaryPlan();
        case "createdAt" -> sub.getCreatedAt();
        default -> throw new IllegalArgumentException("Unexpected field: " + field);
    };
}
```

**Key rules:**
- Field selection checks against a **fixed allow-list**
- Return **400 with rejected fields** — the attempt is visible in logs
- Do **not silently filter** — that hides the attack from monitoring
- Never pass the `fields` list directly to a repository or database query
- Re-derive values server-side from a safe subset of the entity

---

## 6. Stated Response Contracts & CI Testing

**CWE-213** — *No Stated Response Contract*

### The Problem

When an API has no documented or machine-readable response contract, there is no way to verify that the response contains only the fields it should. New entity columns automatically become API output without review. Without a contract test, data exposure regressions are invisible until a security audit or a breach.

```java
// ❌ VULNERABLE — no stated response contract
@GetMapping("/subscribers/{id}")
public ResponseEntity<?> getSubscriber(@PathVariable String id) {
    Subscriber sub = subscriberRepository.findById(id).orElseThrow();
    return ResponseEntity.ok(sub);  // Whatever fields the entity has, goes out
    // If a new column "passwordHash" is added to the entity,
    // it automatically appears in the API response
}
```

### The Fix

State the contract explicitly via a self-test endpoint and enforce it with contract tests in CI.

```java
// ✅ SAFE — selftest endpoint states the contract
@GetMapping("/selftest")
public ResponseEntity<?> selftest() {
    return ResponseEntity.ok(Map.of(
        "exposedFields", List.of("id", "username", "maskedEmail", "primaryPlan"),
        "neverExposed", List.of("passwordHash", "refreshToken", "inn", "snils", "internalRiskScore"),
        "maxPageSize", 100
    ));
}

// ✅ SAFE — Contract test (JUnit / integration test)
// src/test/java/ContractTest.java
@Test
void testSubscriberResponseContract() {
    // 1. Get the contract from selftest
    ResponseEntity<Map> selftestResp = restTemplate.getForEntity("/safe11/selftest", Map.class);
    List<String> exposedFields = (List<String>) selftestResp.getBody().get("exposedFields");
    List<String> neverExposed = (List<String>) selftestResp.getBody().get("neverExposed");

    // 2. Fetch an actual subscriber
    ResponseEntity<String> resp = restTemplate.getForEntity("/safe11/subscribers/USR-0001", String.class);
    JsonNode body = objectMapper.readTree(resp.getBody());

    // 3. Assert: response has exactly the exposed fields
    Set<String> actualFields = body.fieldNames().collect(Collectors.toSet());
    assertEquals(new HashSet<>(exposedFields), actualFields, 
        "Response fields changed! New fields must be reviewed for data exposure.");

    // 4. Assert: response does NOT contain any never-exposed fields
    for (String forbidden : neverExposed) {
        assertFalse(body.has(forbidden), 
            "Sensitive field '" + forbidden + "' leaked in response!");
    }
}
```

**Key rules:**
- `/selftest` lists `exposedFields` and `neverExposed` — the response contract
- A **contract test fails the build** when the two lists change
- This is the moment a review should happen — when a new column is added
- Run contract tests in CI on every merge request
- Treat any change to `exposedFields` as a security review blocker

---

## Summary Checklist

| # | Control | CWE | Priority |
|---|---------|-----|----------|
| 1 | DTO/View as response, not `@Entity` | CWE-213, CWE-312 | CRITICAL |
| 2 | Server-owned page size, clamped | CWE-770 | HIGH |
| 3 | PII in POST body, not GET query string | CWE-598, CWE-532 | HIGH |
| 4 | `Authorization: Bearer` header, no echoing | CWE-598, CWE-532 | CRITICAL |
| 5 | Field selection allow-list + 400 on reject | CWE-213 | HIGH |
| 6 | `/selftest` + contract test in CI | CWE-213 | HIGH |

---

## Detection & Review Heuristics

| Check | Command / Pattern |
|-------|-------------------|
| Entity as response type | `grep -r 'ResponseEntity<.*Entity\|ResponseEntity<.*Subscriber'` → should use DTOs |
| PII in query params | `grep -r '@RequestParam.*email\|@RequestParam.*token\|@RequestParam.*password'` → should use POST body |
| accessToken in URL | `grep -r 'accessToken\|apiKey\|secret'` in `@RequestParam` → should be `@RequestHeader` |
| Client page size | `grep -r '@RequestParam.*size\|@RequestParam.*limit'` → should have `@Min/@Max` or `Math.clamp` |
| Field selection passthrough | `grep -r 'fields.*repository\|fields.*query'` → should validate against allow-list |
| Missing selftest | `grep -r 'exposedFields\|neverExposed'` → should exist in safe endpoints |
| Lazy serialization | Check `spring.jpa.open-in-view` → should be `false` in production |

---

## References

- [OWASP REST Security Cheat Sheet — Response Data Control](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
- [OWASP Data Exposure](https://cheatsheetseries.owasp.org/cheatsheets/Data_Validation_Cheat_Sheet.html)
- [OWASP Mass Assignment](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [Spring Data Pagination](https://docs.spring.io/spring-data/commons/reference/repository/exposing-query.html)
- [RFC 7807: Problem Details for HTTP APIs](https://datatracker.ietf.org/doc/html/rfc7807)
