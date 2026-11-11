# CWE Reference — §09 Error Handling, Logging and Security Events

CWEs extracted from `docs/09-logging-errors.md` with developer-focused comments.

---

## CWE-209 — Information Exposure Through Error Messages

**Why it matters:** Detailed error responses (stack traces, SQL errors, framework internals, validation messages that echo stored state) reveal the technology stack, database schema, query structure, internal architecture, and data formats. This information is a force multiplier for every other attack: it helps attackers craft targeted exploits, understand the data model, and identify the next attack surface.

**Attack vector in Spring:**
```java
// VULNERABLE — stack trace returned in HTTP response
// application.yml: server.error.include-stacktrace=always
@GetMapping("/boom")
public ResponseEntity<?> boom() {
    throw new RuntimeException("Database connection failed: relation \"integration_credentials\" does not exist");
}
// Response: {"timestamp":"...","status":500,"error":"Internal Server Error",
//           "message":"Database connection failed: relation \"integration_credentials\" does not exist",
//           "trace":"java.lang.RuntimeException: ...\n\tat com.example...\n\tat ..."}
```
The stack trace reveals:
- Full class names and package structure
- Line numbers in the source code
- Database product and version (from the error message)
- Table names (`integration_credentials`)
- Framework version (from stack frame names)

```java
// VULNERABLE — SQL text and internals in error body
@GetMapping("/report")
public ResponseEntity<?> report(@RequestParam long id) {
    try {
        return ResponseEntity.ok(jdbcTemplate.queryForObject(
            "SELECT * FROM subscriptions WHERE id = " + id,  // also SQLi!
            Subscription.class
        ));
    } catch (Exception e) {
        // Returns: "column \"subscription_id\" does not exist"
        // Attacker learns column names from the error
        return ResponseEntity.status(500).body(Map.of("error", e.getMessage()));
    }
}

// VULNERABLE — validation errors echo stored state
@PostMapping("/register")
public ResponseEntity<?> register(@RequestBody RegisterRequest req) {
    try {
        validator.validate(req);
    } catch (ValidationException e) {
        // Returns: "Field 'email' value 'alice@example.invalid' already exists in database"
        // This confirms the email is registered
        return ResponseEntity.status(400).body(Map.of("errors", e.getMessage()));
    }
}
```

**How to prevent:**
```java
// SAFE — one generic client-facing error
// application-prod.yml
server:
  error:
    include-stacktrace: never
    include-message: never
    include-binding-errors: never

// Global exception handler
@RestControllerAdvice
public class SafeApiExceptionHandler {
    
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handle(Exception e) {
        String incidentId = generateIncidentId();  // unique per error
        log.error("Error [{}]: {}", incidentId, e.getMessage(), e);  // full details in log
        return ResponseEntity.of(ProblemDetail.forStatusAndDetail(
            HttpStatus.INTERNAL_SERVER_ERROR,
            "An internal error occurred. Reference: " + incidentId
        )).build();
    }
}
```
- `server.error.include-stacktrace=never` is the baseline configuration.
- Every exception should return a stable problem detail (RFC 7807) with an incident ID.
- The incident ID lets the caller look up details separately (support ticket, log store).

---

## CWE-200 — Information Exposure (SQL Internals / Runtime Topology Disclosure)

**Why it matters:** Beyond error messages, any endpoint that returns internal system information — database types, table schemas, runtime environment, topology, build metadata — gives attackers a blueprint of the application. This is reconnaissance data that accelerates every subsequent attack phase.

**Attack vector in Spring:**
```java
// VULNERABLE — SQL error reveals database internals
@GetMapping("/report")
public ResponseEntity<?> report(@RequestParam long id) {
    try {
        jdbcTemplate.queryForObject("SELECT * FROM subscriptions WHERE id = " + id, Subscription.class);
    } catch (Exception e) {
        // Returns PostgreSQL-specific error: "column \"subscription_id\" does not exist"
        // Attacker learns: PostgreSQL, column names, table structure
        return ResponseEntity.status(500).body(Map.of("error", e.getMessage()));
    }
}

// VULNERABLE — runtime and topology disclosure
@GetMapping("/debug/info")
public ResponseEntity<?> debugInfo() {
    Map<String, Object> info = new HashMap<>();
    info.put("javaVersion", System.getProperty("java.version"));
    info.put("springBootVersion", SpringBootVersion.getVersion());
    info.put("hostname", InetAddress.getLocalHost().getHostName());
    info.put("processId", ProcessHandle.current().pid());
    info.put("activeProfiles", Arrays.toString(environment.getActiveProfiles()));
    info.put("availableProcessors", Runtime.getRuntime().availableProcessors());
    // Returns a full map of the runtime environment
    return ResponseEntity.ok(info);
}
```
`GET /vuln9/debug/info` returns the Java version, Spring Boot version, hostname, process ID, active profiles, and CPU count. Combined with stack traces from CWE-209, this is a complete reconnaissance report.

**How to prevent:**
- Never expose runtime internals to API callers.
- Remove debug endpoints from production entirely.
- Actuator endpoints should be on a separate management port with authentication (see m12).
- Error responses should contain only a generic message and an incident ID.

---

## CWE-204 — Observable Response Discrepancy (User Enumeration)

**Why it matters:** When an application returns different responses (both in message content and response timing) for "user not found" vs "wrong password", an attacker can enumerate valid usernames. This turns a login endpoint into a user directory, enabling targeted attacks (credential stuffing, social engineering, phishing) against real accounts.

**Attack vector in Spring:**
```java
// VULNERABLE — different messages and timing for different failures
@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginRequest req) {
    User user = userRepository.findByUsername(req.getUsername());
    if (user == null) {
        // Different message: "User not found"
        // Different timing: no bcrypt call → faster response
        return ResponseEntity.status(401).body(Map.of("error", "User not found"));
    }
    if (!passwordEncoder.matches(req.getPassword(), user.getPassword())) {
        // Different message: "Wrong password"
        // Different timing: bcrypt call → slower response
        return ResponseEntity.status(401).body(Map.of("error", "Wrong password"));
    }
    return ResponseEntity.ok(Map.of("token", generateToken(user)));
}
```
`POST /vuln9/login` with `{"username":"alice","password":"x"}` returns "Wrong password" (alice exists).
`POST /vuln9/login` with `{"username":"nobody","password":"x"}` returns "User not found" (nobody doesn't exist).
Response timing differs too — bcrypt on existing user takes ~100ms, no bcrypt on non-existing user takes ~1ms.

**How to prevent:**
```java
// SAFE — same body, same work for all failures
@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginRequest req) {
    User user = userRepository.findByUsername(req.getUsername());
    
    // Always run the password hasher to equalize timing
    String dummyHash = passwordEncoder().encode("dummy");
    String actualHash = user != null ? user.getPassword() : dummyHash;
    boolean valid = passwordEncoder().matches(req.getPassword(), actualHash);
    
    // Always return the same response
    if (!valid) {
        return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
    }
    return ResponseEntity.ok(Map.of("token", generateToken(user)));
}
```
- Same HTTP status (401) for all login failures.
- Same response body: "Invalid credentials".
- Same timing: always run the password hasher, even for non-existent users.

---

## CWE-208 — Observable Timing Discrepancy (Login Timing)

**Why it matters:** CWE-208 in the context of authentication refers to response timing differences that leak information about internal state. A bcrypt hash takes ~100ms; a non-existent user triggers no hash call and returns in ~1ms. An attacker can measure response times to determine whether a username exists, even if error messages are identical.

**Attack vector in Spring:**
```java
// VULNERABLE — timing differs between "user not found" and "wrong password"
if (user == null) {
    return ResponseEntity.status(401).body("Invalid credentials");  // ~1ms
}
if (!passwordEncoder.matches(req.getPassword(), user.getPassword())) {
    return ResponseEntity.status(401).body("Invalid credentials");  // ~100ms
}
// Same message, but timing reveals whether the user exists
```
An attacker sends 1,000 requests per username and measures average response time. If the average is ~100ms, the user exists. If ~1ms, the user does not exist.

**How to prevent:**
```java
// SAFE — always run the hasher
String dummyHash = passwordEncoder().encode("dummy");
String actualHash = user != null ? user.getPassword() : dummyHash;
boolean valid = passwordEncoder().matches(req.getPassword(), actualHash);
```
- Always execute the password hasher, even for non-existent users.
- The dummy hash has the same cost factor as a real hash, so timing is identical.

---

## CWE-532 — Information Exposure Through Log Files

**Why it matters:** Writing PII (card numbers, emails, government IDs) or authentication tokens to application logs turns every log consumer into a secret store. Log pipelines (ELK, Datadog, Splunk) have weaker access controls than databases, retention policies rarely match data-protection requirements, and CI/CD logs are often publicly accessible.

**Attack vector in Spring:**
```java
// VULNERABLE — PII and tokens written to logs
@PostMapping("/audit/checkout")
public ResponseEntity<?> checkout(@RequestBody CheckoutRequest req) {
    log.info("Checkout: cardNumber={}, email={}, token={}", 
        req.getCardNumber(), req.getEmail(), req.getToken());
    // Log output: "Checkout: cardNumber=4111111111111111, email=alice@example.invalid, token=demo-token"
    // This appears in: application.log, ELK, Datadog, CI artifacts, log backups
    return ResponseEntity.ok("processed");
}
```
`grep 4111111111111111 logs/m09-logging-errors.log` finds the full card number in the log file. The same card number is now in every log aggregator, backup, and CI artifact.

**How to prevent:**
```java
// SAFE — mask before logging
@PostMapping("/audit/checkout")
public ResponseEntity<?> checkout(@RequestBody CheckoutRequest req) {
    log.info("Checkout: cardNumber={}, email={}, token={}",
        maskPan(req.getCardNumber()),    // "4111****1111"
        maskEmail(req.getEmail()),        // "a***e@example.invalid"
        maskToken(req.getToken()));       // "dem****ken"
    return ResponseEntity.ok("processed");
}

private String maskPan(String pan) {
    if (pan == null || pan.length() < 8) return "****";
    return pan.substring(0, 4) + "****" + pan.substring(pan.length() - 4);
}

private String maskEmail(String email) {
    int at = email.indexOf('@');
    if (at < 2) return "***@***";
    return email.charAt(0) + "***" + email.substring(at - 1);
}
```
- Use structured JSON logging with field-level redaction filters.
- Implement a `SecretHandle` class that never reveals material in `toString()`.
- Mask PII at the log encoder level, not per-call.
- Short retention for high-detail logs, strict read access, encryption at rest.

---

## CWE-117 — Improper Neutralization of Log Injection Characters (CRLF Injection)

**Why it matters:** When user input containing CR (`\r`) or LF (`\n`) characters is written to logs without sanitization, an attacker can forge log entries. In structured JSON logging, a newline breaks the JSON structure, allowing the attacker to inject arbitrary JSON fields that can hide attacks, create false audit trails, or poison log aggregation systems.

**Attack vector in Spring:**
```java
// VULNERABLE — user input written to log without sanitization
@PostMapping("/audit/message")
public ResponseEntity<?> logMessage(@RequestParam String message) {
    log.info("User message: {}", message);
    // Attacker sends: message=%0d%0a{"level":"INFO","user":"admin","action":"login"}
    // This forges a log entry that looks like an admin login
    return ResponseEntity.ok("logged");
}
```
Payload: `message=\r\n{"level":"INFO","user":"admin","action":"login"}` — injects a fake JSON log entry that looks like an admin action.

**How to prevent:**
```java
// SAFE — sanitize before logging
@PostMapping("/audit/message")
public ResponseEntity<?> logMessage(@RequestParam String message) {
    String sanitized = message.replaceAll("[\\r\\n\\x00]", "");
    log.info("User message: {}", sanitized);
    return ResponseEntity.ok("logged");
}
```
- Strip CR, LF, and NUL from all log input.
- Use structured JSON logging (Logback JSON encoder) which escapes special characters automatically.
- Implement a `CorrelationIdFilter` that sanitizes correlation IDs for log use.

---

## CWE-778 — Insufficient Logging of Security Events

**Why it matters:** Without logging security events (logins, authz decisions, token rejections, password changes), security incidents go undetected. An attacker can operate undetected for months. When logging exists but is incomplete, the investigation timeline has gaps that make forensics impossible and compliance audits fail.

**Attack vector in Spring:**
```java
// VULNERABLE — no security events recorded
@GetMapping("/audit/trail")
public ResponseEntity<?> auditTrail() {
    // Returns: {"message": "nothing is recorded"}
    // No login events, no authz decisions, no password changes
    // An attacker can brute-force, exfiltrate data, and change passwords
    // with zero audit trail
    return ResponseEntity.ok(Map.of("events", List.of()));
}
```
`GET /vuln9/audit/trail` returns nothing. There is no record of who logged in, who was denied access, or what changes were made.

**How to prevent:**
```java
// SAFE — log security events with masked subjects
@Component
public class SecurityEventLogger {
    
    public void logLoginOk(String maskedUsername, String correlationId) {
        log.info("login_ok: actor={}, correlationId={}", maskedUsername, correlationId);
    }
    
    public void logLoginFailed(String maskedUsername, String reason, String correlationId) {
        log.info("login_failed: actor={}, reason={}, correlationId={}", 
            maskedUsername, reason, correlationId);
    }
    
    public void logLoginThrottled(String maskedUsername, String correlationId) {
        log.info("login_throttled: actor={}, correlationId={}", maskedUsername, correlationId);
    }
    
    public void logAuthzDenied(String maskedActor, String resource, String correlationId) {
        log.info("authz_denied: actor={}, resource={}, correlationId={}", 
            maskedActor, resource, correlationId);
    }
    
    public void logPasswordChanged(String maskedActor, String correlationId) {
        log.info("password_changed: actor={}, correlationId={}", maskedActor, correlationId);
    }
    
    public void logTokenRejected(String reason, String correlationId) {
        log.info("token_rejected: reason={}, correlationId={}", reason, correlationId);
    }
}
```
- Log: `login_ok`, `login_failed`, `login_throttled`, `authz_denied`, `token_rejected`, `password_changed`, `config_changed`.
- Include: masked actor, resource, outcome, correlation ID.
- Alert on: failure spikes, denial spikes, unusual export volumes, authentication from new regions.

---

## CWE-778 — No Correlation ID (Insufficient Operational Visibility)

**Why it matters:** Without a correlation ID, there is no way to trace a single request across multiple services, log files, and monitoring systems. When an incident occurs, investigators cannot reconstruct the timeline. A correlation ID links the HTTP response, application logs, security events, and distributed traces into a single searchable entity.

**Attack vector in Spring:**
```java
// VULNERABLE — no correlation ID
// When a user reports "something went wrong at 14:32",
// there is no way to find the relevant log entries across
// multiple services and log files
```

**How to prevent:**
```java
// SAFE — CorrelationIdFilter
@Component
public class CorrelationIdFilter implements Filter {
    
    private static final String HEADER = "X-Correlation-Id";
    
    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) 
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        String correlationId = request.getHeader(HEADER);
        if (correlationId == null || correlationId.isBlank()) {
            correlationId = UUID.randomUUID().toString();
        }
        
        // Put in MDC for all log entries
        MDC.put("correlationId", correlationId);
        
        HttpServletResponse response = (HttpServletResponse) res;
        response.setHeader(HEADER, correlationId);
        
        try {
            chain.doFilter(req, res);
        } finally {
            MDC.remove("correlationId");
        }
    }
}
```
- Generate a correlation ID if the client does not send one.
- Put it in the MDC so every log entry includes it.
- Return it in the `X-Correlation-Id` response header.
- Carry it into the incident ID of a 500 error.
