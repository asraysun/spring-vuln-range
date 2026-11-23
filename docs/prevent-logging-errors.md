# Spring Security: How to Prevent Logging, Error Handling & Security Event Vulnerabilities

A practical guide to securing Spring Boot's error responses, logging practices, user enumeration prevention, and audit trails — covering 6 CWEs found in real Spring applications.

---

## Table of Contents

1. [Error Response Sanitization](#1-error-response-sanitization)
2. [Runtime Topology Protection](#2-runtime-topology-protection)
3. [User Enumeration Prevention](#3-user-enumeration-prevention)
4. [Log File Security](#4-log-file-security)
5. [Log Injection / CRLF Prevention](#5-log-injection--crlf-prevention)
6. [Security Event Logging & Correlation](#6-security-event-logging--correlation)

---

## 1. Error Response Sanitization

**CWE-209** — *Information Exposure Through Error Messages*

### The Problem

Detailed error responses (stack traces, SQL errors, framework internals) reveal the technology stack, database schema, query structure, and internal architecture. This information is a force multiplier for every other attack: it helps attackers craft targeted exploits, understand the data model, and identify the next attack surface.

```java
// ❌ VULNERABLE — stack trace returned in HTTP response
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
// ❌ VULNERABLE — SQL text and internals in error body
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

// ❌ VULNERABLE — validation errors echo stored state
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

### The Fix

Return one generic client-facing error with an incident ID for reference.

```java
// ✅ SAFE — baseline configuration
// application-prod.yml
server:
  error:
    include-stacktrace: never
    include-message: never
    include-binding-errors: never

// ✅ SAFE — global exception handler returning RFC 7807 Problem Details
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

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ProblemDetail> handleAccessDenied(AccessDeniedException e) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
            HttpStatus.FORBIDDEN,
            "Access denied"
        );
        return ResponseEntity.status(403).body(problem);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ProblemDetail> handleValidation(MethodArgumentNotValidException e) {
        List<FieldError> errors = e.getBindingResult().getFieldErrors().stream()
            .map(fe -> new FieldErrorDetail(fe.getField(), fe.getDefaultMessage()))
            .toList();

        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
            HttpStatus.BAD_REQUEST,
            "Request validation failed"
        );
        problem.setProperty("errors", errors);
        return ResponseEntity.badRequest().body(problem);
    }
}

private String generateIncidentId() {
    return UUID.randomUUID().toString();
}
```

**Key rules:**
- Set `server.error.include-stacktrace: never`, `include-message: never`, and `include-binding-errors: never` in production
- Use a global `@RestControllerAdvice` to map exceptions to stable Problem Details (RFC 7807)
- Include an incident ID in the response so the caller can look up details separately
- **Never return `e.getMessage()`** from database operations or security failures to the caller
- Log the full exception (message + stack trace) server-side with the incident ID for debugging

---

## 2. Runtime Topology Protection

**CWE-200** — *Information Exposure (SQL Internals / Runtime Topology Disclosure)*

### The Problem

Beyond error messages, any endpoint that returns internal system information — database types, table schemas, runtime environment, topology, build metadata — gives attackers a blueprint of the application. This is reconnaissance data that accelerates every subsequent attack phase.

```java
// ❌ VULNERABLE — runtime and topology disclosure
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

### The Fix

Never expose runtime internals to API callers. Remove debug endpoints entirely from production.

```java
// ✅ SAFE — no debug endpoints in production
// Simply do not implement endpoints like /debug/info, /env-dump, /heap-dump
// Actuator endpoints should be on a separate management port with authentication

// application.yml
management:
  server:
    port: 8099  # Separate management port
  endpoints:
    web:
      exposure:
        include: health, info  # Minimal exposure
  endpoint:
    health:
      show-details: when-authorized  # Require auth for details
```

**Key rules:**
- **Never expose runtime internals** to public API callers
- Remove debug endpoints (`/debug/info`, `/env-dump`, `/heap-dump`) from production entirely
- Actuator endpoints should be on a **separate management port** with authentication (see module m12)
- If an endpoint must be public, it should only report boolean presence flags (e.g., "dbConfigured: true")

---

## 3. User Enumeration Prevention

**CWE-204** — *Observable Response Discrepancy*  
**CWE-208** — *Observable Timing Discrepancy (Login Timing)*

### The Problem

When an application returns different responses (both in message content and response timing) for "user not found" vs "wrong password", an attacker can enumerate valid usernames. This turns a login endpoint into a user directory, enabling targeted attacks (credential stuffing, social engineering, phishing) against real accounts.

```java
// ❌ VULNERABLE — different messages and timing for different failures
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

### The Fix

Return the **same body**, use the **same work** (hashing), and return the **same status** for all login failures.

```java
// ✅ SAFE — same body, same work for all failures
@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginRequest req) {
    User user = userRepository.findByUsername(req.getUsername());

    // Always run the password hasher to equalize timing
    String dummyHash = passwordEncoder().encode("dummy");
    String actualHash = user != null ? user.getPassword() : dummyHash;
    boolean valid = passwordEncoder().matches(req.getPassword(), actualHash);

    // Always return the same response regardless of whether the user exists
    if (!valid) {
        return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
    }
    return ResponseEntity.ok(Map.of("token", generateToken(user)));
}
```

**Key rules:**
- **Same HTTP status** (401) for all login failures
- **Same response body**: "Invalid credentials" (or similar generic message)
- **Same timing**: always run the password hasher, even for non-existent users
- The dummy hash has the same cost factor as a real hash, so timing is identical
- Apply the same logic to "email not found" vs "wrong password" on password reset flows

---

## 4. Log File Security

**CWE-532** — *Information Exposure Through Log Files*

### The Problem

Writing PII (card numbers, emails, government IDs) or authentication tokens to application logs turns every log consumer into a secret store. Log pipelines (ELK, Datadog, Splunk) have weaker access controls than databases, retention policies rarely match data-protection requirements, and CI/CD logs are often publicly accessible.

```java
// ❌ VULNERABLE — PII and tokens written to logs
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

### The Fix

Mask sensitive data before writing to logs. Use structured JSON logging with field-level redaction.

```java
// ✅ SAFE — mask before logging
@PostMapping("/audit/checkout")
public ResponseEntity<?> checkout(@RequestBody CheckoutRequest req) {
    log.info("Checkout: cardNumber={}, email={}, token={}",
        maskPan(req.getCardNumber()),    // "4111****1111"
        maskEmail(req.getEmail()),        // "a***e@example.invalid"
        maskToken(req.getToken()));       // "dem****ken"
    return ResponseEntity.ok("processed");
}

// Masking utilities
private String maskPan(String pan) {
    if (pan == null || pan.length() < 8) return "****";
    return pan.substring(0, 4) + "****" + pan.substring(pan.length() - 4);
}

private String maskEmail(String email) {
    int at = email.indexOf('@');
    if (at < 2) return "***@***";
    return email.charAt(0) + "***" + email.substring(at - 1);
}

private String maskToken(String token) {
    if (token == null || token.length() <= 4) return "****";
    return token.substring(0, 3) + "****" + token.substring(token.length() - 1);
}

// ✅ SAFE — use SecretHandle for classes containing sensitive data
public final class SecretHandle implements Closeable {
    private final char[] value;

    @Override
    public String toString() {
        if (value == null || value.length == 0) return "[Secret: empty]";
        return "[Secret length=" + value.length + " first=" + value[0] + " last=" + value[value.length - 1] + "]";
    }

    @Override
    public void close() {
        Arrays.fill(value, '\0');  // zero out
        value[0] = '\0';  // null out
    }
}

// Usage
public class CheckoutRequest {
    private SecretHandle cardNumber;  // toString() is safe to log
    private String email;
    private SecretHandle token;       // toString() is safe to log
}
```

**Key rules:**
- **Never log PII or secrets in cleartext** — use masking utilities (`maskPan`, `maskEmail`, `maskToken`)
- Use structured JSON logging with field-level redaction filters
- Implement a `SecretHandle` class that never reveals material in `toString()`
- Mask at the log encoder level if possible, not per-call
- Short retention for high-detail logs, strict read access, encryption at rest
- Audit log pipelines quarterly for credential patterns

---

## 5. Log Injection / CRLF Prevention

**CWE-117** — *Improper Neutralization of Log Injection Characters*

### The Problem

When user input containing CR (`\r`) or LF (`\n`) characters is written to logs without sanitization, an attacker can forge log entries. In structured JSON logging, a newline breaks the JSON structure, allowing the attacker to inject arbitrary JSON fields that can hide attacks, create false audit trails, or poison log aggregation systems.

```java
// ❌ VULNERABLE — user input written to log without sanitization
@PostMapping("/audit/message")
public ResponseEntity<?> logMessage(@RequestParam String message) {
    log.info("User message: {}", message);
    // Attacker sends: message=%0d%0a{"level":"INFO","user":"admin","action":"login"}
    // This forges a log entry that looks like an admin login
    return ResponseEntity.ok("logged");
}
```

Payload: `message=\r\n{"level":"INFO","user":"admin","action":"login"}` — injects a fake JSON log entry that looks like an admin action.

### The Fix

Strip CR, LF, and NUL from all log input. Use structured JSON logging which escapes special characters automatically.

```java
// ✅ SAFE — sanitize before logging
@PostMapping("/audit/message")
public ResponseEntity<?> logMessage(@RequestParam String message) {
    String sanitized = message.replaceAll("[\\r\\n\\x00]", "");
    log.info("User message: {}", sanitized);
    return ResponseEntity.ok("logged");
}

// ✅ SAFE — reusable sanitization utility
public final class LogSanitizer {
    private LogSanitizer() {}

    public static String sanitize(String input) {
        if (input == null) return null;
        return input.replace("\r", "").replace("\n", "").replace("\u0000", "");
    }
}

// ✅ SAFE — structured JSON logging (Logback JSON encoder)
// logback-spring.xml
// <configuration>
//     <appender name="JSON" class="ch.qos.logback.core.ConsoleAppender">
//         <encoder class="net.logstash.logback.encoder.LogstashEncoder">
//             <!-- Automatically escapes special characters -->
//         </encoder>
//     </appender>
// </configuration>
```

**Key rules:**
- **Strip CR/LF/NUL** from any user input before writing to logs
- Use **structured JSON logging** (Logstash encoder) which automatically escapes special characters
- Add a `CorrelationIdFilter` that sanitizes correlation IDs for log use
- Bound log message length — truncate very long inputs before logging
- Audit log pipelines quarterly for broken JSON structures (a sign of log injection)

---

## 6. Security Event Logging & Correlation

**CWE-778** — *Insufficient Logging of Security Events*  
**CWE-778** — *No Correlation ID (Insufficient Operational Visibility)*

### The Problem

Without logging security events (logins, authz decisions, token rejections, password changes), security incidents go undetected. An attacker can operate undetected for months. When logging exists but is incomplete, the investigation timeline has gaps that make forensics impossible and compliance audits fail.

Additionally, without a correlation ID, there is no way to trace a single request across multiple services, log files, and monitoring systems.

```java
// ❌ VULNERABLE — no security events recorded
@GetMapping("/audit/trail")
public ResponseEntity<?> auditTrail() {
    // Returns: {"message": "nothing is recorded"}
    // No login events, no authz decisions, no password changes
    // An attacker can brute-force, exfiltrate data, and change passwords
    // with zero audit trail
    return ResponseEntity.ok(Map.of("events", List.of()));
}
```

### The Fix

Log security events with masked subjects and correlation IDs. Implement a `CorrelationIdFilter`.

```java
// ✅ SAFE — security event logger
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

// ✅ SAFE — CorrelationIdFilter
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

// ✅ SAFE — use MDC in log configuration
// logback-spring.xml
// <configuration>
//     <appender name="JSON" class="ch.qos.logback.core.ConsoleAppender">
//         <encoder class="net.logstash.logback.encoder.LogstashEncoder">
//             <customFields>{"correlationId":"%X{correlationId}"}</customFields>
//         </encoder>
//     </appender>
// </configuration>
```

**Required security events:**

| Event | When to log | Fields |
|-------|-------------|--------|
| `login_ok` | Successful authentication | masked actor, correlationId |
| `login_failed` | Failed authentication | masked actor, reason, correlationId |
| `login_throttled` | Rate limit exceeded | masked actor, correlationId |
| `authz_denied` | Access denied | masked actor, resource, correlationId |
| `token_rejected` | Invalid/expired token | reason, correlationId |
| `password_changed` | Password modification | masked actor, correlationId |
| `config_changed` | Security config change | actor, resource, correlationId |

**Key rules:**
- **Log every security event**: logins, authz decisions, token rejections, password changes
- **Include masked actor, resource, outcome, and correlation ID** in every security log entry
- **Alert on failure spikes, denial spikes, unusual export volumes, and authentication from new regions**
- **Generate a correlation ID** if the client does not send one
- **Put it in the MDC** so every log entry includes it
- **Return it in the `X-Correlation-Id`** response header
- **Carry it into the incident ID** of a 500 error
- Mask actors in logs — never log full PII (use `***` for sensitive parts)

---

## Summary Checklist

| # | Control | CWE | Priority |
|---|---------|-----|----------|
| 1 | `server.error.include-*: never` + `@RestControllerAdvice` | CWE-209 | CRITICAL |
| 2 | No debug endpoints, actuator on separate port | CWE-200 | HIGH |
| 3 | Same response + same timing for all login failures | CWE-204, CWE-208 | CRITICAL |
| 4 | Mask PII/secrets before logging | CWE-532 | CRITICAL |
| 5 | Strip CR/LF/NUL, structured JSON logging | CWE-117 | HIGH |
| 6 | Security event logging + CorrelationIdFilter | CWE-778 | HIGH |

---

## Detection & Review Heuristics

| Check | Command / Pattern |
|-------|-------------------|
| Verbose error responses | `grep -r 'include-stacktrace:\s*always\|include-message:\s*always'` → CI should fail |
| Returning e.getMessage() | `grep -r 'e.getMessage()'` → should not appear in HTTP responses |
| PII in logs | `grep -r 'log.info.*card\|log.info.*password\|log.info.*token'` → should mask |
| CRLF in logs | `grep -r 'log.info.*request\|log.info.*@RequestParam'` → should sanitize |
| Missing security events | Check for `SecurityEventLogger` or equivalent → should log login_ok/failed, authz_denied |
| Missing correlation ID | `grep -r 'MDC.put.*correlation' \| 'CorrelationIdFilter'` → should exist |

---

## References

- [OWASP Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [OWASP User Enumeration](https://cheatsheetseries.owasp.org/cheatsheets/User_Enumeration_Cheat_Sheet.html)
- [RFC 7807: Problem Details for HTTP APIs](https://datatracker.ietf.org/doc/html/rfc7807)
- [Spring Boot Error Handling](https://docs.spring.io/spring-boot/reference/features/error-handling.html)
- [SLF4J MDC (Mapped Diagnostic Context)](https://www.slf4j.org/api/org/slf4j/MDC.html)
