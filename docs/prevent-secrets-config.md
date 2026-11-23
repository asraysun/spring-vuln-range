# Spring Security: How to Prevent Secrets & Configuration Vulnerabilities

A practical guide to protecting credentials, managing configuration securely, and preventing secret leakage in Spring Boot applications — covering 8 CWEs found in real Spring applications.

---

## Table of Contents

1. [Never Return Secrets in API Responses](#1-never-return-secrets-in-api-responses)
2. [No Environment Variable Dumping](#2-no-environment-variable-dumping)
3. [Services Never Hand Out Their Own Credentials](#3-services-never-hand-out-their-own-credentials)
4. [Mask Before Logging](#4-mask-before-logging)
5. [Disable Dev Tooling in Production](#5-disable-dev-tooling-in-production)
6. [Per-Environment Credentials](#6-per-environment-credentials)
7. [Fail-Fast Instead of Silent Fallbacks](#7-fail-fast-instead-of-silent-fallbacks)
8. [Protect Secret Material in toString() and Serialization](#8-protect-secret-material-in-tostring-and-serialization)

---

## 1. Never Return Secrets in API Responses

**CWE-200** — *Information Exposure*

### The Problem

An endpoint that returns configuration details gives attackers a blueprint of the application's internals — database types, connection strings, feature flags, and worst of all, credentials. This accelerates every subsequent attack phase: target selection, gadget chain selection, and social engineering.

```java
// ❌ VULNERABLE — returns full configuration including credential-shaped values
@GetMapping("/config")
public ResponseEntity<?> getConfig() {
    Map<String, Object> config = new HashMap<>();
    config.put("dbHost", dbProperties.getHost());
    config.put("dbUser", dbProperties.getUsername());
    config.put("dbPassword", dbProperties.getPassword());  // credential in response!
    config.put("apiKey", externalServiceApiKey);
    config.put("featureFlags", featureFlagService.allFlags());
    return ResponseEntity.ok(config);
}
```

### The Fix

A service **uses** secrets; it may only report whether one is present.

```java
// ✅ SAFE — presence only, no values
@GetMapping("/config-summary")
public ResponseEntity<?> getConfigSummary() {
    return ResponseEntity.ok(Map.of(
        "dbConfigured", dbProperties.isConfigured(),
        "apiKeyPresent", !Strings.isNullOrEmpty(apiKey),
        "jwtSecretPresent", !Strings.isNullOrEmpty(jwtSecret),
        "credentialValuesReturned", 0
    ));
}

// ✅ SAFE — fingerprint-based verification
@GetMapping("/integration/status")
public ResponseEntity<?> integrationStatus() {
    return ResponseEntity.ok(Map.of(
        "service", "external-api",
        "configured", apiKey != null && !apiKey.isBlank(),
        "lastRotated", lastRotationDate,
        "credentialValuesReturned", 0
    ));
}
```

**Key rules:**
- Never return credential-shaped values in API responses
- If callers need to verify configuration, return boolean presence flags only
- Log and alert on any response field whose name matches credential patterns (`password`, `secret`, `token`, `api_key`)
- Add contract tests that assert `GET` responses never contain credential-named fields

---

## 2. No Environment Variable Dumping

**CWE-540** — *Information Exposure Through Environment Variables*  
**CWE-526** — *Information Exposure Through Environment Variables (Credential Exposure)*

### The Problem

Returning environment variables or `PropertySources` to API callers exposes every credential injected into the container. In containerized deployments, environment variables are the primary injection mechanism for secrets — compromising one endpoint compromises the entire deployment.

```java
// ❌ VULNERABLE — dumps all environment variables
@GetMapping("/config")
public ResponseEntity<?> getConfig(Environment env) {
    MutablePropertySources sources = ((ConfigurableEnvironment) env).getPropertySources();
    Map<String, Object> result = new LinkedHashMap<>();
    for (PropertySource<?> ps : sources) {
        if (ps instanceof MapPropertySource mps) {
            result.putAll(mps.getSource());  // includes DB_PASSWORD, API_KEY, etc.
        }
    }
    return ResponseEntity.ok(result);
}

// ❌ VULNERABLE — returns all system environment variables
@GetMapping("/env-dump")
public ResponseEntity<?> envDump() {
    Map<String, String> env = System.getenv();
    // Includes: DB_PASSWORD, API_KEY, JWT_SECRET, AWS_SECRET_KEY, etc.
    return ResponseEntity.ok(env);
}
```

### The Fix

Never expose `Environment` or `PropertySources` to API callers. Disable actuator env endpoint in production.

```java
// ✅ SAFE — config summary with presence flags only
@GetMapping("/config-summary")
public ResponseEntity<?> summary() {
    return ResponseEntity.ok(Map.of(
        "dbPasswordPresent", !Strings.isNullOrEmpty(System.getenv("DB_PASSWORD")),
        "apiKeyPresent", !Strings.isNullOrEmpty(System.getenv("API_KEY")),
        "credentialValuesReturned", 0
    ));
}

// ✅ SAFE — application.yml: disable actuator env
management:
  endpoint:
    env:
      enabled: false      # or true for dev only
      show-values: never  # NEVER in production
    health:
      show-details: when-authorized

// ✅ SAFE — error configuration
server:
  error:
    include-exception: never
    include-message: never
    include-stacktrace: never
```

**Key rules:**
- Never expose `System.getenv()` or `System.getProperties()` to API callers
- Set `management.endpoint.env.enabled: false` in production profiles
- Set `management.endpoint.env.show-values: never` if the endpoint must stay enabled
- Never expose `/actuator/env` on any public-facing port (see CWE-1188, actuator misconfig)
- Use `server.error.include-*: never` to prevent stack traces and messages in production errors

---

## 3. Services Never Hand Out Their Own Credentials

**CWE-522** — *Insufficiently Protected Credentials*

### The Problem

A service that hands out its own credentials to callers turns every authenticated user into a proxy for that service. The attacker can then use those credentials to interact with the downstream service at full privilege, bypassing all audit controls and rate limits.

```java
// ❌ VULNERABLE — returns the service's own API token
@GetMapping("/integration/token")
public ResponseEntity<?> getIntegrationToken() {
    return ResponseEntity.ok(Map.of(
        "token", integrationApiKey,  // the service's own credential
        "endpoint", externalServiceUrl
    ));
}
// Any caller can then use this key to interact with the external service as the app
```

### The Fix

A service uses credentials; it never returns them. If a downstream call is needed, make the call server-side and return only the result.

```java
// ✅ SAFE — signs a request, returns fingerprint
@PostMapping("/integration/call")
@PreAuthorize("hasRole('SERVICE_INTEGRATION')")
public ResponseEntity<?> callIntegration(@Valid @RequestBody IntegrationRequest req) {
    String signature = hmacSha256(integrationSecret, req.toPayload());
    String result = externalServiceClient.call(signature, req.toPayload());
    
    return ResponseEntity.ok(Map.of(
        "requestId", req.getRequestId(),
        "resultFingerprint", sha256(result).substring(0, 16),
        "credentialValuesReturned", 0
    ));
}

// ✅ SAFE — if the caller needs to verify, use a short-lived signed ticket
@PostMapping("/integration/ticket")
public ResponseEntity<?> createTicket() {
    String ticketId = UUID.randomUUID().toString();
    String signedTicket = Jwts.builder()
        .setSubject(ticketId)
        .setIssuedAt(new Date())
        .setExpiration(new Date(System.currentTimeMillis() + 5 * 60 * 1000))  // 5 min
        .signWith(jwtKey, SignatureAlgorithm.HS256)
        .compact();
    
    ticketStore.store(ticketId, SignedTicket.Status.VALID);
    return ResponseEntity.ok(Map.of("ticket", signedTicket));
}
```

**Key rules:**
- A service **uses** credentials; it never **returns** them
- If a downstream call is needed, make the call server-side and return only the result
- Return fingerprints or request IDs for verification, never the credential itself
- Restrict integration endpoints with explicit role-based access
- Rotate credentials immediately if they are ever leaked through an endpoint

---

## 4. Mask Before Logging

**CWE-532** — *Information Exposure Through Log Files*

### The Problem

Writing credentials, tokens, or PII to application logs turns every log consumer (ELK stack, Datadog, Splunk, CI artifacts, CI/CD logs) into a secret store. Log retention policies rarely match data-protection requirements, and log access controls are often far weaker than database access controls.

```java
// ❌ VULNERABLE — logs the password in cleartext
@PostMapping("/integration/check")
public ResponseEntity<?> check(@RequestBody ConnectionRequest req) {
    log.info("Connecting with user={} password={}", req.getUser(), req.getPassword());
    // "Connecting with user=espd_app password=MY-MARKER" appears in the log pipeline
    // grep MY-MARKER logs/m03-secrets-config.log → instant breach
}
```

### The Fix

Never log credential-shaped fields. Mask before logging.

```java
// ✅ SAFE — masked output
@PostMapping("/integration/check")
public ResponseEntity<?> check(@Valid @RequestBody ConnectionRequest req) {
    log.info("Connecting with user={} password={}", req.getUser(), mask(req.getPassword()));
    // "Connecting with user=espd_app password=***"
    return ResponseEntity.ok("connected");
}

// ✅ SAFE — reusable masking utilities
public final class LogMasker {
    private LogMasker() {}

    public static String mask(String s) {
        if (s == null || s.isBlank()) return "***";
        if (s.length() <= 2) return "***";
        return s.charAt(0) + "***" + s.charAt(s.length() - 1);
    }

    public static String maskFull(String s) {
        if (s == null || s.isBlank()) return "***";
        return "***";  // or maskFull -> "********"
    }

    public static String maskToken(String token) {
        if (token == null || token.length() < 16) return "***";
        return token.substring(0, 8) + "..." + token.substring(token.length() - 4);
    }
}

// Usage
log.info("Auth user={} token={}", username, LogMasker.maskToken(authToken));
// "Auth user=admin token=abcd1234...5678"
```

**Structured logging with field-level redaction:**

```java
// ✅ SAFE — JSON logging with custom redaction
@Bean
public Converter<String, String> secretMaskingConverter() {
    return new Converter<String, String>() {
        @Override
        public String convert(String value) {
            return LogMasker.mask(value);
        }
    };
}

// ✅ SAFE — Logback pattern with redacted MDC
// logback-spring.xml
<configuration>
    <conversionRule conversionWord="secret" converterClass="com.app.LogMaskConverter"/>
    <appender name="JSON" class="ch.qos.logback.core.ConsoleAppender">
        <encoder class="ch.qos.logback.classic.encoder.JSONEncoder">
            <customFields>{"maskFields":["password","token","secret","apiKey"]}</customFields>
        </encoder>
    </appender>
</configuration>
```

**Key rules:**
- Never log credential-shaped fields in cleartext
- Use masking utilities consistently — create shared utilities, don't inline
- Add MDC fields carefully — they appear in every log line and all log aggregators
- Implement a secret-aware `Converter` for structured JSON logging
- Audit log pipelines quarterly for credential patterns

---

## 5. Disable Dev Tooling in Production

**CWE-489** — *Active Debug Program in Production*

### The Problem

Development tooling left in production configurations creates unrestricted access to internal systems. The H2 console, for example, provides a full SQL IDE against the production database — any anonymous caller can execute arbitrary queries.

```yaml
# ❌ VULNERABLE — H2 console enabled in production
spring:
  h2:
    console:
      enabled: true   # accessible at /h2-console, anonymous, full SQL access
```

```java
// ❌ VULNERABLE — debug endpoint in production
@PostMapping("/diagnostics")
public ResponseEntity<?> diagnostics() {
    // Full thread dump, heap info, DB connections — all anonymous
    return ResponseEntity.ok(threadMXBean.getThreadInfo(-1, true));
}
```

### The Fix

Disable all dev tooling in production profiles. Never include dev dependencies in the runtime image.

```yaml
# ✅ SAFE — application-prod.yml
spring:
  h2:
    console:
      enabled: false
  # devtools not in the production dependency tree

# ✅ SAFE — application-local.yml (dev only)
spring:
  h2:
    console:
      enabled: true
  # devtools in the local dependency scope only

# ✅ SAFE — explicit profile assertion at startup
@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        String activeProfile = Arrays.asList(args)
            .stream()
            .filter(a -> a.startsWith("--spring.profiles.active="))
            .map(a -> a.split("=")[1])
            .findFirst()
            .orElse("local");
        
        if ("prod".equals(activeProfile)) {
            assertProdHardening();
        }
        SpringApplication.run(Application.class, args);
    }

    static void assertProdHardening() {
        // Verify dev tooling is disabled
        assert !Boolean.parseBoolean(System.getenv("H2_CONSOLE_ENABLED"));
        assert !Thread.currentThread().getStackTrace()[1].getClassName().contains("DevTools");
    }
}
```

**Dependency scoping:**

```xml
<!-- ❌ VULNERABLE — devtools in default scope -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-devtools</artifactId>
</dependency>

<!-- ✅ SAFE — devtools only in dev scope -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-devtools</artifactId>
    <scope>development</scope>
    <optional>true</optional>
</dependency>
```

**Key rules:**
- Disable H2 console, actuator debug endpoints, and all dev tooling in production profiles
- Never include `spring-boot-devtools` in the production runtime image
- Scope dev dependencies with `<scope>development</scope>` and `<optional>true</optional>`
- Assert production hardening at startup — fail if dev tooling is detected
- Use separate Docker images for dev and prod (no conditional logic in prod images)

---

## 6. Per-Environment Credentials

**CWE-522** — *Insufficiently Protected Credentials (Single Credential Across Environments)*

### The Problem

Using the same credential for development, integration testing, and production means a compromise in any lower environment cascades to production. A developer's local log, a CI/CD artifact, or a test environment breach gives the attacker production credentials.

```yaml
# ❌ VULNERABLE — same secret for dev, integration, and production
app:
  db-password: "super-secret-123"  # committed to repo, same everywhere
  api-key: "AKIAIOSFODNN7EXAMPLE"  # same in all environments
```

### The Fix

One credential per environment, per service, with least privilege.

```yaml
# ✅ SAFE — per-environment files, values from env vars only
# application-dev.yml
spring:
  datasource:
    password: ${DEV_DB_PASSWORD}

# application-ift.yml (integration test framework)
spring:
  datasource:
    password: ${IFT_DB_PASSWORD}

# application-prod.yml — no defaults, fail if missing
spring:
  datasource:
    password: ${PROD_DB_PASSWORD}
```

```java
// ✅ SAFE — resolve from Vault, env, or secret file
@Component
class SecretResolver {
    private final ConfigurableEnvironment env;

    SecretResolver(ConfigurableEnvironment env) {
        this.env = env;
    }

    String resolve(String envName, String key) {
        String envVar = envName + "_" + key;
        String value = System.getenv(envVar);
        
        if (value == null || value.isBlank()) {
            value = env.getProperty(key);
        }
        
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Secret not found: " + envVar + 
                " (checked env var and spring property)");
        }
        
        return value;
    }
}

// Usage
@PostConstruct
void init() {
    this.dbPassword = secretResolver.resolve(
        "prod", "datasource.password"
    );
}
```

**Key rules:**
- **One credential per environment** — dev, ift, staging, prod must never share
- **One credential per service** — auth DB, user DB, cache, message queue each get unique credentials
- Use **least privilege** — the prod DB user gets no DDL, integration tokens get one scope
- Inject via environment variables or secret manager — never commit to repository
- Use Vault, AWS Secrets Manager, or Azure Key Vault for runtime injection

---

## 7. Fail-Fast Instead of Silent Fallbacks

**CWE-1188** — *Insecure Default Configuration / Hardcoded Fallback*

### The Problem

A compiled-in default value used as a "silent fallback" when an environment variable is missing means that a shared development credential becomes the production credential. This is one of the most insidious secret leaks — the application starts, appears to work, and nobody notices that production is using a default from source control.

```java
// ❌ VULNERABLE — fallback to a hardcoded default
@Value("${db.password:postgres}")  // if env var missing, uses "postgres"
private String password;

// Or with Spring property syntax:
@Value("${db.password:${DEFAULT_DB_PASSWORD:postgres}}")
private String password;
// If the env var is not injected, the app silently uses "postgres" in production
```

### The Fix

Fail fast at startup if a required secret is missing.

```java
// ✅ SAFE — throws if env var is missing, no fallback
@Value("${VAULT_DB_PASSWORD}")
private String password;

@PostConstruct
void validate() {
    if (Strings.isNullOrEmpty(password)) {
        throw new IllegalStateException("VAULT_DB_PASSWORD is required but not set");
    }
}

// ✅ SAFE — custom SecretProvider that throws on missing
@Component
class VaultFileSecretProvider {
    private final Path secretDir;

    VaultFileSecretProvider(@Value("${secrets.dir}") Path secretDir) {
        this.secretDir = secretDir;
    }

    String resolve(String name) {
        Path file = secretDir.resolve(name);
        try {
            String value = Files.readString(file).strip();
            if (value.isBlank()) {
                throw new IllegalStateException("Secret file is empty: " + file);
            }
            return value;
        } catch (IOException e) {
            throw new IllegalStateException("Secret not found: " + file + " (" + e.getMessage() + ")");
        }
    }
}

// Usage
@PostConstruct
void init() {
    this.dbPassword = secretProvider.resolve("db-password");
    this.apiKey = secretProvider.resolve("api-key");
}
```

**Startup validation with `@EventListener`:**

```java
// ✅ SAFE — comprehensive startup validation
@Component
class SecretValidationListener {
    private final ConfigurableEnvironment env;

    SecretValidationListener(ConfigurableEnvironment env) {
        this.env = env;
    }

    @EventListener(ApplicationStartedEvent.class)
    void validateSecrets() {
        List<String> missing = List.of(
            "VAULT_DB_PASSWORD",
            "VAULT_API_KEY",
            "VAULT_JWT_SECRET"
        ).stream()
        .filter(name -> System.getenv(name) == null || System.getenv(name).isBlank())
        .toList();

        if (!missing.isEmpty()) {
            throw new IllegalStateException("Missing required secrets: " + missing);
        }
    }
}
```

**Key rules:**
- **Never** use `@Value("${prop:default}")` for secrets — no fallback defaults
- Fail fast: throw during `@PostConstruct` or via `ApplicationListener<ApplicationStartingEvent>` if a required secret is missing
- Use secret files mounted as Kubernetes/Vault volumes and read them at startup
- Validate all required secrets at startup — log a clear error listing which ones are missing
- "Fail closed" — the application must not start with missing secrets, never fall back to a placeholder

---

## 8. Protect Secret Material in toString() and Serialization

**CWE-532** — *Information Exposure Through Log Files (toString() Leakage)*

### The Problem

A class's `toString()` method that includes credential fields will leak secrets whenever the object is logged, included in error messages, serialized to JSON, or printed in debug output. This is a silent, pervasive leak vector — every `log.info(user)` or `e.getMessage()` becomes a credential exposure.

```java
// ❌ VULNERABLE — toString() prints all fields including secrets
public class LegacyIntegrationProperties {
    private String dbPassword;
    private String apiKey;

    @Override
    public String toString() {
        return "LegacyIntegrationProperties{dbPassword='" + dbPassword +
               "', apiKey='" + apiKey + "'}";
    }
}
// log.info("Config: {}", properties);  // password in logs!
// return ResponseEntity.ok(properties);  // password in JSON response!
```

### The Fix

Use a `SecretHandle` class that never reveals material. Override `toString()` on any class containing secrets.

```java
// ✅ SAFE — SecretHandle that never reveals the value
public final class SecretHandle implements Closeable {
    private char[] value;
    private final boolean released;

    public SecretHandle(String secret) {
        this.value = secret.toCharArray();
        this.released = false;
    }

    public static SecretHandle of(String secret) {
        return new SecretHandle(secret);
    }

    public static SecretHandle of(byte[] secret) {
        return new SecretHandle(new String(secret, StandardCharsets.UTF_8));
    }

    @Override
    public String toString() {
        if (isReleased()) return "[Secret: released]";
        return "[Secret length=" + value.length + 
               " first=" + value[0] + 
               " last=" + value[value.length - 1] + "]";
    }

    public String getPlainText() {
        if (isReleased()) throw new IllegalStateException("Secret already released");
        return new String(value);
    }

    public byte[] getBytes() {
        if (isReleased()) throw new IllegalStateException("Secret already released");
        return value.clone();  // return a copy
    }

    public boolean isReleased() {
        return released || (value != null && value.length == 0);
    }

    @Override
    public void close() {
        if (!isReleased() && value != null) {
            Arrays.fill(value, '\0');  // zero out
            value = null;
        }
    }

    @Override
    protected void finalize() {
        close();
    }
}

// ✅ SAFE — entity with overridden toString()
@Entity
public class IntegrationConfig {
    private SecretHandle dbPassword;
    private SecretHandle apiKey;

    @Override
    public String toString() {
        return "IntegrationConfig{" +
               "dbPassword=" + (dbPassword != null ? dbPassword.toString() : "null") +
               ", apiKey=" + (apiKey != null ? apiKey.toString() : "null") +
               "}";
        // Output: "IntegrationConfig{dbPassword=[Secret length=12 first=H last=r], apiKey=[Secret length=32 first=A last=z]}"
    }
}

// ✅ SAFE — Jackson serializer for JSON
public class SecretHandleSerializer extends JsonSerializer<SecretHandle> {
    @Override
    public void serialize(SecretHandle value, JsonGenerator gen, SerializerProvider provider) {
        gen.writeString("[REDACTED]");
    }
}

// Usage in entity
@JsonSerialize(using = SecretHandleSerializer.class)
public SecretHandle getApiKey() {
    return apiKey;
}
```

**Auto-close pattern for secrets:**

```java
// ✅ SAFE — try-with-resources for secret lifecycle
try (SecretHandle token = SecretHandle.of(accessToken)) {
    response = externalApi.call(token.getPlainText());
}  // token is zeroed automatically
```

**Key rules:**
- Never store passwords, tokens, or API keys as plain `String` — use `SecretHandle` (char[])
- Override `toString()` on any class containing secrets to redact them
- Use custom Jackson serializers that output `[REDACTED]` for sensitive fields
- Apply `@JsonIgnore` on sensitive fields that should never be serialized
- Close/secrets using `Closeable` pattern — zero out on close, not at GC time
- Remember: `String` is immutable and stays in memory until GC — `char[]` can be zeroed

---

## Summary Checklist

| # | Control | CWE | Priority |
|---|---------|-----|----------|
| 1 | No secrets in API responses | CWE-200 | CRITICAL |
| 2 | No env/PropertySources dumping | CWE-540, CWE-526 | CRITICAL |
| 3 | Services don't return their own credentials | CWE-522 | CRITICAL |
| 4 | Mask before logging | CWE-532 | CRITICAL |
| 5 | Disable dev tooling in prod | CWE-489 | HIGH |
| 6 | Per-env, per-service credentials | CWE-522 | CRITICAL |
| 7 | Fail-fast, no hardcoded fallbacks | CWE-1188 | CRITICAL |
| 8 | Protect toString() and serialization | CWE-532 | HIGH |

---

## Detection & Review Heuristics

| Check | Command / Pattern |
|-------|-------------------|
| Secrets in git history | `gitleaks detect --source . --redact` |
| Credential-shaped grep | `(password|secret|token|api[_-]?key)\s*[:=]\s*['"]?[A-Za-z0-9/+]{12,}` |
| H2 console in prod | `grep -r 'h2.console.enabled' --include='*.yml'` → should not appear in prod |
| Default fallback in @Value | `grep -r '@Value.*:.*}'` → no hardcoded defaults for secrets |
| toString() with sensitive fields | `grep -r 'toString.*password\|toString.*secret\|toString.*key'` |
| log.info with request params | `grep -r 'log.info.*req\.\(getPassword\|getToken\|getSecret\)'` |
| Actuator exposure | Check that `/actuator/env` is not exposed on any public port |

---

## References

- [OWASP Secret Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [OWASP Log forking Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [Spring Boot Actuator Security](https://docs.spring.io/spring-boot/reference/features/actuator.html#actuator.security)
- [HashiCorp Vault Integration with Spring Boot](https://developer.hashicorp.com/vault/docs/platform/java/spring-boot)
- [NIST SP 800-57: Recommendation for Key Management](https://pages.nist.gov/800-57-Part1r5/)
