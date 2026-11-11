# CWE Reference — §03 Secrets and Configuration

CWEs extracted from `docs/03-secrets-config.md` with developer-focused comments.

---

## CWE-200 — Information Exposure

**Why it matters:** An endpoint that returns configuration details gives attackers a blueprint of the application's internals — database types, connection strings, feature flags, third-party service URLs. This information accelerates every subsequent attack phase: target selection, gadget chain selection, and social engineering.

**Attack vector in Spring:**
```java
// VULNERABLE — returns full configuration including credential-shaped values
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
`GET /vuln3/config` returns the entire application configuration — anyone with HTTP access gets the database credentials, API keys, and internal architecture.

**How to prevent:**
- Never return credential-shaped values in API responses. A service *uses* secrets; it may only report whether one is present.
```java
// SAFE — presence only, no values
@GetMapping("/config-summary")
public ResponseEntity<?> getConfigSummary() {
    return ResponseEntity.ok(Map.of(
        "dbConfigured", dbProperties.isConfigured(),
        "apiKeyPresent", !Strings.isNullOrEmpty(apiKey),
        "credentialValuesReturned", 0
    ));
}
```

---

## CWE-540 — Information Exposure Through Environment Variables

**Why it matters:** Returning environment variables or configuration properties that contain credentials exposes secrets to any caller of the endpoint. This is particularly dangerous because environment variables are the primary mechanism for injecting secrets into containers and PaaS platforms — compromising one endpoint compromises the entire deployment.

**Attack vector in Spring:**
```java
// VULNERABLE — dumps all environment variables
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
```

**How to prevent:**
- Never expose `Environment` or `PropertySources` to API callers.
- If a config-summary endpoint is needed, only report boolean presence flags:
```java
// SAFE
@GetMapping("/config-summary")
public ResponseEntity<?> summary() {
    return ResponseEntity.ok(Map.of(
        "dbPasswordPresent", !Strings.isNullOrEmpty(System.getenv("DB_PASSWORD")),
        "credentialValuesReturned", 0
    ));
}
```

---

## CWE-522 — Insufficiently Protected Credentials

**Why it matters:** A service that hands out its own credentials to callers turns every authenticated user into a proxy for that service. The attacker can then use those credentials to interact with the downstream service at full privilege, bypassing all audit controls and rate limits tied to the original service account.

**Attack vector in Spring:**
```java
// VULNERABLE — returns the service's own API token
@GetMapping("/integration/token")
public ResponseEntity<?> getIntegrationToken() {
    return ResponseEntity.ok(Map.of(
        "token", integrationApiKey,  // the service's own credential
        "endpoint", externalServiceUrl
    ));
}
```
`GET /vuln3/integration/token` returns the application's own API key for a third-party service. Any caller can then use that key to interact with the third party as the application.

**How to prevent:**
- A service uses credentials; it never returns them. If a downstream call is needed, make the call server-side and return only the result.
```java
// SAFE — signs a request, returns fingerprint
@PostMapping("/integration/call")
public ResponseEntity<?> callIntegration(@RequestBody Request req) {
    String signature = hmacSha256(integrationSecret, req.toPayload());
    String result = externalService.call(signature, req.toPayload());
    return ResponseEntity.ok(Map.of(
        "fingerprint", sha256(result).substring(0, 16),
        "credentialValuesReturned", 0
    ));
}
```

---

## CWE-526 — Information Exposure Through Environment Variables (Credential Exposure)

**Why it matters:** Dumping the environment returns every credential-shaped variable — database passwords, API keys, JWT secrets, cloud provider tokens. In containerized deployments, these variables are the primary injection mechanism for secrets, making an env-dump endpoint equivalent to a secret-store breach.

**Attack vector in Spring:**
```java
// VULNERABLE — returns all environment variables with values
@GetMapping("/env-dump")
public ResponseEntity<?> envDump() {
    Map<String, String> env = System.getenv();
    // Includes: DB_PASSWORD, API_KEY, JWT_SECRET, AWS_SECRET_KEY, etc.
    return ResponseEntity.ok(env);
}
```
`GET /vuln3/env-dump` returns the full process environment — every credential injected into the container is exposed.

**How to prevent:**
- Never expose `System.getenv()` or `System.getProperties()` to API callers.
- In production, `management.endpoint.env.enabled: false` and ensure no custom endpoint reads environment variables.
- Use `server.error.include-exception=never` and `management.endpoint.env.show-values=never` as a baseline.

---

## CWE-532 — Information Exposure Through Log Files

**Why it matters:** Writing credentials, tokens, or PII to application logs turns every log consumer (ELK stack, Datadog, Splunk, CI artifacts, CI/CD logs) into a secret store. Log retention policies rarely match data-protection requirements, and log access controls are often far weaker than database access controls.

**Attack vector in Spring:**
```java
// VULNERABLE — logs the password in cleartext
@PostMapping("/integration/check")
public ResponseEntity<?> check(@RequestBody ConnectionRequest req) {
    log.info("Connecting with user={} password={}", req.getUser(), req.getPassword());
    // "Connecting with user=espd_app password=MY-MARKER" appears in the log pipeline
    return ResponseEntity.ok("connected");
}
```
`grep MY-MARKER logs/m03-secrets-config.log` finds the password in the log file. The same password is now in every log aggregator, backup, and CI artifact.

**How to prevent:**
- Never log credential-shaped fields. Use masking:
```java
// SAFE — masked output
@PostMapping("/integration/check")
public ResponseEntity<?> check(@RequestBody ConnectionRequest req) {
    log.info("Connecting with user={} password={}", req.getUser(), mask(req.getPassword()));
    // "Connecting with user=espd_app password=***"
    return ResponseEntity.ok("connected");
}

private String mask(String s) {
    if (s == null || s.length() <= 2) return "***";
    return s.charAt(0) + "***" + s.charAt(s.length() - 1);
}
```
- Use structured JSON logging with field-level redaction filters.
- Implement a `SecretHandle` class that never reveals material in `toString()`.

---

## CWE-489 — Active Debug Program in Production

**Why it matters:** Development tooling left in production configurations (H2 console, debug endpoints, actuator with full exposure) creates unrestricted access to internal systems. The H2 console, for example, provides a full SQL IDE against the production database — any anonymous caller can execute arbitrary queries.

**Attack vector in Spring:**
```yaml
# VULNERABLE — H2 console enabled in production
spring:
  h2:
    console:
      enabled: true   # accessible at /h2-console, anonymous, full SQL access
  # Also: devtools in production runtime image
```
`POST /diagnostics` + `GET /h2-console` gives anyone a SQL IDE against the production database. Combined with SQL injection (CWE-89), this is full data exfiltration.

**How to prevent:**
- Disable all dev tooling in production profiles:
```yaml
# application-prod.yml
spring:
  h2:
    console:
      enabled: false
  # devtools not in the production dependency tree
```
- Use Spring profiles to separate dev and prod configurations explicitly.
- Never include `spring-boot-devtools` in the production runtime image.

---

## CWE-522 — Insufficiently Protected Credentials (Single Credential Across Environments)

**Why it matters:** Using the same credential for development, integration testing, and production means a compromise in any lower environment cascades to production. A developer's local log, a CI/CD artifact, or a test environment breach gives the attacker production credentials.

**Attack vector in Spring:**
```yaml
# VULNERABLE — same secret for dev, integration, and production
app:
  db-password: "super-secret-123"  # committed to repo, same everywhere
  api-key: "AKIAIOSFODNN7EXAMPLE"  # same in all environments
```
`GET /vuln3/per-env-credentials` returns the same credential for all environments. A developer who sees the local config has production access.

**How to prevent:**
- One credential per environment, per service, with least privilege:
```yaml
# application-dev.yml — local dev only
app:
  db-password: ${DEV_DB_PASSWORD}

# application-prod.yml — no defaults, fail if missing
app:
  db-password: ${PROD_DB_PASSWORD}
```
- Use a secret manager (Vault, AWS Secrets Manager, Azure Key Vault) to inject credentials at runtime.
- Never commit environment-specific credentials to the repository.

---

## CWE-1188 — Insecure Default Configuration / Hardcoded Fallback

**Why it matters:** A compiled-in default value used as a "silent fallback" when an environment variable is missing means that a shared development credential becomes the production credential. This is one of the most insidious secret leaks because it happens silently — the application starts, appears to work, and nobody notices that production is using a default from source control.

**Attack vector in Spring:**
```java
// VULNERABLE — fallback to a hardcoded default
@Value("${db.password:postgres}")  // if env var missing, uses "postgres"
private String password;

// Or with Spring property syntax:
@Value("${db.password:${DEFAULT_DB_PASSWORD:postgres}}")
private String password;
```
If the environment variable is not injected (e.g., a deployment oversight), the application silently falls back to `postgres` — a shared development credential used in production.

**How to prevent:**
- Fail fast at startup if a required secret is missing:
```java
// SAFE — throws if env var is missing
@Value("${VAULT_DB_PASSWORD}")
private String password;

@PostConstruct
void validate() {
    if (Strings.isNullOrEmpty(password)) {
        throw new IllegalStateException("VAULT_DB_PASSWORD is required but not set");
    }
}
```
- Or use a custom `SecretProvider` that throws on missing values:
```java
@Component
class VaultFileSecretProvider {
    String resolve(String path) {
        String value = readFile(path);
        if (value == null) throw new IllegalStateException("Secret not found: " + path);
        return value;
    }
}
```

---

## CWE-532 — Information Exposure Through Log Files (toString() / toString() Leakage)

**Why it matters:** A class's `toString()` method that includes credential fields will leak secrets whenever the object is logged, included in error messages, serialized to JSON, or printed in debug output. This is a silent, pervasive leak vector — every `log.info(user)` or `e.getMessage()` becomes a credential exposure.

**Attack vector in Spring:**
```java
// VULNERABLE — toString() prints all fields including secrets
public class LegacyIntegrationProperties {
    private String dbPassword;
    private String apiKey;
    
    @Override
    public String toString() {
        return "LegacyIntegrationProperties{dbPassword='" + dbPassword +
               "', apiKey='" + apiKey + "'}";
    }
}

// Then: log.info("Config: {}", properties);  // password in logs!
// Or: return ResponseEntity.ok(properties);  // password in JSON response!
```
The `toString()` method is called implicitly during logging, JSON serialization, and error reporting — every time credentials leak.

**How to prevent:**
- Use a `SecretHandle` class that never reveals material:
```java
// SAFE — SecretHandle shows length + 2 chars, never the value
public final class SecretHandle implements Closeable {
    private final char[] value;
    
    @Override
    public String toString() {
        return "[Secret length=" + value.length + " first=" + value[0] + " last=" + value[value.length-1] + "]";
    }
    
    @Override
    public void close() {
        Arrays.fill(value, '\0');  // zero out on close
    }
}
```
- Override `toString()` on any class containing secrets to redact them.
- Use Jackson `@JsonInclude(NON_NULL)` and custom serializers for sensitive fields.
