# CWE Reference — §12 Management Endpoints, API Documentation and Debug Surfaces

CWEs extracted from `docs/12-actuator.md` with developer-focused comments.

---

## CWE-200 — Information Exposure (Actuator Endpoints)

**Why it matters:** Spring Boot Actuator endpoints expose runtime internals — health details, property sources with values, configuration properties, heap dumps, thread dumps, log levels, build metadata. When exposed on the public port without authentication, an anonymous caller gets a complete map of the application's architecture, technology stack, database types, connection strings, feature flags, and in-memory state. This is reconnaissance data that accelerates every subsequent attack phase.

**Attack vector in Spring:**
```yaml
# VULNERABLE — every actuator endpoint exposed on the public port
management:
  endpoints:
    web:
      exposure:
        include: '*'  # Everything!
  # No separate management port
  # No authentication
```

```bash
# Anonymous caller sees full actuator inventory
curl -s http://127.0.0.1:8092/actuator
# Returns: [health,info,env,configprops,heapdump,threaddump,loggers,shutdown,...]

# Health details with component data (database product, disk path, internal names)
curl -s http://127.0.0.1:8092/actuator/health
# Returns: {"status":"UP","components":{"db":{"status":"UP","detail":{"database":"PostgreSQL",
#   "helloResult":1,"validationQuery":"SELECT 1"}},"disk":{"status":"UP","detail":{"total":500GB}}}}

# Property sources with VALUES (including credentials)
curl -s http://127.0.0.1:8092/actuator/env
# Returns: {"propertySources":[{"name":"applicationConfigurationProperties",
#   "properties":{"db.password":{"value":"super-secret-123"},
#   "jwt.secret":{"value":"my-secret-key"}}}]}

# Configuration properties with values
curl -s http://127.0.0.1:8092/actuator/configprops
# Returns: All @ConfigurationProperties with their current values

# Memory dump in one request
curl -s -o /tmp/heapdump.hprof http://127.0.0.1:8092/actuator/heapdump
# Returns: full JVM heap — all objects, all in-memory secrets, all session data

# Thread dump — shows all running threads, frame names, locked monitors
curl -s http://127.0.0.1:8092/actuator/threaddump
# Returns: frame names naming internal classes, libraries, connection pools

# Remote log level change
curl -s -X POST -H 'Content-Type: application/json' \
     -d '{"configuredLevel":"DEBUG"}' http://127.0.0.1:8092/actuator/loggers/ROOT
# Now ALL requests are logged at DEBUG — including credentials in logs

# Remote shutdown
curl -s -X POST http://127.0.0.1:8092/actuator/shutdown
# Application stops
```

**How to prevent:**
```yaml
# SAFE — minimal exposure, separate port, authentication
# application-safe.yml
management:
  server:
    port: 8192           # Separate management port
    address: 127.0.0.1   # Loopback only
  endpoints:
    web:
      exposure:
        include: 'health,info'  # Only probes, nothing else
  endpoint:
    health:
      show-details: never      # No component data
      show-components: never
    env:
      enabled: false           # /actuator/env → 404
    configprops:
      enabled: false           # /actuator/configprops → 404
    heapdump:
      enabled: false           # /actuator/heapdump → 401
    threaddump:
      enabled: false           # /actuator/threaddump → 404
    loggers:
      enabled: false           # /actuator/loggers → 404
    shutdown:
      enabled: false           # /actuator/shutdown → 404
    info:
      enabled: false           # Trimmed info
  info:
    env:
      enabled: false           # No build metadata
```
```java
// SAFE — security chain for management port
@Bean
public SecurityFilterChain actuatorChain(HttpSecurity http) {
    http.securityMatcher("/actuator/**")
        .authorizeHttpRequests(a -> a
            .requestMatchers("/actuator/health", "/actuator/info").permitAll()
            .requestMatchers("/actuator/**").hasRole("ACTUATOR")
            .anyRequest().denyAll()
        )
        .httpBasic(Customizer.withDefaults())  // Operator authentication
        .csrf(Customizer.enable());  // CSRF on for management port
    return http.build();
}
```
- `management.endpoints.web.exposure.include: 'health,info'` is the baseline.
- Everything else is disabled, not merely unlisted.
- Separate management port on loopback (`:8192`, `127.0.0.1`).
- Authorize the management surface with a dedicated security chain.

---

## CWE-306 — Missing Authentication for Critical Function

**Why it matters:** Actuator endpoints like `/actuator/shutdown`, `/actuator/env`, and `/actuator/loggers` are critical management functions. When exposed without authentication on the public port, any anonymous caller can shut down the application, read all configuration values (including credentials), or change log levels to flood the system with debug output.

**Attack vector in Spring:**
```yaml
# VULNERABLE — shutdown enabled on public port, no authentication
management:
  endpoints:
    web:
      exposure:
        include: '*'
  endpoint:
    shutdown:
      enabled: true  # POST /actuator/shutdown stops the application
```
```bash
# Anonymous caller shuts down the application
curl -s -X POST http://127.0.0.1:8092/actuator/shutdown
# Application stops — denial of service
```
`POST /actuator/shutdown` on the public port with no authentication is a one-request denial of service. Any anonymous caller can stop the application.

**How to prevent:**
```yaml
# SAFE — shutdown disabled
management:
  endpoint:
    shutdown:
      enabled: false  # /actuator/shutdown → 404
```
- If a break-glass shutdown is genuinely required, put it on its own port behind the platform's access control.
- Never expose shutdown on the public port.
- All actuator endpoints on the management port should require authentication.

---

## CWE-749 — Exposed Dangerous Method or Function

**Why it matters:** CWE-749 covers actuator endpoints that expose dangerous operations — heap dumps, thread dumps, log level changes, remote shutdown. These are "dangerous methods" of the application's management interface. When exposed without authentication, they become attack vectors for data exfiltration, denial of service, and operational disruption.

**Attack vector in Spring:**
```yaml
# VULNERABLE — dangerous methods exposed
management:
  endpoints:
    web:
      exposure:
        include: '*'  # heapdump, threaddump, loggers, shutdown all exposed
```
```bash
# Heap dump — one request, everything in memory
curl -s -o /tmp/heapdump.hprof http://127.0.0.1:8092/actuator/heapdump
# Contains: all session data, all in-memory secrets, all user data

# Thread dump — reveals internal architecture
curl -s http://127.0.0.1:8092/actuator/threaddump
# Frame names name internal classes, libraries, connection pools

# Log level change — floods the system with debug output
curl -s -X POST -H 'Content-Type: application/json' \
     -d '{"configuredLevel":"DEBUG"}' http://127.0.0.1:8092/actuator/loggers/ROOT
# Every request now logs at DEBUG → credential exposure, disk exhaustion
```

**How to prevent:**
```yaml
# SAFE — all dangerous methods disabled
management:
  endpoint:
    heapdump:
      enabled: false
    threaddump:
      enabled: false
    loggers:
      enabled: false
    shutdown:
      enabled: false
```
- Only `health` and `info` should be exposed.
- Everything else has `enabled: false`.
- Test the negative in CI: assert `404` for `/actuator/env` and `401` for `/actuator/heapdump`.

---

## CWE-1188 — Insecure Default Configuration (H2 Console, API Docs)

**Why it matters:** Development tools left in production configurations (H2 console, OpenAPI docs with debug routes) create unrestricted access to internal systems. The H2 console provides a full SQL IDE against the production database — any anonymous caller can execute arbitrary queries. OpenAPI docs list all endpoints including debug and internal routes, giving attackers a complete route map.

**Attack vector in Spring:**
```yaml
# VULNERABLE — H2 console enabled in production
spring:
  h2:
    console:
      enabled: true  # Accessible at /h2-console, anonymous, full SQL access
```
```bash
# H2 console — full SQL IDE against production database
curl -s http://127.0.0.1:8092/h2-console
# Anonymous caller can execute: SELECT * FROM users; DROP TABLE users;--

# OpenAPI docs — complete route map including debug routes
curl -s http://127.0.0.1:8092/api-docs/openapi.json
# Lists /vuln12/debug/reset-cache and all other endpoints
```
`GET /h2-console` gives anyone a SQL IDE against the production database. Combined with SQL injection (CWE-89), this is full data exfiltration.

**How to prevent:**
```yaml
# SAFE — dev tooling disabled in production
# application-prod.yml
spring:
  h2:
    console:
      enabled: false  # /h2-console → 404
```
- Delete debug surfaces from production.
- No `api-docs/openapi.json` in the deployed artifact.
- `spring.h2.console.enabled: false` is non-negotiable in production.

---

## CWE-200 — Information Exposure (Build Metadata)

**Why it matters:** Actuator `/info` endpoint that includes build metadata (SCM URL, branch name, commit hash, build timestamp) maps the entire development estate. An attacker can determine which branch the application was deployed from, when it was built, and what internal SCM URLs are used — all of which aid in targeted attacks and social engineering.

**Attack vector in Spring:**
```yaml
# VULNERABLE — full build metadata exposed
info:
  build:
    name: espd-service
    artifact: espd-service
    version: 1.2.3
    time: 2025-11-10T14:32:00Z
  git:
    branch: main
    commit:
      id: abc1234
      time: 2025-11-10T10:00:00Z
    url: https://git.internal.example.org/espd/espd-service
```
```bash
curl -s http://127.0.0.1:8092/actuator/info
# Returns: full build metadata including internal SCM URL
```

**How to prevent:**
```yaml
# SAFE — minimal info
info:
  app:
    name: espd-service  # App name is enough for a dashboard
# No build, no git, no SCM URL
```
- `app.name` and a version is enough for a dashboard.
- Internal SCM URL, branch, and commit build a map of the estate — they belong in the deployment record, not in an HTTP response.
- `management.info.env.enabled: false`.
