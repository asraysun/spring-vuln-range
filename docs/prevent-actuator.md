# Spring Security: How to Prevent Actuator, API Docs & Debug Surface Vulnerabilities

A practical guide to securing Spring Boot's management endpoints, API documentation, and debug surfaces against information exposure, unauthenticated operations, and dangerous methods — covering 5 CWEs found in real Spring applications.

---

## Table of Contents

1. [Actuator Endpoint Hardening](#1-actuator-endpoint-hardening)
2. [Management Port Isolation](#2-management-port-isolation)
3. [Authentication on Management Surface](#3-authentication-on-management-surface)
4. [Disable Dangerous Operations](#4-disable-dangerous-operations)
5. [Remove Debug Surfaces](#5-remove-debug-surfaces)
6. [Trim Build Metadata](#6-trim-build-metadata)

---

## 1. Actuator Endpoint Hardening

**CWE-200** — *Information Exposure (Actuator Endpoints)*

### The Problem

Spring Boot Actuator endpoints expose runtime internals — health details, property sources with values, configuration properties, heap dumps, thread dumps, log levels, build metadata. When exposed on the public port without authentication, an anonymous caller gets a complete map of the application's architecture, technology stack, database types, connection strings, feature flags, and in-memory state. This is reconnaissance data that accelerates every subsequent attack phase.

```yaml
# ❌ VULNERABLE — every actuator endpoint exposed on the public port
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

# Property sources with VALUES (including credentials)
curl -s http://127.0.0.1:8092/actuator/env
# Returns: {"propertySources":[{"name":"applicationConfigurationProperties",
#   "properties":{"db.password":{"value":"super-secret-123"},
#   "jwt.secret":{"value":"my-secret-key"}}}]}

# Memory dump in one request
curl -s -o /tmp/heapdump.hprof http://127.0.0.1:8092/actuator/heapdump
# Returns: full JVM heap — all objects, all in-memory secrets, all session data
```

### The Fix

Expose only what a probe needs. Disable everything else.

```yaml
# ✅ SAFE — minimal exposure
# application-prod.yml
management:
  endpoints:
    web:
      exposure:
        include: 'health,info'  # Only probes, nothing else
  endpoint:
    health:
      enabled: true
      show-details: never       # No component data (DB product, disk path, etc.)
      show-components: never    # No component details
    env:
      enabled: false            # /actuator/env → 404
    configprops:
      enabled: false            # /actuator/configprops → 404
    heapdump:
      enabled: false            # /actuator/heapdump → 404
    threaddump:
      enabled: false            # /actuator/threaddump → 404
    loggers:
      enabled: false            # /actuator/loggers → 404
    shutdown:
      enabled: false            # /actuator/shutdown → 404
    info:
      enabled: true
  info:
    env:
      enabled: false            # No build metadata in /info
```

**Key rules:**
- `management.endpoints.web.exposure.include: 'health,info'` is the **baseline**
- Everything else is **disabled**, not merely unlisted
- `show-details: never` and `show-components: never` for health
- `management.info.env.enabled: false` to prevent build metadata leaks
- Test the negative in CI: assert `404` for `/actuator/env` and `401` for `/actuator/heapdump`

---

## 2. Management Port Isolation

**CWE-200** — *Information Exposure (Actuator Endpoints)*

### The Problem

When actuator endpoints live on the same port as the public API, ingress proxies, load balancers, and external networks can reach them directly. Even with careful endpoint exposure, the management surface becomes part of the external attack surface.

### The Fix

Run actuator on a **separate, loopback-only management port**.

```yaml
# ✅ SAFE — separate management port on loopback
# application-prod.yml
management:
  server:
    port: 8192           # Separate management port
    address: 127.0.0.1   # Loopback only — inaccessible from external networks
```

**Port separation strategy:**

| Port | Purpose | Access |
|------|---------|--------|
| `:8080` (or configured) | Public API (business endpoints) | Internet / VPC |
| `:8192` | Management (actuator, probes) | Loopback only (`127.0.0.1`) |
| `:9090` | CI health checks (internal) | Internal network |

**Kubernetes NetworkPolicy example:**

```yaml
# ✅ SAFE — Kubernetes NetworkPolicy blocks external access to management port
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: app-actuator-restrict
spec:
  podSelector:
    matchLabels:
      app: spring-app
  policyTypes:
  - Ingress
  ingress:
  # Only allow from same pod (loopback)
  - from:
    - podSelector: {}
    ports:
    - protocol: TCP
      port: 8192  # Management port
  # All other ingress to :8192 is denied
```

**Key rules:**
- Management port on **loopback only** (`127.0.0.1`)
- Ingress proxies and load balancers should **not route** to the management port
- If you need remote access to actuator (e.g., for monitoring), use **mTLS with a separate certificate** and restrict to specific monitoring servers

---

## 3. Authentication on Management Surface

**CWE-306** — *Missing Authentication for Critical Function*  
**CWE-749** — *Exposed Dangerous Method or Function*

### The Problem

Actuator endpoints like `/actuator/shutdown`, `/actuator/env`, and `/actuator/loggers` are critical management functions. When exposed without authentication on the public port, any anonymous caller can shut down the application, read all configuration values (including credentials), or change log levels to flood the system with debug output.

CWE-749 covers actuator endpoints that expose dangerous operations — heap dumps, thread dumps, log level changes, remote shutdown. These are "dangerous methods" of the application's management interface. When exposed without authentication, they become attack vectors for data exfiltration, denial of service, and operational disruption.

```yaml
# ❌ VULNERABLE — shutdown enabled on public port, no authentication
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

# Remote log level change — floods system with debug output
curl -s -X POST -H 'Content-Type: application/json' \
     -d '{"configuredLevel":"DEBUG"}' http://127.0.0.1:8092/actuator/loggers/ROOT
# Every request now logs at DEBUG → credential exposure, disk exhaustion
```

### The Fix

Secure the management port with a dedicated Spring Security chain.

```java
// ✅ SAFE — security chain for management port
@Configuration
public class ActuatorSecurityConfig {

    @Bean
    public SecurityFilterChain actuatorChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/actuator/**")
            .authorizeHttpRequests(a -> a
                // Probes accessible without auth (for orchestrators)
                .requestMatchers("/actuator/health").permitAll()
                .requestMatchers("/actuator/info").permitAll()
                
                // Everything else requires operator role
                .requestMatchers("/actuator/**").hasRole("ACTUATOR")
                .anyRequest().denyAll()
            )
            .httpBasic(Customizer.withDefaults())  // Operator authentication
            .csrf(Customizer.enable());  // CSRF on for management port
            
        return http.build();
    }
}
```

```yaml
# ✅ SAFE — operator credentials from env, not hardcoded
# application-prod.yml
management:
  server:
    port: 8192
    address: 127.0.0.1
  endpoints:
    web:
      exposure:
        include: 'health,info'
  endpoint:
    health:
      show-details: never
      show-components: never
    env:
      enabled: false
    configprops:
      enabled: false
    heapdump:
      enabled: false
    threaddump:
      enabled: false
    loggers:
      enabled: false
    shutdown:
      enabled: false
    info:
      enabled: true
```

**User credentials in production:**

```yaml
# ❌ NEVER hardcode credentials in code
# ActuatorSecurityConfig.java — BAD
// @Bean UserDetailsService userDetailsService() {
//     InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
//     manager.createUser(User.withUsername("operator").password("password123").roles("ACTUATOR").build());
//     return manager;
// }

# ✅ SAFE — use external identity provider or environment variables
# application-prod.yml
spring:
  security:
    user:
      name: ${ACTUATOR_USERNAME}
      password: ${ACTUATOR_PASSWORD}  # From Vault or K8s Secrets
```

**Key rules:**
- **Every actuator endpoint on the management port should require authentication**
- Probes (`/actuator/health`, `/actuator/info`) can be public for orchestrator compatibility
- Use **HTTP Basic** for operator authentication (or mTLS with a certificate)
- Credentials come from **env/Vault/K8s Secrets**, not hardcoded in code
- If a break-glass shutdown is genuinely required, put it on its **own port** behind the platform's access control

---

## 4. Disable Dangerous Operations

**CWE-749** — *Exposed Dangerous Method or Function*

### The Problem

CWE-749 covers actuator endpoints that expose dangerous operations — heap dumps, thread dumps, log level changes, remote shutdown. When exposed without authentication, they become attack vectors for data exfiltration, denial of service, and operational disruption.

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

### The Fix

Only `health` and `info` should be exposed. Everything else has `enabled: false`.

```yaml
# ✅ SAFE — all dangerous methods disabled
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
    env:
      enabled: false
    configprops:
      enabled: false
```

**Dangerous endpoints reference:**

| Endpoint | Risk | Severity | Action |
|----------|------|----------|--------|
| `/actuator/shutdown` | Remote DoS | CRITICAL | Disable (`enabled: false`) |
| `/actuator/heapdump` | Memory dump, secrets | CRITICAL | Disable (`enabled: false`) |
| `/actuator/env` | Credentials exposure | CRITICAL | Disable (`enabled: false`) |
| `/actuator/configprops` | Config values | HIGH | Disable (`enabled: false`) |
| `/actuator/loggers` | Debug flood, logging secrets | HIGH | Disable (`enabled: false`) |
| `/actuator/threaddump` | Architecture disclosure | MEDIUM | Disable (`enabled: false`) |

**CI test to assert dangerous endpoints are disabled:**

```java
// ✅ SAFE — contract test for actuator security
@Test
void actuatorDangerousEndpointsDisabled() {
    // On the application port (public)
    assertResponseCode(404, "/actuator/env");
    assertResponseCode(404, "/actuator/heapdump");
    assertResponseCode(404, "/actuator/configprops");
    assertResponseCode(404, "/actuator/loggers");
    assertResponseCode(404, "/actuator/threaddump");
    assertResponseCode(404, "/actuator/shutdown");

    // On the management port (authenticated)
    assertResponseCode(401, "/actuator/env");
    assertResponseCode(401, "/actuator/heapdump");
}

private void assertResponseCode(int expected, String path) {
    int actual = restTemplate.getForObject(path, String.class) != null ? 200 : 404;
    // Or using MockMvc / TestRestTemplate
    assertEquals(expected, actual, "Expected " + expected + " for " + path);
}
```

**Key rules:**
- Only `health` and `info` should be exposed
- Everything else has `enabled: false`
- Test the negative in CI: assert `404` for dangerous endpoints
- If a dangerous operation is genuinely required (e.g., heap dump for debugging), restrict it to a **separate management port with mTLS**

---

## 5. Remove Debug Surfaces

**CWE-1188** — *Insecure Default Configuration (H2 Console, API Docs)*

### The Problem

Development tools left in production configurations (H2 console, OpenAPI docs with debug routes) create unrestricted access to internal systems. The H2 console provides a full SQL IDE against the production database — any anonymous caller can execute arbitrary queries. OpenAPI docs list all endpoints including debug and internal routes, giving attackers a complete route map.

```yaml
# ❌ VULNERABLE — H2 console enabled in production
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

### The Fix

Delete debug surfaces from production. No OpenAPI docs in the deployed artifact.

```yaml
# ✅ SAFE — dev tooling disabled in production
# application-prod.yml
spring:
  h2:
    console:
      enabled: false  # /h2-console → 404
```

```xml
<!-- ✅ SAFE — exclude OpenAPI docs from production JAR -->
<!-- pom.xml or build.gradle: only include in dev profile -->
<profiles>
    <profile>
        <id>dev</id>
        <dependencies>
            <dependency>
                <groupId>org.springdoc</groupId>
                <artifactId>springdoc-openapi-ui</artifactId>
            </dependency>
        </dependencies>
    </profile>
    <!-- No OpenAPI dependency in the default/production build -->
</profiles>
```

**Key rules:**
- **`spring.h2.console.enabled: false`** is non-negotiable in production
- **No `/api-docs/openapi.json`** in the deployed artifact (exclude dependency from production build)
- Delete all debug endpoints and routes from production code
- If OpenAPI docs are needed for developers, serve them from a **separate internal service** or from the CI/CD portal
- Audit `static/` resources in the JAR for any leaked internal documentation or debug routes

---

## 6. Trim Build Metadata

**CWE-200** — *Information Exposure (Build Metadata)*

### The Problem

Actuator `/info` endpoint that includes build metadata (SCM URL, branch name, commit hash, build timestamp) maps the entire development estate. An attacker can determine which branch the application was deployed from, when it was built, and what internal SCM URLs are used — all of which aid in targeted attacks and social engineering.

```yaml
# ❌ VULNERABLE — full build metadata exposed
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

### The Fix

Keep only `app.name` for dashboards. Internal SCM URL, branch, and commit build a map of the estate — they belong in the deployment record, not in an HTTP response.

```yaml
# ✅ SAFE — minimal info
info:
  app:
    name: espd-service  # App name is enough for a dashboard
# No build, no git, no SCM URL
```

```java
// ✅ SAFE — or disable /info entirely
@Configuration
public class InfoConfig {
    @Bean
    public EndpointInfoContributor infoContributor() {
        return (builder) -> {
            // No additional info — return empty builder
        };
    }
}
```

**Key rules:**
- `app.name` and a version is enough for a dashboard
- **Internal SCM URL, branch, and commit** build a map of the estate — they belong in the deployment record, not in an HTTP response
- `management.info.env.enabled: false` to prevent environment variable leakage
- If versioning is needed, expose a non-sensitive version string (semver only, no commit hash)

---

## Summary Checklist

| # | Control | CWE | Priority |
|---|---------|-----|----------|
| 1 | `management.endpoints.web.exposure.include: 'health,info'` | CWE-200 | CRITICAL |
| 2 | Management port on loopback (`:8192`, `127.0.0.1`) | CWE-200 | CRITICAL |
| 3 | Auth on management port (`hasRole("ACTUATOR")`) | CWE-306, CWE-749 | CRITICAL |
| 4 | Disable dangerous endpoints (`enabled: false`) | CWE-749 | CRITICAL |
| 5 | `spring.h2.console.enabled: false`, no OpenAPI in prod | CWE-1188 | CRITICAL |
| 6 | Trim `info` to `app.name` only | CWE-200 | HIGH |

---

## Detection & Review Heuristics

| Check | Command / Pattern |
|-------|-------------------|
| All actuator endpoints exposed | `grep -r 'include:\s*"' | "` |
| H2 console enabled | `grep -r 'h2.console.enabled:\s*true'` → should be `false` |
| Missing management port | `grep -r 'management.server.port'` → should exist in prod |
| Missing actuator auth | `grep -r 'permitAll.*actuator'` → should have `hasRole("ACTUATOR")` |
| Shutdown enabled | `grep -r 'shutdown.enabled:\s*true'` → should be `false` |
| Show details/ values | `grep -r 'show-details:\s*always\|show-values:\s*always'` → should be `never` |
| OpenAPI in prod | Check JAR contents: `jar tf app.jar | grep -i 'openapi\|swagger'` → should not exist |
| Build metadata | `grep -r 'info.build\|info.git'` → should not exist |

---

## References

- [Spring Boot Actuator Security](https://docs.spring.io/spring-boot/reference/features/actuator.html#actuator.security)
- [OWASP Actuator Hardening](https://cheatsheetseries.owasp.org/cheatsheets/Spring_Boot_Security_Cheat_Sheet.html)
- [Kubernetes NetworkPolicies for Service Isolation](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [NIST SP 800-53: SC-7 (Boundary Protection)](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
