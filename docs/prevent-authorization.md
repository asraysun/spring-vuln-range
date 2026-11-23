# Spring Security: How to Prevent Authorization & Access Control Vulnerabilities

A practical guide to securing Spring Boot authorization, object-level access control, and filter chain configuration — covering 10 CWEs found in real Spring applications.

---

## Table of Contents

1. [IDOR / BOLA Prevention](#1-idor--bola-prevention)
2. [Enumeration Prevention](#2-enumeration-prevention)
3. [CSRF Protection](#3-csrf-protection)
4. [HTTP Method Semantics](#4-http-method-semantics)
5. [Default-Deny Configuration](#5-default-deny-configuration)
6. [Security Filter Chain Integrity](#6-security-filter-chain-integrity)
7. [Tenant Boundary Enforcement](#7-tenant-boundary-enforcement)
8. [Object-Level Authorization](#8-object-level-authorization)
9. [Privilege Escalation Prevention](#9-privilege-escalation-prevention)
10. [Mass Assignment Protection](#10-mass-assignment-protection)

---

## 1. IDOR / BOLA Prevention

**CWE-639** — *Authorization Bypass Through User-Controlled Key*

### The Problem

IDOR (Insecure Direct Object Reference) and BOLA (Broken Object Level Authorization) is the most common and dangerous web vulnerability. When an endpoint uses a client-supplied identifier to fetch a resource without verifying ownership, any authenticated user can access, modify, or delete any other user's data.

```java
// ❌ VULNERABLE — no ownership check
@GetMapping("/subscriptions/{id}")
public ResponseEntity<?> getSubscription(@PathVariable String id) {
    Subscription sub = subscriptionRepository.findById(id).orElseThrow();
    return ResponseEntity.ok(sub);  // Bob reads Alice's data
}
```

### The Fix

Query by **both ID and owner**, enforced at the repository and method level.

```java
// ✅ SAFE — repository layer enforces ownership
public interface SubscriptionRepository extends JpaRepository<Subscription, String> {
    Optional<Subscription> findByIdAndOwner(String id, String owner);
}

// ✅ SAFE — method-level check
@GetMapping("/subscriptions/{id}")
@PreAuthorize("@subscriptionAccess.isOwner(authentication.name, #id)")
public ResponseEntity<?> getSubscription(@PathVariable String id) {
    Subscription sub = subscriptionRepository.findByIdAndOwner(id, authentication.getName())
        .orElseThrow(() -> new NotFoundException("Subscription not found"));
    return ResponseEntity.ok(sub);
}

// Policy bean
@Component
public class SubscriptionAccess {
    public boolean isOwner(String caller, String resourceId) {
        // Called from SpEL expression: @subscriptionAccess.isOwner(...)
        Subscription sub = repository.findByIdAndOwner(resourceId, caller).orElse(null);
        return sub != null;
    }
}
```

**Key rules:**
- Always query by both resource ID and owner: `findByIdAndOwner(id, principal.getName())`
- Use `@PreAuthorize` with a policy bean for business-level checks
- Return **404** (not 403) for foreign rows to avoid leaking existence
- Scope JPA `@Query` clauses with owner/tenant from the principal, never from request params

---

## 2. Enumeration Prevention

**CWE-200** — *Information Exposure Through Throttling / Enumeration*

### The Problem

Sequential IDs (SUB-1001, SUB-1002, ...) make enumeration trivial. Even with proper ownership checks, sequential IDs combined with distinguishable responses (200 vs 404) leak the total count of records.

```
GET /subscriptions/SUB-1001 → 200  (Alice's)
GET /subscriptions/SUB-1002 → 404  (exists but Bob doesn't own it)
GET /subscriptions/SUB-9999 → 404  (doesn't exist)
// Bob can distinguish "exists but not mine" from "doesn't exist"
```

### The Fix

Use non-sequential IDs and return uniform responses.

```java
// ✅ SAFE — UUIDs, no pattern to guess
@Entity
public class Subscription {
    @Id
    private String id;  // UUID: "550e8400-e29b-41d4-a716-446655440000"

    @PrePersist
    void onCreate() {
        this.id = UUID.randomUUID().toString();
    }
}

// ✅ SAFE — same 404 for "not found" and "not owned"
@PreAuthorize("@subscriptionAccess.isOwner(authentication.name, #id)")
public ResponseEntity<?> getSubscription(@PathVariable String id) {
    Subscription sub = repository.findByIdAndOwner(id, authentication.getName())
        .orElseThrow(() -> new NotFoundException());  // always 404
    return ResponseEntity.ok(sub);
}
```

**ID generation options:**

| Type | Format | Collision Risk | Orderable |
|------|--------|----------------|-----------|
| UUID v4 | `550e8400-e29b...` | Negligible | No |
| Snowflake | `18446744073709551615` | None | Yes |
| ULID | `01ARZ3NDEKTSV4RRFFQ69G5FAV` | Negligible | Yes |
| NanoID | `V1StGXR8_Z5jdHi6B-myT` | Negligible | No |

**Key rules:**
- Use UUIDs, Snowflake IDs, or ULIDs — never auto-increment integers in URLs
- Return 404 for both "not found" and "not owned" — authorization should not be an oracle
- Consider hiding IDs entirely in external-facing APIs; use opaque references

---

## 3. CSRF Protection

**CWE-352** — *Cross-Site Request Forgery on State-Changing Endpoint*

### The Problem

If a state-changing operation is reachable via GET, an attacker can trigger it with a simple link or image tag. The victim's browser automatically sends cookies, making the request authenticated without their knowledge.

```html
<!-- ❌ VULNERABLE — state change via GET -->
<img src="http://app:8082/subscriptions/SUB-1001/cancel">
<!-- or -->
<a href="http://app:8082/subscriptions/SUB-1001/cancel">Click me</a>
```

```java
// ❌ VULNERABLE — GET that mutates state
@GetMapping("/subscriptions/{id}/cancel")
public ResponseEntity<?> cancelSubscription(@PathVariable String id) {
    subscriptionService.cancel(id);  // state change via GET!
    return ResponseEntity.ok("cancelled");
}
```

### The Fix

Use POST/PUT/PATCH/DELETE for all state changes. Never mutate state on GET.

```java
// ✅ SAFE — POST for state change
@PostMapping("/subscriptions/{id}/cancel")
@PreAuthorize("@subscriptionAccess.isOwner(authentication.name, #id)")
public ResponseEntity<?> cancelSubscription(@PathVariable String id) {
    subscriptionService.cancel(id);
    return ResponseEntity.ok("cancelled");
}

// ✅ SAFE — Spring Security CSRF protection
@Bean
SecurityFilterChain chain(HttpSecurity http) {
    http.csrf(csrf -> csrf
        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
    );
    return http.build();
}
```

**Key rules:**
- **Never** mutate state on GET — GET must be safe and idempotent
- Use POST for create/cancel, PUT for full update, PATCH for partial update, DELETE for removal
- Enable CSRF protection for cookie-based auth (disabled by default for REST APIs with JWT)
- For JWT stateless APIs, CSRF protection can stay disabled — but never use GET for mutations

---

## 4. HTTP Method Semantics

**CWE-650** — *Misinterpretation of Request / Unsafe GET with Side Effects*

### The Problem

HTTP semantics assume GET is safe and idempotent. When a GET endpoint has side effects, it breaks caching proxies, browser prefetching, link preloading, and accessibility tools that pre-fetch links — all of which can trigger unintended operations.

```java
// ❌ VULNERABLE — GET mutates state
@GetMapping("/subscriptions/{id}/cancel")
public ResponseEntity<?> cancel(...) {
    subscriptionService.cancel(id);  // side effect on GET
}
// A browser prefetch, a proxy cache miss, or a web crawler triggers this.
```

### The Fix

Follow HTTP semantics strictly.

```java
// ✅ SAFE — GET reads only
@GetMapping("/subscriptions/{id}")
public ResponseEntity<?> getSubscription(@PathVariable String id) {
    return ResponseEntity.ok(subscriptionService.findById(id));
}

// ✅ SAFE — POST/PUT/DELETE for state changes
@PostMapping("/subscriptions/{id}/cancel")
@PreAuthorize("@subscriptionAccess.isOwner(authentication.name, #id)")
public ResponseEntity<?> cancelSubscription(@PathVariable String id) { ... }

@PutMapping("/subscriptions/{id}")
@PreAuthorize("@subscriptionAccess.isOwner(authentication.name, #id)")
public ResponseEntity<?> updateSubscription(@PathVariable String id,
                                            @Valid @RequestBody UpdateRequest req) { ... }

@DeleteMapping("/subscriptions/{id}")
@PreAuthorize("@subscriptionAccess.isOwner(authentication.name, #id)")
public ResponseEntity<?> deleteSubscription(@PathVariable String id) { ... }
```

**HTTP method mapping:**

| Operation | Method | Idempotent? | Safe? |
|-----------|--------|-------------|-------|
| Create | POST | No | No |
| Read | GET | Yes | Yes |
| Full Update | PUT | Yes | No |
| Partial Update | PATCH | Yes | No |
| Delete | DELETE | Yes | No |
| Cancel | POST | No | No |

**Key rules:**
- GET = read-only, safe, idempotent
- POST = create or non-idempotent state change
- PUT/PATCH/DELETE = idempotent state change
- If a GET endpoint has side effects, it's a design flaw — refactor immediately

---

## 5. Default-Deny Configuration

**CWE-285** — *Improper Authorization / Insecure Default Permissions*

### The Problem

A `permitAll()` rule added for development or testing can leave sensitive endpoints accessible to anonymous callers. Without a default-deny tail, any new endpoint added without an explicit security rule becomes public.

```java
// ❌ VULNERABLE — no default-deny tail
@Override
protected void configure(HttpSecurity http) {
    http.requestMatcher("/vuln2/**")
        .authorizeHttpRequests(a -> a
            .requestMatchers("/vuln2/admin/subscriptions").permitAll()
            .requestMatchers("/vuln2/internal/metrics").permitAll()
            // No .anyRequest().denyAll() — everything else is implicitly permitted!
        );
}

// A new endpoint added later is anonymous
@GetMapping("/debug/secret")
public ResponseEntity<?> secret() {
    return ResponseEntity.ok("sensitive data with PII");  // public!
}
```

### The Fix

End every security chain with explicit deny.

```java
// ✅ SAFE — default deny
@Bean
SecurityFilterChain chain(HttpSecurity http) {
    http.authorizeHttpRequests(a -> a
        .requestMatchers("/public/**").permitAll()
        .requestMatchers("/admin/**").hasRole("ADMIN")
        .requestMatchers("/internal/**").hasRole("ADMIN")
        .anyRequest().denyAll()  // everything else is rejected
    );
    return http.build();
}

// ✅ SAFE — method-level second check
@PreAuthorize("hasRole('ADMIN')")
@GetMapping("/admin/subscriptions")
public ResponseEntity<?> allSubscriptions() { ... }
```

**Key rules:**
- Always end with `.anyRequest().denyAll()` (or `.anyRequest().authenticated()` for fully private APIs)
- Every `permitAll()` must be explicit, reviewed, and justified
- Add method-level `@PreAuthorize` as a second defense layer
- Default to deny: explicit allow is the only path
- Log denied requests with actor, resource, and outcome for early IDOR probe detection

---

## 6. Security Filter Chain Integrity

**CWE-1188** — *Insecure Default Initialization of Resource / Security Filter Bypass*

### The Problem

`WebSecurityCustomizer.ignoring().requestMatchers(...)` completely removes the security filter chain for matched paths. This is not just `permitAll()` — it bypasses authentication, CSRF, session management, CORS, and every other security layer. The path becomes invisible to the security framework.

```java
// ❌ VULNERABLE — ignoring() bypasses the entire security chain
@Bean
public WebSecurityCustomizer webSecurityCustomizer() {
    return (web) -> web.ignoring()
        .requestMatchers("/vuln2/bypass/**");  // NO filters at all!
}

// Even SecurityContextHolder is not populated on these paths
@GetMapping("/bypass/whoami")
public ResponseEntity<?> whoami() {
    // SecurityContextHolder.getContext().getAuthentication() == null
    return ResponseEntity.ok("anonymous");
}
```

### The Fix

Never call `.ignoring()`. Use `permitAll()` for public paths so they stay visible in the security chain.

```java
// ✅ SAFE — permitAll() stays visible in the security chain
@Bean
SecurityFilterChain chain(HttpSecurity http) {
    http
        .securityMatcher("/safe2/**")  // scope the chain explicitly
        .authorizeHttpRequests(a -> a
            .requestMatchers("/safe2/public/**").permitAll()
            .requestMatchers("/safe2/admin/**").hasRole("ADMIN")
            .anyRequest().authenticated()
        );
    return http.build();
}

// ❌ NEVER do this
@Bean
public WebSecurityCustomizer webSecurityCustomizer() {
    return (web) -> web.ignoring().requestMatchers("/public/**");
}
```

**Key rules:**
- Never use `.ignoring()` — it removes paths from security inspection entirely
- Use `permitAll()` so every public path is visible and reviewable
- Use `securityMatcher()` to scope filter chains to specific path prefixes
- Every `permitAll()` should be a line a reviewer can see and argue about
- Prefer explicit `permitAll()` over implicit bypass

---

## 7. Tenant Boundary Enforcement

**CWE-863** — *Incorrect Authorization (Tenant Boundary from Request Parameter)*

### The Problem

When a tenant, user, or role is derived from a request parameter instead of the authenticated principal, an attacker can impersonate any tenant by changing one query parameter.

```java
// ❌ VULNERABLE — tenant from request parameter
@GetMapping("/tenant/subscriptions")
public ResponseEntity<?> getTenantSubscriptions(@RequestParam String tenantId) {
    // Bob (tenant-A) reads tenant-B's data
    return ResponseEntity.ok(subscriptionRepository.findByTenant(tenantId));
}
// GET /tenant/subscriptions?tenantId=tenant-B
```

### The Fix

Derive tenant from the authenticated principal, never from request parameters.

```java
// ✅ SAFE — tenant from principal (JWT claim or session attribute)
@GetMapping("/tenant/subscriptions")
public ResponseEntity<?> getTenantSubscriptions(Authentication auth) {
    String tenant = getTenantFromPrincipal(auth);  // from token, not from request
    return ResponseEntity.ok(subscriptionRepository.findByTenant(tenant));
}

// ✅ SAFE — validate tenant parameter against principal's tenant
@GetMapping("/tenant/subscriptions")
public ResponseEntity<?> getTenantSubscriptions(
        @RequestParam(required = false) String tenantId,
        Authentication auth) {
    
    String principalTenant = getTenantFromPrincipal(auth);
    
    if (tenantId != null && !tenantId.equals(principalTenant)) {
        throw new AccessDeniedException("Tenant mismatch");
    }
    
    return ResponseEntity.ok(subscriptionRepository.findByTenant(principalTenant));
}

// ✅ SAFE — JPA repository with tenant scope
public interface SubscriptionRepository extends JpaRepository<Subscription, String> {
    @Query("SELECT s FROM Subscription s WHERE s.tenant = :tenant")
    List<Subscription> findByTenant(@Param("tenant") String tenant);
}
```

**Key rules:**
- Always derive tenant from the authenticated principal (JWT claim, session attribute)
- If a tenant parameter is needed for filtering, validate it against the principal's tenant
- Scope all repository queries with tenant from the principal
- Never trust `tenantId` from `@RequestParam`, `@PathVariable`, or request body

---

## 8. Object-Level Authorization

**CWE-863** — *Vacuous Method Security (Insufficient Authorization Check)*

### The Problem

`@PreAuthorize("isAuthenticated()")` only checks that the caller has a valid token — it does NOT check ownership, role, or any business-level permission. Any logged-in user can access any resource.

```java
// ❌ VULNERABLE — isAuthenticated() is not authorization
@GetMapping("/profile/{username}")
@PreAuthorize("isAuthenticated()")  // any logged-in user can access
public ResponseEntity<?> getProfile(@PathVariable String username) {
    // Bob reads Alice's profile
    return ResponseEntity.ok(userRepository.findByUsername(username));
}
```

### The Fix

Use object-level authorization with a policy bean.

```java
// ✅ SAFE — object-level policy bean
@Component
public class UserPolicy {
    public boolean canView(String caller, String target) {
        return caller.equals(target) || hasRole("ADMIN");
    }

    public boolean canEdit(String caller, String target) {
        return caller.equals(target) || hasRole("ADMIN");
    }
}

// ✅ SAFE — method-level with policy
@GetMapping("/profile/{username}")
@PreAuthorize("@userPolicy.canView(authentication.name, #username)")
public ResponseEntity<?> getProfile(@PathVariable String username) {
    return ResponseEntity.ok(userRepository.findByUsername(username));
}

@PutMapping("/profile/{username}")
@PreAuthorize("@userPolicy.canEdit(authentication.name, #username)")
public ResponseEntity<?> updateProfile(@PathVariable String username,
                                       @Valid @RequestBody UpdateRequest req) {
    return ResponseEntity.ok(userRepository.findByUsername(username));
}
```

**Policy patterns:**

| Pattern | SpEL Expression | Use Case |
|---------|-----------------|----------|
| Self-only | `@policy.canAccess(authentication.name, #id)` | User profiles, own resources |
| Role-gated | `hasRole('ADMIN')` | Admin endpoints |
| Owner + Role | `hasRole('ADMIN') or @policy.isOwner(authentication.name, #id)` | Multi-tenant + personal |
| Relationship | `@policy.hasRelationship(authentication.name, #resourceId, 'FRIEND')` | Social graphs |

**Key rules:**
- Never rely on `isAuthenticated()` alone for resource-specific endpoints
- Extract authorization logic into policy beans for testability and reviewability
- Test each `(endpoint, caller, resource_ownership, expected_status)` matrix
- Log `authz_denied` with actor, resource, and outcome — denial spikes indicate IDOR probes

---

## 9. Privilege Escalation Prevention

**CWE-269** — *Improper Privilege Management (Client-Supplied Authorities)*

### The Problem

When user roles or authorities are derived from client input (query parameters, request body), an attacker can escalate privileges to any level, including admin. The server trusts the client to self-assign permissions.

```java
// ❌ VULNERABLE — authorities from request parameter
@PostMapping("/register")
public ResponseEntity<?> register(@RequestParam String authorities) {
    List<SimpleGrantedAuthority> auths = Arrays.stream(authorities.split(","))
        .map(SimpleGrantedAuthority::new)
        .toList();
    // Mallory registers with authorities=ROLE_ADMIN → gets ROLE_ADMIN
    User user = new User(req.getUsername(), passwordEncoder().encode(req.getPassword()));
    user.setAuthorities(auths);
    userRepository.save(user);
    return ResponseEntity.ok("registered with " + authorities);
}
```

### The Fix

Always assign fixed, server-side roles. Never map request parameters to `GrantedAuthority`.

```java
// ✅ SAFE — fixed USER role, no client input
@PostMapping("/register")
public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest req) {
    User user = new User(
        req.getUsername(),
        passwordEncoder().encode(req.getPassword())
    );
    user.setAuthorities(Set.of(new SimpleGrantedAuthority("USER")));  // fixed
    userRepository.save(user);
    return ResponseEntity.status(201).body("registered");
}

// ✅ SAFE — admin roles only via approval workflow
@PostMapping("/admin/users/{id}/promote")
@PreAuthorize("hasRole('ADMIN')")
public ResponseEntity<?> promoteUser(@PathVariable String id) {
    User user = userRepository.findById(id).orElseThrow();
    user.setAuthorities(Set.of(new SimpleGrantedAuthority("USER"),
                               new SimpleGrantedAuthority("ADMIN")));
    userRepository.save(user);
    return ResponseEntity.ok("promoted");
}
```

**Key rules:**
- Always assign fixed, server-side roles at registration
- Never map `@RequestParam` or `@RequestBody` fields to `GrantedAuthority`
- Admin roles should only be assigned by an admin action (approval workflow)
- Use DTOs to enforce boundaries — authorities are never part of client input

---

## 10. Mass Assignment Protection

**CWE-915** — *Improper Control of Dynamically Managed Object Resources*

### The Problem**

Mass assignment allows attackers to set arbitrary fields on domain objects, including role, authority, and ownership fields. When combined with client-supplied authorities (CWE-269), the authorization model is completely broken.

```java
// ❌ VULNERABLE — client can set authorities via JSON body
@PostMapping("/register")
public ResponseEntity<?> register(@RequestBody Map<String, String> body) {
    // Mallory sends: {"username": "mallory", "authorities": "ROLE_ADMIN"}
    User user = new User();
    user.setUsername(body.get("username"));
    user.setAuthorities(parseAuthorities(body.get("authorities")));  // mass assignment
    userRepository.save(user);
    return ResponseEntity.ok("registered");
}
```

### The Fix

Use explicit DTOs with only permitted fields. Never bind directly to domain entities.

```java
// ✅ SAFE — explicit DTO with only permitted fields
public record RegisterRequest(
    @NotBlank String username,
    @NotBlank @Size(min = 8) String password
    // No "authorities" field — client cannot send it
) {}

// ✅ SAFE — @JsonIgnoreProperties as defense-in-depth
@Entity
public class User {
    @JsonIgnoreProperties({"authorities", "role", "admin"})
    // Even if client sends these, Jackson ignores them
}

// ✅ SAFE — explicit field mapping
@PostMapping("/register")
public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest req) {
    User user = new User(req.username(), passwordEncoder().encode(req.password()));
    user.setAuthorities(Set.of(new SimpleGrantedAuthority("USER")));  // fixed
    userRepository.save(user);
    return ResponseEntity.status(201).body("registered");
}
```

**DTO best practices:**

| Pattern | Purpose |
|---------|---------|
| Explicit record/class DTO | Only include writable fields |
| `@JsonIgnoreProperties` | Ignore unknown/dangerous fields |
| `@JsonProperty` whitelist | Explicitly declare allowed properties |
| `@ModelAttribute` for forms | Bind only declared fields |

**Key rules:**
- Use DTOs with explicit field lists — never expose domain entities directly to API
- Apply `@JsonIgnoreProperties(ignoreUnknown = true)` as defense-in-depth
- Never accept `authorities`, `roles`, or `isAdmin` in any client input
- Audit entity-to-DTO mappings regularly for accidental field leaks

---

## Summary Checklist

| # | Control | CWE | Priority |
|---|---------|-----|----------|
| 1 | Query by ID + owner | CWE-639 | CRITICAL |
| 2 | UUIDs + 404 for foreign rows | CWE-200 | HIGH |
| 3 | POST for state changes | CWE-352, CWE-650 | CRITICAL |
| 4 | Default-deny tail | CWE-285, CWE-1188 | CRITICAL |
| 5 | No `.ignoring()` | CWE-1188 | CRITICAL |
| 6 | Tenant from principal | CWE-863 | CRITICAL |
| 7 | Object-level policy bean | CWE-863 | HIGH |
| 8 | Fixed server-side roles | CWE-269, CWE-915 | CRITICAL |
| 9 | DTOs + `@JsonIgnoreProperties` | CWE-915 | HIGH |
| 10 | Auth matrix testing | — | HIGH |

---

## Detection & Review Heuristics

| Check | Command / Pattern |
|-------|-------------------|
| `permitAll` ratio | `git grep -c '@*Mapping' | git grep -c '@PreAuthorize'` — if 40:3, 3 endpoints are exposed |
| MR diff check | `git diff -U0 | grep 'permitAll\|ignoring()'` |
| Missing default-deny | Search for `.anyRequest()` — should end with `denyAll()` or `authenticated()` |
| GET mutations | `git grep -n '@GetMapping' | grep -v 'ResponseEntity.*get\|findById'` |
| Tenant from params | `git grep '@RequestParam.*tenant'` — should not exist |
| Authorities from input | `git grep 'SimpleGrantedAuthority'` — should only appear in fixed assignments |

---

## References

- [OWASP Broken Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Broken_Access_Control_Cheat_Sheet.html)
- [OWASP CSRF Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Spring Security Method Security](https://docs.spring.io/spring-security/reference/servlet_authorization_method.html)
- [OWASP Mass Assignment](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
