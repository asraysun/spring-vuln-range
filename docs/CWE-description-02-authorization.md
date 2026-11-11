# CWE Reference — §02 Authorization and Access Control

CWEs extracted from `docs/02-authorization.md` with developer-focused comments.

---

## CWE-639 — Authorization Bypass Through User-Controlled Key (IDOR / BOLA)

**Why it matters:** This is arguably the most common and most dangerous web vulnerability. When an endpoint uses a client-supplied identifier to fetch a resource without verifying that the caller owns that resource, any authenticated user can read, modify, or delete any other user's data.

**Attack vector in Spring:**
```java
// VULNERABLE — no ownership check
@GetMapping("/subscriptions/{id}")
public ResponseEntity<?> getSubscription(@PathVariable String id) {
    // Returns ANY subscription — bob can read alice's data
    Subscription sub = subscriptionRepository.findById(id).orElseThrow();
    return ResponseEntity.ok(sub);
}
```
Bob calls `GET /vuln2/subscriptions/SUB-1001` and gets Alice's subscription data. The only check is `isAuthenticated()` — no ownership verification.

**How to prevent:**
- Query by both ID and owner:
```java
// SAFE
@GetMapping("/subscriptions/{id}")
@PreAuthorize("@subscriptionAccess.isOwner(authentication.name, #id)")
public ResponseEntity<?> getSubscription(@PathVariable String id) {
    Subscription sub = subscriptionRepository.findByIdAndOwner(id, authentication.getName())
        .orElseThrow(() -> new NotFoundException());
    return ResponseEntity.ok(sub);
}
```
- Or use a repository method with owner predicate:
```java
Optional<Subscription> findByIdAndOwner(String id, String owner);
```
- Return 404 (not 403) for foreign rows to avoid enumeration.

---

## CWE-200 — Information Exposure Through Throttling / Enumeration

**Why it matters:** Sequential IDs (SUB-1001, SUB-1002, ...) make enumeration trivial. An attacker can iterate through all resources without any authorization bypass — they just guess the IDs. Even with proper ownership checks, sequential IDs combined with distinguishable error responses (200 vs 404) leak the total count of records.

**Attack vector in Spring:**
```java
// VULNERABLE — sequential IDs allow enumeration
// GET /vuln2/subscriptions/SUB-1001 → 200 (alice's)
// GET /vuln2/subscriptions/SUB-1002 → 404 (bob's, but bob doesn't own it)
// GET /vuln2/subscriptions/SUB-9999 → 404 (doesn't exist)
// Bob can distinguish "exists but not mine" from "doesn't exist"
```

**How to prevent:**
- Use non-sequential IDs (UUIDs, Snowflake IDs, ULIDs).
- Return 404 for both "not found" and "not owned" — authorization should not be an oracle.
```java
// SAFE — non-sequential IDs + uniform response
// UUIDs: "550e8400-e29b-41d4-a716-446655440000"
// No pattern to guess
```

---

## CWE-352 — Cross-Site Request Forgery (CSRF) on State-Changing Endpoint

**Why it matters:** If a state-changing operation (cancel, delete, transfer) is reachable via GET, an attacker can trigger it with a simple link or image tag. A logged-in user's browser automatically sends cookies, making the request authenticated without the user's knowledge.

**Attack vector in Spring:**
```java
// VULNERABLE — GET that mutates state
@GetMapping("/subscriptions/{id}/cancel")
public ResponseEntity<?> cancelSubscription(@PathVariable String id) {
    subscriptionService.cancel(id);  // state change via GET!
    return ResponseEntity.ok("cancelled");
}
```
Attacker sends victim a link: `<img src="http://app:8082/vuln2/subscriptions/SUB-1001/cancel">`.
The browser fetches it with the session cookie — subscription is cancelled.

**How to prevent:**
- Use POST/PUT/PATCH/DELETE for all state changes. Never mutate state on GET.
```java
// SAFE — POST for state change
@PostMapping("/subscriptions/{id}/cancel")
@PreAuthorize("@subscriptionAccess.isOwner(authentication.name, #id)")
public ResponseEntity<?> cancelSubscription(@PathVariable String id) {
    subscriptionService.cancel(id);
    return ResponseEntity.ok("cancelled");
}
```
- Enable CSRF protection in Spring Security for cookie-based auth.

---

## CWE-650 — Misinterpretation of Request / Unsafe GET with Side Effects

**Why it matters:** HTTP semantics assume GET is safe and idempotent. When a GET endpoint has side effects (state changes), it breaks caching proxies, browser prefetching, link preloading, and accessibility tools that pre-fetch links — all of which can trigger unintended operations.

**Attack vector in Spring:**
```java
// VULNERABLE — GET mutates state
@GetMapping("/subscriptions/{id}/cancel")
public ResponseEntity<?> cancel(...) {
    subscriptionService.cancel(id);  // side effect on GET
}
```
A browser prefetch, a proxy cache miss, or a web crawler can trigger this. The same request repeated changes state each time.

**How to prevent:**
- Follow HTTP semantics: GET = read-only, POST/PUT/DELETE = state-changing.
- If you need an idempotent state change, use PATCH with a well-defined idempotency key.

---

## CWE-285 — Improper Authorization / Insecure Default Permissions

**Why it matters:** A `permitAll()` rule that was added for development or testing can leave sensitive endpoints accessible to anonymous callers. If the endpoint returns data with PII (personally identifiable information), this is a full data breach.

**Attack vector in Spring:**
```java
// VULNERABLE — permitAll() on admin endpoint
@Override
protected void configure(HttpSecurity http) {
    http.requestMatcher("/vuln2/**")
        .authorizeHttpRequests(a -> a
            .requestMatchers("/vuln2/admin/subscriptions").permitAll()  // anyone!
            .requestMatchers("/vuln2/internal/metrics").permitAll()     // anyone!
            .anyRequest().authenticated()
        );
}

// This endpoint returns PII — subscription data with names, emails
@GetMapping("/admin/subscriptions")
public ResponseEntity<?> allSubscriptions() {
    return ResponseEntity.ok(subscriptionRepository.findAll());
}
```

**How to prevent:**
- Use explicit role-based protection on admin/internal endpoints:
```java
// SAFE
http.requestMatcher("/safe2/**")
    .authorizeHttpRequests(a -> a
        .requestMatchers("/safe2/admin/**").hasRole("ADMIN")
        .anyRequest().authenticated()
    );
```
- Apply `@PreAuthorize("hasRole('ADMIN')")` at the method level as a second check.
- Default to deny: `.anyRequest().denyAll()` at the end of the chain.

---

## CWE-1188 — Insecure Default Initialization of Resource / Security Filter Bypass

**Why it matters:** `WebSecurityCustomizer.ignoring().requestMatchers(...)` completely removes the security filter chain for matched paths. This is not just `permitAll()` — it bypasses authentication, CSRF protection, session management, CORS filters, and every other security layer. The path becomes invisible to the security framework.

**Attack vector in Spring:**
```java
// VULNERABLE — ignoring() bypasses the entire security chain
@Bean
public WebSecurityCustomizer webSecurityCustomizer() {
    return (web) -> web.ignoring()
        .requestMatchers("/vuln2/bypass/**");  // NO filters at all!
}

// This endpoint is completely unprotected — no auth, no CSRF, no session mgmt
@GetMapping("/bypass/whoami")
public ResponseEntity<?> whoami() {
    // Even SecurityContextHolder is not populated!
    return ResponseEntity.ok("anonymous");
}
```

**How to prevent:**
- Never call `.ignoring()`. If a path must be public, use `permitAll()` explicitly:
```java
// SAFE — permitAll() stays visible in the security chain
http.authorizeHttpRequests(a -> a
    .requestMatchers("/public/**").permitAll()  // visible, reviewable
    .anyRequest().authenticated()
);
```
- Every `permitAll()` becomes a line a reviewer can see and argue about.
- Use `securityMatcher()` to scope filter chains explicitly.

---

## CWE-863 — Incorrect Authorization (Tenant Boundary from Request Parameter)

**Why it matters:** When a tenant, user, or role is derived from a request parameter instead of the authenticated principal, an attacker can impersonate any tenant. The authorization check is trivially bypassed by changing one query parameter.

**Attack vector in Spring:**
```java
// VULNERABLE — tenant from request parameter
@GetMapping("/tenant/subscriptions")
public ResponseEntity<?> getTenantSubscriptions(@RequestParam String tenantId) {
    // Bob can read Alice's tenant data by changing tenantId
    return ResponseEntity.ok(subscriptionRepository.findByTenant(tenantId));
}
```
Bob (tenant-A) calls `GET /vuln2/tenant/subscriptions?tenantId=tenant-B` and gets tenant-B's data.

**How to prevent:**
- Derive tenant from the authenticated principal, never from request parameters:
```java
// SAFE — tenant from principal
@GetMapping("/tenant/subscriptions")
public ResponseEntity<?> getTenantSubscriptions(Authentication auth) {
    String tenant = auth.getTenant();  // from token, not from request
    return ResponseEntity.ok(subscriptionRepository.findByTenant(tenant));
}
```
- If a tenant parameter is needed for filtering, validate it against the principal's tenant.

---

## CWE-863 — Vacuous Method Security (Insufficient Authorization Check)

**Why it matters:** `@PreAuthorize("isAuthenticated()")` only checks that the caller has a valid token — it does NOT check ownership, role, or any business-level permission. An endpoint protected only by `isAuthenticated()` is accessible to any valid user, regardless of whether they should have access to the specific resource.

**Attack vector in Spring:**
```java
// VULNERABLE — isAuthenticated() is not authorization
@GetMapping("/profile/{username}")
@PreAuthorize("isAuthenticated()")  // any logged-in user can access
public ResponseEntity<?> getProfile(@PathVariable String username) {
    // Bob can read Alice's profile
    return ResponseEntity.ok(userRepository.findByUsername(username));
}
```

**How to prevent:**
- Use object-level authorization with a policy bean:
```java
// SAFE — object-level policy
@PreAuthorize("@userPolicy.canView(authentication.name, #username)")
public ResponseEntity<?> getProfile(@PathVariable String username) {
    return ResponseEntity.ok(userRepository.findByUsername(username));
}

// Policy bean
@Component
class UserPolicy {
    boolean canView(String caller, String target) {
        return caller.equals(target);  // or has admin role
    }
}
```
- Never rely on `isAuthenticated()` alone for resource-specific endpoints.

---

## CWE-269 — Improper Privilege Management (Client-Supplied Authorities)

**Why it matters:** When user roles or authorities are derived from client input (query parameters, request body), an attacker can escalate their privileges to any level, including admin. The server trusts the client to self-assign permissions.

**Attack vector in Spring:**
```java
// VULNERABLE — authorities from request parameter
@PostMapping("/register")
public ResponseEntity<?> register(@RequestParam String authorities) {
    // Mallory registers with authorities=ROLE_ADMIN
    List<SimpleGrantedAuthority> auths = Arrays.stream(authorities.split(","))
        .map(SimpleGrantedAuthority::new)
        .toList();
    // Mallory gets ROLE_ADMIN
    return ResponseEntity.ok("registered with " + authorities);
}
```

**How to prevent:**
- Always assign fixed, server-side roles:
```java
// SAFE — fixed USER role, no client input
@PostMapping("/register")
public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest req) {
    User user = new User(req.getUsername(), passwordEncoder().encode(req.getPassword()));
    user.setAuthorities(Set.of(new SimpleGrantedAuthority("USER")));  // fixed
    userRepository.save(user);
    return ResponseEntity.status(201).body("registered");
}
```
- Never map request parameters to `GrantedAuthority`.
- Admin roles should only be assigned by an admin action (approval workflow).

---

## CWE-915 — Improper Control of Dynamically Managed Object Resources (Mass Assignment)

**Why it matters:** CWE-915 in the context of authorization refers to privilege escalation through mass assignment of authorities or roles. When the server accepts role/authority values from the client, the authorization model is completely broken — every user can grant themselves any privilege.

**Attack vector in Spring:**
```java
// VULNERABLE — authorities from client = privilege escalation
@PostMapping("/register?authorities=ROLE_ADMIN")
public ResponseEntity<?> register(...) {
    // The query param becomes the user's authority
    // CWE-915: dynamically managed object resource (the authority list)
    // is controlled by the attacker
}
```

**How to prevent:**
- Same as CWE-269: fixed server-side roles, DTO boundaries, no authority mapping from input.
- Use `@JsonIgnoreProperties(ignoreUnknown = true)` or explicit DTOs to prevent field injection.

---

## CWE-1188 — Insecure Default Configuration / Missing Default-Deny

**Why it matters:** When the security filter chain does not end with `.anyRequest().denyAll()` (or `.authenticated()`), unmatched paths implicitly fall through to `permitAll()`. Any new endpoint added without an explicit security rule becomes public. This is the absence of a default-deny posture.

**Attack vector in Spring:**
```java
// VULNERABLE — no default-deny tail
http.authorizeHttpRequests(a -> a
    .requestMatchers("/vuln2/admin/**").hasRole("ADMIN")  // only explicit rules
    // No .anyRequest().denyAll() — everything else is implicitly permitted!
);

// A new endpoint /vuln2/debug/secret added later is anonymous
@GetMapping("/debug/secret")
public ResponseEntity<?> secret() {
    return ResponseEntity.ok("sensitive data");  // public!
}
```

**How to prevent:**
- Always end the chain with explicit deny:
```java
// SAFE — default deny
http.authorizeHttpRequests(a -> a
    .requestMatchers("/public/**").permitAll()
    .requestMatchers("/admin/**").hasRole("ADMIN")
    .anyRequest().denyAll()  // everything else is rejected
);
```
- Every new endpoint must be explicitly authorized — there is no implicit permission.
