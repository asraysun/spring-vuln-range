# Spring Security: How to Prevent Authentication & Token Vulnerabilities

A practical guide to securing Spring Boot authentication, sessions, tokens, and cryptographic operations — covering 14 CWEs found in real Spring applications.

---

## Table of Contents

1. [Password Storage](#1-password-storage)
2. [Brute Force Protection](#2-brute-force-protection)
3. [User Enumeration Prevention](#3-user-enumeration-prevention)
4. [Session Fixation](#4-session-fixation)
5. [Cookie Hardening](#5-cookie-hardening)
6. [JWT Security](#6-jwt-security)
7. [Cryptographic Key Management](#7-cryptographic-key-management)
8. [Random Value Generation](#8-random-value-generation)
9. [Constant-Time Comparisons](#9-constant-time-comparisons)
10. [Session Expiration](#10-session-expiration)
11. [Authorization Integrity](#11-authorization-integrity)

---

## 1. Password Storage

**CWE-916** — *Use of One-Way Hash without a Salt*

### The Problem

Using unsalted, fast hash functions like MD5 or SHA-256 for passwords allows attackers to crack thousands of passwords per second via rainbow tables or GPU-accelerated brute force.

```java
// ❌ VULNERABLE
String hash(String pwd) {
    return DigestUtils.md5Hex(pwd);  // no salt, fast, reversible via rainbow tables
}
```

### The Fix

Use **Argon2id** (preferred) or **BCrypt** with a tuned work factor. These are intentionally slow and include a random salt.

```java
// ✅ SAFE — Spring Security bean
@Bean
PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(12);  // cost factor ≥ 12
}

// ✅ BETTER — Argon2id
@Bean
PasswordEncoder passwordEncoder() {
    return new Argon2PasswordEncoder(16, 64, 1, 65536, 3);
    // parallelism=1, memory=64MB, iterations=1, hashLength=32
}
```

**Key rules:**
- Never use MD5, SHA-1, or SHA-256 for passwords
- Work factor should be tuned so hashing takes ~100ms on production hardware
- Spring Security auto-configures `PasswordEncoder` beans — don't replace them with `DigestUtils`

---

## 2. Brute Force Protection

**CWE-307** — *Restriction of Lifetime of Authenticating Credentials (No Throttling)*

### The Problem

Without rate limiting, an attacker can fire thousands of login attempts per second, exhausting even long passwords.

```java
// ❌ VULNERABLE
@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginRequest req) {
    // No throttling — 10,000 requests/second possible
    return authenticate(req.getUsername(), req.getPassword());
}
```

### The Fix

Implement **per-account AND per-IP rate limiting**.

```java
// ✅ SAFE — using Bucket4j
@Bean
public Filter throttleFilter(RateLimitService rateLimitService) {
    return new OncePerRequestFilter() {
        @Override
        protected void doFilterInternal(HttpServletRequest request,
                                        HttpServletResponse response,
                                        FilterChain filterChain) {
            String key = getThrottleKey(request);
            if (!rateLimitService.tryAcquire(key)) {
                response.setStatus(429);
                response.setHeader("Retry-After", "300");  // 5 minutes
                response.getWriter().write("Too Many Attempts");
                return;
            }
            filterChain.doFilter(request, response);
        }
    };
}
```

**Implementation options:**
| Approach | Scale | Persistence |
|----------|-------|-------------|
| `Bucket4j` (in-memory) | Single instance | Lost on restart |
| Redis + Spring Session | Distributed | Survives restarts |
| Spring Cloud Gateway | Edge level | Centralized |

**Key rules:**
- Return `429 Too Many Attempts` with a `Retry-After` header
- Use generic error messages to prevent user enumeration
- Track limits per username AND per source IP

---

## 3. User Enumeration Prevention

**CWE-204** — *Response Discrepancy / Information Exposure Through Timing Differences*

### The Problem

Different error messages or response times for "user not found" vs "wrong password" let attackers enumerate valid usernames.

```java
// ❌ VULNERABLE
if (user == null) {
    return ResponseEntity.status(401).body("User not found");
}
if (!matches) {
    return ResponseEntity.status(401).body("Wrong password");
}
```

Timing also leaks info: hashing a non-existent user is faster (no bcrypt call) than hashing an existing one.

### The Fix

Return the **same response** and **same timing** regardless of whether the user exists.

```java
// ✅ SAFE — constant response + constant timing
@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginRequest req) {
    User user = repository.findByUsername(req.getUsername());
    
    String passwordToCheck = user != null ? user.getPassword() : DUMMY_HASH;
    boolean matches = passwordEncoder().matches(req.getPassword(), passwordToCheck);
    
    // Always returns the same response
    if (!matches) {
        return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
    }
    
    return authenticate(user, req.getPassword());
}
```

**Key rules:**
- Always return the same HTTP status and response body for login failures
- Always run the password hasher (even for non-existent users) to equalize timing
- Use a dummy hash when the user doesn't exist: `passwordEncoder().matches(pwd, DUMMY_HASH)`

---

## 4. Session Fixation

**CWE-384** — *Session Fixation*

### The Problem

If the session ID doesn't change after authentication, an attacker who obtained the session cookie before login (via XSS, log files, or referrer leaks) can hijack the account.

```java
// ❌ VULNERABLE — session ID survives login
@GetMapping("/session-id")
public String getSessionId(HttpServletRequest req) {
    return req.getSession().getId();  // same ID before and after login
}
```

### The Fix

Invalidate the old session and create a new one upon authentication.

```java
// ✅ SAFE — Spring Security config
@Bean
SecurityFilterChain chain(HttpSecurity http) {
    http.sessionManagement(s -> s
        .sessionFixation(SessionFixationMigrator::migrateSession)
        .sessionFixationDelegate(session -> {
            // custom logic if needed
        })
    );
    return http.build();
}
```

**Key rules:**
- Call `sessionFixation().migrateSession()` in Spring Security config
- Also set session timeouts: idle timeout (15 min) and absolute timeout (8 hours)
- Log out the user and force re-login on privilege changes

---

## 5. Cookie Hardening

**CWE-1004** — *HTTP Cookie Without HttpOnly Flag*  
**CWE-614** — *Secure Communication Channel Not Used (Cookie Without Secure Flag)*

### The Problem

- Without `HttpOnly`: JavaScript (including injected scripts from XSS) can read the session cookie via `document.cookie`
- Without `Secure`: Cookies are sent over plain HTTP and can be captured on unencrypted connections

```java
// ❌ VULNERABLE
Cookie cookie = new Cookie("JSESSIONID", id);
// No flags set — readable by JS and sent over HTTP
resp.addCookie(cookie);
```

### The Fix

Set all three security flags on authentication cookies.

```java
// ✅ SAFE — Spring Security config
http.sessionManagement(s -> s.sessionCookieConfig(c -> {
    c.setHttpOnly(true);    // not accessible from JavaScript
    c.setSecure(true);      // only sent over HTTPS
    // SameSite configured via Spring Boot property
}));

// application.yml
server:
  cookie:
    same-site: lax  # or "strict" for high-security apps
```

**Key rules:**
- `HttpOnly = true` — prevents XSS-based cookie theft
- `Secure = true` — prevents MITM capture over HTTP
- `SameSite = Lax` or `Strict` — prevents CSRF via browser navigation
- Always serve the application over TLS in production
- Use HSTS (`Strict-Transport-Security`) to prevent downgrade attacks

---

## 6. JWT Security

**CWE-347** — *Improper Verification of Cryptographic Signature*

### The Problem

Accepting `alg: none` in JWT means the signature is completely bypassed. An attacker can forge any token with any payload without knowing the secret.

```java
// ❌ VULNERABLE — default parser accepts alg: none
public Claims verify(String token) {
    return Jwts.parser()               // accepts alg: none by default in older jjwt
               .parseClaimsJws(token)
               .getBody();
}
// Attacker payload: {"alg":"none"}.{"role":"ADMIN","sub":"attacker"}.
```

### The Fix

Pin the algorithm explicitly — never use a parser that accepts any algorithm.

```java
// ✅ SAFE — algorithm is a constant, not parsed from the token
private static final SignatureAlgorithm SIG_ALG = SignatureAlgorithm.HS256;
private static final byte[] SECRET_KEY;

static {
    try {
        SECRET_KEY = Base64.getDecoder().decode(System.getenv("JWT_SECRET"));
    } catch (Exception e) {
        throw new IllegalStateException("JWT_SECRET env var required");
    }
}

public Claims verify(String token) {
    return Jwts.parser()
               .setSigningKey(SECRET_KEY)   // key required, alg is fixed
               .parseClaimsJws(token)
               .getBody();
}
```

**Key rules:**
- Pin `alg` to a specific algorithm (HS256, ES256, RS256)
- Use jjwt 0.12+ where `alg: none` is rejected by default
- Consider using EC/RS keys (ES256, RS256) for better security and HSM compatibility

---

## 7. Cryptographic Key Management

**CWE-321** — *Use of Hard-coded Cryptographic Key*  
**CWE-521** — *Weak Password Requirements for Cryptographic Operations*

### The Problem

A hard-coded, weak secret (e.g., `"mysecret"`) used for HMAC signing is visible in source code and trivially brute-forced.

```java
// ❌ VULNERABLE — dictionary word, fallback in config
@Value("${m01.jwt-secret:password}")
private SecretKey key;  // 8 chars, dictionary word, in source

// ❌ VULNERABLE — static key in compiled code
public class StaticKeyRememberMeServices {
    private static final byte[] KEY = "a-static-key-for-remember-me".getBytes();
}
```

### The Fix

Store secrets in environment variables, Vault, or Kubernetes Secrets. Use keys ≥ 256 bits.

```java
// ✅ SAFE — required env var, no fallback, validated at startup
@Value("${JWT_SECRET}")
private String secret;

@PostConstruct
void init() {
    byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
    if (keyBytes.length < 32) {
        throw new IllegalStateException("JWT_SECRET must be ≥ 256 bits");
    }
    this.key = new SecretKeySpec(keyBytes, "HmacSHA256");
}

// ✅ Generate a secure key
// java -jar jjwt-cli-0.12.5.jar genkey -t HS256 -l 256
// Or in code:
byte[] secureKey = new byte[32];
new SecureRandom().nextBytes(secureKey);
```

**Key rules:**
- JWT HMAC keys must be ≥ 256 bits (32 bytes)
- Never use dictionary words or short secrets
- Never include fallback defaults in production code
- Store in Vault, environment variables, or K8s Secrets
- Rotate keys periodically and implement key versioning

---

## 8. Random Value Generation

**CWE-330** — *Use of Insufficiently Random Values*

### The Problem

`java.util.Random` is seeded by system time (milliseconds). Observing one token lets you predict all future (and past) tokens.

```java
// ❌ VULNERABLE — predictable reset code
int generateResetCode() {
    Random rand = new Random();  // seeded by System.nanoTime()
    return rand.nextInt(9_000_000) + 1_000_000;  // 6 digits, predictable
}
```

### The Fix

Use `SecureRandom`, which reads from the OS entropy pool.

```java
// ✅ SAFE — OS entropy pool
private static final SecureRandom SECURE_RANDOM = new SecureRandom();

int generateResetCode() {
    return SECURE_RANDOM.nextInt(9_000_000) + 1_000_000;  // 8 digits
}

// Store only a digest, not plaintext
String code = String.valueOf(generateResetCode());
String storedHash = passwordEncoder().encode(code);  // BCrypt hash
repository.saveResetCode(user, storedHash, Duration.ofMinutes(5));
```

**Key rules:**
- Always use `SecureRandom` for security-sensitive values (tokens, reset codes, CSRF tokens)
- Store only a hash of the code in the database
- Expire codes after 5 minutes
- Mark as single-use after redemption
- Rate-limit password reset requests per email

---

## 9. Constant-Time Comparisons

**CWE-208** — *Observable Timing Discrepancy*

### The Problem

Non-constant-time comparison of secrets lets an attacker determine the correct value byte-by-byte by measuring response times.

```java
// ❌ VULNERABLE — String.equals() returns early on first mismatch
boolean valid(String provided, String expected) {
    return provided.equals(expected);  // timing leak
}
// "abc..." vs "xyz..." returns faster than "abc..." vs "abd..."
```

### The Fix

Use `MessageDigest.isEqual()` which compares all bytes regardless of where they differ.

```java
// ✅ SAFE — compares all bytes
boolean valid(byte[] a, byte[] b) {
    return MessageDigest.isEqual(a, b);
}

// ✅ For strings, convert to bytes first
boolean validString(String a, String b) {
    return MessageDigest.isEqual(
        a.getBytes(StandardCharsets.UTF_8),
        b.getBytes(StandardCharsets.UTF_8)
    );
}
```

**Key rules:**
- Always use `MessageDigest.isEqual()` for comparing MACs, tokens, signatures
- Never use `==`, `.equals()`, or `Objects.equals()` for cryptographic secrets
- Apply to all secret comparisons: JWT verification, API key matching, HMAC validation

---

## 10. Session Expiration

**CWE-613** — *Insufficient Session Expiration*

### The Problem

Without `exp`, `iss`, `aud` claims, a JWT never expires. A stolen token becomes a permanent backdoor.

```java
// ❌ VULNERABLE — no exp, iss, aud validation
public Claims verify(String token) {
    Claims claims = Jwts.parser().parseClaimsJws(token).getBody();
    // No expiration check
    // No issuer validation
    // No audience validation
    return claims;
}
```

### The Fix

Always include and validate standard JWT claims.

```java
// ✅ SAFE — full claim validation
public Claims verify(String token) {
    Date now = new Date();
    Claims claims = Jwts.parser()
        .setSigningKey(SECRET_KEY)
        .requireIssuer(expectedIssuer)
        .requireAudience(expectedAudience)
        .parseClaimsJws(token)
        .getBody();

    // Check expiration
    if (claims.getExpiration().before(now)) {
        throw new JwtException("Token expired");
    }
    
    // Check not-before
    if (claims.getNotBefore() != null && claims.getNotBefore().after(now)) {
        throw new JwtException("Token not yet valid");
    }
    
    return claims;
}

// Token generation with all claims
public String generateToken(String subject) {
    return Jwts.builder()
        .setSubject(subject)
        .setIssuer(expectedIssuer)
        .setAudience(expectedAudience)
        .setIssuedAt(new Date())
        .setExpiration(new Date(System.currentTimeMillis() + 15 * 60 * 1000))  // 15 min
        .setNotBefore(new Date())
        .signWith(key, SignatureAlgorithm.HS256)
        .compact();
}
```

**Key rules:**
- Always include: `exp` (expiration), `iss` (issuer), `aud` (audience), `nbf` (not-before)
- Access tokens: 5-15 minutes
- Refresh tokens: 1-24 hours, rotated on each use
- Use short-lived access tokens + refresh token rotation for better security

---

## 11. Authorization Integrity

**CWE-863** — *Incorrect Authorization*

### The Problem

If authorization relies on a broken token validator (e.g., one accepting `alg: none`), the guard becomes a no-op and protected endpoints are effectively public.

```java
// ❌ VULNERABLE — endpoint guarded by broken token check
@GetMapping("/admin/espd-summary")
@PreAuthorize("isAuthenticated()")  // passes because alg: none token verifies
public ResponseEntity<?> adminSummary() {
    // Returns sensitive admin data to any forged token
}
```

### The Fix

Ensure token verification is correct first, then add explicit role checks.

```java
// ✅ SAFE — fix root cause + explicit role check
@Bean
SecurityFilterChain chain(HttpSecurity http) {
    http
        // 1. Fix the root: proper JWT verification (see CWE-347)
        .jwt(jwt -> jwt
            .decoder(jwtDecoder())
            .authenticationEntryPoint(entryPoint())
        )
        // 2. Explicit role-based access
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/admin/**").hasRole("ADMIN")
            .requestMatchers("/api/**").authenticated()
            .anyRequest().permitAll()
        );
    return http.build();
}

// ✅ SAFE — Spring Security method-level
@PreAuthorize("hasRole('ADMIN')")
@GetMapping("/admin/users")
public ResponseEntity<?> listUsers() { ... }

@PreAuthorize("hasRole('USER') and #userId == authentication.principal.id")
@GetMapping("/profile/{userId}")
public ResponseEntity<?> getProfile(@PathVariable String userId) { ... }
```

**Key rules:**
- Fix the root cause first: ensure token verification is cryptographically sound
- Never rely solely on `isAuthenticated()` for sensitive endpoints
- Use `@PreAuthorize` with explicit role and ownership checks
- Verify both: (1) the token is cryptographically valid, (2) the principal has required authority

---

## Summary Checklist

| # | Control | CWE | Priority |
|---|---------|-----|----------|
| 1 | BCrypt/Argon2 for password hashing | CWE-916 | CRITICAL |
| 2 | Rate limiting on login endpoints | CWE-307 | CRITICAL |
| 3 | Generic error messages + constant timing | CWE-204 | HIGH |
| 4 | Session rotation on login | CWE-384 | HIGH |
| 5 | HttpOnly + Secure + SameSite on cookies | CWE-1004, CWE-614 | HIGH |
| 6 | Pin JWT algorithm, reject `alg: none` | CWE-347 | CRITICAL |
| 7 | ≥ 256-bit secrets from env/Vault | CWE-321, CWE-521 | CRITICAL |
| 8 | Validate `exp`, `iss`, `aud` claims | CWE-613 | CRITICAL |
| 9 | `SecureRandom` for all security values | CWE-330 | HIGH |
| 10 | `MessageDigest.isEqual()` for secrets | CWE-208 | HIGH |
| 11 | Explicit role checks on sensitive endpoints | CWE-863 | CRITICAL |
| 12 | No hard-coded credentials | CWE-798 | CRITICAL |

---

## References

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JWT_Cheat_Sheet.html)
- [Spring Security Documentation](https://docs.spring.io/spring-security/reference/)
- [NIST SP 800-63B: Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
