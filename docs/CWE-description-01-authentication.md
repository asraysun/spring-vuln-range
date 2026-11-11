# CWE Reference — §01 Authentication, Sessions and Tokens

CWEs extracted from `docs/01-authentication.md` with developer-focused comments.

---

## CWE-916 — Use of One-Way Hash without a Salt

**Why it matters:** MD5/SHA without salt produces identical hashes for identical passwords. An attacker who obtains the hash database can pre-compute a rainbow table and crack thousands of passwords in minutes.

**Attack vector in Spring:**
```java
// VULNERABLE — stored in /vuln1/debug/users
@Value("${m01.hasher:md5}")
String algo;

String hash(String pwd) {
    return DigestUtils.md5Hex(pwd);  // no salt, fast, reversible via rainbow tables
}
```
The vulnerable module exposes an endpoint `GET /vuln1/debug/users` that returns all user hashes. Combined with unsalted MD5, every password is instantly crackable.

**How to prevent:**
- Use `Argon2PasswordEncoder` (preferred) or `BCryptPasswordEncoder` with a tuned work factor (cost ≥ 12).
- Never use MD5/SHA-1/SHA-256 for passwords — these are fast, single-pass digests meant for integrity, not secrets.
- Spring Security auto-configures `PasswordEncoder` beans — don't replace them with `DigestUtils`.

```java
// SAFE
@Bean
PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(12);  // cost factor 12
}
```

---

## CWE-307 — Restriction of Lifetime of Authenticating Credentials (No Throttling)

**Why it matters:** Without rate limiting, an attacker can try millions of passwords per second against a login endpoint. Automated brute force tools can exhaust even long passwords within hours.

**Attack vector in Spring:**
```java
// VULNERABLE — POST /vuln1/login
@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginRequest req) {
    // No throttling, no cooldown, no max-attempt tracking
    // An attacker can fire 10,000 requests/second
    return authenticate(req.getUsername(), req.getPassword());
}
```

**How to prevent:**
- Implement per-account AND per-IP rate limiting (e.g., 5 attempts per account per 5 minutes).
- Use Spring Session + Redis for distributed rate limiting, or `Bucket4j` for in-memory.
- Return `429 Too Many Attempts` with a `Retry-After` header.
- Use a generic error message ("invalid username or password") to prevent user enumeration alongside throttling.

---

## CWE-204 — Response Discrepancy / Information Exposure Through Timing Differences

**Why it matters:** Different error messages or response times for "user not found" vs "wrong password" let an attacker enumerate valid usernames. Combined with brute force (CWE-307), this turns a login endpoint into a full user directory.

**Attack vector in Spring:**
```java
// VULNERABLE — different responses reveal existence
if (user == null) {
    return ResponseEntity.status(401).body("User not found");  // leaks non-existence
}
if (!matches) {
    return ResponseEntity.status(401).body("Wrong password");  // leaks existence
}
```
Response timing differs too — hashing a non-existent user is faster (no bcrypt call) than hashing an existing one.

**How to prevent:**
- Always return the same response body and HTTP status for any login failure.
- Always run the password hasher (even for non-existent users) to equalize timing:
```java
// SAFE — dummy hash for non-existent users
User user = repository.findByUsername(username);
String dummy = passwordEncoder().encode("dummy");
passwordEncoder().matches(password, user != null ? user.getPassword() : dummy);
return ResponseEntity.status(401).body("Invalid credentials");
```

---

## CWE-384 — Session Fixation

**Why it matters:** If the session ID does not change after authentication, an attacker who obtained the session cookie before login (via XSS, log files, or referer leaks) can hijack the account immediately after the victim logs in.

**Attack vector in Spring:**
```java
// VULNERABLE — session ID survives login
@GetMapping("/session-id")
public String getSessionId(HttpServletRequest req) {
    return req.getSession().getId();  // same ID before and after login
}

@PostMapping("/login")
public ResponseEntity<?> login(...) {
    // Spring Security authenticates but does NOT invalidate/recreate the session
    // The attacker's session ID is now the authenticated session
}
```

**How to prevent:**
- Call `sessionFixation().migrateSession()` in Spring Security config — this invalidates the old session and issues a new one on login.
```java
@Bean
SecurityFilterChain chain(HttpSecurity http) {
    http.sessionManagement(s -> s
        .sessionFixation(SessionFixationMigrator::migrateSession)
    );
    return http.build();
}
```

---

## CWE-1004 — HTTP Cookie Without HttpOnly Flag

**Why it matters:** Without `HttpOnly`, JavaScript on the page (including injected scripts from XSS) can read the session cookie via `document.cookie`. An XSS vulnerability becomes a full account takeover.

**Attack vector in Spring:**
```java
// VULNERABLE — cookie is accessible from JavaScript
@PostMapping("/set-cookie-demo")
public ResponseEntity<?> setCookie(HttpServletResponse resp) {
    Cookie cookie = new Cookie("session", sessionId);
    // No .setHttpOnly(true) — JavaScript can read this
    resp.addCookie(cookie);
}
```

**How to prevent:**
- Set `HttpOnly = true` on all session and authentication cookies.
- In Spring Security, configure the cookie serializer:
```java
http.sessionManagement(s -> s.sessionCookieConfig(c -> {
    c.setHttpOnly(true);
    c.setSecure(true);    // see CWE-614
    c.getSamesite();      // "Lax" or "Strict"
}));
```

---

## CWE-614 — Secure Communication Channel Not Used (Cookie Without Secure Flag)

**Why it matters:** Without the `Secure` flag, cookies are sent over plain HTTP. On any unencrypted connection (public Wi-Fi, MITM), the session cookie is transmitted in cleartext and can be captured.

**Attack vector in Spring:**
```java
// VULNERABLE — cookie sent over HTTP
Cookie cookie = new Cookie("JSESSIONID", id);
// No .setSecure(true) — cookie leaks on plain HTTP
```

**How to prevent:**
- Set `Secure = true` on all authentication cookies.
- Always serve the application over TLS in production.
- Use HSTS (`Strict-Transport-Security`) to prevent downgrade attacks.

---

## CWE-347 — Improper Verification of Cryptographic Signature

**Why it matters:** Accepting `alg: none` in JWT means the signature is completely bypassed. An attacker can forge any token with any payload (any user, any role) without knowing the secret.

**Attack vector in Spring:**
```java
// VULNERABLE — accepts alg: none
public Claims verify(String token) {
    return Jwts.parser()           // default parser accepts alg: none
               .parseClaimsJws(token)
               .getBody();
}
```
Payload: `{"alg":"none"}.{"role":"ADMIN","sub":"attacker"}.` — verifies successfully.

**How to prevent:**
- Pin the algorithm explicitly — never use a parser that accepts any algorithm.
```java
// SAFE — algorithm is a constant, not parsed from the token
private static final SignatureAlgorithm SIG_ALG = SignatureAlgorithm.HS256;

public Claims verify(String token) {
    return Jwts.parser()
               .setSigningKey(SECRET_KEY)   // key required, alg is fixed
               .parseClaimsJws(token)
               .getBody();
}
```
- Use `jjwt` 0.12+ where `alg: none` is rejected by default.

---

## CWE-321 — Use of Hard-coded Cryptographic Key

**Why it matters:** A hard-coded JWT secret (especially a dictionary word) is visible in source code, configuration files, and git history. Anyone with repo access can forge tokens for any user.

**Attack vector in Spring:**
```java
// VULNERABLE — secret is a dictionary word, stored in application.yml
@Value("${m01.jwt-secret:password}")
private SecretKey key;
```
The secret is both weak ("password") and hardcoded (fallback in config).

**How to prevent:**
- Store secrets in environment variables, Vault, or Kubernetes Secrets.
- Use keys ≥ 256 bits (for HMAC-SHA256).
- Never use a fallback default in production code.
```java
// SAFE — required env var, throws if missing
@Value("${JWT_SECRET}")
private SecretKey key;

@PostConstruct
void init() {
    if (key == null || key.getEncoded().length < 32) {
        throw new IllegalStateException("JWT_SECRET must be ≥ 256 bits");
    }
}
```

---

## CWE-521 — Weak Password Requirements for Cryptographic Operations

**Why it matters:** A weak secret used for cryptographic operations (HMAC signing, encryption keys) is trivially brute-forced. The attacker recovers the key and can forge or decrypt anything.

**Attack vector in Spring:**
```java
// VULNERABLE — JWT secret is a dictionary word
// application.yml: jwt-secret: "mysecret"  (8 chars, dictionary word)
```
An HMAC-SHA256 with an 8-character dictionary word can be cracked in seconds.

**How to prevent:**
- Use `SecretKeySpec` with ≥ 256 bits of random data.
- Generate with `SecureRandom`:
```java
byte[] key = new byte[32];  // 256 bits
new SecureRandom().nextBytes(key);
```
- Store in Vault/env, never in config files.

---

## CWE-613 — Insufficient Session Expiration

**Why it matters:** Without `exp`, `iss`, and `aud` claims, a JWT never expires, can be issued by anyone, and can be used against any service. A stolen token is a permanent backdoor.

**Attack vector in Spring:**
```java
// VULNERABLE — no exp, iss, aud validation
public Claims verify(String token) {
    Claims claims = Jwts.parser().parseClaimsJws(token).getBody();
    // No claims.getExpiration().before(now) check
    // No claims.getIssuer().equals(expectedIssuer) check
    // No claims.getAudience().contains(expectedAudience) check
    // No constant-time comparison of any secret
    return claims;
}
```

**How to prevent:**
- Always include and validate `exp`, `iss`, `aud`, and optionally `nbf`:
```java
// SAFE
public Claims verify(String token) {
    Date now = new Date();
    Claims claims = Jwts.parser()
        .setSigningKey(SECRET_KEY)
        .requireIssuer(expectedIssuer)
        .requireAudience(expectedAudience)
        .parseClaimsJws(token)
        .getBody();
    
    if (claims.getExpiration().before(now)) {
        throw new JwtException("Token expired");
    }
    return claims;
}
```

---

## CWE-208 — Observable Timing Discrepancy

**Why it matters:** Non-constant-time comparison of secrets (tokens, MACs, signatures) lets an attacker determine the correct value byte-by-byte by measuring response times. A 32-byte HMAC can be recovered in ~800 requests.

**Attack vector in Spring:**
```java
// VULNERABLE — String.equals() returns early on first mismatch
boolean valid(String provided, String expected) {
    return provided.equals(expected);  // timing leak
}
```
Response time for `"abc..."` vs `"xyz..."` is shorter than `"abc..."` vs `"abd..."`.

**How to prevent:**
- Use `MessageDigest.isEqual()` which compares all bytes regardless of where they differ:
```java
// SAFE
boolean valid(byte[] a, byte[] b) {
    return MessageDigest.isEqual(a, b);
}
```
- Or use Spring Security's `ConstantTimeEquals` utility.

---

## CWE-330 — Use of Insufficiently Random Values

**Why it matters:** `java.util.Random` is seeded by system time (milliseconds). An attacker who observes one token can predict the seed and compute all future (and past) tokens. Password reset codes become trivially guessable.

**Attack vector in Spring:**
```java
// VULNERABLE — predictable reset code
int generateResetCode() {
    Random rand = new Random();  // seeded by System.nanoTime()
    return rand.nextInt(9_000_000) + 1_000_000;  // 6 digits, predictable
}
```
The seed is deterministic — observing one code lets you predict the next.

**How to prevent:**
- Use `SecureRandom` which reads from the OS entropy pool:
```java
// SAFE
int generateResetCode() {
    SecureRandom rand = new SecureRandom();
    return rand.nextInt(9_000_000) + 1_000_000;
}
```
- Store only a digest of the code (not the plaintext) in the database.
- Expire codes after 5 minutes and mark as single-use.

---

## CWE-798 — Use of Hard-coded Credentials

**Why it matters:** A static key compiled into the application for "remember-me" authentication means anyone with the JAR can forge authentication tokens for any user. This is equivalent to having the master key to every account.

**Attack vector in Spring:**
```java
// VULNERABLE — key is compiled into the class
public class StaticKeyRememberMeServices {
    private static final byte[] KEY = "a-static-key-for-remember-me".getBytes();
    // Anyone decompiling the JAR gets this key and can forge tokens
}
```

**How to prevent:**
- Derive remember-me tokens from a per-user rotating secret, or better, drop the feature entirely.
- If used, load the key from Vault/env with no fallback:
```java
@Value("${REMEMBER_ME_KEY}")
private SecretKey key;  // required, no default, rotated periodically
```

---

## CWE-863 — Incorrect Authorization

**Why it matters:** If the authorization check relies on a broken token validator (e.g., one that accepts `alg: none`), then the authorization guard is a no-op. Any endpoint protected by that check is effectively public.

**Attack vector in Spring:**
```java
// VULNERABLE — endpoint guarded by broken token check
@GetMapping("/admin/espd-summary")
@PreAuthorize("isAuthenticated()")  // passes because alg: none token verifies
public ResponseEntity<?> adminSummary() {
    // Returns sensitive admin data to any forged token
}
```
The `@PreAuthorize("isAuthenticated()")` check passes because the underlying token verification accepts forged tokens.

**How to prevent:**
- Fix the root cause: ensure token verification is correct (see CWE-347, CWE-613).
- Add explicit role/authority checks:
```java
// SAFE
@PreAuthorize("hasRole('ADMIN') and #subscription.owner == authentication.name")
```
- Always verify both: (1) the token is cryptographically valid, and (2) the principal has the required authority.
