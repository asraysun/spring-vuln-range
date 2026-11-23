# Spring Security: How to Prevent Web Layer Vulnerabilities (CSRF, CORS, Headers, XSS)

A practical guide to securing Spring Boot's web layer against CSRF, CORS misconfiguration, missing security headers, XSS, clickjacking, and output encoding flaws — covering 6 CWEs found in real Spring applications.

---

## Table of Contents

1. [CSRF Protection](#1-csrf-protection)
2. [CORS Configuration](#2-cors-configuration)
3. [Security Headers](#3-security-headers)
4. [XSS Prevention](#4-xss-prevention)
5. [Clickjacking Prevention](#5-clickjacking-prevention)
6. [JavaScript Inlining Safety](#6-javascript-inlining-safety)

---

## 1. CSRF Protection

**CWE-352** — *Cross-Site Request Forgery*

### The Problem

CSRF allows an attacker to trick an authenticated user's browser into performing an unintended state-changing action on a trusted application. Since browsers automatically include cookies (including session cookies) with every request, the forged request is authenticated without the user's knowledge. This can lead to unauthorized account changes, fund transfers, subscription cancellations, or data deletion.

```html
<!-- Attacker's page on evil.com -->
<form id="f" method="POST" action="http://127.0.0.1:8087/vuln7/subscriptions/SUB-1001/cancel"></form>
<script>document.getElementById('f').submit()</script>
```

```java
// ❌ VULNERABLE — no CSRF token required on state-changing endpoint
@PostMapping("/subscriptions/{id}/cancel")
public ResponseEntity<?> cancelSubscription(@PathVariable String id) {
    subscriptionService.cancel(id);  // Any request cancels the subscription
    return ResponseEntity.ok("cancelled");
}
```

A logged-in victim who visits the attacker's page has their subscription cancelled. No CSRF token is needed — the browser sends the session cookie automatically.

### The Fix

Enable CSRF protection for all cookie-authenticated state-changing endpoints.

```java
// ✅ SAFE — CSRF protection with cookie-based token repository
@Bean
SecurityFilterChain chain(HttpSecurity http) {
    http.csrf(csrf -> csrf
        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
        // Optional: define which paths to skip
        // .ignoringRequestMatchers(
        //     AntPathRequestMatcher.of("/api/**", "POST"),
        //     AntPathRequestMatcher.of("/webhook/**", "POST")
        // )
    );
    return http.build();
}

// The client flow:
// 1. GET /safe7/csrf → reads the CSRF token from the cookie
//    Response: {"token":"abc123...","headerName":"X-XSRF-TOKEN"}
// 2. POST /safe7/subscriptions/SUB-1001/cancel
//    Header: X-XSRF-TOKEN: abc123...
//    Cookie: XSRF-TOKEN=abc123...  (double-submit cookie pattern)
```

**JavaScript client integration:**

```javascript
// ✅ SAFE — read CSRF token from cookie and attach to every state-changing request
function getCsrfToken() {
    const cookies = document.cookie.split(';');
    for (const cookie of cookies) {
        const [name, value] = cookie.trim().split('=');
        if (name === 'XSRF-TOKEN') return decodeURIComponent(value);
    }
    return null;
}

// Attach to all fetch/axios requests
axios.defaults.xsrfHeaderName = 'X-XSRF-TOKEN';
axios.defaults.xsrfCookieName = 'XSRF-TOKEN';  // must match CookieCsrfTokenRepository

// Or manual:
fetch('/api/subscriptions/SUB-1001/cancel', {
    method: 'POST',
    credentials: 'include',  // send cookies
    headers: {
        'X-XSRF-TOKEN': getCsrfToken(),
        'Content-Type': 'application/json'
    }
});
```

**When CSRF can be disabled:**

```java
// ✅ Acceptable — stateless JWT API (no cookies, no automatic token sending)
@Bean
SecurityFilterChain jwtChain(HttpSecurity http) {
    http
        .securityMatcher("/api/**")
        .csrf(csrf -> csrf.disable())  // No cookies sent with requests
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(a -> a.anyRequest().authenticated())
        .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
    
    return http.build();
}
// Justification: JWT bearer tokens are not sent automatically by the browser.
// Each request must include the Authorization: Bearer <token> header explicitly.
// An attacker cannot forge a request with a valid bearer token from a cross-origin page.
```

**Key rules:**
- **CSRF is mandatory** for any state-changing endpoint that uses cookie-based authentication
- Use `CookieCsrfTokenRepository.withHttpOnlyFalse()` — the CSRF token must be readable by JavaScript for the double-submit pattern to work
- Stateless JWT APIs **do not need CSRF protection** — the bearer token is not sent automatically by the browser
- Never disable CSRF (`csrf().disable()`) without a written justification and an alternative security model (e.g., stateless JWT with `SessionCreationPolicy.STATELESS`)
- Log `csrf_token_missing` events — high volumes indicate automated attack tools

---

## 2. CORS Configuration

**CWE-942** — *Permissive Cross-Origin Resource Sharing*

### The Problem

An overly permissive CORS configuration allows any website to make cross-origin requests to the application. When combined with `allowCredentials(true)`, any website can read the user's authenticated data. This turns the application into a proxy that any attacker can use to exfiltrate data from a logged-in user's browser.

```java
// ❌ VULNERABLE — wildcard origin with credentials
@Bean
SecurityFilterChain chain(HttpSecurity http) {
    http.cors(cors -> cors.configurationSource(request -> {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOriginPatterns(List.of("*"));  // any origin!
        config.setAllowCredentials(true);               // send cookies!
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
        return config;
    }));
    return http.build();
}

// Attacker's page on evil.com:
// fetch("http://127.0.0.1:8087/vuln7/profile", { credentials: "include" })
// Response headers:
//   Access-Control-Allow-Origin: http://evil.example.invalid
//   Access-Control-Allow-Credentials: true
// → Returns the victim's profile data with PII
```

### The Fix

Use explicit origins and minimal methods. Never use `"*"` with `allowCredentials(true)`.

```java
// ✅ SAFE — explicit origins, minimal methods
@Bean
SecurityFilterChain chain(HttpSecurity http) {
    http.cors(cors -> cors.configurationSource(request -> {
        CorsConfiguration config = new CorsConfiguration();
        
        // Only allow your own frontend domain(s)
        config.setAllowedOrigins(List.of(
            "http://localhost:4200",    // local dev Angular
            "https://app.example.com",  // production frontend
            "https://staging.example.com" // staging frontend
        ));
        
        // Credentials only to trusted origins (explicit list above)
        config.setAllowCredentials(true);
        
        // Minimal HTTP methods
        config.setAllowedMethods(List.of("GET", "POST"));
        
        // Minimal headers
        config.setAllowedHeaders(List.of("Content-Type", "X-XSRF-TOKEN"));
        
        // Minimal exposed headers
        config.setExposedHeaders(List.of("X-XSRF-TOKEN"));
        
        // Cache preflight for 30 minutes
        config.setMaxAge(1800L);
        
        return config;
    }));
    return http.build();
}

// ✅ SAFE — alternative: pattern-based for multiple domains
@Bean
SecurityFilterChain chain(HttpSecurity http) {
    http.cors(cors -> cors.configurationSource(request -> {
        CorsConfiguration config = new CorsConfiguration();
        
        // Allow patterns — not wildcard
        config.setAllowedOriginPatterns(List.of(
            "https://*.example.com",   // any subdomain of example.com
            "https://*.example.org"    // any subdomain of example.org
        ));
        
        config.setAllowCredentials(true);
        config.setAllowedMethods(List.of("GET", "POST"));
        config.setAllowedHeaders(List.of("Content-Type", "Authorization"));
        
        return config;
    }));
    return http.build();
}
```

**If you don't need credentials:**

```java
// ✅ SAFE — public API, no cookies needed
@Bean
SecurityFilterChain chain(HttpSecurity http) {
    http.cors(cors -> cors.configurationSource(request -> {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("*"));  // OK only when allowCredentials is false
        config.setAllowCredentials(false);       // explicitly set to false
        config.setAllowedMethods(List.of("GET"));
        return config;
    }));
    return http.build();
}
```

**Key rules:**
- **Never use `"*"` with `allowCredentials(true)`** — this is always a finding
- **Never reflect the request origin** back to the caller (`request.getHeader("Origin")`)
- Credentials should only go to the front-end **you own**
- Use explicit origin lists in production (`app.example.com`), not patterns
- Use patterns (`*.example.com`) only when you control all subdomains
- Limit `allowedMethods` to what the API actually needs (GET, POST)
- Limit `allowedHeaders` to what the client actually sends

---

## 3. Security Headers

**CWE-693** — *Missing Security Headers*

### The Problem

Security headers provide defense-in-depth against common web attacks. Without them, browsers have no guidance on how to handle the response safely. This leaves users vulnerable to clickjacking, MIME-type sniffing attacks, cross-origin data leakage via referrer headers, and downgrade attacks.

```java
// ❌ VULNERABLE — no security headers set
// No Content-Security-Policy → inline scripts execute, XSS payloads load external resources
// No X-Content-Type-Options → browser MIME-sniffs, JSON served as executable script
// No X-Frame-Options → page can be embedded in iframe for clickjacking
// No Strict-Transport-Security → browser downgrades to HTTP
// No Referrer-Policy → full URL (with tokens) sent to third parties
```

### The Fix

Set comprehensive security headers via Spring Security's headers filter chain.

```java
// ✅ SAFE — comprehensive security headers
@Bean
SecurityFilterChain chain(HttpSecurity http) {
    http.headers(headers -> {
        // 1. Content Security Policy — controls what resources the browser can load
        headers.contentSecurityPolicy(csp -> csp
            .policyDirectives(
                "default-src 'self'; " +                     // Only load from same origin
                "script-src 'self'; " +                      // No inline scripts
                "style-src 'self' 'unsafe-inline'; " +       // Allow inline styles (common for CSS frameworks)
                "img-src 'self' data: https:; " +            // Allow images from same origin + HTTPS
                "font-src 'self'; " +                        // Fonts from same origin
                "connect-src 'self'; " +                     // AJAX/fetch to same origin
                "frame-ancestors 'none'; " +                 // No framing (replaces X-Frame-Options)
                "base-uri 'self'; " +                        // Base element from same origin
                "form-action 'self'; " +                     // Forms submit to same origin
                "upgrade-insecure-requests"                  // Upgrade HTTP to HTTPS
            )
        );

        // 2. X-Frame-Options: DENY — modern replacement: CSP frame-ancestors (above)
        headers.frameOptions(frame -> frame.deny());

        // 3. X-Content-Type-Options: nosniff — prevents MIME-type sniffing
        headers.contentTypeOptions(c -> c.nosniff());

        // 4. Strict-Transport-Security — prevents SSL-stripping and downgrade attacks
        headers.httpStrictTransportSecurity(hsts -> hsts
            .includeSubDomains(true)
            .maxAgeInSeconds(31536000)  // 1 year
        );

        // 5. Referrer-Policy — controls referrer information sent with requests
        headers.referrerPolicy(ref -> ref
            .policy(ReferrerPolicyPolicy.SAME_ORIGIN)  // Only send origin, not full URL
            // Alternatives:
            // .policy(ReferrerPolicyPolicy.STRICT_ORIGIN_WHEN_ORIGIN)
            // .policy(ReferrerPolicyPolicy.NO_REFERRER)
        );

        // 6. X-Permitted-Cross-Domain-Policies (for Flash/PDF, mostly legacy)
        headers.xContentTypeOptions(c -> c.nosniff());

        // 7. X-Download-Options (IE-specific)
        headers.xDownloadOptions(options -> options.noopen());

        // 8. X-Permitted-Cross-Domain-Policies
        // headers.permittedCrossDomainPolicies(p -> p.none());
    });
    return http.build();
}
```

**CSP policy guide:**

| Directive | Value | Purpose |
|-----------|-------|---------|
| `default-src` | `'self'` | Default: only load from same origin |
| `script-src` | `'self'` | No inline scripts, no external CDNs |
| `style-src` | `'self' 'unsafe-inline'` | Inline styles needed for CSS frameworks |
| `img-src` | `'self' data: https:` | Allow images from same origin + HTTPS + data URIs |
| `font-src` | `'self'` | Fonts from same origin |
| `connect-src` | `'self'` | AJAX/fetch/WebSocket to same origin |
| `frame-ancestors` | `'none'` | No framing (replaces X-Frame-Options) |
| `base-uri` | `'self'` | No arbitrary `<base>` elements |
| `form-action` | `'self'` | Forms only submit to same origin |
| `upgrade-insecure-requests` | — | Automatically upgrade HTTP to HTTPS |

**How to find the right CSP:**

```bash
# 1. Start with a permissive reporting-only CSP in production
#    report-to="csp-endpoint"; report-uri /api/csp-reports

# 2. Collect violations from /api/csp-reports

# 3. Analyze violations and add allowed sources one by one

# 4. Once stable for 30+ days, tighten to the strict CSP above
```

**Key rules:**
- `CSP with frame-ancestors 'none'` is the modern replacement for `X-Frame-Options`
- `X-Content-Type-Options: nosniff` prevents MIME-type confusion attacks
- `HSTS` with `max-age=31536000` (1 year) prevents SSL-stripping and downgrade attacks
- `Referrer-Policy: same-origin` prevents full URL leakage (which may contain auth tokens)
- Use reporting mode (`report-uri` / `report-to`) during CSP development
- CSP is the second layer for XSS — output encoding is the first

---

## 4. XSS Prevention

**CWE-79** — *Cross-Site Scripting*

### The Problem

XSS allows an attacker to inject malicious JavaScript into pages viewed by other users. When executed in the context of the victim's browser, the script has full access to the application: read cookies (session hijacking), read/modify page content, make authenticated requests on behalf of the user, and capture keystrokes.

**Reflected XSS** requires a crafted link. **Stored XSS** persists in the database and affects all visitors.

```java
// ❌ VULNERABLE — reflected XSS via th:utext
@GetMapping("/page")
public String page(@RequestParam String name, Model model) {
    model.addAttribute("name", name);
    return "page";  // Thymeleaf template uses th:utext (unescaped!)
}
<!-- page.html -->
<div th:utext="${name}">  <!-- UNESCAPED HTML! -->

// Payload: ?name=%3Cimg%20src%3Dx%20onerror%3Dalert(document.cookie)%3E
// The onerror handler executes JavaScript in the victim's browser, reading the session cookie

// ❌ VULNERABLE — stored XSS
@PostMapping("/notes")
public ResponseEntity<?> createNote(@RequestBody NoteRequest req) {
    noteService.save(req.getContent());  // Stores <script>steal()</script> in DB
    // Every user who views the note gets the script
}
```

### The Fix

Use escaped output (`th:text`) everywhere. Sanitize if unescaped HTML is truly required.

```java
// ✅ SAFE — use th:text (escaped) instead of th:utext
<!-- page.html -->
<div th:text="${name}">  <!-- Escaped: &lt;img src=x onerror=...&gt; -->

// ✅ SAFE — if you must render user HTML, sanitize it server-side
@GetMapping("/page")
public String page(@RequestParam String name, Model model) {
    model.addAttribute("safeName", Encode.forHtml(name));  // OWASP Java Encoder
    return "page";  // Template uses th:text="${safeName}" or th:utext with pre-sanitized data
}

// ✅ SAFE — stored content rendered as plain text
@PostMapping("/notes")
public ResponseEntity<?> createNote(@Valid @RequestBody NoteRequest req) {
    // Content is saved to DB, rendered as text (not HTML) via th:text
    noteService.save(req.getContent());
    return ResponseEntity.ok("saved");
}
<!-- note.html -->
<div th:text="${note.content}">  <!-- Always escaped, never interpreted -->

// ✅ SAFE — if you need rich text, use a sanitizer library
import org.owasp.html.PolicyConfig;
import org.owasp.html.Sanitizers;
import org.owasp.html.HTMLPolicyBuilder;

public String sanitizeHtml(String input) {
    HTMLPolicy policy = new HTMLPolicyBuilder()
        .allowElements("p", "b", "i", "em", "strong", "ul", "ol", "li", "a")
        .allowAttributes("href").onElements("a")
        .allowUrlProtocols("https")
        .build();
    
    return Sanitifiers.FORMATTING.sanitize(input, policy);
}
```

**OWASP Java Encoder utilities:**

```java
import org.owasp.encoder.Encode;

// For HTML context
model.addAttribute("safeName", Encode.forHtml(name));
// < → &lt;, > → &gt;, " → &quot;, ' → &#x27;

// For HTML attribute context
model.addAttribute("safeAttr", Encode.forHtmlAttribute(value));
// " → &quot;, ' → &#x27;

// For JavaScript context
model.addAttribute("safeJs", Encode.forJavaScriptContent(value));
// \ → \\, " → \", ' → \', line terminator → \u2028

// For CSS context
model.addAttribute("safeCss", Encode.forCssString(value));
```

**Key rules:**
- **`th:text` escapes HTML entities by default. `th:utext` renders raw HTML** — review every `th:utext` use as a security blocker
- For stored XSS, render stored content as escaped text (`th:text`), never as raw HTML
- If rich text is required, sanitize it server-side using OWASP Java HTML Sanitizer or equivalent
- CSP is the **second layer** for XSS: `script-src 'self'` blocks inline handlers even if the template forgets escaping
- Never use `innerHTML` in client-side JavaScript with user-controlled data

---

## 5. Clickjacking Prevention

**CWE-1021** — *Improper Restriction of Rendered UI Layers or Frames*

### The Problem

Without frame protection, an attacker can embed the application in a transparent iframe and overlay deceptive UI elements on top. Users interact with the visible overlay while the hidden iframe captures their clicks, tricking them into performing unintended actions (e.g., transferring money, changing email, granting permissions).

```java
// ❌ VULNERABLE — page is frameable (no frame protection)
@GetMapping("/clickjacking")
public String sensitivePage() {
    // Returns a page with account settings, transfer buttons, etc.
    // No headers prevent it from being embedded in an iframe
    return "sensitive-page";
}
```

```html
<!-- Attacker's page -->
<iframe src="http://127.0.0.1:8087/vuln7/clickjacking" style="opacity:0;position:absolute;top:0;left:0;width:100%;height:100%"></iframe>
<button style="position:absolute;top:50%;left:50%" onclick="document.querySelector('iframe').contentWindow.click()">Click me!</button>
```

The victim clicks the button thinking it's a normal page element, but the click lands on the hidden iframe's transfer button.

### The Fix

Use both `X-Frame-Options: DENY` and CSP `frame-ancestors` for defense-in-depth.

```java
// ✅ SAFE — deny framing + CSP frame-ancestors
@Bean
SecurityFilterChain chain(HttpSecurity http) {
    http.headers(headers -> {
        // 1. X-Frame-Options: DENY — legacy browser support
        headers.frameOptions(frame -> frame.deny());
        
        // 2. CSP frame-ancestors — modern equivalent
        headers.contentSecurityPolicy(csp -> csp
            .policyDirectives("default-src 'self'; frame-ancestors 'none'")
        );
    });
    return http.build();
}

// If you need to allow framing from the same origin:
// headers.frameOptions(frame -> frame.sameorigin());
// CSP: "frame-ancestors 'self'"

// If you need to allow framing from a specific trusted domain:
// CSP: "frame-ancestors https://trusted-partner.com"
```

**Key rules:**
- `X-Frame-Options: DENY` blocks all framing (legacy browser support)
- CSP `frame-ancestors 'none'` is the modern equivalent
- Use `frame-ancestors 'self'` if framing from the same origin is needed
- Use `frame-ancestors https://trusted-domain.com` for specific trusted partners
- Protect all sensitive pages — account settings, payment forms, admin panels

---

## 6. JavaScript Inlining Safety

**CWE-79** — *JavaScript Inlining Vulnerability (Thymeleaf)*

### The Problem

When a template engine inlines server-side data directly into JavaScript without proper escaping, user-controlled data can break out of the JavaScript string context and execute arbitrary code. This is a JavaScript-specific XSS variant that bypasses HTML-escaping protections.

```yaml
# ❌ VULNERABLE — JavaScript inlining enabled in Thymeleaf
spring:
  thymeleaf:
    javascript-inlining: true  # Allows ${...} in <script> blocks
```

```html
<!-- ❌ VULNERABLE — data inlined into JS without escaping -->
<script th:inline="javascript">
    var userName = /*[[${userName}]]*/ 'guest';
    // If userName = </script><script>alert(1)</script>
    // The </script> tag closes the script block, and the second script executes
</script>
```

### The Fix

Disable JavaScript inlining in production. If required, use proper escaping.

```yaml
# ✅ SAFE — disable JavaScript inlining in production
spring:
  thymeleaf:
    javascript-inlining: false
```

```html
<!-- ✅ SAFE — manual escaping with OWASP encoder -->
<script>
    var userName = /*[[${safeUserName}]]*/ 'guest';
    // safeUserName uses Encode.forJavaScriptContent()
    // </script> becomes <\/script>, preventing tag closure
</script>
```

```java
// ✅ SAFE — use JavaScript-safe encoding
import org.owasp.encoder.Encode;

@GetMapping("/dashboard")
public String dashboard(@RequestParam String userName, Model model) {
    model.addAttribute("safeUserName", Encode.forJavaScriptContent(userName));
    return "dashboard";
}
```

**JavaScript context escaping reference:**

| Input | HTML-escaped (`forHtml`) | JS-escaped (`forJavaScriptContent`) |
|-------|--------------------------|-------------------------------------|
| `</script><script>alert(1)</script>` | `&lt;/script&gt;...` (safe in HTML, but breaks JS string) | `<\/script>...` (safe in JS string) |
| `"onerror=alert(1)"` | `&quot;onerror=alert(1)&quot;` | `\"onerror=alert(1)\"` |
| Newline | `&#10;` (no effect in JS) | `\n` or `\u000A` |

**Key rules:**
- **Disable `javascript-inlining` in production** unless you have a proven escaping strategy
- If JavaScript inlining is required, use `Encode.forJavaScriptContent()` from OWASP Java Encoder
- Always set CSP `script-src 'self'` to block inline scripts as a **second layer**
- Never use `eval()` with user-controlled data
- Use `JSON.stringify()` for complex objects instead of manual string concatenation

---

## Summary Checklist

| # | Control | CWE | Priority |
|---|---------|-----|----------|
| 1 | CSRF on cookie-auth state changes | CWE-352 | CRITICAL |
| 2 | Explicit CORS origins, no `"*"` with credentials | CWE-942 | CRITICAL |
| 3 | CSP, nosniff, HSTS, frame-ancestors | CWE-693 | HIGH |
| 4 | `th:text` over `th:utext`, OWASP sanitizer | CWE-79 | CRITICAL |
| 5 | `X-Frame-Options: DENY` + CSP `frame-ancestors` | CWE-1021 | HIGH |
| 6 | `javascript-inlining: false` or proper escaping | CWE-79 | HIGH |

---

## Detection & Review Heuristics

| Check | Command / Pattern |
|-------|-------------------|
| CSRF disabled | `grep -r 'csrf().disable()'` → should have written justification + stateless model |
| CORS wildcard + credentials | `grep -r 'setAllowedOriginPatterns.*\*\|setAllowedOrigins.*\*'` → never with `setAllowCredentials(true)` |
| `th:utext` usage | `grep -r 'th:utext'` → review every instance, prefer `th:text` |
| Missing security headers | `grep -r 'headers('` → should set CSP, nosniff, frame-options, HSTS |
| JavaScript inlining | `grep -r 'javascript-inlining'` → should be `false` in prod |
| Missing frame protection | Check that all `SecurityFilterChain` beans set `frameOptions.deny()` or CSP `frame-ancestors` |

---

## References

- [OWASP CSRF Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP CORS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/CORS_Cheat_Sheet.html)
- [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [OWASP XSS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_XSS_Cheat_Sheet.html)
- [OWASP Clickjacking Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)
- [Spring Security Headers Documentation](https://docs.spring.io/spring-security/reference/servlet/configuration/html5headers.html)
- [OWASP Java Encoder Project](https://owasp.org/www-project-java-encoder/)
