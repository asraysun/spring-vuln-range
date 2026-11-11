# CWE Reference — §07 Web Layer: CSRF, CORS, Security Headers, XSS

CWEs extracted from `docs/07-web-layer.md` with developer-focused comments.

---

## CWE-352 — Cross-Site Request Forgery (CSRF)

**Why it matters:** CSRF allows an attacker to trick an authenticated user's browser into performing an unintended state-changing action on a trusted application. Since browsers automatically include cookies (including session cookies) with every request, the forged request is authenticated without the user's knowledge. This can lead to unauthorized account changes, fund transfers, subscription cancellations, or data deletion.

**Attack vector in Spring:**
```java
// VULNERABLE — no CSRF token required on state-changing endpoint
@PostMapping("/subscriptions/{id}/cancel")
public ResponseEntity<?> cancelSubscription(@PathVariable String id) {
    subscriptionService.cancel(id);  // Any request cancels the subscription
    return ResponseEntity.ok("cancelled");
}
```
Attacker hosts a page on `evil.com`:
```html
<form id="f" method="POST" action="http://127.0.0.1:8087/vuln7/subscriptions/SUB-1001/cancel"></form>
<script>document.getElementById('f').submit()</script>
```
A logged-in victim who visits `evil.com` has their subscription cancelled. No CSRF token is needed — the browser sends the session cookie automatically.

**How to prevent:**
```java
// SAFE — CSRF protection enabled for cookie-based auth
http.csrf(csrf -> csrf
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
);

// The client must read the CSRF token from a cookie and send it in a header:
// GET /safe7/csrf → {"token":"abc123..."}
// POST /safe7/subscriptions/SUB-1001/cancel with header: X-XSRF-TOKEN: abc123...
```
- CSRF protection is mandatory for any state-changing endpoint that uses cookie-based authentication.
- Stateless APIs using Bearer tokens (JWT) do not need CSRF protection — the token is not sent automatically by the browser.
- Never disable CSRF (`csrf().disable()`) without a written justification and an alternative security model.

---

## CWE-942 — Permissive Cross-Origin Resource Sharing (CORS)

**Why it matters:** An overly permissive CORS configuration allows any website to make cross-origin requests to the application. When combined with `allowCredentials(true)`, any website can read the user's authenticated data. This turns the application into a proxy that any attacker can use to exfiltrate data from a logged-in user's browser.

**Attack vector in Spring:**
```java
// VULNERABLE — wildcard origin with credentials
http.cors(cors -> cors.configurationSource(request -> {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOriginPatterns(List.of("*"));  // any origin!
    config.setAllowCredentials(true);               // send cookies!
    config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
    return config;
}));

// Attacker's page on evil.com:
// fetch("http://127.0.0.1:8087/vuln7/profile", { credentials: "include" })
// Returns the victim's profile data with PII
```
Response headers:
```
Access-Control-Allow-Origin: http://evil.example.invalid
Access-Control-Allow-Credentials: true
```
This pair turns any website into a proxy for a logged-in user's data.

**How to prevent:**
```java
// SAFE — explicit origins, minimal methods
http.cors(cors -> cors.configurationSource(request -> {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(List.of("http://localhost:4200"));  // only our frontend
    config.setAllowCredentials(true);
    config.setAllowedMethods(List.of("GET", "POST"));
    config.setAllowedHeaders(List.of("Content-Type", "X-XSRF-TOKEN"));
    return config;
}));
```
- Never use `"*"` with `allowCredentials(true)` — this is always a finding.
- Never reflect the request origin back to the caller.
- Credentials should only go to the front-end you own.

---

## CWE-693 — Missing Security Headers

**Why it matters:** Security headers provide defense-in-depth against common web attacks. Without them, browsers have no guidance on how to handle the response safely. This leaves users vulnerable to clickjacking, MIME-type sniffing attacks, cross-origin data leakage via referrer headers, and downgrade attacks.

**Attack vector in Spring:**
```java
// VULNERABLE — no security headers set
// No Content-Security-Policy → inline scripts execute, XSS payloads load external resources
// No X-Content-Type-Options → browser MIME-sniffs, JSON served as executable script
// No X-Frame-Options → page can be embedded in iframe for clickjacking
// No Strict-Transport-Security → browser downgrades to HTTP
// No Referrer-Policy → full URL (with tokens) sent to third parties
```

**How to prevent:**
```java
// SAFE — comprehensive security headers
http.headers(headers -> {
    headers.contentSecurityPolicy(csp -> csp
        .policyDirectives("default-src 'self'; frame-ancestors 'none'; script-src 'self'")
    );
    headers.frameOptions(frame -> frame.deny());  // X-Frame-Options: DENY
    headers.contentTypeOptions(c -> c.nosniff());  // X-Content-Type-Options: nosniff
    headers.httpStrictTransportSecurity(hsts -> hsts
        .includeSubDomains(true).maxAgeInSeconds(31536000)
    );  // Strict-Transport-Security
    headers.referrerPolicy(ref -> ref
        .policy(ReferrerPolicyPolicy.SAME_ORIGIN)
    );  // Referrer-Policy: same-origin
});
```
- CSP with `frame-ancestors 'none'` is the modern replacement for X-Frame-Options.
- `X-Content-Type-Options: nosniff` prevents MIME-type confusion attacks.
- HSTS prevents SSL-stripping and downgrade attacks.

---

## CWE-79 — Cross-Site Scripting (XSS)

**Why it matters:** XSS allows an attacker to inject malicious JavaScript into pages viewed by other users. When executed in the context of the victim's browser, the script has full access to the application: read cookies (session hijacking), read/modify page content, make authenticated requests on behalf of the user, and capture keystrokes. Reflected XSS requires a crafted link; stored XSS persists in the database and affects all visitors.

**Attack vector in Spring:**
```java
// VULNERABLE — reflected XSS via th:utext
@GetMapping("/page")
public String page(@RequestParam String name, Model model) {
    model.addAttribute("name", name);
    return "page";  // Thymeleaf template uses th:utext (unescaped!)
}
<!-- page.html -->
<div th:utext="${name}">  <!-- UNESCAPED HTML! -->
```
Payload: `?name=<img src=x onerror=alert(document.cookie)>`
The `onerror` handler executes JavaScript in the victim's browser, reading the session cookie.

```java
// VULNERABLE — stored XSS
@PostMapping("/notes")
public ResponseEntity<?> createNote(@RequestBody NoteRequest req) {
    noteService.save(req.getContent());  // Stores <script>steal()</script> in DB
    // Every user who views the note gets the script
}
```

**How to prevent:**
```java
// SAFE — use th:text (escaped) instead of th:utext
<!-- page.html -->
<div th:text="${name}">  <!-- Escaped: &lt;img src=x onerror=...&gt; -->

// If unescaped HTML is truly required, sanitize it server-side:
import org.owasp.encoder.Encode;
model.addAttribute("safeName", Encode.forHtml(name));
```
- `th:text` escapes HTML entities by default. `th:utext` renders raw HTML — review every use as a security blocker.
- CSP is the second layer: `script-src 'self'` blocks inline handlers even if the template forgets escaping.
- For stored XSS, sanitize input at the trust boundary or use a library like OWASP Java HTML Sanitizer.

---

## CWE-1021 — Improper Restriction of Rendered UI Layers or Frames (Clickjacking)

**Why it matters:** Without frame protection, an attacker can embed the application in a transparent iframe and overlay deceptive UI elements on top. Users interact with the visible overlay while the hidden iframe captures their clicks, tricking them into performing unintended actions (e.g., transferring money, changing email, granting permissions).

**Attack vector in Spring:**
```java
// VULNERABLE — page is frameable (no frame protection)
@GetMapping("/clickjacking")
public String sensitivePage() {
    // Returns a page with account settings, transfer buttons, etc.
    // No headers prevent it from being embedded in an iframe
    return "sensitive-page";
}
```
Attacker's page:
```html
<iframe src="http://127.0.0.1:8087/vuln7/clickjacking" style="opacity:0;position:absolute;top:0;left:0;width:100%;height:100%"></iframe>
<button style="position:absolute;top:50%;left:50%" onclick="document.querySelector('iframe').contentWindow.click()">Click me!</button>
```
The victim clicks the button thinking it's a normal page element, but the click lands on the hidden iframe's transfer button.

**How to prevent:**
```java
// SAFE — deny framing + CSP frame-ancestors
http.headers(headers -> {
    headers.frameOptions(frame -> frame.deny());  // X-Frame-Options: DENY
    headers.contentSecurityPolicy(csp -> csp
        .policyDirectives("default-src 'self'; frame-ancestors 'none'")
    );
});
```
- `X-Frame-Options: DENY` blocks all framing.
- CSP `frame-ancestors 'none'` is the modern equivalent.
- Use `frame-ancestors 'self'` if framing from the same origin is needed.

---

## CWE-693 — Missing X-Content-Type-Options: nosniff

**Why it matters:** Without `X-Content-Type-Options: nosniff`, browsers may MIME-sniff a response and interpret it as a different content type than declared. A JSON response containing user-controlled data can be interpreted as an executable script, enabling XSS attacks. A file upload with a user-controlled extension can be executed as server-side code.

**Attack vector in Spring:**
```java
// VULNERABLE — no nosniff header
@GetMapping("/upload-preview")
public ResponseEntity<?> preview(@RequestParam String content) {
    // Returns user-controlled content as JSON
    // Without nosniff, a browser might sniff it as text/html + script
    return ResponseEntity
        .contentType(MediaType.APPLICATION_JSON)
        .body(content);  // Could be: <script>alert(1)</script>
}
```
If the response is served as `application/json` but the body starts with `<script>`, some browsers may sniff it as HTML and execute the script.

**How to prevent:**
```java
// SAFE — nosniff header set by the security filter chain
http.headers(headers -> {
    headers.contentTypeOptions(c -> c.nosniff());
    // Produces: X-Content-Type-Options: nosniff
});
```
- Always set `X-Content-Type-Options: nosniff` for all responses.
- Ensure the `Content-Type` header accurately reflects the response body.

---

## CWE-79 — JavaScript Inlining Vulnerability (Thymeleaf)

**Why it matters:** When a template engine inlines server-side data directly into JavaScript without proper escaping, user-controlled data can break out of the JavaScript string context and execute arbitrary code. This is a JavaScript-specific XSS variant that bypasses HTML-escaping protections.

**Attack vector in Spring:**
```yaml
# VULNERABLE — JavaScript inlining enabled in Thymeleaf
spring:
  thymeleaf:
    javascript-inlining: true  # Allows ${...} in <script> blocks
```
```html
<!-- VULNERABLE — data inlined into JS without escaping -->
<script th:inline="javascript">
    var userName = /*[[${userName}]]*/ 'guest';
    // If userName = </script><script>alert(1)</script>
    // The </script> tag closes the script block, and the second script executes
</script>
```

**How to prevent:**
```yaml
# SAFE — disable JavaScript inlining in production
spring:
  thymeleaf:
    javascript-inlining: false
```
- If JavaScript inlining is required, ensure all data is properly escaped for the JavaScript context.
- Use `Encode.forJavaScriptContent()` from OWASP Java Encoder.
- Set CSP `script-src 'self'` to block inline scripts as a second layer.
