# 07 · CSRF, CORS, security headers and output encoding

Checklist section: **§7 Web layer: CSRF, CORS, headers, XSS** · Module: `m07-web-layer` · Port: **8087**
PoC: [`attacks/07-web-layer.sh`](../attacks/07-web-layer.sh) · Run: `scripts/run-module.sh m07-web-layer`

Two security filter chains live in this module: `/vuln7/**` (CSRF off, headers off, wildcard CORS) and
`/safe7/**` (CSRF with a double-submit cookie, explicit CORS allow-list, full header set). They are
separate `SecurityFilterChain` beans selected by `securityMatcher`, so the difference is configuration
you can diff, not a narrative.

## What this module demonstrates

| # | Vulnerability | CWE | Insecure | Hardened |
|---|---------------|-----|----------|----------|
| 1 | CSRF on a cookie-authorised state change | CWE-352 | `POST /vuln7/subscriptions/{id}/cancel` | `POST /safe7/subscriptions/{id}/cancel` (+ `GET /safe7/csrf`) |
| 2 | CORS: wildcard origin patterns **with credentials** | CWE-942 | preflight/GET `/vuln7/profile` from `http://evil.example.invalid` | `/safe7/profile` allows `http://localhost:4200` only |
| 3 | Security headers disabled | CWE-693 | no CSP / nosniff / frame options / HSTS / referrer policy | `headers(...)` with CSP, `frame-ancestors 'none'`, HSTS, `nosniff`, `Referrer-Policy` |
| 4 | Reflected XSS via `th:utext` | CWE-79 | `GET /vuln7/page?name=` | `GET /safe7/page` (`th:text`) |
| 5 | Stored XSS | CWE-79 | `POST /vuln7/notes` then `GET /vuln7/page` | `/safe7/notes` stored and rendered as text |
| 6 | Clickjacking (page is frameable) | CWE-1021 | `GET /vuln7/clickjacking` | `frameOptions.deny()` + CSP `frame-ancestors` |
| 7 | Missing `nosniff` on a user-controlled body | CWE-693 | `GET /vuln7/upload-preview` | header set by the chain |
| 8 | Thymeleaf JavaScript inlining | CWE-79 | `spring.thymeleaf.javascript-inlining: true` | set `false` in production |
| 9 | Self-inspection endpoint for CI | — | — | `GET /safe7/headers-selftest` |

## Reproduce

```bash
attacks/07-web-layer.sh
```

### CSRF: the attacker page

The vulnerable endpoint needs only the victim's session cookie. A page hosted anywhere is enough:

```html
<!-- evil.example.invalid/keep-tariff.html -->
<form id="f" method="POST" action="http://127.0.0.1:8087/vuln7/subscriptions/SUB-1001/cancel"></form>
<script>document.getElementById('f').submit()</script>
```

A browser that holds the session cookie sends it automatically. From a shell the same effect is one
`curl` with no token — which is why the PoC is safe to run:

```bash
curl -s -X POST http://127.0.0.1:8087/vuln7/subscriptions/SUB-1001/cancel
```

Against `/safe7`, get the token first and send it in the header:

```bash
TOKEN=$(curl -s http://127.0.0.1:8087/safe7/csrf | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
curl -s -i -X POST -H "X-XSRF-TOKEN: $TOKEN" -H "Cookie: XSRF-TOKEN=$TOKEN" \
     http://127.0.0.1:8087/safe7/subscriptions/SUB-1001/cancel
```

### CORS

```bash
curl -s -i -H 'Origin: http://evil.example.invalid' http://127.0.0.1:8087/vuln7/profile | grep -i access-control
# Access-Control-Allow-Origin: http://evil.example.invalid
# Access-Control-Allow-Credentials: true
```

That pair turns any website into a proxy for a logged-in user's data. `/safe7/profile` sends no CORS
headers for that origin.

### XSS

```bash
curl -s 'http://127.0.0.1:8087/vuln7/page?name=%3Cimg%20src=x%20onerror=alert(document.cookie)%3E'
```

The payload is in the HTML as markup. `/safe7/page` renders it as text (`&lt;img …`), and the CSP would
block the inline handler even if some other template forgot the escaping.

## Fix, in the order that matters

1. **CSRF on every cookie-authenticated state change.** Vary the token per session, verify on the
   server, and scope any `csrf().disable()` to a stateless token API with a written justification.
2. **CORS: explicit origins, minimal methods/headers.** Never `"*"` with `allowCredentials(true)`, never
   reflect the request origin. Credentials go to exactly the front-end you own.
3. **Headers are one line and cover a whole class of attacks:** CSP (with `frame-ancestors 'none'`),
   `X-Content-Type-Options: nosniff`, `Referrer-Policy`, HSTS.
4. **Output encoding is the template's job:** `th:text` everywhere, `th:utext` reviewed as a blocker.
   CSP is the second layer, not the first.
5. **Contract test the headers** (`/safe7/headers-selftest` exists so CI can assert them).

## Detection

* Semgrep: `spring-csrf-disabled`, `spring-cors-wildcard-with-credentials`,
  `spring-security-headers-disabled`.
* DAST baseline scan on staging (`scripts/run_dast_zap.sh`) reports missing CSP/nosniff/HSTS and
  frame-able pages in one pass.
* Grep the diff for `utext`, `innerHTML`, `csrf().disable`, `setAllowedOriginPatterns`.
