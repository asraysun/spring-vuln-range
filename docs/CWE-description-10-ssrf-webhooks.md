# CWE Reference — §10 Outbound Calls and Webhooks

CWEs extracted from `docs/10-ssrf-webhooks.md` with developer-focused comments.

---

## CWE-918 — Server-Side Request Forgery (SSRF)

**Why it matters:** SSRF allows an attacker to make the server initiate HTTP requests to arbitrary URLs. The server has network access that the attacker does not — it can reach internal services, cloud metadata endpoints, and other resources behind firewalls. SSRF can lead to internal data exfiltration, cloud credential theft (via metadata services), port scanning of internal networks, and in some configurations, Remote Code Execution through internal admin panels.

**Attack vector in Spring:**
```java
// VULNERABLE — caller-supplied URL fetched with the service's network position
@PostMapping("/fetch")
public ResponseEntity<?> fetch(@RequestBody FetchRequest req) {
    // Attacker sends: {"url":"http://127.0.0.1:8090/vuln10/internal-admin/users"}
    // The server makes a request to an internal admin surface the caller cannot reach directly
    RestTemplate rt = new RestTemplate();  // No timeouts, no redirect control
    String body = rt.getForObject(req.getUrl(), String.class);
    return ResponseEntity.ok(Map.of("body", body));
}

// VULNERABLE — metadata service reachable
// Attacker sends: {"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials"}
// The server fetches AWS IAM credentials running on the instance
// Returns: {"body":"{...accessKeyId, secretAccessKey, token...}"}

// VULNERABLE — redirect-following defeats naive allow-list
// Attacker sends: {"url":"http://127.0.0.1:8090/vuln10/redirect-to-internal"}
// The server follows the redirect to an internal endpoint
// The allow-list is checked on the first URL, not the redirect target
```

**How to prevent:**
```java
// SAFE — egress allow-list with DNS resolution check
@PostMapping("/fetch")
public ResponseEntity<?> fetch(@RequestBody FetchRequest req) {
    URL url = new URL(req.getUrl());
    
    // 1. Scheme allow-list
    if (!Set.of("http", "https").contains(url.getProtocol())) {
        return ResponseEntity.badRequest().body("Scheme not allowed");
    }
    
    // 2. Host allow-list
    if (!ALLOWED_HOSTS.contains(url.getHost())) {
        return ResponseEntity.badRequest().body("Host not allowed");
    }
    
    // 3. Port allow-list
    int port = url.getPort() > 0 ? url.getPort() : (url.getProtocol().equals("https") ? 443 : 80);
    if (!ALLOWED_PORTS.contains(port)) {
        return ResponseEntity.badRequest().body("Port not allowed");
    }
    
    // 4. Path allow-list
    if (!ALLOWED_PATH_PREFIXES.stream().anyMatch(url.getPath()::startsWith)) {
        return ResponseEntity.badRequest().body("Path not allowed");
    }
    
    // 5. Resolve DNS and check the resolved IP address
    InetAddress[] addresses = InetAddress.getAllByName(url.getHost());
    for (InetAddress addr : addresses) {
        if (addr.isAnyLocalAddress() ||    // 0.0.0.0
            addr.isLoopbackAddress() ||     // 127.0.0.1
            addr.isLinkLocalAddress() ||    // 169.254.0.0/16 (metadata)
            addr.isSiteLocalAddress()) {    // 10.x.x.x, 192.168.x.x
            return ResponseEntity.badRequest().body("Private address not allowed");
        }
    }
    
    // 6. Disable redirect-following
    SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
    factory.setInstanceFollowRedirects(false);
    factory.setConnectTimeout(2000);
    factory.setReadTimeout(4000);
    
    RestTemplate rt = new RestTemplate(factory);
    String body = rt.getForObject(req.getUrl(), String.class);
    return ResponseEntity.ok(Map.of("body", body));
}
```
- Resolve the hostname BEFORE making the connection and check the resolved IP address.
- Disable redirect-following — an allow-list checked once is not a control.
- Judge the resolved address, not the hostname (DNS rebinding attacks).
- Use an egress proxy or network policies to close the resolution gap.

---

## CWE-306 — Missing Authentication for Critical Function (Internal Admin Surface)

**Why it matters:** Internal admin endpoints are often left without authentication because "they are only reachable internally, so they are safe." But SSRF (CWE-918) turns any URL-fetching endpoint into a proxy that can reach these internal surfaces. An unauthenticated admin endpoint becomes accessible to any attacker who can trigger an outbound request.

**Attack vector in Spring:**
```java
// VULNERABLE — internal admin surface with no authentication
// "It is internal, so it is safe" — but SSRF reaches it
@GetMapping("/internal-admin/users")
public ResponseEntity<?> internalAdminUsers() {
    // No authentication required
    // SSRF from POST /vuln10/fetch can reach this endpoint
    return ResponseEntity.ok(userRepository.findAll());
}

// Combined with SSRF:
// Attacker calls POST /vuln10/fetch with {"url":"http://127.0.0.1:8090/vuln10/internal-admin/users"}
// The server fetches the admin endpoint and returns all user data
```

**How to prevent:**
- Every endpoint must have authentication, even if it is "internal."
- Use network policies (Kubernetes NetworkPolicy) to isolate internal services.
- If an endpoint is only reachable via SSRF, remove it from the public attack surface entirely.
```java
// SAFE — internal endpoints still need authentication
@GetMapping("/internal-admin/users")
@PreAuthorize("hasRole('ADMIN')")
public ResponseEntity<?> internalAdminUsers() {
    return ResponseEntity.ok(userRepository.findAll());
}
```
- In the safe module (`/safe10`), there is no admin surface — the fetcher only allows paths under an allow-list, and no admin endpoints exist there.

---

## CWE-434 — Unrestricted Upload of File with Dangerous Type (Fetch-and-Store)

**Why it matters:** When a server fetches a URL and stores the response without validating the content type or size, an attacker can store arbitrary files on the server. This includes executable files, scripts, or large files that exhaust disk space. Combined with SSRF, the attacker can fetch internal files and store them externally.

**Attack vector in Spring:**
```java
// VULNERABLE — fetch and store without type or size checks
@PostMapping("/avatar")
public ResponseEntity<?> storeAvatar(@RequestBody FetchRequest req) {
    // Attacker sends: {"url":"http://127.0.0.1:8090/vuln10/internal-admin/users"}
    // Server fetches internal data and writes it to disk
    byte[] data = rt.getForObject(req.getUrl(), byte[].class);
    Files.write(Path.of("/var/uploads/avatar.bin"), data);  // No size check, no type check
    return ResponseEntity.ok("stored");
}
```
The attacker fetches internal data and stores it on the server's filesystem. No size limit means a gigabyte response fills the disk. No type check means any content is accepted.

**How to prevent:**
```java
// SAFE — size cap, no store endpoint
private static final int MAX_RESPONSE_BYTES = 256 * 1024;  // 256 KB

@PostMapping("/fetch-preview")
public ResponseEntity<?> fetchPreview(@RequestBody FetchRequest req) {
    URL url = new URL(req.getUrl());
    // Validate URL (see CWE-918 prevention)
    
    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
    conn.setInstanceFollowRedirects(false);
    conn.setConnectTimeout(2000);
    conn.setReadTimeout(4000);
    
    int contentLength = conn.getContentLength();
    if (contentLength > MAX_RESPONSE_BYTES) {
        return ResponseEntity.status(413).body("Response too large");
    }
    
    byte[] data = conn.getInputStream().readAllBytes();
    if (data.length > MAX_RESPONSE_BYTES) {
        return ResponseEntity.status(413).body("Response too large");
    }
    
    // No store endpoint — just return the preview
    return ResponseEntity.ok(Map.of("preview", Base64.getEncoder().encodeToString(data)));
}
```
- Cap the response size before writing to disk.
- Validate content type against an allow-list.
- Consider not storing fetched content at all — return a preview instead.

---

## CWE-400 — Uncontrolled Resource Consumption (Outbound Client Without Timeouts)

**Why it matters:** An outbound HTTP client without timeouts holds a request thread indefinitely when the downstream service is slow or unresponsive. An attacker can trigger many slow requests, exhausting all available threads and causing a denial of service. This is a resource exhaustion attack that doesn't require network bandwidth.

**Attack vector in Spring:**
```java
// VULNERABLE — outbound client without timeouts
RestTemplate rt = new RestTemplate();  // Default: no timeout
// Attacker sends: {"url":"http://127.0.0.1:8090/vuln10/slow"}
// The /slow endpoint never responds
// The request thread is held forever
// 200 slow requests = 200 held threads = service outage
```

**How to prevent:**
```java
// SAFE — connect 2s, read 4s
SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
factory.setConnectTimeout(2000);   // 2 seconds
factory.setReadTimeout(4000);      // 4 seconds
RestTemplate rt = new RestTemplate(factory);
```
- Connect timeout: time to establish the TCP connection.
- Read timeout: time to receive the first byte of the response.
- A downstream that never answers must not hold a request thread.

---

## CWE-770 — Allocation of Resources Without Limits (Response Size)

**Why it matters:** Without a response size cap, a downstream service can return an arbitrarily large response that fills the server's memory or disk. An attacker can trigger this by fetching a URL that returns a large payload, causing an OutOfMemoryError or disk exhaustion.

**Attack vector in Spring:**
```java
// VULNERABLE — no size cap on fetched response
@PostMapping("/fetch")
public ResponseEntity<?> fetch(@RequestBody FetchRequest req) {
    byte[] data = rt.getForObject(req.getUrl(), byte[].class);
    // Attacker sends: {"url":"http://some-server/large-file"}
    // Server returns 10 GB → OOM crash
    Files.write(Path.of("/var/data/fetched.bin"), data);
    // Or: 10 GB written to disk → disk exhaustion
    return ResponseEntity.ok(Map.of("size", data.length));
}
```

**How to prevent:**
```java
// SAFE — MAX_RESPONSE_BYTES cap
private static final int MAX_RESPONSE_BYTES = 256 * 1024;  // 256 KB

// Check Content-Length header before reading the body
int contentLength = conn.getContentLength();
if (contentLength > MAX_RESPONSE_BYTES) {
    return ResponseEntity.status(413).body("Response too large");
}

// Also check actual read size
byte[] data = conn.getInputStream().readAllBytes();
if (data.length > MAX_RESPONSE_BYTES) {
    return ResponseEntity.status(413).body("Response too large");
}
```

---

## CWE-345 — Insufficient Variable Integrity Validation (Unsigned Webhook)

**Why it matters:** When a webhook does not verify the signature of the incoming request, any attacker can send a fake webhook and make the server perform unintended actions. The server trusts the request body completely — status, amount, subscription ID, and other critical values are all attacker-controlled.

**Attack vector in Spring:**
```java
// VULNERABLE — unsigned payment webhook
@PostMapping("/webhook/payment")
public ResponseEntity<?> paymentWebhook(@RequestBody PaymentWebhook req) {
    // signatureChecked: false — no signature verification
    // Attacker sends: {"subscriptionId":"SUB-2001","status":"PAID","amount":"0.00","days":3650}
    // The server marks any subscription as PAID, for any amount, for any duration
    paymentService.processPayment(req.getSubscriptionId(), req.getStatus(), req.getAmount());
    return ResponseEntity.ok("processed");
}
```
`POST /vuln10/webhook/payment` with `{"subscriptionId":"SUB-2001","status":"PAID","amount":"0.00","days":3650}` marks any subscription as paid without any authentication. Anyone can mark anything paid, as often as they like.

**How to prevent:**
```java
// SAFE — HMAC-SHA256 signature verification
@PostMapping("/webhook/payment")
public ResponseEntity<?> paymentWebhook(@RequestBody String rawBody,
                                         @RequestHeader("X-Webhook-Signature") String signature,
                                         @RequestHeader("X-Webhook-Timestamp") String timestamp) {
    // 1. Verify timestamp window (replay protection)
    long ts = Long.parseLong(timestamp);
    if (Math.abs(System.currentTimeMillis() - ts) > 300_000) {  // 5 minutes
        return ResponseEntity.status(400).body("Timestamp outside window");
    }
    
    // 2. Verify HMAC signature over timestamp + raw body
    String expectedSignature = hmacSha256(webhookSecret, timestamp + "." + rawBody);
    if (!MessageDigest.isEqual(
            expectedSignature.getBytes(),
            Base64.getDecoder().decode(signature))) {
        return ResponseEntity.status(401).body("Invalid signature");
    }
    
    // 3. Verify idempotency key
    String eventId = request.getHeader("X-Webhook-Event-Id");
    if (processedEvents.contains(eventId)) {
        return ResponseEntity.ok("duplicate");  // Already processed
    }
    processedEvents.add(eventId);
    
    // 4. Re-derive the expected values from the order record
    // A correctly signed message can still be a business-logic bug
    PaymentEvent event = objectMapper.readValue(rawBody, PaymentEvent.class);
    Order order = orderRepository.findById(event.getSubscriptionId()).orElseThrow();
    // Verify amount matches the order, status is valid transition, etc.
    
    return ResponseEntity.ok("processed");
}
```
- Sign over `timestamp + rawBody` with HMAC-SHA256.
- Compare signatures with `MessageDigest.isEqual` (constant-time).
- The secret comes from env/Vault, not from a repository default.

---

## CWE-347 — Improper Verification of Cryptographic Signature (Webhook)

**Why it matters:** CWE-347 in the context of webhooks refers to accepting a webhook without verifying its cryptographic signature. The signature is the webhook's authentication mechanism — without it, the server has no way to verify that the request came from the legitimate provider.

**Attack vector in Spring:**
```java
// VULNERABLE — signatureChecked: false
@PostMapping("/webhook/payment")
public ResponseEntity<?> paymentWebhook(@RequestBody PaymentWebhook req) {
    // No signature verification at all
    // The server processes the webhook as if it came from the payment provider
    // But anyone can send this request
}
```

**How to prevent:**
- Same as CWE-345: HMAC-SHA256 over `timestamp + rawBody`, verified with `MessageDigest.isEqual`.
- Signature proves origin, not correctness — re-derive prices and statuses from the order record.

---

## CWE-294 — Authentication Bypass Using a Replay Attack

**Why it matters:** Without an idempotency key and timestamp window, a valid webhook can be resent multiple times and each replay is processed as a new event. This leads to duplicate payments, extended subscriptions, or repeated actions. An attacker can replay old webhooks to re-apply benefits.

**Attack vector in Spring:**
```java
// VULNERABLE — replayable webhook: no timestamp window, no idempotency key
@PostMapping("/webhook/payment")
public ResponseEntity<?> paymentWebhook(@RequestBody PaymentWebhook req) {
    // Same request processed N times = N payments applied
    for (int i = 0; i < 3; i++) {
        // Attacker sends the same webhook 3 times
        // Each one marks the subscription as PAID for 30 days
        // Subscription expires in 90 days instead of 30
        paymentService.processPayment(req.getSubscriptionId(), req.getStatus(), req.getAmount());
    }
    return ResponseEntity.ok("processed");
}
```
`POST /vuln10/webhook/payment` sent three times with the same body → three applications of the payment.

**How to prevent:**
```java
// SAFE — timestamp window + idempotency key
@PostMapping("/webhook/payment")
public ResponseEntity<?> paymentWebhook(...) {
    // 1. Timestamp window (300 seconds)
    long ts = Long.parseLong(timestamp);
    if (Math.abs(System.currentTimeMillis() - ts) > 300_000) {
        return ResponseEntity.status(400).body("Stale timestamp");
    }
    
    // 2. Idempotency key
    String eventId = request.getHeader("X-Webhook-Event-Id");
    if (processedEvents.contains(eventId)) {
        return ResponseEntity.ok(Map.of("duplicate", true, "originallyAppliedAt", ...));
    }
    processedEvents.add(eventId);
    
    // In production: this is a unique index on the payment-event table,
    // not a ConcurrentHashMap
}
```
- `REPLAY_WINDOW_SECONDS` (300) rejects stale messages.
- `X-Webhook-Event-Id` idempotency store turns replays into no-ops.
- In production, use a unique index in the database, not an in-memory map.
