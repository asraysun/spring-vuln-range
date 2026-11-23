# Spring Security: How to Prevent SSRF & Webhook Vulnerabilities

A practical guide to securing Spring Boot against Server-Side Request Forgery (SSRF), unsafe outbound calls, and unauthenticated webhooks — covering 7 CWEs found in real Spring applications.

---

## Table of Contents

1. [SSRF Prevention (Egress Control)](#1-ssrf-prevention-egress-control)
2. [Internal Admin Surface Protection](#2-internal-admin-surface-protection)
3. [Secure Fetch-and-Store](#3-secure-fetch-and-store)
4. [Outbound Client Timeouts](#4-outbound-client-timeouts)
5. [Response Size Limits](#5-response-size-limits)
6. [Webhook Signature Verification](#6-webhook-signature-verification)
7. [Webhook Replay Protection](#7-webhook-replay-protection)

---

## 1. SSRF Prevention (Egress Control)

**CWE-918** — *Server-Side Request Forgery*

### The Problem

SSRF allows an attacker to make the server initiate HTTP requests to arbitrary URLs. The server has network access that the attacker does not — it can reach internal services, cloud metadata endpoints, and other resources behind firewalls. SSRF can lead to internal data exfiltration, cloud credential theft (via metadata services), port scanning of internal networks, and in some configurations, Remote Code Execution through internal admin panels.

```java
// ❌ VULNERABLE — caller-supplied URL fetched with the service's network position
@PostMapping("/fetch")
public ResponseEntity<?> fetch(@RequestBody FetchRequest req) {
    // Attacker sends: {"url":"http://127.0.0.1:8090/vuln10/internal-admin/users"}
    // The server makes a request to an internal admin surface the caller cannot reach directly
    RestTemplate rt = new RestTemplate();  // No timeouts, no redirect control
    String body = rt.getForObject(req.getUrl(), String.class);
    return ResponseEntity.ok(Map.of("body", body));
}

// ❌ VULNERABLE — metadata service reachable
// Attacker sends: {"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials"}
// The server fetches AWS IAM credentials running on the instance

// ❌ VULNERABLE — redirect-following defeats naive allow-list
// Attacker sends: {"url":"http://127.0.0.1:8090/vuln10/redirect-to-internal"}
// The server follows the redirect to an internal endpoint
// The allow-list is checked on the first URL, not the redirect target
```

### The Fix

Validate the URL **before** making the connection. Resolve DNS and check the resolved IP address. Disable redirect-following.

```java
// ✅ SAFE — egress allow-list with DNS resolution check
private static final Set<String> ALLOWED_HOSTS = Set.of("api.example.com", "cdn.example.com");
private static final Set<Integer> ALLOWED_PORTS = Set.of(80, 443);
private static final Set<String> ALLOWED_PATH_PREFIXES = Set.of("/api/v1/", "/public/");

@PostMapping("/fetch")
public ResponseEntity<?> fetch(@RequestBody FetchRequest req) {
    try {
        URL url = new URL(req.getUrl());

        // 1. Scheme allow-list
        if (!Set.of("http", "https").contains(url.getProtocol().toLowerCase())) {
            return ResponseEntity.badRequest().body("Scheme not allowed");
        }

        // 2. Host allow-list
        String host = url.getHost();
        if (host == null || !ALLOWED_HOSTS.contains(host)) {
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
        InetAddress[] addresses = InetAddress.getAllByName(host);
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
        factory.setConnectTimeout(2000);  // 2 seconds
        factory.setReadTimeout(4000);     // 4 seconds

        RestTemplate rt = new RestTemplate(factory);
        String body = rt.getForObject(url, String.class);
        return ResponseEntity.ok(Map.of("body", body));

    } catch (Exception e) {
        log.error("Fetch failed for URL: {}", req.getUrl(), e);
        return ResponseEntity.status(500).body("Fetch failed");
    }
}
```

**Key rules:**
- **Resolve the hostname BEFORE making the connection** and check the resolved IP address
- Judge the resolved address, not the hostname (DNS rebinding attacks can change the target between validation and connection)
- **Disable redirect-following** (`setInstanceFollowRedirects(false)`) — an allow-list checked once is not a control
- Use an egress proxy or network policies to close the resolution gap
- Log all egress attempts with the target URL and resolved IP for security monitoring

---

## 2. Internal Admin Surface Protection

**CWE-306** — *Missing Authentication for Critical Function*

### The Problem

Internal admin endpoints are often left without authentication because "they are only reachable internally, so they are safe." But SSRF turns any URL-fetching endpoint into a proxy that can reach these internal surfaces. An unauthenticated admin endpoint becomes accessible to any attacker who can trigger an outbound request.

```java
// ❌ VULNERABLE — internal admin surface with no authentication
// "It is internal, so it is safe" — but SSRF reaches it
@GetMapping("/internal-admin/users")
public ResponseEntity<?> internalAdminUsers() {
    // No authentication required
    // SSRF from POST /fetch can reach this endpoint
    return ResponseEntity.ok(userRepository.findAll());
}

// Combined with SSRF:
// Attacker calls POST /fetch with {"url":"http://127.0.0.1:8090/internal-admin/users"}
// The server fetches the admin endpoint and returns all user data
```

### The Fix

Every endpoint must have authentication, even if it is "internal." Use network policies to isolate internal services.

```java
// ✅ SAFE — internal endpoints still need authentication
@GetMapping("/internal-admin/users")
@PreAuthorize("hasRole('ADMIN')")
public ResponseEntity<?> internalAdminUsers() {
    return ResponseEntity.ok(userRepository.findAll());
}

// ✅ SAFE — network isolation (Kubernetes NetworkPolicy example)
# networkpolicy.yaml
# apiVersion: networking.k8s.io/v1
# kind: NetworkPolicy
# metadata:
#   name: app-egress-policy
# spec:
#   podSelector:
#     matchLabels:
#       app: spring-app
#   policyTypes:
#   - Egress
#   egress:
#   - to:
#     - podSelector:
#         matchLabels:
#           app: postgres
#     ports:
#     - port: 5432
#   - to:
#     - ipBlock:
#         cidr: 0.0.0.0/0
#         except:
#         - 169.254.169.254/32    # Block cloud metadata
#         - 10.0.0.0/8            # Block internal ranges
#         - 172.16.0.0/12
#         - 192.168.0.0/16
```

**Key rules:**
- **Every endpoint must have authentication**, even if it is "internal"
- Use network policies (Kubernetes NetworkPolicy, Docker network ACLs) to restrict egress traffic
- If an endpoint is only reachable via SSRF, remove it from the public attack surface entirely
- Never rely on "internal-only" or "behind the firewall" as a security control

---

## 3. Secure Fetch-and-Store

**CWE-434** — *Unrestricted Upload of File with Dangerous Type (Fetch-and-Store)*

### The Problem

When a server fetches a URL and stores the response without validating the content type or size, an attacker can store arbitrary files on the server. This includes executable files, scripts, or large files that exhaust disk space. Combined with SSRF, the attacker can fetch internal files and store them externally.

```java
// ❌ VULNERABLE — fetch and store without type or size checks
@PostMapping("/avatar")
public ResponseEntity<?> storeAvatar(@RequestBody FetchRequest req) {
    // Attacker sends: {"url":"http://127.0.0.1:8090/internal-admin/users"}
    // Server fetches internal data and writes it to disk
    byte[] data = rt.getForObject(req.getUrl(), byte[].class);
    Files.write(Path.of("/var/uploads/avatar.bin"), data);  // No size check, no type check
    return ResponseEntity.ok("stored");
}
```

### The Fix

Cap response size, validate content type, and avoid storing fetched content when possible.

```java
// ✅ SAFE — size cap, no store endpoint (return preview instead)
private static final int MAX_RESPONSE_BYTES = 256 * 1024;  // 256 KB

@PostMapping("/fetch-preview")
public ResponseEntity<?> fetchPreview(@RequestBody FetchRequest req) {
    // Validate URL first (see CWE-918 prevention above)
    URL url = new URL(req.getUrl());
    if (!ALLOWED_HOSTS.contains(url.getHost())) {
        return ResponseEntity.badRequest().body("Host not allowed");
    }

    try {
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setInstanceFollowRedirects(false);
        conn.setConnectTimeout(2000);
        conn.setReadTimeout(4000);

        // Check Content-Length header before reading the body
        int contentLength = conn.getContentLength();
        if (contentLength > MAX_RESPONSE_BYTES) {
            return ResponseEntity.status(413).body("Response too large");
        }

        byte[] data = conn.getInputStream().readAllBytes();
        if (data.length > MAX_RESPONSE_BYTES) {
            return ResponseEntity.status(413).body("Response too large");
        }

        // Validate content type (optional, based on use case)
        String contentType = conn.getContentType();
        if (contentType != null && !contentType.startsWith("image/")) {
            return ResponseEntity.badRequest().body("Only image content allowed");
        }

        // No store endpoint — just return the preview
        return ResponseEntity.ok(Map.of(
            "preview", Base64.getEncoder().encodeToString(data),
            "contentType", contentType,
            "size", data.length
        ));

    } catch (IOException e) {
        log.error("Fetch failed for URL: {}", req.getUrl(), e);
        return ResponseEntity.status(500).body("Fetch failed");
    }
}
```

**Key rules:**
- **Cap the response size** before writing to disk or memory
- Validate `Content-Type` against an allow-list when applicable
- Consider **not storing fetched content at all** — return a preview instead
- If storage is required, generate a random filename and store outside the web root
- Scan fetched content with AV/CDR if it will be served to users

---

## 4. Outbound Client Timeouts

**CWE-400** — *Uncontrolled Resource Consumption (Outbound Client Without Timeouts)*

### The Problem

An outbound HTTP client without timeouts holds a request thread indefinitely when the downstream service is slow or unresponsive. An attacker can trigger many slow requests, exhausting all available threads and causing a denial of service.

```java
// ❌ VULNERABLE — outbound client without timeouts
RestTemplate rt = new RestTemplate();  // Default: no timeout
// Attacker sends: {"url":"http://127.0.0.1:8090/slow"}
// The /slow endpoint never responds
// The request thread is held forever
// 200 slow requests = 200 held threads = service outage
```

### The Fix

Set explicit connect and read timeouts on all outbound HTTP clients.

```java
// ✅ SAFE — connect 2s, read 4s
SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
factory.setInstanceFollowRedirects(false);
factory.setConnectTimeout(2000);   // 2 seconds to establish TCP connection
factory.setReadTimeout(4000);      // 4 seconds to receive first byte of response

RestTemplate rt = new RestTemplate(factory);
// Or with modern Spring WebClient:
HttpClient httpClient = HttpClient.create()
    .responseTimeout(Duration.ofSeconds(4))
    .connectTimeout(Duration.ofSeconds(2));

WebClient webClient = WebClient.builder()
    .clientConnector(new ReactorClientHttpConnector(httpClient))
    .build();
```

**Timeout configuration reference:**

| Timeout Type | Value | Purpose |
|--------------|-------|---------|
| Connect Timeout | 2-5 seconds | Time to establish TCP connection |
| Read Timeout | 5-10 seconds | Time to receive first byte of response |
| Write Timeout | 5-10 seconds | Time to send request body |

**Key rules:**
- **Always set connect and read timeouts** on outbound HTTP clients
- A downstream service that never answers must not hold a request thread
- Use `WebClient` with `reactor-netty` for reactive, non-blocking timeout handling
- Log timeout events — high timeout rates indicate downstream issues or DoS attempts

---

## 5. Response Size Limits

**CWE-770** — *Allocation of Resources Without Limits (Response Size)*

### The Problem

Without a response size cap, a downstream service can return an arbitrarily large response that fills the server's memory or disk. An attacker can trigger this by fetching a URL that returns a large payload, causing an OutOfMemoryError or disk exhaustion.

```java
// ❌ VULNERABLE — no size cap on fetched response
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

### The Fix

Cap the response size before reading the body and before writing to disk.

```java
// ✅ SAFE — MAX_RESPONSE_BYTES cap
private static final int MAX_RESPONSE_BYTES = 256 * 1024;  // 256 KB

@PostMapping("/fetch")
public ResponseEntity<?> fetch(@RequestBody FetchRequest req) {
    HttpURLConnection conn = (HttpURLConnection) new URL(req.getUrl()).openConnection();
    conn.setInstanceFollowRedirects(false);
    conn.setConnectTimeout(2000);
    conn.setReadTimeout(4000);

    // Check Content-Length header before reading
    int contentLength = conn.getContentLength();
    if (contentLength > MAX_RESPONSE_BYTES) {
        return ResponseEntity.status(413).body("Response too large");
    }

    // Also check actual read size
    byte[] data = conn.getInputStream().readAllBytes();
    if (data.length > MAX_RESPONSE_BYTES) {
        return ResponseEntity.status(413).body("Response too large");
    }

    return ResponseEntity.ok(Map.of("body", Base64.getEncoder().encodeToString(data)));
}
```

**Key rules:**
- **Check `Content-Length` header** before reading the response body
- **Check actual read size** after reading (header can be missing or misleading)
- Return `413 Payload Too Large` for oversized responses
- Set `MAX_RESPONSE_BYTES` to the maximum reasonable size for your use case (256 KB for previews, 1 MB for API responses)

---

## 6. Webhook Signature Verification

**CWE-345** — *Insufficient Variable Integrity Validation (Unsigned Webhook)*  
**CWE-347** — *Improper Verification of Cryptographic Signature*

### The Problem

When a webhook does not verify the signature of the incoming request, any attacker can send a fake webhook and make the server perform unintended actions. The server trusts the request body completely — status, amount, subscription ID, and other critical values are all attacker-controlled.

```java
// ❌ VULNERABLE — unsigned payment webhook
@PostMapping("/webhook/payment")
public ResponseEntity<?> paymentWebhook(@RequestBody PaymentWebhook req) {
    // signatureChecked: false — no signature verification
    // Attacker sends: {"subscriptionId":"SUB-2001","status":"PAID","amount":"0.00","days":3650}
    // The server marks any subscription as PAID, for any amount, for any duration
    paymentService.processPayment(req.getSubscriptionId(), req.getStatus(), req.getAmount());
    return ResponseEntity.ok("processed");
}
```

### The Fix

Verify HMAC-SHA256 signature over `timestamp + raw body`. Use constant-time comparison.

```java
// ✅ SAFE — HMAC-SHA256 signature verification
@PostMapping("/webhook/payment")
public ResponseEntity<?> paymentWebhook(
        @RequestBody String rawBody,
        @RequestHeader("X-Webhook-Signature") String signature,
        @RequestHeader("X-Webhook-Timestamp") String timestampStr,
        @RequestHeader("X-Webhook-Event-Id") String eventId,
        HttpServletRequest request) {

    // 1. Verify timestamp window (replay protection)
    long ts;
    try {
        ts = Long.parseLong(timestampStr);
    } catch (NumberFormatException e) {
        return ResponseEntity.badRequest().body("Invalid timestamp");
    }
    
    if (Math.abs(System.currentTimeMillis() - ts) > 300_000) {  // 5 minutes
        return ResponseEntity.status(400).body("Timestamp outside window");
    }

    // 2. Verify HMAC signature over timestamp + raw body
    String expectedSignature = hmacSha256(webhookSecret, timestampStr + "." + rawBody);
    if (!MessageDigest.isEqual(
            expectedSignature.getBytes(StandardCharsets.UTF_8),
            Base64.getDecoder().decode(signature))) {
        log.warn("Webhook signature verification failed for event {}", eventId);
        return ResponseEntity.status(401).body("Invalid signature");
    }

    // 3. Verify idempotency key (replay protection)
    if (processedEvents.contains(eventId)) {
        log.info("Duplicate webhook event {}", eventId);
        return ResponseEntity.ok(Map.of("duplicate", true, "originallyProcessedAt", Instant.now()));
    }
    processedEvents.add(eventId);

    // 4. Parse and validate business logic
    PaymentEvent event;
    try {
        event = objectMapper.readValue(rawBody, PaymentEvent.class);
    } catch (JsonProcessingException e) {
        return ResponseEntity.badRequest().body("Invalid JSON");
    }

    // 5. Re-derive expected values from the order record
    // A correctly signed message can still be a business-logic bug
    Order order = orderRepository.findById(event.getSubscriptionId()).orElseThrow();
    if (!order.getStatus().equals("PENDING") && !order.getStatus().equals("ACTIVE")) {
        return ResponseEntity.badRequest().body("Order not in valid state");
    }
    if (event.getAmount().compareTo(order.getAmount()) != 0) {
        return ResponseEntity.badRequest().body("Amount mismatch");
    }

    paymentService.processPayment(event.getSubscriptionId(), event.getStatus(), event.getAmount());
    return ResponseEntity.ok("processed");
}

// HMAC-SHA256 utility
private String hmacSha256(String secret, String data) {
    try {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(keySpec);
        byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hash);
    } catch (Exception e) {
        throw new CryptoException("HMAC computation failed", e);
    }
}
```

**Key rules:**
- **Sign over `timestamp + rawBody`** with HMAC-SHA256
- **Compare signatures with `MessageDigest.isEqual`** (constant-time, prevents timing attacks)
- The secret comes from env/Vault, not from a repository default
- **Signature proves origin, not correctness** — re-derive prices and statuses from the order record
- Log signature failures for security monitoring

---

## 7. Webhook Replay Protection

**CWE-294** — *Authentication Bypass Using a Replay Attack*

### The Problem

Without an idempotency key and timestamp window, a valid webhook can be resent multiple times and each replay is processed as a new event. This leads to duplicate payments, extended subscriptions, or repeated actions. An attacker can replay old webhooks to re-apply benefits.

```java
// ❌ VULNERABLE — replayable webhook: no timestamp window, no idempotency key
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

### The Fix

Implement a bounded timestamp window and an idempotency key store.

```java
// ✅ SAFE — timestamp window + idempotency key
private static final long REPLAY_WINDOW_SECONDS = 300;  // 5 minutes
private static final Set<String> PROCESSED_EVENTS = ConcurrentHashMap.newKeySet();

@PostMapping("/webhook/payment")
public ResponseEntity<?> paymentWebhook(
        @RequestBody String rawBody,
        @RequestHeader("X-Webhook-Signature") String signature,
        @RequestHeader("X-Webhook-Timestamp") String timestampStr,
        @RequestHeader("X-Webhook-Event-Id") String eventId) {

    // 1. Timestamp window (replay protection)
    long ts = Long.parseLong(timestampStr);
    if (Math.abs(System.currentTimeMillis() - ts) > REPLAY_WINDOW_SECONDS * 1000) {
        return ResponseEntity.status(400).body("Stale timestamp");
    }

    // 2. Idempotency key
    if (!PROCESSED_EVENTS.add(eventId)) {
        // Already processed — return success to avoid provider retries
        return ResponseEntity.ok(Map.of("duplicate", true));
    }

    // 3. Process the webhook...
    return ResponseEntity.ok("processed");
}
```

**Production idempotency store:**

```java
// ✅ SAFE — database-backed idempotency (not in-memory)
// SQL schema:
// CREATE TABLE webhook_events (
//     event_id VARCHAR(255) PRIMARY KEY,
//     webhook_type VARCHAR(50) NOT NULL,
//     payload JSONB NOT NULL,
//     processed_at TIMESTAMP NOT NULL DEFAULT NOW(),
//     status VARCHAR(20) NOT NULL  -- 'pending', 'processed', 'failed'
// );

@Entity
@Table(name = "webhook_events")
public class WebhookEvent {
    @Id
    private String eventId;
    private String webhookType;
    @Column(columnDefinition = "jsonb")
    private String payload;
    private Instant processedAt;
    private String status;
}

// Spring Data repository
public interface WebhookEventRepository extends JpaRepository<WebhookEvent, String> {
    Optional<WebhookEvent> findByEventId(String eventId);
    
    @Modifying
    @Query(value = """
        INSERT INTO webhook_events (event_id, webhook_type, payload, status)
        VALUES (:eventId, :type, :payload, 'pending')
        ON CONFLICT (event_id) DO NOTHING
        """, nativeQuery = true)
    @QueryHint(name = "jakarta.persistence.query.timeout", value = "2000")
    int markAsProcessed(@Param("eventId") String eventId,
                       @Param("type") String type,
                       @Param("payload") String payload);
}
```

**Key rules:**
- **Timestamp window** (`REPLAY_WINDOW_SECONDS = 300`) rejects stale messages
- **`X-Webhook-Event-Id`** idempotency store turns replays into no-ops
- In production, use a **unique index in the database**, not an in-memory `ConcurrentHashMap`
- Return `200 OK` for duplicate events to avoid provider retries
- Clean up processed events after a retention period (e.g., 30 days) to prevent unbounded storage growth

---

## Summary Checklist

| # | Control | CWE | Priority |
|---|---------|-----|----------|
| 1 | Egress allow-list + DNS IP check + no redirects | CWE-918 | CRITICAL |
| 2 | Auth on all endpoints, network policies | CWE-306 | CRITICAL |
| 3 | Size cap + content-type validation | CWE-434 | HIGH |
| 4 | Connect/read timeouts on outbound clients | CWE-400 | HIGH |
| 5 | Response size limits (`Content-Length` + actual read) | CWE-770 | HIGH |
| 6 | HMAC-SHA256 signature verification | CWE-345, CWE-347 | CRITICAL |
| 7 | Timestamp window + idempotency key | CWE-294 | CRITICAL |

---

## Detection & Review Heuristics

| Check | Command / Pattern |
|-------|-------------------|
| SSRF URL from request | `grep -r 'RestTemplate\|WebClient\|HttpClient' \| grep '$URL'` → should validate hostname, IP, and disable redirects |
| Missing outbound timeouts | `grep -r 'new RestTemplate()' \| 'new WebClient()'` → should have `ClientHttpRequestFactory` with timeouts |
| Unsigned webhooks | `grep -r '@RequestBody.*Webhook'` → should verify HMAC signature over timestamp + body |
| Missing idempotency | Check webhook handlers for `X-Webhook-Event-Id` or `eventId` → should have replay protection |
| Internal admin no-auth | `grep -r '@GetMapping.*internal\|@GetMapping.*admin'` → should have `@PreAuthorize` |
| Fetch-and-store size | `grep -r 'Files.write.*rt.getForObject'` → should cap size, validate content type |

---

## References

- [OWASP SSRF Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP Webhook Security](https://cheatsheetseries.owasp.org/cheatsheets/Webhook_Security_Cheat_Sheet.html)
- [Cloud Security Alliance: Cloud Metadata Threats](https://cloudsecurityalliance.org/artifacts/cloud-metadata-service-threats/)
- [RFC 7515: JSON Web Signature (JWS) - HMAC-SHA256](https://datatracker.ietf.org/doc/html/rfc7518#section-3.2)
- [Spring WebClient Timeout Configuration](https://docs.spring.io/spring-framework/reference/integration/http-clients.html)
- [Idempotency Patterns in Distributed Systems](https://www.infoq.com/articles/idempotent-api-design/)
