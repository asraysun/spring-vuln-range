package com.example.vulnrange.m10.safe;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.client.SimpleClientHttpRequestFactory;

/**
 * Reference implementation of checklist section 10.
 *
 * <p>Outbound calls: allow-list of scheme + host + port + path prefix, resolved before connecting,
 * redirects off, timeouts and response-size caps on, and an egress policy that is stated in code
 * rather than assumed from the network. Webhooks: signature over timestamp + raw body, replay window
 * and idempotency keys.
 */
@RestController
@RequestMapping("/safe10")
public class SafeFetchController {

    private static final Logger log = org.slf4j.LoggerFactory.getLogger(SafeFetchController.class);
    private static final Set<String> ALLOWED_HOSTS = Set.of("127.0.0.1", "localhost");
    private static final Set<Integer> ALLOWED_PORTS = Set.of(8090);
    private static final Set<String> ALLOWED_PATH_PREFIXES = Set.of("/safe10/public/");
    private static final int MAX_RESPONSE_BYTES = 256 * 1024;
    private static final long REPLAY_WINDOW_SECONDS = 300;

    private final RestTemplate client;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final String webhookSecret;

    /** Idempotency store. A real deployment uses the database (unique index) or a shared cache. */
    private final Map<String, Instant> processedEvents = new ConcurrentHashMap<>();

    public SafeFetchController(
            @Value("${vulnrange.safe.webhook-secret:local-demo-webhook-secret-not-a-real-credential}") String webhookSecret) {
        this.webhookSecret = webhookSecret;
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory() {
            @Override
            protected void prepareConnection(java.net.HttpURLConnection connection, String httpMethod)
                    throws IOException {
                // Redirects must be re-validated against the policy; the cheapest safe answer is off.
                connection.setInstanceFollowRedirects(false);
                super.prepareConnection(connection, httpMethod);
            }
        };
        factory.setConnectTimeout(2_000);
        factory.setReadTimeout(4_000);
        this.client = new RestTemplate(factory);
    }

    /** The only outbound destination this service is allowed to reach, used by the PoC. */
    @GetMapping("/public/price-list")
    public Map<String, Object> publicPriceList() {
        return Map.of("ESPD-BASIC", 990, "ESPD-PRO", 2490, "ESPD-TRIAL", 0);
    }

    @PostMapping("/fetch")
    public ResponseEntity<Map<String, Object>> fetch(@RequestBody Map<String, String> body) {
        String url = body.getOrDefault("url", "");
        Map<String, Object> out = new LinkedHashMap<>();
        URI uri;
        try {
            uri = new URI(url);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "invalid url"));
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase();
        String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase();
        int port = uri.getPort() == -1 ? ("https".equals(scheme) ? 443 : 80) : uri.getPort();

        if (!Set.of("http", "https").contains(scheme)) {
            return ResponseEntity.badRequest().body(Map.of("error", "scheme not allowed"));
        }
        if (!ALLOWED_HOSTS.contains(host) || !ALLOWED_PORTS.contains(port)) {
            return ResponseEntity.badRequest().body(Map.of("error", "destination not on the allow-list",
                    "allowed", Map.of("hosts", ALLOWED_HOSTS, "ports", ALLOWED_PORTS)));
        }
        String path = uri.getPath() == null ? "" : uri.getPath();
        boolean pathAllowed = ALLOWED_PATH_PREFIXES.stream().anyMatch(path::startsWith);
        if (!pathAllowed) {
            return ResponseEntity.badRequest().body(Map.of("error", "path not on the allow-list",
                    "allowedPrefixes", ALLOWED_PATH_PREFIXES));
        }
        try {
            // Resolve first, then judge: a hostname must not be able to point at an internal address.
            // For production-grade protection pair this with an egress proxy and DNS pinning.
            for (InetAddress address : InetAddress.getAllByName(host)) {
                if (address.isLoopbackAddress() && !ALLOWED_HOSTS.contains(host)) {
                    return ResponseEntity.badRequest().body(Map.of("error", "loopback resolved, refusing"));
                }
                if (address.isLinkLocalAddress() || address.isSiteLocalAddress() || address.isAnyLocalAddress()) {
                    // Demo policy allows the loopback literal above; every other private range is refused.
                    if (!address.isLoopbackAddress()) {
                        return ResponseEntity.badRequest().body(Map.of("error", "private range refused",
                                "resolved", address.getHostAddress()));
                    }
                }
            }
            byte[] response = client.getForObject(uri.toString(), byte[].class);
            int length = response == null ? 0 : response.length;
            if (length > MAX_RESPONSE_BYTES) {
                return ResponseEntity.status(413).body(Map.of("error", "response too large"));
            }
            out.put("fetched", true);
            out.put("bytes", length);
            out.put("body", new String(response == null ? new byte[0] : response, StandardCharsets.UTF_8));
            out.put("redirectsFollowed", false);
            return ResponseEntity.ok(out);
        } catch (Exception e) {
            return ResponseEntity.status(502).body(Map.of("error", "fetch failed",
                    "detail", e.getClass().getSimpleName()));
        }
    }

    /**
     * Signed webhook: {@code signature = HMAC-SHA256(secret, timestamp + "." + rawBody)} compared in
     * constant time, a bounded timestamp window, and an idempotency key that makes replays no-ops.
     */
    @PostMapping("/webhook/payment")
    public ResponseEntity<Map<String, Object>> paymentWebhook(
            @RequestBody String rawBody,
            @RequestHeader(value = "X-Webhook-Timestamp", required = false) String timestamp,
            @RequestHeader(value = "X-Webhook-Signature", required = false) String signature,
            @RequestHeader(value = "X-Webhook-Event-Id", required = false) String eventId) {

        if (timestamp == null || signature == null || eventId == null) {
            return ResponseEntity.status(401).body(Map.of("error", "missing webhook authentication headers"));
        }
        long ts;
        try {
            ts = Long.parseLong(timestamp);
        } catch (NumberFormatException e) {
            return ResponseEntity.status(401).body(Map.of("error", "bad timestamp"));
        }
        long now = Instant.now().getEpochSecond();
        if (Math.abs(now - ts) > REPLAY_WINDOW_SECONDS) {
            return ResponseEntity.status(401).body(Map.of("error", "timestamp outside the accepted window"));
        }
        String expected = sign(timestamp + "." + rawBody);
        if (!MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8), signature.getBytes(StandardCharsets.UTF_8))) {
            log.warn("webhook signature mismatch eventId={}", eventId);
            return ResponseEntity.status(401).body(Map.of("error", "invalid signature"));
        }
        Instant previous = processedEvents.putIfAbsent(eventId, Instant.now());
        if (previous != null) {
            return ResponseEntity.ok(Map.of("duplicate", true, "eventId", eventId, "applied", false));
        }
        Map<String, Object> payload = parse(rawBody);
        if (payload == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "invalid payload"));
        }
        // Amount/status are still re-derived from the order record in a real system; a signed message
        // proves origin, not business correctness.
        return ResponseEntity.ok(Map.of("accepted", true, "eventId", eventId,
                "applied", Map.of("subscriptionId", payload.getOrDefault("subscriptionId", "?"),
                        "status", payload.getOrDefault("status", "?"))));
    }

    @GetMapping("/egress-policy")
    public Map<String, Object> egressPolicy() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("allowedSchemes", List.of("http", "https"));
        out.put("allowedHosts", List.copyOf(ALLOWED_HOSTS));
        out.put("allowedPorts", List.copyOf(ALLOWED_PORTS));
        out.put("allowedPathPrefixes", List.copyOf(ALLOWED_PATH_PREFIXES));
        out.put("deniedAlways", new java.util.ArrayList<>(List.of("169.254.0.0/16 metadata", "127.0.0.0/8 except the allow-list", "10/8, 172.16/12, 192.168/16", "file://, gopher://, dict://")));
        out.put("redirects", "disabled (re-validation would be required)");
        out.put("connectTimeoutMillis", 2_000);
        out.put("readTimeoutMillis", 4_000);
        out.put("maxResponseBytes", MAX_RESPONSE_BYTES);
        out.put("webhookSignature", "HMAC-SHA256 over timestamp + raw body, constant-time compare");
        out.put("webhookReplayWindowSeconds", REPLAY_WINDOW_SECONDS);
        return out;
    }

    /** Returns the set of already-applied event ids (so the PoC can show the replay rejection). */
    @GetMapping("/webhook/processed")
    public Set<String> processed() {
        return new LinkedHashSet<>(processedEvents.keySet());
    }

    private String sign(String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(webhookSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return Base64.getEncoder().encodeToString(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("cannot sign", e);
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> parse(String rawBody) {
        try {
            return objectMapper.readValue(rawBody, Map.class);
        } catch (Exception e) {
            return null;
        }
    }

    /** Not used by the endpoints; documents that content sniffing needs an explicit decision. */
    @SuppressWarnings("unused")
    private static String probeContentType(byte[] body) throws IOException {
        return URLConnection.guessContentTypeFromStream(new java.io.ByteArrayInputStream(body)) == null
                ? "application/octet-stream"
                : String.valueOf(java.util.Arrays.hashCode(body));
    }
}
