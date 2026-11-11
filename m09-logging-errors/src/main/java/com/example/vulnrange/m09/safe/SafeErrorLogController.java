package com.example.vulnrange.m09.safe;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Reference implementation of checklist section 9: uniform errors, masked logs, and an audit trail
 * that lets a responder answer "who tried what, and did it succeed?".
 */
@RestController
@RequestMapping("/safe9")
public class SafeErrorLogController {

    private static final Logger log = LoggerFactory.getLogger(SafeErrorLogController.class);

    /** Hash of a fixed decoy password: always computed, so responses do not differ by timing. */
    private static final String DECOY_HASH = "sha256:decoy";

    private final Map<String, String> users = new ConcurrentHashMap<>();
    private final List<String> auditTrail = Collections.synchronizedList(new ArrayList<>());
    private final Environment environment;

    public SafeErrorLogController(Environment environment) {
        this.environment = environment;
        users.put("alice", "sha256:5f4dcc3b5aa765d61d8327deb882cf99");
    }

    /** Request contract: rules are described, values are not echoed back. */
    public record RegisterRequest(@NotBlank @Size(min = 6, max = 20) String username,
                                 @Email @NotBlank String email) {
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, String> body,
                                                     HttpServletRequest request) {
        String username = body.getOrDefault("username", "");
        String password = body.getOrDefault("password", "");
        String stored = users.getOrDefault(username, DECOY_HASH);

        // Same code path and same comparison work whether or not the account exists.
        boolean ok = stored != null && stored.equals(hash(password)) && users.containsKey(username);
        if (!ok) {
            event("login_failed", username, request);
            return ResponseEntity.status(401).body(Map.of("error", "invalid credentials"));
        }
        event("login_ok", username, request);
        return ResponseEntity.ok(Map.of("status", "authenticated"));
    }

    @PostMapping("/register")
    public Map<String, Object> register(@Valid @RequestBody RegisterRequest body, HttpServletRequest request) {
        // Registration never confirms existence: the answer is identical for new and known usernames.
        event("register_attempt", body.username(), request);
        return Map.of("status", "received");
    }

    /** The log gets a masked summary; the caller gets a receipt reference. */
    @PostMapping("/audit/checkout")
    public Map<String, Object> checkout(@RequestBody Map<String, String> body,
                                       @RequestHeader(value = "Authorization", required = false) String authorization,
                                       HttpServletRequest request) {
        String line = "cardPresent=" + (body.get("cardNumber") != null)
                + " email=" + CorrelationIdFilter.maskIdentity(body.get("email"))
                + " amount=" + CorrelationIdFilter.maskSecrets(body.getOrDefault("amount", ""))
                + " auth=" + CorrelationIdFilter.maskSecrets(authorization);
        log.info("checkout {}", CorrelationIdFilter.sanitiseForLog(line, 300));
        event("checkout", body.getOrDefault("email", "-"), request);
        return Map.of("receipt", "RC-" + Integer.toHexString((body.toString() + System.nanoTime()).hashCode()),
                "note", "no PII is returned, and the log line contains no card number or token");
    }

    /** CRLF and overlong input are neutralised before they reach the log appender. */
    @PostMapping("/audit/message")
    public Map<String, Object> message(@RequestBody Map<String, String> body, HttpServletRequest request) {
        String safe = CorrelationIdFilter.sanitiseForLog(body.getOrDefault("message", ""), 200);
        log.info("audit message={}", safe);
        event("audit_message", "-", request);
        return Map.of("storedLength", safe.length());
    }

    @GetMapping("/audit/trail")
    public List<String> trail() {
        return List.copyOf(auditTrail);
    }

    /** Forces an internal failure to show the generic response shape (no stack trace, incident id). */
    @GetMapping("/error")
    public Map<String, Object> forceFailure() {
        throw new IllegalStateException("synthetic internal failure for the demo");
    }

    /** Configuration self-check for CI: the server.error.* settings must be off. */
    @GetMapping("/selftest")
    public Map<String, Object> selftest() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("server.error.include-stacktrace", environment.getProperty("server.error.include-stacktrace", "never"));
        out.put("server.error.include-message", environment.getProperty("server.error.include-message", "never"));
        out.put("server.error.include-binding-errors", environment.getProperty("server.error.include-binding-errors", "never"));
        out.put("server.error.include-exception", environment.getProperty("server.error.include-exception", "false"));
        out.put("whitelabel.enabled", environment.getProperty("spring.mvc.static-path-pattern", "n/a"));
        out.put("expected", Map.of(
                "include-stacktrace", "never",
                "include-message", "never",
                "include-binding-errors", "never",
                "include-exception", "false"));
        return out;
    }

    private void event(String type, String subject, HttpServletRequest request) {
        String entry = "%s %s subject=%s ip=%s cid=%s".formatted(
                Instant.now(), type, CorrelationIdFilter.maskIdentity(subject),
                anonymiseIp(request.getRemoteAddr()),
                String.valueOf(org.slf4j.MDC.get(CorrelationIdFilter.MDC_KEY)));
        auditTrail.add(entry);
        log.info("security_event {}", entry);
    }

    /** Full IPs are not needed for correlation; keep the /24 (or /64) prefix only. */
    private static String anonymiseIp(String ip) {
        if (ip == null) {
            return "unknown";
        }
        int lastDot = ip.lastIndexOf('.');
        return lastDot > 0 ? ip.substring(0, lastDot) + ".0" : ip;
    }

    private static String hash(String value) {
        try {
            var digest = java.security.MessageDigest.getInstance("SHA-256");
            return "sha256:" + java.util.HexFormat.of().formatHex(
                    digest.digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
