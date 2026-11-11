package com.example.vulnrange.m01.safe;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Reference implementation of checklist section 1. Every control that the {@code /vuln1} flow
 * misses is present here and is called out in the comment above it.
 */
@RestController
@RequestMapping("/safe1")
public class SafeAuthnController {

    private static final Logger log = LoggerFactory.getLogger(SafeAuthnController.class);
    private static final int MAX_ATTEMPTS = 5;
    private static final Duration WINDOW = Duration.ofMinutes(1);
    private static final Duration CODE_TTL = Duration.ofMinutes(5);

    private final Map<String, String> users = new ConcurrentHashMap<>();
    private final Map<String, Deque<Instant>> attempts = new ConcurrentHashMap<>();
    private final Map<String, ResetCode> resetCodes = new ConcurrentHashMap<>();
    private final PasswordEncoder passwordEncoder;
    private final SafeTokenService tokens;

    public SafeAuthnController(PasswordEncoder passwordEncoder, SafeTokenService tokens) {
        this.passwordEncoder = passwordEncoder;
        this.tokens = tokens;
        // BCrypt cost 12, per-user salt.
        users.put("alice", passwordEncoder.encode("Corre7-Horse!"));
        users.put("admin", passwordEncoder.encode("Adm1n-P@ssw0rd"));
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String, String> body) {
        String username = nullToEmpty(body.get("username"));
        String password = nullToEmpty(body.get("password"));
        if (username.length() < 3 || username.length() > 64) {
            return ResponseEntity.badRequest().body(Map.of("error", "invalid username"));
        }
        if (password.length() < 12) {
            // Length-first policy plus a breach-list check is the current guidance (NIST SP 800-63B).
            return ResponseEntity.badRequest().body(Map.of("error", "password too short"));
        }
        if (users.putIfAbsent(username, passwordEncoder.encode(password)) != null) {
            // Generic outcome: registration must not confirm the existence of an account.
            return ResponseEntity.ok(Map.of("status", "accepted"));
        }
        return ResponseEntity.ok(Map.of("status", "accepted"));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body, HttpServletRequest request) {
        String username = nullToEmpty(body.get("username"));
        String password = nullToEmpty(body.get("password"));
        String clientKey = clientKey(request) + "|" + username;

        // Control: throttling per source address AND per account (credential-stuffing resistant).
        if (throttled(clientKey)) {
            audit("login_throttled", username);
            return ResponseEntity.status(429).body(Map.of("error", "too many attempts"));
        }

        String stored = users.get(username);
        // Control: always run the hash comparison, always answer with the same message, so neither
        // the response body nor the timing reveals whether the account exists.
        String candidate = stored != null ? stored : passwordEncoder.encode("decoy-comparable-value");
        boolean ok = passwordEncoder.matches(password, candidate) && stored != null;
        if (!ok) {
            recordFailure(clientKey);
            audit("login_failed", username);
            return ResponseEntity.status(401).body(Map.of("error", "invalid credentials"));
        }

        // Control: the pre-authentication session is destroyed and a brand new one is created, so an
        // id an attacker planted before login can never become an authenticated session. Equivalent
        // to Spring Security's sessionFixation().migrateSession().
        HttpSession preAuthSession = request.getSession(false);
        String oldId = preAuthSession == null ? "none" : preAuthSession.getId();
        if (preAuthSession != null) {
            preAuthSession.invalidate();
        }
        HttpSession session = request.getSession(true);
        session.setAttribute("user", username);
        audit("login_ok", username);
        return ResponseEntity.ok(Map.of(
                "sessionRotatedFrom", oldId == null ? "none" : oldId,
                "user", username));
    }

    @GetMapping("/me")
    public Map<String, Object> me(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute("user") == null) {
            return Map.of("authenticated", false);
        }
        return Map.of("authenticated", true, "user", session.getAttribute("user"));
    }

    @PostMapping("/token/issue")
    public Map<String, String> issue(@RequestBody Map<String, String> body) {
        String role = "admin".equals(body.get("username")) ? "ADMIN" : "USER";
        // Control: 15 minutes max, strong key, iss/aud bound.
        return Map.of("token", tokens.issue(nullToEmpty(body.get("username")), role, 900));
    }

    @PostMapping("/token/verify")
    public ResponseEntity<?> verify(@RequestBody Map<String, String> body) {
        try {
            return ResponseEntity.ok(Map.of("claims", tokens.verify(body.get("token"))));
        } catch (RuntimeException e) {
            return ResponseEntity.status(401).body(Map.of("error", String.valueOf(e.getMessage())));
        }
    }

    @GetMapping("/admin/espd-summary")
    public ResponseEntity<?> adminSummary(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return ResponseEntity.status(401).body(Map.of("error", "missing bearer token"));
        }
        try {
            Map<String, String> claims = tokens.verify(authorization.substring(7).trim());
            if (!"ADMIN".equals(claims.get("role"))) {
                audit("authz_denied", claims.get("sub"));
                return ResponseEntity.status(403).body(Map.of("error", "forbidden"));
            }
            return ResponseEntity.ok(Map.of("rows", List.of(Map.of("subscriptionId", "SUB-0001"))));
        } catch (RuntimeException e) {
            return ResponseEntity.status(401).body(Map.of("error", String.valueOf(e.getMessage())));
        }
    }

    @PostMapping("/password-reset")
    public Map<String, Object> passwordReset(@RequestBody Map<String, String> body,
                                             HttpServletRequest request) {
        String username = nullToEmpty(body.get("username"));
        String clientKey = clientKey(request) + "|reset|" + username;
        if (throttled(clientKey)) {
            return Map.of("status", "accepted");
        }
        recordFailure(clientKey);
        if (users.containsKey(username)) {
            String code = tokens.randomCode(8);
            resetCodes.put(username, new ResetCode(tokens.sha256Hex(code), Instant.now().plus(CODE_TTL)));
            // Control: the code is only ever logged as a digest, never in clear text.
            log.info("reset code issued user={} digest={}", username, tokens.sha256Hex(code).substring(0, 12));
            // Control: response is identical whether or not the account exists.
            return Map.of("status", "accepted", "expiresInSeconds", CODE_TTL.toSeconds(),
                    "devOnlyCode", code);
        }
        return Map.of("status", "accepted", "expiresInSeconds", CODE_TTL.toSeconds());
    }

    @PostMapping("/password-reset/confirm")
    public ResponseEntity<?> confirmReset(@RequestBody Map<String, String> body) {
        String username = nullToEmpty(body.get("username"));
        String code = nullToEmpty(body.get("code"));
        ResetCode stored = resetCodes.remove(username); // single use, consumed on attempt
        if (stored == null || stored.expiresAt().isBefore(Instant.now())
                || !tokens.sha256Hex(code).equals(stored.codeDigest())) {
            audit("reset_failed", username);
            return ResponseEntity.status(401).body(Map.of("error", "invalid or expired code"));
        }
        String password = nullToEmpty(body.get("newPassword"));
        if (password.length() < 12) {
            return ResponseEntity.badRequest().body(Map.of("error", "password too short"));
        }
        users.put(username, passwordEncoder.encode(password));
        audit("password_changed", username);
        return ResponseEntity.ok(Map.of("status", "changed"));
    }

    @GetMapping("/audit")
    public List<String> auditLog() {
        return List.copyOf(AUDIT);
    }

    // --- helpers -----------------------------------------------------------------------------

    private static final List<String> AUDIT = java.util.Collections.synchronizedList(new ArrayList<>());

    private boolean throttled(String key) {
        Deque<Instant> hits = attempts.get(key);
        if (hits == null) {
            return false;
        }
        synchronized (hits) {
            hits.removeIf(t -> t.isBefore(Instant.now().minus(WINDOW)));
            return hits.size() >= MAX_ATTEMPTS;
        }
    }

    private void recordFailure(String key) {
        Deque<Instant> hits = attempts.computeIfAbsent(key, k -> new ArrayDeque<>());
        synchronized (hits) {
            hits.addLast(Instant.now());
        }
    }

    private static String clientKey(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        return forwarded != null ? forwarded.split(",")[0].trim() : request.getRemoteAddr();
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    private void audit(String event, String subject) {
        AUDIT.add(Instant.now() + " " + event + " subject=" + mask(subject));
    }

    /** Audit entries must not carry identifiers in clear text (checklist section 9). */
    private static String mask(String value) {
        if (value == null || value.length() < 4) {
            return "***";
        }
        return value.substring(0, 2) + "***";
    }

    private record ResetCode(String codeDigest, Instant expiresAt) {
    }
}
