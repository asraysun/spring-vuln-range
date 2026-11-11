package com.example.vulnrange.m01.vuln;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * VULNERABLE (intentional): the "legacy" authentication flow of the range.
 *
 * <p>Reproduce with {@code attacks/01-authentication.sh}; read {@code docs/01-authentication.md}.
 */
@RestController
@RequestMapping("/vuln1")
public class VulnerableAuthnController {

    /** username -> md5(password). A leak of this map is a full credential leak. */
    private final Map<String, String> users = new ConcurrentHashMap<>();
    private final InsecureTokenService tokenService;

    public VulnerableAuthnController(InsecureTokenService tokenService) {
        this.tokenService = tokenService;
        users.put("alice", InsecureTokenService.md5Hex("Corre7-Horse!"));
        users.put("admin", InsecureTokenService.md5Hex("Adm1n-P@ssw0rd"));
    }

    @PostMapping("/register")
    public Map<String, Object> register(@RequestBody Map<String, String> body) {
        String username = body.getOrDefault("username", "");
        String password = body.getOrDefault("password", "");
        // VULNERABLE: no password policy, no breach-list check, unsalted MD5.
        String hash = InsecureTokenService.md5Hex(password);
        users.put(username, hash);
        return Map.of("stored", "md5", "hash", hash);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body, HttpServletRequest request) {
        String username = body.getOrDefault("username", "");
        String password = body.getOrDefault("password", "");
        String stored = users.get(username);

        // VULNERABLE: no throttling/lockout (brute force) and user enumeration via distinct
        // messages ("unknown user" vs "wrong password").
        if (stored == null) {
            return ResponseEntity.status(401).body(Map.of("error", "unknown user: " + username));
        }
        if (!stored.equals(InsecureTokenService.md5Hex(password))) {
            return ResponseEntity.status(401).body(Map.of("error", "wrong password for " + username));
        }

        // VULNERABLE: the pre-authentication session id is reused after login -> session fixation.
        HttpSession session = request.getSession();
        session.setAttribute("user", username);
        return ResponseEntity.ok(Map.of("session", session.getId(), "user", username));
    }

    @GetMapping("/session-id")
    public Map<String, Object> sessionId(HttpServletRequest request) {
        // VULNERABLE: the pre-auth session id is handed out and stays valid after login.
        HttpSession session = request.getSession();
        return Map.of("session", session.getId(),
                "authenticated", session.getAttribute("user") != null);
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
    public Map<String, Object> issue(@RequestBody Map<String, Object> body) {
        Map<String, Object> claims = new LinkedHashMap<>(body);
        claims.putIfAbsent("iat", System.currentTimeMillis() / 1000);
        // VULNERABLE: signed with the dictionary secret from application.yml, no expiry at all.
        return Map.of("token", tokenService.issueHs256(claims));
    }

    @PostMapping("/token/verify")
    public ResponseEntity<?> verify(@RequestBody Map<String, String> body) {
        try {
            return ResponseEntity.ok(Map.of("claims", tokenService.verify(body.getOrDefault("token", ""))));
        } catch (RuntimeException e) {
            return ResponseEntity.status(401).body(Map.of("error", String.valueOf(e.getMessage())));
        }
    }

    /** Privileged endpoint guarded only by the broken token check above. */
    @GetMapping("/admin/espd-summary")
    public ResponseEntity<?> adminSummary(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return ResponseEntity.status(401).body(Map.of("error", "missing bearer token"));
        }
        try {
            Map<String, Object> claims = tokenService.verify(authorization.substring(7).trim());
            if (!"ADMIN".equals(String.valueOf(claims.get("role")))) {
                return ResponseEntity.status(403).body(Map.of("error", "role must be ADMIN", "claims", claims));
            }
            return ResponseEntity.ok(Map.of(
                    "message", "privileged ESPD subscription report",
                    "grantedTo", claims,
                    "rows", List.of(Map.of("subscriptionId", "SUB-0001", "status", "ACTIVE"))));
        } catch (RuntimeException e) {
            return ResponseEntity.status(401).body(Map.of("error", String.valueOf(e.getMessage())));
        }
    }

    @PostMapping("/password-reset")
    public ResponseEntity<?> passwordReset(@RequestBody Map<String, String> body) {
        String username = body.getOrDefault("username", "");
        if (!users.containsKey(username)) {
            // VULNERABLE: enumeration and no rate limit on a sensitive endpoint.
            return ResponseEntity.status(404).body(Map.of("error", "no such user"));
        }
        // VULNERABLE: the seed is the current minute, so the "6-digit code" is reproducible for
        // anyone who knows the approximate time. Never derive security tokens from Random.
        Random random = new Random(System.currentTimeMillis() / 60_000L);
        String code = String.format("%06d", random.nextInt(1_000_000));
        return ResponseEntity.ok(Map.of("delivered", code, "note", "a real app emails this"));
    }

    @GetMapping("/token/predict")
    public Map<String, String> predictResetCode(@RequestParam long seed) {
        // VULNERABLE: mirrors the same Random(seed) logic from passwordReset so the attack
        // script can demonstrate that reset codes are computable from the time seed.
        Random random = new Random(seed);
        String code = String.format("%06d", random.nextInt(1_000_000));
        return Map.of("predictedToken", code);
    }

    @GetMapping("/remember-me/{username}")
    public Map<String, String> rememberMe(@PathVariable String username) {
        // VULNERABLE: static key => mintable offline by anyone holding the artifact or sources.
        return Map.of("rememberMe", tokenService.rememberMe(username));
    }

    @PostMapping("/remember-me/login")
    public ResponseEntity<?> rememberMeLogin(
            @RequestHeader(value = "X-Remember-Me", required = false) String rememberMe) {
        if (rememberMe == null || !tokenService.rememberMeMatches(rememberMe)) {
            return ResponseEntity.status(401).body(Map.of("error", "bad remember-me token"));
        }
        return ResponseEntity.ok(Map.of("logged in as", rememberMe.substring(0, rememberMe.lastIndexOf(':'))));
    }

    /** VULNERABLE: unauthenticated "admin" dump — shows why unsalted MD5 is fatal. */
    @GetMapping("/debug/users")
    public List<Map<String, String>> dumpUsers() {
        List<Map<String, String>> out = new ArrayList<>();
        users.forEach((username, hash) -> out.add(Map.of("username", username, "md5", hash)));
        return out;
    }

    @PostMapping("/set-cookie-demo")
    public ResponseEntity<?> setCookieDemo(HttpServletRequest request) {
        HttpSession session = request.getSession();
        Cookie cookie = new Cookie("TRACK", "session=" + session.getId());
        // VULNERABLE: HttpOnly off and Secure off — cookie is readable by JavaScript and sent over
        // plain HTTP. SameSite is additionally disabled in application.yml.
        cookie.setHttpOnly(false);
        cookie.setSecure(false);
        cookie.setPath("/");
        return ResponseEntity.ok()
                .body(Map.of("cookie", "TRACK=session=" + session.getId(),
                        "cookieName", cookie.getName(),
                        "cookieValue", cookie.getValue(),
                        "note", "no HttpOnly: readable by JavaScript"));
    }
}
