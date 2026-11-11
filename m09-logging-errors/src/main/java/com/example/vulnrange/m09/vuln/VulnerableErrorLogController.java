package com.example.vulnrange.m09.vuln;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * VULNERABLE (intentional): diagnostics turned into a product feature. PoC:
 * {@code attacks/09-logging-errors.sh}.
 */
@RestController
@RequestMapping("/vuln9")
public class VulnerableErrorLogController {

    private static final Logger log = LoggerFactory.getLogger(VulnerableErrorLogController.class);
    private final Map<String, String> users = new ConcurrentHashMap<>();

    /** Request DTO used to demonstrate verbose validation feedback. */
    public record RegisterRequest(@NotBlank @Size(min = 6, max = 20) String username,
                                 @Email @NotBlank String email) {
    }

    public VulnerableErrorLogController() {
        users.put("alice", "hashed");
    }

    /** VULNERABLE: unhandled exception + server.error.include-stacktrace=always = full internals. */
    @GetMapping("/boom")
    public Map<String, Object> boom(@RequestParam(required = false) String tenant) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("rows", tenant.toUpperCase()); // NPE for a missing parameter
        return out;
    }

    /** VULNERABLE: exception message and SQL text are copied into the response body. */
    @GetMapping("/report")
    public ResponseEntity<Map<String, Object>> report(@RequestParam String id) {
        String sql = "SELECT * FROM subscription WHERE id = '" + id + "'";
        try {
            if (id.contains("'")) {
                throw new RuntimeException("Syntax error in SQL statement \"" + sql
                        + "\""); // VULNERABLE: query text to the client
            }
            return ResponseEntity.ok(Map.of("id", id));
        } catch (RuntimeException e) {
            return ResponseEntity.status(500).body(Map.of(
                    "error", e.getMessage(),
                    "stackTrace", java.util.Arrays.stream(e.getStackTrace()).map(StackTraceElement::toString).toList(),
                    "environment", System.getProperty("os.name") + " " + System.getProperty("java.version")));
        }
    }

    /** VULNERABLE: per-user "not found" answers reveal which accounts exist. */
    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody Map<String, String> body) {
        String username = body.getOrDefault("username", "");
        String stored = users.get(username);
        if (stored == null) {
            return ResponseEntity.status(404).body(Map.of("error", "no such user: " + username));
        }
        // VULNERABLE: hash computation only for existing users -> a measurable timing difference.
        sleepForHashing();
        return ResponseEntity.status(401).body(Map.of("error", "bad password for existing user " + username));
    }

    /** VULNERABLE: constraint violations echoed with the submitted value (enumeration + noisy logs). */
    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(Map.of("created", request.username()));
    }

    /** VULNERABLE: raw PII and a bearer token written into the log pipeline. */
    @PostMapping("/audit/checkout")
    public Map<String, Object> checkout(@RequestBody Map<String, String> body,
                                       @RequestHeader(value = "Authorization", required = false) String authorization) {
        // VULNERABLE: card number, e-mail and the caller's token all end up in a searchable index.
        log.info("checkout card={} email={} auth={} amount={}",
                body.get("cardNumber"), body.get("email"), authorization, body.get("amount"));
        return Map.of("logged", true, "hint", "grep the log file for the card number you sent");
    }

    /** VULNERABLE: un-sanitised CRLF allows fabricating log entries (audit forgery, SIEM noise). */
    @PostMapping("/audit/message")
    public Map<String, Object> forgedLogLine(@RequestParam String message) {
        log.info("audit: {}", message);
        return Map.of("written", message);
    }

    /** VULNERABLE: no security events are recorded anywhere, so a brute-force run is invisible. */
    @GetMapping("/audit/trail")
    public List<String> trail() {
        return List.of("nothing is recorded in this service");
    }

    /** VULNERABLE: runtime/configuration details on an unauthenticated endpoint. */
    @GetMapping("/debug/info")
    public Map<String, Object> debugInfo() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("javaVersion", System.getProperty("java.version"));
        out.put("javaVendor", System.getProperty("java.vendor"));
        out.put("os", System.getProperty("os.name") + " " + System.getProperty("os.arch"));
        out.put("hostname", hostName());
        out.put("workingDirectory", System.getProperty("user.dir"));
        out.put("classpathEntries", System.getProperty("java.class.path").split(java.io.File.pathSeparator).length);
        out.put("memoryMb", Runtime.getRuntime().maxMemory() / (1024 * 1024));
        out.put("internalHosts", List.of("kafka-broker-1.internal:9092", "postgres-primary.internal:5432"));
        return out;
    }

    private static void sleepForHashing() {
        try {
            Thread.sleep(120);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static String hostName() {
        try {
            return java.net.InetAddress.getLocalHost().getCanonicalHostName();
        } catch (Exception e) {
            return "unknown";
        }
    }
}
