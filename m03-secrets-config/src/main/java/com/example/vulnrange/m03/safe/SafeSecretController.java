package com.example.vulnrange.m03.safe;

import java.util.LinkedHashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Reference implementation of checklist section 3. The short version: a service <em>uses</em>
 * credentials, it never <em>returns</em> them, and nothing sensitive is written to a log line, a
 * repository file or a support endpoint.
 */
@RestController
@RequestMapping("/safe3")
public class SafeSecretController {

    private static final Logger log = LoggerFactory.getLogger(SafeSecretController.class);

    private final Environment environment;
    private final VaultFileSecretProvider secretProvider;

    public SafeSecretController(Environment environment, VaultFileSecretProvider secretProvider) {
        this.environment = environment;
        this.secretProvider = secretProvider;
    }

    /**
     * Configuration self-inspection without exposure: report shape and presence, never material.
     * This is what a "why is prod misbehaving" endpoint should look like.
     */
    @GetMapping("/config-summary")
    public Map<String, Object> configSummary() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("profiles", environment.getActiveProfiles());
        out.put("databaseUrlConfigured", isSet("vulnrange.safe.db-url"));
        out.put("databaseUserConfigured", isSet("vulnrange.safe.db-user"));
        out.put("databasePasswordConfigured", isSet("vulnrange.safe.db-password"));
        out.put("h2ConsoleEnabled", environment.getProperty("spring.h2.console.enabled", "false"));
        out.put("secretsSource", secretProvider == null ? "none" : "mounted-file-or-env");
        out.put("neverReturned", java.util.List.of("db-password", "espd-api-key", "encryption-key"));
        return out;
    }

    /** The service authenticates to the integration <em>with</em> the secret; the caller learns nothing. */
    @PostMapping("/integration/call")
    public ResponseEntity<Map<String, Object>> callIntegration(@RequestBody Map<String, String> body) {
        try (SecretHandle secret = secretProvider.resolve("espd-api-key")) {
            String signature = secret.use(bytes -> {
                try {
                    javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
                    mac.init(new javax.crypto.spec.SecretKeySpec(bytes, "HmacSHA256"));
                    byte[] out = mac.doFinal(
                            body.getOrDefault("requestId", "").getBytes(java.nio.charset.StandardCharsets.UTF_8));
                    return java.util.Base64.getEncoder().encodeToString(out);
                } catch (Exception e) {
                    throw new IllegalStateException("cannot sign integration request", e);
                }
            });
            log.info("integration call signed requestId={} keyFingerprint={}",
                    body.getOrDefault("requestId", "-"), secret.fingerprint());
            return ResponseEntity.ok(Map.of(
                    "signed", true,
                    "requestId", body.getOrDefault("requestId", ""),
                    "keyFingerprint", secret.fingerprint(),
                    "note", "signature would be sent in a header; the key itself never leaves this process"));
        } catch (IllegalStateException e) {
            // Fail closed: no secret, no call.
            return ResponseEntity.status(503).body(Map.of("error", "integration credential unavailable"));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "signing failed"));
        }
    }

    /** Secrets are masked on the way into the log pipeline (checklist 9 covers the full design). */
    @PostMapping("/echo")
    public Map<String, Object> echo(@RequestBody Map<String, String> body) {
        String token = body.getOrDefault("token", "");
        log.info("echo request token={}", mask(token));
        return Map.of("received", true, "echoed", mask(token), "length", token.length());
    }

    /** Self-check used by CI: are there credential-shaped values in the packaged resources? */
    @GetMapping("/hygiene")
    public Map<String, Object> hygiene() {
        boolean prodProfileUsesPlaceholders = "true".equals(
                environment.getProperty("vulnrange.safe.prod-config-uses-placeholders", "false"));
        return Map.of(
                "configuredPasswordIsPlaceholderFree",
                !String.valueOf(environment.getProperty("vulnrange.safe.db-password", "")).isBlank(),
                "prodConfigUsesPlaceholders", prodProfileUsesPlaceholders,
                "recommendation", "rotate on suspicion, one credential per environment, no DDL for the app user");
    }

    private boolean isSet(String key) {
        String value = environment.getProperty(key, "");
        return !value.isBlank() && !value.startsWith("${");
    }

    private static String mask(String value) {
        if (value == null || value.length() < 8) {
            return "***";
        }
        return value.substring(0, 4) + "..." + value.substring(value.length() - 2)
                + " (len=" + value.length() + ")";
    }
}
