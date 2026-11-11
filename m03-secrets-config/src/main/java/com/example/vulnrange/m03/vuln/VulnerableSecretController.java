package com.example.vulnrange.m03.vuln;

import java.security.Principal;
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
 * VULNERABLE (intentional): configuration and secret handling as it tends to look after three
 * quarters of "quick" delivery. See {@code docs/03-secrets-config.md}.
 */
@RestController
@RequestMapping("/vuln3")
public class VulnerableSecretController {

    private static final Logger log = LoggerFactory.getLogger(VulnerableSecretController.class);

    /** VULNERABLE: secret compiled into the source, therefore into git history and the jar. */
    private static final String ESPD_API_KEY = "AKIAIOSFODNN7EXAMPLE";

    private final LegacyIntegrationProperties legacy;
    private final Environment environment;

    public VulnerableSecretController(LegacyIntegrationProperties legacy, Environment environment) {
        this.legacy = legacy;
        this.environment = environment;
    }

    /** VULNERABLE: returns live configuration values to any caller (CWE-200 / CWE-540). */
    @GetMapping("/config")
    public Map<String, String> config() {
        Map<String, String> out = new LinkedHashMap<>();
        out.put("espdApiKey", ESPD_API_KEY);
        out.put("espdApiKeyFromProps", legacy.espdApiKey());
        out.put("databaseUrl", legacy.databaseUrl());
        out.put("databasePassword", legacy.databasePassword());
        out.put("encryptionKey", legacy.encryptionKey());
        return out;
    }

    /** VULNERABLE: "support tooling" endpoint that dumps the environment. */
    @GetMapping("/env-dump")
    public Map<String, Object> envDump(@Value("${server.port}") String port) {
        Map<String, Object> env = new LinkedHashMap<>();
        System.getenv().forEach((k, v) -> {
            // VULNERABLE: no allow-list, no masking - everything that smells like a secret is here.
            if (k.toUpperCase().contains("TOKEN") || k.toUpperCase().contains("PASSWORD")
                    || k.toUpperCase().contains("KEY") || k.toUpperCase().contains("SECRET")) {
                env.put(k, v);
            }
        });
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("port", port);
        out.put("profiles", environment.getActiveProfiles());
        out.put("suspiciousEnv", env);
        out.put("javaOpts", System.getProperty("sun.java.command"));
        return out;
    }

    /** VULNERABLE: secret written to logs, which are shipped to the SIEM and read by everyone. */
    @PostMapping("/integration/check")
    public Map<String, Object> checkIntegration(@RequestBody Map<String, String> body) {
        String user = body.getOrDefault("dbUser", "unknown");
        String password = body.getOrDefault("dbPassword", "");
        // VULNERABLE: credential in a log line. Log rotation, index and vendor now hold the secret.
        log.info("checking connectivity for {} with password {}", user, password);
        return Map.of("checked", user, "usedCredentialLength", password.length(),
                "note", "the credential above was written to the application log");
    }

    /** VULNERABLE: dev tooling and debug surface switched on in a prod-shaped profile. */
    @GetMapping("/diagnostics")
    public Map<String, Object> diagnostics() {
        return Map.of(
                "h2ConsoleEnabled", environment.getProperty("spring.h2.console.enabled", "false"),
                "h2ConsolePath", environment.getProperty("spring.h2.console.path", "/h2-console"),
                "profiles", environment.getActiveProfiles(),
                "devtoolsPresent", hasClass("spring-boot-devtools"),
                "hint", "an in-process SQL console reachable from the network is a full DB takeover");
    }

    /** VULNERABLE: same credential in every environment - a dev leak is a prod leak. */
    @GetMapping("/per-env-credentials")
    public Map<String, Object> perEnv() {
        Map<String, Object> out = new LinkedHashMap<>();
        for (String profile : new String[] {"dev", "ift", "prod"}) {
            out.put(profile, Map.of("dbUser", "espd_app",
                    "dbPassword", legacy.databasePassword(),
                    "identicalAcrossEnvironments", true));
        }
        return out;
    }

    /**
     * VULNERABLE: the service hands out its own credential instead of using it, turning every caller
     * into a holder of the secret (and every log/proxy into a leak).
     */
    @GetMapping("/integration/token")
    public ResponseEntity<Map<String, String>> token(Principal principal) {
        return ResponseEntity.ok(Map.of(
                "tokenType", "Bearer",
                "access_token", legacy.espdApiKey(),
                "issuedTo", principal == null ? "anonymous" : principal.getName()));
    }

    private boolean hasClass(String className) {
        try {
            Class.forName(className);
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }
}
