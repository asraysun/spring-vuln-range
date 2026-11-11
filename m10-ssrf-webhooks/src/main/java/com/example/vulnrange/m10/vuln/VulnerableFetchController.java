package com.example.vulnrange.m10.vuln;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

/**
 * VULNERABLE (intentional): the server becomes a request generator for the caller, and the payment
 * webhook trusts the payload. PoC: {@code attacks/10-ssrf-webhooks.sh}.
 */
@RestController
@RequestMapping("/vuln10")
public class VulnerableFetchController {

    private static final Logger log = LoggerFactory.getLogger(VulnerableFetchController.class);

    /** VULNERABLE: no timeouts, so one slow dependency occupies a request thread indefinitely. */
    private final RestTemplate noTimeouts = new RestTemplate();

    /** Payment state mutated by the unsigned webhook. */
    private final List<Map<String, Object>> payments = Collections.synchronizedList(new ArrayList<>());

    /**
     * VULNERABLE: SSRF (CWE-918). The URL comes from the request and nothing constrains host, port,
     * scheme or redirect target, so the caller can reach anything this process can reach: admin
     * panels on localhost, internal microservices, the metadata service, internal-only VPS ranges.
     */
    @PostMapping("/fetch")
    public Map<String, Object> fetch(@RequestBody Map<String, String> body) {
        String url = body.getOrDefault("url", "http://127.0.0.1:8090/vuln10/internal-admin/users");
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("requested", url);
        try {
            Object response = noTimeouts.getForObject(url, Object.class);
            out.put("fetched", true);
            out.put("body", abbreviate(String.valueOf(response)));
            out.put("note", "server-side request with the service's own network position and no egress policy");
        } catch (Exception e) {
            out.put("fetched", false);
            out.put("error", String.valueOf(e.getMessage()));
        }
        return out;
    }

    /** VULNERABLE: "it is internal, so it is safe" — no authentication on an admin surface. */
    @GetMapping("/internal-admin/users")
    public List<Map<String, String>> internalAdminUsers() {
        return List.of(
                Map.of("username", "alice", "email", "alice@example.invalid", "role", "USER"),
                Map.of("username", "root", "email", "root@example.invalid", "role", "ADMIN"));
    }

    /**
     * Simulated cloud instance metadata service (IMDS), hosted here so that the SSRF demo proves the
     * primitive without contacting a real provider. In production this address is link-local and the
     * response is a temporary IAM credential — the single most rewarding SSRF target.
     */
    @RequestMapping("/imds/**")
    public Map<String, Object> simulatedImds() {
        return Map.of(
                "Code", "Success",
                "AccessKeyId", "ASIAPLACEHOLDER00000",
                "SecretAccessKey", "placeholder-secret-access-key-000000",
                "Token", "placeholder-session-token",
                "Expiration", "2099-01-01T00:00:00Z",
                "simulated", true);
    }

    /** VULNERABLE: redirect-following turns a "safe" allow-list check into an SSRF anyway. */
    @GetMapping("/redirect-to-internal")
    public ResponseEntity<Void> redirectToInternal() {
        return ResponseEntity.status(302)
                .header("Location", "http://127.0.0.1:8090/vuln10/imds/latest/meta-data/iam/security-credentials")
                .build();
    }

    /** VULNERABLE: fetch-and-store of a remote "avatar" — SSRF plus unbounded write of attacker bytes. */
    @PostMapping("/avatar")
    public Map<String, Object> avatar(@RequestBody Map<String, String> body) {
        String url = body.getOrDefault("url", "http://127.0.0.1:8090/vuln10/internal-admin/users");
        Map<String, Object> out = new LinkedHashMap<>();
        try {
            byte[] fetched = noTimeouts.getForObject(url, byte[].class);
            Path target = Path.of(System.getProperty("java.io.tmpdir"), "vulnrange-m10-avatar.bin");
            Files.write(target, fetched == null ? new byte[0] : fetched);
            out.put("stored", target.toString());
            out.put("bytes", fetched == null ? 0 : fetched.length);
            out.put("contentTypeChecked", false);
            out.put("sizeChecked", false);
        } catch (Exception e) {
            out.put("error", String.valueOf(e.getMessage()));
        }
        return out;
    }

    /** VULNERABLE: no read timeout; used together with the missing pool limit for thread exhaustion. */
    @GetMapping("/slow")
    public Map<String, Object> slow() {
        try {
            Thread.sleep(8_000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return Map.of("tookMillis", 8_000);
    }

    /**
     * VULNERABLE: payment webhook with no signature, no timestamp window and no idempotency key.
     * Anyone can post {@code status=PAID} for any subscription, and the same message can be replayed
     * forever (double activation, double credit).
     */
    @PostMapping("/webhook/payment")
    public Map<String, Object> paymentWebhook(@RequestBody Map<String, Object> payload) {
        payments.add(payload);
        log.info("payment webhook accepted (unsigned) {}", payload);
        return Map.of(
                "accepted", true,
                "applied", Map.of("subscriptionId", payload.getOrDefault("subscriptionId", "?"),
                        "status", payload.getOrDefault("status", "?"),
                        "amount", payload.getOrDefault("amount", "?")),
                "signatureChecked", false,
                "replayChecked", false);
    }

    private static String abbreviate(String value) {
        return value.length() > 400 ? value.substring(0, 400) + "…" : value;
    }
}
