package com.example.vulnrange.m13.safe;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Reference implementation of checklist section 13 — the dependency and parser posture this module is
 * the counter-example for.
 */
@RestController
@RequestMapping("/safe13")
public class SafeSupplyChainController {

    private static final int MAX_PAYLOAD_BYTES = 64 * 1024;

    /** A concrete target type, unknown properties rejected, no polymorphic type handling at all. */
    private final ObjectMapper strictMapper = new ObjectMapper()
            .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .disable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    @GetMapping("/policy")
    public Map<String, Object> policy() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("versions", "every dependency pinned (BOM + lockfile); no range versions, no LATEST/SNAPSHOT");
        out.put("scanners", List.of("OWASP dependency-check (CI gate)", "Trivy or Snyk for image + registry scan",
                "Semgrep / SpotBugs+FindSecBugs for code patterns", "gitleaks for credentials"));
        out.put("gate", "fail the build on CVSS >= 7.0 and on any reachable Critical; explicit, dated suppressions only");
        out.put("pluginIntegrity", "build plugins are pinned and scanned too (dependency confusion hits plugins)");
        out.put("artifacts", "resolved from an internal proxy with checksums; 'latest' tags are not deployable");
        out.put("images", "minimal base image, pinned by digest, SBOM attached to every build");
        out.put("updates", "Renovate/Dependabot PRs with a fast lane for security patches");
        out.put("transitiveRisk", "report is reviewed per service, not per team: a transitive CVE is your CVE");
        return out;
    }

    /** The same JSON the vulnerable endpoint eats; here it can only ever become one known type. */
    @PostMapping("/parse-json")
    public ResponseEntity<Map<String, Object>> parseJson(@RequestBody String json) {
        if (json.length() > MAX_PAYLOAD_BYTES) {
            return ResponseEntity.status(413).body(Map.of("error", "payload too large"));
        }
        try {
            OrderDocument document = strictMapper.readValue(json, OrderDocument.class);
            return ResponseEntity.ok(Map.of("parsedClass", document.getClass().getName(),
                    "subscriptionId", String.valueOf(document.subscriptionId())));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "invalid document",
                    "detail", e.getClass().getSimpleName()));
        }
    }

    /**
     * If a binary/serialized format cannot be removed today, a filter is the compensating control that
     * buys the time to remove it — the same control that neutralises the commons-collections gadgets.
     */
    @PostMapping("/deserialize-with-filter")
    public Map<String, Object> deserializeWithFilter(@RequestBody Map<String, String> body) {
        try {
            byte[] bytes = Base64.getDecoder().decode(body.getOrDefault("base64", ""));
            if (bytes.length > MAX_PAYLOAD_BYTES) {
                return Map.of("rejected", true, "detail", "payload too large");
            }
            try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
                in.setObjectInputFilter(ObjectInputFilter.Config.createFilter(
                        "com.example.vulnrange.m13.safe.SafeSupplyChainController$OrderDocument;java.lang.String;java.base/java.util.*;!*"));
                Object restored = in.readObject();
                return Map.of("restored", restored.getClass().getName());
            }
        } catch (Exception e) {
            return Map.of("rejected", true, "detail", e.getClass().getSimpleName());
        }
    }

    /** Only the fields this API has any business accepting. */
    public record OrderDocument(String subscriptionId) {
    }
}
