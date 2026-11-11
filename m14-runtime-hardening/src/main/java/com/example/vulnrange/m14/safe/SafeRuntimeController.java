package com.example.vulnrange.m14.safe;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Reference implementation of checklist section 14: a service that reports <em>whether</em> it is
 * running in a safe shape, never the contents of its own configuration.
 */
@RestController
@RequestMapping("/safe14")
public class SafeRuntimeController {

    /** Only paths this service is designed to write to; everything else is refused. */
    private static final List<Path> WRITABLE_ALLOW_LIST = List.of(
            Path.of(System.getProperty("java.io.tmpdir"), "vulnrange-m14").toAbsolutePath().normalize());

    /**
     * Hardening self-report: booleans and counts only. No environment map, no secret names with
     * values, no mount list an attacker can turn into a target map.
     */
    @GetMapping("/hardening")
    public Map<String, Object> hardening() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("runsAsNonRoot", !isRoot());
        out.put("workingDirectoryPresent", Files.isDirectory(Path.of(System.getProperty("user.dir"))));
        out.put("serviceAccountTokenMounted",
                Files.exists(Path.of("/var/run/secrets/kubernetes.io/serviceaccount/token")));
        out.put("credentialVariablesSeen", System.getenv().keySet().stream()
                .filter(key -> key.toUpperCase().matches(".*(PASSWORD|TOKEN|SECRET|KEY).*"))
                .count());
        out.put("credentialValuesReturned", 0);
        out.put("writableAllowList", WRITABLE_ALLOW_LIST.stream().map(String::valueOf).toList());
        out.put("expectedPlatformControls", List.of(
                "runAsNonRoot: true + explicit runAsUser",
                "allowPrivilegeEscalation: false",
                "capabilities.drop: [ALL]",
                "readOnlyRootFilesystem: true with tmpfs only where needed",
                "seccompProfile: RuntimeDefault",
                "resources.requests/limits set",
                "automountServiceAccountToken: false unless the token is required",
                "NetworkPolicy default-deny in and out",
                "PodDisruptionBudget + topologySpreadConstraints",
                "image pinned by digest, minimal base, no shell"));
        return out;
    }

    /** Writes are confined to the allow-listed scratch directory. */
    @PostMapping("/write")
    public ResponseEntity<Map<String, Object>> write(@RequestBody Map<String, String> body) {
        String requested = body.getOrDefault("path", "");
        Path target = Path.of(requested).toAbsolutePath().normalize();
        boolean allowed = WRITABLE_ALLOW_LIST.stream().anyMatch(target::startsWith);
        if (!allowed) {
            return ResponseEntity.status(422).body(Map.of(
                    "blocked", true,
                    "reason", "path is outside the writable allow-list",
                    "allowList", WRITABLE_ALLOW_LIST.stream().map(String::valueOf).toList()));
        }
        try {
            Files.createDirectories(target.getParent());
            Files.writeString(target, body.getOrDefault("content", "ok"));
            return ResponseEntity.ok(Map.of("written", target.toString()));
        } catch (Exception e) {
            return ResponseEntity.status(422).body(Map.of("blocked", true,
                    "detail", e.getClass().getSimpleName()));
        }
    }

    @GetMapping("/egress-and-integrity")
    public Map<String, Object> egressAndIntegrity() {
        List<String> notes = new ArrayList<>();
        notes.add("liveness/readiness/startup probes are separate endpoints");
        notes.add("graceful shutdown with preStop sleep so in-flight requests drain during a patch rollout");
        notes.add("JVM: -XX:MaxRAMPercentage instead of -Xmx guesswork, -XX:+ExitOnOutOfMemoryError");
        notes.add("no package manager, compiler or shell in the runtime image");
        notes.add("SBOM and image digest recorded in the deployment record");
        return Map.of("notes", notes);
    }

    private static boolean isRoot() {
        return "0".equals(System.getProperty("user.name")) || "root".equals(System.getProperty("user.name"));
    }
}
