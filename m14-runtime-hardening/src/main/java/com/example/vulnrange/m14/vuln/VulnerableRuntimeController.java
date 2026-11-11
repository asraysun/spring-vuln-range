package com.example.vulnrange.m14.vuln;

import java.io.IOException;
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
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * VULNERABLE (intentional): the "container context inspector" that ships in far too many services,
 * plus the filesystem behaviour a hardened pod would refuse. PoC: {@code attacks/14-runtime-hardening.sh}.
 */
@RestController
@RequestMapping("/vuln14")
public class VulnerableRuntimeController {

    /**
     * VULNERABLE: identity, mounts, credentials layout and internal coordinates in one anonymous call.
     * With any request-level primitive (SSRF in another service, one leaked ingress) this is the
     * post-exploitation checklist: which service account, which secret files, which namespaces.
     */
    @GetMapping("/context")
    public Map<String, Object> context() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("user", System.getProperty("user.name"));
        out.put("home", System.getProperty("user.home"));
        out.put("workingDirectory", System.getProperty("user.dir"));
        out.put("os", System.getProperty("os.name") + " " + System.getProperty("os.arch"));
        out.put("uid", uid());
        out.put("env", new LinkedHashMap<>(System.getenv()));
        out.put("serviceAccountTokenMounted",
                Files.exists(Path.of("/var/run/secrets/kubernetes.io/serviceaccount/token")));
        out.put("serviceAccountNamespace", readOrNull("/var/run/secrets/kubernetes.io/serviceaccount/namespace"));
        out.put("writableDirs", writableDirectories());
        out.put("commandLine", System.getProperty("sun.java.command"));
        return out;
    }

    /**
     * VULNERABLE (behaviour): any writable path means a request-level file-write primitive becomes a
     * persistent one (dropped JSP, poisoned config, planted crontab). A hardened pod mounts
     * {@code readOnlyRootFilesystem: true} with tmpfs only where needed.
     */
    @PostMapping("/write")
    public ResponseEntity<Map<String, Object>> write(@RequestBody Map<String, String> body) {
        String path = body.getOrDefault("path", "");
        if (path.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "path required"));
        }
        Path target = Path.of(path).normalize();
        try {
            Files.createDirectories(target.getParent() == null ? Path.of(".") : target.getParent());
            Files.writeString(target, body.getOrDefault("content", "written by the vulnerable endpoint"));
            return ResponseEntity.ok(Map.of("written", target.toString(),
                    "readOnlyRootFilesystem", false,
                    "note", "on a hardened pod this call fails with Read-only file system"));
        } catch (IOException | SecurityException e) {
            return ResponseEntity.status(422).body(Map.of("blocked", true, "detail", String.valueOf(e.getMessage())));
        }
    }

    /** VULNERABLE: secrets read from env are echoed back; env is also visible in {@code /proc/self/environ}. */
    @GetMapping("/config-check")
    public Map<String, String> configCheck(@RequestParam(required = false) String name) {
        Map<String, String> out = new LinkedHashMap<>();
        System.getenv().forEach((key, value) -> {
            String upper = key.toUpperCase();
            if (upper.contains("PASSWORD") || upper.contains("TOKEN") || upper.contains("SECRET")
                    || upper.contains("KEY") || (name != null && key.contains(name))) {
                out.put(key, value);
            }
        });
        return out;
    }

    private static String uid() {
        // ProcessHandle works on every platform and needs no JDK-internal packages: the account the
        // process runs as is the first thing an attacker checks, and "root" answers a lot of questions.
        return ProcessHandle.current().info().user().orElse("unknown");
    }

    private static String readOrNull(String path) {
        try {
            return Files.readString(Path.of(path));
        } catch (Exception e) {
            return "not present";
        }
    }

    private static List<String> writableDirectories() {
        List<String> writable = new ArrayList<>();
        for (String candidate : List.of("/", "/tmp", "/app", "/opt", "/usr/local/tomcat", "/var/log", "/etc")) {
            Path path = Path.of(candidate);
            if (Files.isDirectory(path) && Files.isWritable(path)) {
                writable.add(candidate);
            }
        }
        return writable;
    }
}
