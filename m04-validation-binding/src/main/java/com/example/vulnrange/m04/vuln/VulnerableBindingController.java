package com.example.vulnrange.m04.vuln;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.view.RedirectView;

/**
 * VULNERABLE (intentional): request data is trusted at every boundary. PoC: {@code attacks/04-validation-binding.sh}.
 */
@RestController
@RequestMapping("/vuln4")
public class VulnerableBindingController {

    private final List<LegacyUserEntity> users = new ArrayList<>();
    private final Path uploadRoot = Path.of(System.getProperty("java.io.tmpdir"), "vulnrange-m04-uploads");

    public VulnerableBindingController() {
        LegacyUserEntity seed = new LegacyUserEntity();
        seed.setUsername("alice");
        seed.setEmail("alice@example.invalid");
        users.add(seed);
        try {
            Files.createDirectories(uploadRoot);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * VULNERABLE: mass assignment. {@code @ModelAttribute} binds every writable property of the
     * entity, so {@code role=ADMIN&priceOverride=0} in a form field is a privilege and price
     * escalation with no code change anywhere near this line.
     */
    @PostMapping(value = "/users", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public Map<String, Object> createUserForm(@ModelAttribute LegacyUserEntity entity) {
        users.add(entity);
        return Map.of("stored", entity.toString(), "rolesAcceptedFromClient", true);
    }

    /**
     * VULNERABLE: JSON mass assignment. Unknown-property failure is switched off in
     * application.yml, so extra JSON fields silently populate entity properties.
     */
    @PostMapping(value = "/users/json", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> createUserJson(@RequestBody LegacyUserEntity entity) {
        users.add(entity);
        return Map.of("stored", entity.toString());
    }

    /** VULNERABLE: no @Valid, no bounds; a 200-char username and a 2 MB email are accepted. */
    @PostMapping(value = "/notes", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> createNote(@RequestBody Map<String, String> note) {
        String body = note.getOrDefault("body", "");
        return Map.of("accepted", true, "length", body.length());
    }

    /**
     * VULNERABLE: sort/direction from the request go straight into an ORDER BY fragment. The safe
     * version resolves the value against a column allow-list.
     */
    @GetMapping("/subscriptions")
    public Map<String, Object> listSubscriptions(@RequestParam(defaultValue = "createdAt") String sort,
                                                 @RequestParam(defaultValue = "asc") String direction,
                                                 @RequestParam(required = false) String plan) {
        String sql = "SELECT id, plan, created_at FROM subscription WHERE plan = ? "
                + "ORDER BY " + sort + " " + direction;
        return Map.of("query", sql, "note", "sort and direction are concatenated, plan is bound");
    }

    /** VULNERABLE: file name from the client, no normalisation (CWE-22). */
    @GetMapping(value = "/files/{name}", produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> readFile(@PathVariable String name) throws IOException {
        Path target = uploadRoot.resolve(name);
        if (!Files.exists(target)) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(Files.readString(target));
    }

    /** VULNERABLE: original filename trusted, no size/type/extension check, no containment check. */
    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public Map<String, Object> upload(@RequestPart("file") MultipartFile file) throws IOException {
        Path target = uploadRoot.resolve(file.getOriginalFilename());
        file.transferTo(target);
        return Map.of("written", target.toString(),
                "size", file.getSize(),
                "outsideUploadRoot", !target.normalize().startsWith(uploadRoot));
    }

    /**
     * VULNERABLE: binder exposure probe. On a patched Spring this chain is dead (the class resolver
     * blocks {@code class.*}), which is exactly the lesson: the framework patch bought time, the DTO
     * boundary is the fix. Left here so scanners and reviewers see the shape.
     */
    @PostMapping(value = "/binder-probe", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public Map<String, Object> binderProbe(@ModelAttribute LegacyUserEntity entity,
                                          @RequestParam(required = false) String probe) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("entityAfterBinding", entity.toString());
        out.put("probe", probe);
        out.put("hint", "try probe=class.classLoader.name and role=ADMIN");
        return out;
    }

    /** VULNERABLE: user-supplied regular expression on user-supplied text (ReDoS, CWE-1333). */
    @PostMapping(value = "/search/regex", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> regexSearch(@RequestBody Map<String, String> body) {
        String pattern = body.getOrDefault("pattern", ".*");
        String input = body.getOrDefault("input", "");
        long start = System.nanoTime();
        boolean matches = Pattern.compile(pattern).matcher(input).find();
        return Map.of("matches", matches, "elapsedMillis", (System.nanoTime() - start) / 1_000_000);
    }

    /** VULNERABLE: open redirect (CWE-601) — used for phishing and to bounce tokens. */
    @GetMapping("/redirect")
    public RedirectView redirect(@RequestParam String url) {
        return new RedirectView(url);
    }

    /** VULNERABLE: unbounded in-memory aggregation from a client-supplied size (DoS). */
    @GetMapping("/export")
    public Map<String, Object> export(@RequestParam(defaultValue = "1000000") int size) {
        List<String> rows = new ArrayList<>(Math.min(size, 5_000_000));
        for (int i = 0; i < Math.min(size, 5_000_000); i++) {
            rows.add("SUB-" + i);
        }
        return Map.of("rows", rows.size(), "heapGrownByApproxBytes", rows.size() * 48L);
    }
}
