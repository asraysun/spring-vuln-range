package com.example.vulnrange.m04.safe;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import com.example.vulnrange.m04.safe.dto.UserCreateRequest;
import jakarta.annotation.PostConstruct;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

/**
 * Reference implementation of checklist section 4. The pattern to copy is "validate at the boundary,
 * resolve from allow-lists, never interpret client strings as names/paths/patterns/URLs".
 */
@RestController
@RequestMapping("/safe4")
public class SafeValidationController {

    private static final Set<String> SORTABLE_COLUMNS = Set.of("id", "plan", "created_at", "monthly_price");
    private static final Set<String> SORT_DIRECTIONS = Set.of("asc", "desc");
    private static final Set<String> ALLOWED_EXTENSIONS = Set.of("txt", "csv", "pdf");
    private static final long MAX_UPLOAD_BYTES = 2L * 1024 * 1024;
    private static final int MAX_REGEX_INPUT_CHARS = 2_000;

    private final Path storageRoot = Path.of(System.getProperty("java.io.tmpdir"), "vulnrange-m04-safe").toAbsolutePath().normalize();
    private final List<Map<String, String>> users = new ArrayList<>();

    @PostConstruct
    void prepareStorage() {
        try {
            Files.createDirectories(storageRoot);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Defence in depth for any form binding in this controller: dangerous property paths are not
     * bindable at all. On a patched Spring this is belt-and-braces; on an old one it is the fix.
     */
    @InitBinder
    void hardenBinder(WebDataBinder binder) {
        binder.setDisallowedFields("class", "class.*", "Class.*", "*.class.*", "*.Class.*",
                "classLoader", "*.classLoader.*", "protectionDomain.*");
    }

    /** DTO + {@code @Valid} + no privileged fields: mass assignment has nothing to write to. */
    @PostMapping(value = "/users", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> createUser(@Valid @RequestBody UserCreateRequest request) {
        // Role/quota/price are decided by server-side policy, never by the payload.
        Map<String, String> stored = new LinkedHashMap<>();
        stored.put("username", request.getUsername());
        stored.put("email", request.getEmail());
        stored.put("tenantId", request.getTenantId());
        stored.put("role", "USER");
        stored.put("monthlyLimit", "1000");
        users.add(stored);
        return ResponseEntity.status(HttpStatus.CREATED).body(stored);
    }

    @GetMapping("/users")
    public List<Map<String, String>> listUsers() {
        return List.copyOf(users);
    }

    /** Sort and direction resolved against an allow-list; unknown values are a 400, never SQL. */
    @GetMapping("/subscriptions")
    public Map<String, Object> listSubscriptions(@RequestParam(defaultValue = "created_at") String sort,
                                                 @RequestParam(defaultValue = "desc") String direction,
                                                 @RequestParam String plan) {
        String column = SORTABLE_COLUMNS.stream()
                .filter(c -> c.equalsIgnoreCase(sort))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("unknown sort column"));
        String dir = SORT_DIRECTIONS.stream()
                .filter(d -> d.equalsIgnoreCase(direction))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("unknown sort direction"));
        String sql = "SELECT id, plan, created_at FROM subscription WHERE plan = ? ORDER BY "
                + column + " " + dir.toUpperCase(Locale.ROOT);
        return Map.of("query", sql, "note", "identifiers come from an allow-list, plan is bound");
    }

    /** Canonical-path containment: the resolved target must still be inside the base directory. */
    @GetMapping(value = "/files/{name}", produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> readFile(@PathVariable String name) throws IOException {
        Path resolved = storageRoot.resolve(name).normalize();
        if (!resolved.startsWith(storageRoot) || !Files.isRegularFile(resolved)) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(Files.readString(resolved));
    }

    /** Size + extension allow-list + magic bytes + generated name + containment check. */
    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> upload(@RequestPart("file") MultipartFile file) throws IOException {
        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "empty file"));
        }
        if (file.getSize() > MAX_UPLOAD_BYTES) {
            return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE)
                    .body(Map.of("error", "file larger than " + MAX_UPLOAD_BYTES + " bytes"));
        }
        String original = file.getOriginalFilename() == null ? "" : file.getOriginalFilename();
        String extension = extensionOf(original);
        if (!ALLOWED_EXTENSIONS.contains(extension)) {
            return ResponseEntity.badRequest().body(Map.of("error", "extension not allowed",
                    "allowed", ALLOWED_EXTENSIONS));
        }
        if (!magicBytesAcceptable(file, extension)) {
            return ResponseEntity.badRequest().body(Map.of("error", "content does not match extension"));
        }
        // The client-supplied name is only ever used to derive the extension above.
        Path stored = storageRoot.resolve(UUID.randomUUID() + "." + extension).normalize();
        if (!stored.startsWith(storageRoot)) {
            return ResponseEntity.badRequest().body(Map.of("error", "rejected path"));
        }
        Files.write(stored, file.getBytes());
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                "storedAs", stored.getFileName().toString(),
                "originalNameIgnored", original));
    }

    /**
     * Search is a substring/quoting problem, not a regex problem. If a pattern must be user-supplied,
     * bound the input length, run it under a timeout and never accept raw {@code Pattern} syntax.
     */
    @PostMapping(value = "/search", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> search(@RequestBody Map<String, String> body) {
        String query = body.getOrDefault("query", "");
        String input = body.getOrDefault("input", "");
        if (query.length() > 64 || input.length() > MAX_REGEX_INPUT_CHARS) {
            throw new IllegalArgumentException("query or input too long");
        }
        return Map.of("matches", input.contains(query), "engine", "literal-contains");
    }

    /** Redirect targets resolved from an allow-list of logical names — a URL is never a parameter. */
    @GetMapping("/redirect")
    public ResponseEntity<Void> redirect(@RequestParam String url) {
        Map<String, String> allowList = Map.of(
                "subscriptions", "/safe4/subscriptions?plan=ESPD-BASIC",
                "docs", "https://docs.spring.io/spring-security/reference/");
        String location = allowList.get(url);
        if (location == null) {
            return ResponseEntity.badRequest().build();
        }
        return ResponseEntity.status(HttpStatus.FOUND).header(HttpHeaders.LOCATION, location).build();
    }

    /** Pagination is capped; there is no way to ask for the whole table. */
    @GetMapping("/export")
    public Map<String, Object> export(@RequestParam(defaultValue = "50") int size) {
        int limited = Math.clamp(size, 1, 200);
        List<String> rows = new ArrayList<>(limited);
        for (int i = 0; i < limited; i++) {
            rows.add("SUB-" + i);
        }
        return Map.of("rows", rows.size(), "requested", size, "capped", size > limited);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> badRequest(IllegalArgumentException e) {
        // The message is a fixed, non-reflective one; nothing client-supplied is echoed back.
        return ResponseEntity.badRequest().body(Map.of("error", "invalid request"));
    }

    @ExceptionHandler(org.springframework.web.bind.MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> invalid(org.springframework.web.bind.MethodArgumentNotValidException e) {
        List<Map<String, String>> violations = e.getBindingResult().getFieldErrors().stream()
                .map(fe -> Map.of("field", fe.getField(), "message", messageOf(fe)))
                .toList();
        return ResponseEntity.badRequest().body(Map.of("violations", violations));
    }

    /**
     * Unknown JSON fields are refused rather than ignored: Spring wraps Jackson's
     * {@code UnrecognizedPropertyException} into {@link HttpMessageNotReadableException}, and this
     * handler turns it into a fixed 400 so a client trying to set {@code role} fails visibly instead
     * of being silently dropped.
     */
    @ExceptionHandler(org.springframework.http.converter.HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> unreadable(
            org.springframework.http.converter.HttpMessageNotReadableException e) {
        return ResponseEntity.badRequest().body(Map.of("error", "malformed request body"));
    }

    private static String messageOf(FieldError fe) {
        return fe.getDefaultMessage() == null ? "invalid" : fe.getDefaultMessage();
    }

    private static String extensionOf(String name) {
        int dot = name.lastIndexOf('.');
        if (dot < 0 || dot == name.length() - 1) {
            return "";
        }
        return name.substring(dot + 1).toLowerCase(Locale.ROOT);
    }

    /** Cheap signature check; a real service also runs an AV/CDR scan and serves files as downloads. */
    private static boolean magicBytesAcceptable(MultipartFile file, String extension) throws IOException {
        byte[] head = new byte[Math.min(8, (int) file.getSize())];
        try (var in = file.getInputStream()) {
            int read = in.readNBytes(head, 0, head.length);
            if (read < head.length) {
                head = java.util.Arrays.copyOf(head, Math.max(read, 0));
            }
        }
        return switch (extension) {
            case "pdf" -> head.length >= 4 && head[0] == '%' && head[1] == 'P' && head[2] == 'D' && head[3] == 'F';
            case "txt", "csv" -> { for (byte b : head) if (b < 0x20 && b != '\n' && b != '\r' && b != '\t') yield false; yield true; }
            default -> false;
        };
    }

    /** Placeholder so the module compiles even if a future endpoint needs the quota bean. */
    @SuppressWarnings("unused")
    private static final BigDecimal DEFAULT_LIMIT = BigDecimal.valueOf(1000);
}
