# Spring Security: How to Prevent Input Validation & Data Binding Vulnerabilities

A practical guide to securing Spring Boot input validation, data binding, file uploads, and resource allocation — covering 10 CWEs found in real Spring applications.

---

## Table of Contents

1. [Mass Assignment Prevention (Form Binding)](#1-mass-assignment-prevention-form-binding)
2. [Mass Assignment Prevention (JSON)](#2-mass-assignment-prevention-json)
3. [Explicit Input Validation](#3-explicit-input-validation)
4. [SQL Injection in ORDER BY](#4-sql-injection-in-order-by)
5. [Path Traversal Prevention](#5-path-traversal-prevention)
6. [Secure File Uploads](#6-secure-file-uploads)
7. [ReDoS Prevention](#7-redos-prevention)
8. [Open Redirect Prevention](#8-open-redirect-prevention)
9. [Resource Allocation Limits](#9-resource-allocation-limits)
10. [Binder Exposure Prevention](#10-binder-exposure-prevention)

---

## 1. Mass Assignment Prevention (Form Binding)

**CWE-915** — *Improper Control of Dynamically Modified Object (Mass Assignment)*

### The Problem

When a framework binds HTTP request parameters directly to an entity or domain object, an attacker can add extra fields to the request to modify privileged properties they shouldn't have access to — such as `role`, `isAdmin`, or `priceOverride`. This bypasses intended application logic and leads to privilege escalation or data integrity violations.

```java
// ❌ VULNERABLE — form binding maps all request params to the User entity
@PostMapping("/users")
public ResponseEntity<?> createUser(@ModelAttribute User user) {
    // Attacker sends: username=attacker&role=ADMIN&monthlyLimit=999999
    // The 'role' and 'monthlyLimit' fields are set on the entity, bypassing business logic
    userRepository.save(user);
    return ResponseEntity.status(201).body(user);
}
```

### The Fix

Use a **Data Transfer Object (DTO)** that only contains the fields the user is allowed to set.

```java
// ✅ SAFE — strict DTO boundary
public record CreateUserRequest(
    @NotBlank @Size(min = 3, max = 50) String username,
    @Email @Size(max = 255) String email
    // No 'role', 'isAdmin', 'monthlyLimit' fields — attacker cannot send them
) {}

@PostMapping("/users")
public ResponseEntity<?> createUser(@Valid @RequestBody CreateUserRequest req) {
    User user = new User(req.username(), req.email());
    user.setRole("USER");  // server-side assignment, not from request
    user.setMonthlyLimit(1000);  // server-side default, not from request
    userRepository.save(user);
    return ResponseEntity.status(201).body(user);
}
```

**Key rules:**
- Always use DTOs with explicit field lists — never expose domain entities directly to API inputs
- Map the DTO to the entity server-side with explicit field assignment
- Set privileged fields (`role`, `isAdmin`, `status`, `priceOverride`) server-side with business logic
- Use `@Valid` on all DTO parameters to trigger validation at the trust boundary
- Use `@JsonIgnoreProperties(ignoreUnknown = true)` as defense-in-depth on entity classes

---

## 2. Mass Assignment Prevention (JSON)

**CWE-915** — *Improper Control of Dynamically Modified Object*

### The Problem

When Spring deserializes JSON directly into an entity, unknown fields are silently ignored or — worse — bound to entity properties. An attacker can add extra fields to the JSON payload to modify privileged properties.

```java
// ❌ VULNERABLE — JSON deserializes into entity, unknown fields may bind
@PostMapping("/users/json")
public ResponseEntity<?> createUserJson(@RequestBody User user) {
    // Attacker sends: {"username": "attacker", "email": "a@b.com", "role": "ADMIN"}
    // Jackson binds 'role' directly to the User entity
    userRepository.save(user);
    return ResponseEntity.status(201).body(user);
}
```

### The Fix

Use explicit DTOs and configure Jackson to reject unknown properties.

```java
// ✅ SAFE — DTO with explicit fields
public record CreateUserJsonRequest(
    @NotBlank String username,
    @Email String email
) {}

// ✅ SAFE — Jackson rejects unknown fields
@Configuration
public class JacksonConfig {
    @Bean
    public ObjectMapper objectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
        return mapper;
    }
}

// ✅ SAFE — per-DTO annotation as defense-in-depth
@JsonDeserialize(builder = CreateUserRequest.Builder.class)
public class CreateUserRequest {
    // Explicit fields only
}

// Usage
@PostMapping("/users/json")
public ResponseEntity<?> createUserJson(@Valid @RequestBody CreateUserJsonRequest req) {
    User user = new User(req.username(), req.email());
    user.setRole("USER");  // fixed server-side role
    userRepository.save(user);
    return ResponseEntity.status(201).body(user);
}
```

**Key rules:**
- Configure `FAIL_ON_UNKNOWN_PROPERTIES = true` globally as the default
- Use DTOs with explicit field lists for every endpoint
- Apply `@JsonIgnoreProperties(ignoreUnknown = true)` on entity classes to silently ignore unexpected fields during internal deserialization
- Add contract tests: send a request with an extra privileged field and expect `400 Bad Request`

---

## 3. Explicit Input Validation

**CWE-20** — *Insufficient Input Validation*

### The Problem

Without bounds on input size, format, or content, an application can process malicious or malformed data that leads to unexpected behavior, crashes, or injection attacks. This is a catch-all for any validation that should happen at the trust boundary but doesn't.

```java
// ❌ VULNERABLE — no validation on note field
@PostMapping("/notes")
public ResponseEntity<?> createNote(@RequestBody NoteRequest req) {
    // Attacker can send a 50MB string, SQL injection, or a regex payload
    noteService.save(req.getContent());
    return ResponseEntity.ok("saved");
}
```

### The Fix

Apply explicit validation annotations to all input fields.

```java
// ✅ SAFE — validation annotations enforce constraints
public record NoteRequest(
    @NotBlank @Size(max = 1000, message = "Content must be ≤ 1000 characters")
    String content,
    
    @Size(max = 200, message = "Title must be ≤ 200 characters")
    String title,
    
    @Email(message = "Email must be valid")
    @Size(max = 255)
    String authorEmail
) {}

@PostMapping("/notes")
public ResponseEntity<?> createNote(@Valid @RequestBody NoteRequest req) {
    // Validation fails with 400 if constraints are violated
    Note note = noteService.save(new Note(req.content(), req.title(), req.authorEmail()));
    return ResponseEntity.ok(note);
}

// ✅ SAFE — custom validators for business rules
@Target({FIELD})
@Retention(RUNTIME)
@Constraint(validatedBy = {StrongPasswordValidator.class})
public @interface StrongPassword {
    String message() default "Password must be ≥ 12 chars with uppercase, lowercase, digit";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}

public class StrongPasswordValidator implements ConstraintValidator<StrongPassword, String> {
    @Override
    public boolean isValid(String value, ConstraintValidatorContext ctx) {
        if (value == null) return false;
        boolean hasUpper = value.chars().anyMatch(Character::isUpperCase);
        boolean hasLower = value.chars().anyMatch(Character::isLowerCase);
        boolean hasDigit = value.chars().anyMatch(Character::isDigit);
        return value.length() >= 12 && hasUpper && hasLower && hasDigit;
    }
}

// Usage
public record RegisterRequest(
    @NotBlank @Size(min = 3, max = 50) String username,
    @StrongPassword String password,
    @Email String email
) {}
```

**Validation annotations reference:**

| Annotation | Purpose | Example |
|------------|---------|---------|
| `@NotBlank` | String not null, not empty, not whitespace | `@NotBlank String username` |
| `@NotNull` | Value not null | `@NotNull BigDecimal price` |
| `@Size(min/max)` | String or collection length | `@Size(max = 1000) String content` |
| `@Pattern(regex)` | Regex pattern match | `@Pattern(regexp = "^[A-Z]{2}[0-9]{9}$") String ssn` |
| `@Email` | Valid email format | `@Email String email` |
| `@Min/Max` | Numeric range | `@Min(0) @Max(100) Integer percentage` |
| `@Past/@Future` | Date/time constraint | `@Past LocalDateTime birthDate` |
| `@Valid` | Recursive validation | `@Valid Address address` |

**Global validation error handler:**

```java
// ✅ SAFE — consistent 400 responses with field-level details
@RestControllerAdvice
public class ValidationExceptionHandler {
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidation(MethodArgumentNotValidException ex) {
        List<FieldError> errors = ex.getBindingResult().getFieldErrors().stream()
            .map(fe -> new FieldErrorDetail(fe.getField(), fe.getDefaultMessage()))
            .toList();
        
        return ResponseEntity.badRequest().body(
            new ErrorResponse("VALIDATION_ERROR", "Request validation failed", errors)
        );
    }
}
```

**Key rules:**
- Validate at the trust boundary — before any business logic executes
- Use `@NotBlank`, `@Size`, `@Pattern`, `@Email`, `@Min`/`@Max` on all input fields
- Provide clear error messages to the client, never leak internal details
- Create custom validators for complex business rules (password strength, format constraints)
- Use `@Valid` for nested objects to trigger recursive validation

---

## 4. SQL Injection in ORDER BY

**CWE-89** — *SQL Injection (ORDER BY Injection)*

### The Problem

While `?` parameter binding prevents SQL injection for `WHERE` clauses, `ORDER BY` and `GROUP BY` clauses **cannot** use bound parameters. If user input is concatenated directly into the SQL string for sorting, an attacker can inject arbitrary SQL.

```java
// ❌ VULNERABLE — sort parameter concatenated into SQL
@GetMapping("/subscriptions")
public ResponseEntity<?> list(@RequestParam String sort) {
    String sql = "SELECT * FROM subscriptions ORDER BY " + sort;
    // Attacker sends: sort=id; DROP TABLE subscriptions--
    // Result: "SELECT * FROM subscriptions ORDER BY id; DROP TABLE subscriptions--"
    return ResponseEntity.ok(jdbcTemplate.queryForList(sql));
}
```

### The Fix

Resolve sort columns from a server-side allow-list.

```java
// ✅ SAFE — allow-list resolution
private static final Set<String> SAFE_SORTABLE = Set.of(
    "id", "plan", "createdAt", "status", "name", "amount"
);
private static final Set<String> SAFE_DIRECTIONS = Set.of("ASC", "DESC");

@GetMapping("/subscriptions")
public ResponseEntity<?> list(
        @RequestParam(defaultValue = "createdAt") String sort,
        @RequestParam(defaultValue = "DESC") String direction) {
    
    if (!SAFE_SORTABLE.contains(sort)) {
        return ResponseEntity.badRequest().body("Invalid sort column: " + sort);
    }
    
    String normalizedDirection = SAFE_DIRECTIONS.contains(direction.toUpperCase()) 
        ? direction.toUpperCase() 
        : "DESC";
    
    // Safe: column is from allow-list, direction is normalized
    String sql = "SELECT * FROM subscriptions ORDER BY " + sort + " " + normalizedDirection;
    return ResponseEntity.ok(jdbcTemplate.queryForList(sql));
}

// ✅ SAFE — JPA Specification approach (preferred)
@GetMapping("/subscriptions")
public ResponseEntity<?> list(
        @RequestParam(defaultValue = "createdAt") String sort,
        @RequestParam(defaultValue = "DESC") String direction) {
    
    Sort safeSort = Sort.by(
        SAFE_DIRECTIONS.contains(direction.toUpperCase()) 
            ? Sort.Direction.fromString(direction.toUpperCase()) 
            : Sort.Direction.DESC,
        SAFE_SORTABLE.contains(sort) ? sort : "createdAt"
    );
    
    return ResponseEntity.ok(subscriptionRepository.findAll(safeSort));
}
```

**Key rules:**
- Never concatenate user input into `ORDER BY` or `GROUP BY` clauses
- Always resolve sort columns from a server-side allow-list
- Return `400 Bad Request` for any sort column not in the allow-list
- Use JPA `Specification` or `Sort` objects when possible — they parameterize column names safely
- Similarly guard `SELECT` column lists, `LIMIT`/`OFFSET` values, and `HAVING` clauses

---

## 5. Path Traversal Prevention

**CWE-22** — *Path Traversal*

### The Problem

If a user-supplied filename or path is used to access files on the server without validation, an attacker can read arbitrary files (e.g., `/etc/passwd`, application source code, configuration files with secrets) or write files to arbitrary locations.

```java
// ❌ VULNERABLE — user-controlled path
@GetMapping("/files/{name}")
public ResponseEntity<?> readFile(@PathVariable String name) {
    Path file = Path.of("/var/data", name);  // ../../etc/passwd escapes the base dir
    return ResponseEntity.ok(Files.readString(file));
}
// GET /files/../../etc/passwd → reads /etc/passwd
```

### The Fix

Normalize the path and verify it stays within the allowed base directory.

```java
// ✅ SAFE — containment check
@GetMapping("/files/{name}")
public ResponseEntity<?> readFile(@PathVariable String name) {
    Path baseDir = Path.of("/var/data").toAbsolutePath().normalize();
    Path file = baseDir.resolve(name).toAbsolutePath().normalize();

    // Verify the resolved path is still within the base directory
    if (!file.startsWith(baseDir)) {
        log.warn("Path traversal attempt: name={} resolved={}", name, file);
        return ResponseEntity.status(403).body("Access denied");
    }

    // Verify it's a regular file (not a directory or symlink to sensitive path)
    if (!Files.isRegularFile(file)) {
        return ResponseEntity.status(404).body("Not found");
    }

    return ResponseEntity.ok(Files.readString(file));
}

// ✅ SAFE — for uploads, use generated names, not user input
@PostMapping("/upload")
public ResponseEntity<?> uploadFile(@RequestParam("file") MultipartFile file) {
    Path baseDir = Path.of("/var/uploads").toAbsolutePath().normalize();
    String safeName = UUID.randomUUID() + "." + getFileExtension(file.getOriginalFilename());
    Path target = baseDir.resolve(safeName).toAbsolutePath().normalize();

    if (!target.startsWith(baseDir)) {
        return ResponseEntity.status(403).body("Access denied");
    }

    Files.copy(file.getInputStream(), target, StandardCopyOption.REPLACE_EXISTING);
    return ResponseEntity.ok(Map.of("filename", safeName));
}
```

**Key rules:**
- Always resolve to absolute paths and call `.normalize()` to resolve `..` and `.`
- Verify the resolved path `startsWith(baseDir)` — this is the containment check
- Use `Files.isRegularFile()` to reject symlinks and directories
- Serve uploaded files with `Content-Disposition: attachment` and from outside the web root
- Consider using a CDN or object storage (S3) instead of local file serving

---

## 6. Secure File Uploads

**CWE-434** — *Unrestricted Upload of File with Dangerous Type*

### The Problem

Allowing users to upload files without validating the file type, size, or content enables attackers to upload malicious files (JSP shells, JARs, scripts) that can be executed on the server. This is a direct path to Remote Code Execution (RCE).

```java
// ❌ VULNERABLE — no upload validation
@PostMapping("/upload")
public ResponseEntity<?> upload(@RequestParam("file") MultipartFile file) {
    // Attacker uploads: shell.jsp, malware.jar, backdoor.php
    // Then accesses it via http://app/uploads/shell.jsp → RCE
    Path target = Path.of("/var/uploads", file.getOriginalFilename());
    Files.copy(file.getInputStream(), target, StandardCopyOption.REPLACE_EXISTING);
    return ResponseEntity.ok("uploaded");
}
```

### The Fix

Implement **multiple layers** of validation.

```java
// ✅ SAFE — defense in depth for file uploads
private static final Set<String> ALLOWED_EXTENSIONS = Set.of("jpg", "png", "gif", "pdf");
private static final long MAX_FILE_SIZE = 2 * 1024 * 1024;  // 2 MB

@PostMapping("/upload")
public ResponseEntity<?> upload(@RequestParam("file") MultipartFile file) {
    // 1. Size cap
    if (file.getSize() > MAX_FILE_SIZE) {
        return ResponseEntity.status(413).body("File too large (max 2 MB)");
    }

    // 2. Extension allow-list
    String originalName = file.getOriginalFilename();
    String ext = getFileExtension(originalName).toLowerCase();
    if (!ALLOWED_EXTENSIONS.contains(ext)) {
        return ResponseEntity.status(400).body("Invalid file type (allowed: " + ALLOWED_EXTENSIONS + ")");
    }

    // 3. Magic bytes validation (don't trust the filename!)
    byte[] header = file.getInputStream().readNBytes(4);
    if (!isValidMagicBytes(header, ext)) {
        return ResponseEntity.status(400).body("Invalid file content");
    }

    // 4. Use a generated filename, not the user-supplied one
    String safeName = UUID.randomUUID() + "." + ext;
    Path baseDir = Path.of("/var/uploads").toAbsolutePath().normalize();
    Path target = baseDir.resolve(safeName).toAbsolutePath().normalize();

    if (!target.startsWith(baseDir)) {
        return ResponseEntity.status(403).body("Access denied");
    }

    // 5. Store outside web root, or serve with Content-Disposition: attachment
    Files.copy(file.getInputStream(), target, StandardCopyOption.REPLACE_EXISTING);

    return ResponseEntity.ok(Map.of("filename", safeName, "size", file.getSize()));
}

// Magic bytes allow-list
private boolean isValidMagicBytes(byte[] header, String ext) {
    if (ext.equals("jpg") && header.length >= 3) {
        return header[0] == (byte) 0xFF && header[1] == (byte) 0xD8 && header[2] == (byte) 0xFF;
    }
    if (ext.equals("png") && header.length >= 4) {
        return header[0] == (byte) 0x89 && header[1] == 'P' && header[2] == 'N' && header[3] == 'G';
    }
    if (ext.equals("pdf") && header.length >= 4) {
        return header[0] == '%' && header[1] == 'P' && header[2] == 'D' && header[3] == 'F';
    }
    return true;  // unknown type, rely on extension
}

private String getFileExtension(String filename) {
    if (filename == null || !filename.contains(".")) return "";
    return filename.substring(filename.lastIndexOf('.') + 1);
}
```

**Additional hardening measures:**

```java
// ✅ SAFE — store in object storage (S3) instead of local filesystem
@PostMapping("/upload/s3")
public ResponseEntity<?> uploadToS3(@RequestParam("file") MultipartFile file) {
    // Upload directly to S3, never touch local disk
    s3Client.putObject(BUCKET, UUID.randomUUID().toString(), file.getInputStream(), 
        new ObjectMetadata() {{
            setContentType(file.getContentType());
            setContentLength(file.getSize());
        }}
    );
    return ResponseEntity.ok(Map.of("url", s3Client.getUrl(BUCKET, key).toString()));
}

// ✅ SAFE — serve with Content-Disposition: attachment
@GetMapping("/files/{id}")
public ResponseEntity<?> downloadFile(@PathVariable String id) {
    Path file = lookupFile(id);  // database lookup by ID, not by user path
    return ResponseEntity.ok()
        .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + safeName + "\"")
        .header(HttpHeaders.CACHE_CONTROL, "no-store, no-cache, must-revalidate")
        .body(new FileSystemResource(file));
}
```

**Key rules:**
- **Size cap** — reject files exceeding the maximum allowed size
- **Extension allow-list** — only accept known-good extensions (jpg, png, pdf), never block-list
- **Magic bytes** — validate file content headers, don't trust the filename
- **Generated filename** — use `UUID.randomUUID() + "." + ext`, never store the user-supplied name
- **Containment check** — verify the resolved path is within the base directory
- **Serve as attachment** — use `Content-Disposition: attachment` to prevent browser execution
- **Consider object storage** — S3, GCS, or Azure Blob Storage isolates uploaded files from the application server

---

## 7. ReDoS Prevention

**CWE-1333** — *Regular Expression Denial of Service*

### The Problem

A user-supplied regular expression can be crafted to cause catastrophic backtracking, consuming 100% of a CPU core for seconds or minutes. This is a denial-of-service attack that doesn't require network bandwidth — just a single request with a malicious regex pattern.

```java
// ❌ VULNERABLE — user regex used directly in Pattern.compile
@PostMapping("/search/regex")
public ResponseEntity<?> search(@RequestParam String regex, @RequestParam String input) {
    Pattern p = Pattern.compile(regex);  // attacker sends: (((a+)+)+)+$
    Matcher m = p.matcher(input);
    return ResponseEntity.ok(m.matches());
}
// Pattern: (((a+)+)+)+$ on input: aaaaaaaaaaaaaaaaaX causes exponential backtracking
```

### The Fix

Avoid user-supplied regex entirely. Use literal string search when possible.

```java
// ✅ SAFE — literal search (no regex, no ReDoS)
@PostMapping("/search")
public ResponseEntity<?> search(@RequestParam String query, @RequestParam String input) {
    boolean found = input.contains(query);  // no regex, O(n) worst case
    return ResponseEntity.ok(Map.of("found", found));
}

// ✅ SAFE — if regex is required, bound the input and use a timeout
public boolean safeMatches(String regex, String input) {
    if (input.length() > 100) return false;  // bound input length
    
    // Use Java 9+ Matcher timeout API
    try {
        Pattern p = Pattern.compile(regex);
        Matcher m = p.matcher(input);
        
        // Set a timeout (Java 9+)
        if (m.find()) {
            long duration = m.matchedEnd();  // approximate cost indicator
            if (duration > 10000) return false;  // too complex
            return true;
        }
    } catch (StackOverflowError | RuntimeException e) {
        return false;  // regex was too complex
    }
    return false;
}

// ✅ SAFE — server-side regex only (user provides a keyword, not a pattern)
@PostMapping("/search/fuzzy")
public ResponseEntity<?> fuzzySearch(@RequestParam String keyword) {
    // Server defines the regex, user provides only the search term
    Pattern safePattern = Pattern.compile(Pattern.quote(keyword) + ".*", Pattern.CASE_INSENSITIVE);
    return ResponseEntity.ok(list.stream()
        .filter(item -> safePattern.matcher(item.getName()).find())
        .toList()
    );
}
```

**Key rules:**
- Avoid user-supplied regex entirely — use literal string search (`String.contains`, `String.indexOf`)
- If regex is required, bound input length to a small maximum (≤ 100 chars)
- Use `Pattern.quote()` to escape user input when building server-side regexes
- Use Java 9+ `Matcher` timeout or run regex in a separate thread with a timeout
- Never use regexes with nested quantifiers like `(a+)+`, `((a+)*)*`, or `(.*a)+`

---

## 8. Open Redirect Prevention

**CWE-601** — *Open URL Redirection*

### The Problem

If an application redirects to a URL provided by the user without validation, an attacker can craft a link that appears to come from the trusted domain but redirects to a phishing site. This undermines user trust and enables credential theft.

```java
// ❌ VULNERABLE — redirect to user-supplied URL
@GetMapping("/redirect")
public String redirect(@RequestParam String url) {
    return "redirect:" + url;  // ?url=http://evil.com
}
// User clicks: https://trusted-app.com/redirect?url=http://evil.com
// Looks legitimate, but redirects to attacker's phishing site
```

### The Fix

Map logical names to allow-listed targets.

```java
// ✅ SAFE — logical name to allow-listed target
@GetMapping("/redirect")
public String redirect(@RequestParam String destination) {
    Map<String, String> ALLOWED = Map.of(
        "home", "/",
        "profile", "/profile",
        "settings", "/settings",
        "logout", "/logout",
        "docs", "/docs"
    );
    
    String target = ALLOWED.get(destination);
    if (target == null) {
        log.warn("Unknown redirect destination: {}", destination);
        return "redirect:/";  // default to home
    }
    
    return "redirect:" + target;
}

// ✅ SAFE — verify against an allow-list of external domains
@GetMapping("/external-redirect")
public String externalRedirect(@RequestParam String destination) {
    Set<String> ALLOWED_DOMAINS = Set.of(
        "example.com",
        "docs.example.com",
        "support.example.com"
    );
    
    try {
        URI uri = new URI(destination);
        String host = uri.getHost();
        
        if (host == null || !ALLOWED_DOMAINS.contains(host)) {
            return "redirect:/";  // default to home
        }
        
        return "redirect:" + destination;
    } catch (URISyntaxException e) {
        return "redirect:/";  // invalid URI → default to home
    }
}
```

**Key rules:**
- Map logical names (`home`, `profile`, `settings`) to allow-listed internal paths
- For external redirects, verify the host against an allow-list of trusted domains
- Always default to a safe target (home page) for unknown or invalid destinations
- Never concatenate user input directly into `redirect:` URLs
- Log failed redirect attempts for security monitoring

---

## 9. Resource Allocation Limits

**CWE-770** — *Allocation of Resources Without Limits or Throttling*

### The Problem

Without limits on memory allocation, page size, or export volume, an attacker can trigger operations that consume excessive memory or CPU, causing a denial of service. A request with `?size=1000000` can load millions of records into memory, crashing the JVM.

```java
// ❌ VULNERABLE — unbounded export size
@GetMapping("/export")
public ResponseEntity<?> export(@RequestParam(defaultValue = "1000000") int size) {
    // Loads up to 1,000,000 records into memory → OOM crash
    List<Data> all = dataRepository.findAll();
    return ResponseEntity.ok(all.subList(0, Math.min(size, all.size())));
}
```

### The Fix

Cap the page size server-side with explicit limits.

```java
// ✅ SAFE — capped page size
private static final int MAX_PAGE_SIZE = 100;
private static final int MAX_EXPORT_SIZE = 10000;

@GetMapping("/export")
public ResponseEntity<?> export(
        @RequestParam(defaultValue = "100") int size,
        @RequestParam(defaultValue = "csv") String format) {
    
    // Cap the requested size
    int capped = Math.min(size, MAX_EXPORT_SIZE);
    
    // Paginate the query (don't load everything into memory)
    PageRequest pageRequest = PageRequest.of(0, capped);
    Page<Data> result = dataRepository.findAll(pageRequest);
    
    if (result.getTotalElements() > MAX_EXPORT_SIZE) {
        return ResponseEntity.status(422).body(
            "Request exceeds maximum export size of " + MAX_EXPORT_SIZE + " records"
        );
    }
    
    return ResponseEntity.ok(formatExport(result.getContent(), format));
}

// ✅ SAFE — bounded query parameters across all endpoints
@GetMapping("/search")
public ResponseEntity<?> search(
        @RequestParam String query,
        @RequestParam(defaultValue = "10") @Min(1) @Max(50) int limit) {
    // 'limit' is validated by @Min and @Max annotations
    return ResponseEntity.ok(repository.findByQuery(query, PageRequest.of(0, limit)));
}
```

**Global multipart/upload limits:**

```java
// ❌ VULNERABLE — container-wide 1 GB limit
# application.yml
spring:
  servlet:
    multipart:
      max-file-size: 1GB        # too large!
      max-request-size: 1GB     # too large!

// ✅ SAFE — reasonable limits per application.yml
spring:
  servlet:
    multipart:
      max-file-size: 10MB       # reasonable per-file limit
      max-request-size: 20MB    # reasonable per-request limit

# ✅ SAFE — per-endpoint check on top of the container limit
@PostMapping("/upload")
public ResponseEntity<?> upload(@RequestParam("file") MultipartFile file) {
    long maxFileSize = 2 * 1024 * 1024;  // 2 MB for this endpoint
    if (file.getSize() > maxFileSize) {
        return ResponseEntity.status(413).body("File too large (max 2 MB)");
    }
    // ...
}
```

**Key rules:**
- Always cap page sizes, export sizes, and query limits server-side
- Use pagination (`PageRequest`) instead of loading all records into memory
- Set reasonable container-wide limits (`max-file-size`, `max-request-size`)
- Apply per-endpoint checks on top of container limits for tighter control
- Use `@Min` and `@Max` annotations on numeric request parameters
- Monitor memory and CPU usage — set up alerts for unusual spikes

---

## 10. Binder Exposure Prevention

**CWE-915** — *Improper Control of Dynamically Modified Object (Binder Exposure / Spring4Shell Shape)*

### The Problem

Spring's data binder can modify arbitrary properties of objects, including internal framework classes. If the binder is not restricted, an attacker can manipulate class loaders, bean factories, or other internal objects to achieve Remote Code Execution. This is the shape of the Spring4Shell (CVE-2022-22965) vulnerability.

```java
// ❌ VULNERABLE — binder allows class.* properties
@PostMapping("/binder-probe")
public ResponseEntity<?> binderProbe(@ModelAttribute TargetObject obj) {
    // Attacker sends: {"class.classLoader": "...", "class.classLoader.logger": "..."}
    // Spring's binder resolves 'class' as a special property and manipulates the class loader
    // Even if the endpoint doesn't use the data, the binding phase itself triggers RCE
    return ResponseEntity.ok("processed");
}

// ❌ VULNERABLE — Map-based binding
@PostMapping("/binder-map")
public ResponseEntity<?> binderMap(@RequestBody Map<String, Object> data) {
    // The binder can traverse into the map and manipulate internal properties
    return ResponseEntity.ok("processed");
}
```

### The Fix

Use DTOs as the boundary — a field that doesn't exist on the DTO cannot be assigned. Disallow dangerous properties explicitly.

```java
// ✅ SAFE — DTO boundary (primary defense)
public record SafeRequest(
    @NotBlank String username,
    @Email String email
    // No 'class', 'classLoader', or framework properties exist
) {}

@PostMapping("/safe-endpoint")
public ResponseEntity<?> safeEndpoint(@Valid @RequestBody SafeRequest req) {
    // Binding can only set username and email — nothing dangerous
    return ResponseEntity.ok("processed");
}

// ✅ SAFE — @InitBinder to disallow dangerous properties (defense-in-depth)
@Controller
public class BaseController {
    @InitBinder
    public void initBinder(WebDataBinder binder) {
        // Disallow access to class internals, class loaders, and framework objects
        binder.setDisallowedFields("class.*", "getClass.*", "classLoader.*",
                                    "prototype.*", "self.*");
    }
}

// ✅ SAFE — for REST controllers (no @InitBinder at controller level)
@RestController
public class SecureController {
    // Primary defense: DTOs prevent binding to anything but declared fields
    @PostMapping("/api/data")
    public ResponseEntity<?> postData(@Valid @RequestBody DataRequest req) {
        // req only has declared fields — binder cannot touch class internals
        return ResponseEntity.ok("processed");
    }
}
```

**Key rules:**
- **Primary defense:** Use DTOs with explicit field lists — a field that doesn't exist on the DTO cannot be assigned
- **Defense-in-depth:** Add `@InitBinder` in base controllers to disallow `class.*`, `classLoader.*`, and other dangerous patterns
- Never bind directly to `Map`, `Object`, or framework-internal classes
- Keep Spring Framework up to date — Spring4Shell was patched in 6.0.9, 5.3.25+
- Use `@Valid` on all DTO parameters to trigger validation at the trust boundary

---

## Summary Checklist

| # | Control | CWE | Priority |
|---|---------|-----|----------|
| 1 | DTO for form binding, server-side role assignment | CWE-915 | CRITICAL |
| 2 | `FAIL_ON_UNKNOWN_PROPERTIES` + DTOs for JSON | CWE-915 | CRITICAL |
| 3 | `@Size`, `@Pattern`, `@Email` on all inputs | CWE-20 | HIGH |
| 4 | Allow-list for ORDER BY/GROUP BY columns | CWE-89 | CRITICAL |
| 5 | `normalize()` + `startsWith(base)` for file paths | CWE-22 | CRITICAL |
| 6 | Size cap + extension allow-list + magic bytes + generated name | CWE-434 | CRITICAL |
| 7 | Literal search or bounded regex with timeout | CWE-1333 | HIGH |
| 8 | Logical name → allow-listed redirect targets | CWE-601 | HIGH |
| 9 | Cap page size, paginate queries | CWE-770 | HIGH |
| 10 | DTO boundary + `@InitBinder` disallowed fields | CWE-915 | CRITICAL |

---

## Detection & Review Heuristics

| Check | Command / Pattern |
|-------|-------------------|
| Entity as @RequestBody | `grep -r '@RequestBody.*User\|@RequestBody.*Entity'` → should use DTOs |
| String concatenation in SQL | `grep -r 'ORDER BY "' \| 'GROUP BY "'` → should use allow-lists |
| Unbounded @RequestParam int | `grep -r '@RequestParam.*int\|@RequestParam.*Integer'` → should have @Min/@Max |
| User path without normalize | `grep -r 'Path.of.*pathVar\|resolve.*@PathVariable'` → should normalize + check |
| Multipart without size check | `grep -r 'MultipartFile'` → should check `file.getSize()` |
| redirect: + request param | `grep -r '"redirect:"'` → should resolve from allow-list |

---

## References

- [OWASP Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [OWASP Path Traversal Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Cheat_Sheet.html)
- [OWASP Mass Assignment](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [Spring Validation Documentation](https://docs.spring.io/spring-framework/reference/dataaccess/ beanvalidation.html)
- [CVE-2022-22965 (Spring4Shell)](https://spring.io/blog/2022/03/31/spring4shell-a-new-spring-mvc-rce-via-data-binding)
