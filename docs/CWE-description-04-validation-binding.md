# CWE Reference — §04 Input Validation and Data Binding

CWEs extracted from `docs/04-validation-binding.md` with developer-focused comments.

---

## CWE-915 — Improper Control of Dynamically Modified Object (Mass Assignment)

**Why it matters:** When a framework binds HTTP request parameters directly to an entity or domain object, an attacker can add extra fields to the request to modify privileged properties they shouldn't have access to (e.g., `role`, `isAdmin`, `price`). This bypasses the intended application logic and can lead to privilege escalation or data integrity violations.

**Attack vector in Spring:**
```java
// VULNERABLE — form binding maps all request params to the User entity
@PostMapping("/users")
public ResponseEntity<?> createUser(@ModelAttribute User user) {
    // Attacker sends: username=attacker&role=ADMIN
    // The 'role' field is set on the entity, bypassing business logic
    userRepository.save(user);
    return ResponseEntity.status(201).body(user);
}
```
`POST /vuln4/users` with `username=attacker&email=a@b.com&role=ADMIN` creates an admin user. The form binding blindly maps `role=ADMIN` to the entity.

**How to prevent:**
- Use a Data Transfer Object (DTO) that only contains the fields the user is allowed to set.
- Map the DTO to the entity server-side.
```java
// SAFE — strict DTO boundary
public record CreateUserRequest(@NotBlank String username, @Email String email) {}

@PostMapping("/users")
public ResponseEntity<?> createUser(@Valid @RequestBody CreateUserRequest req) {
    User user = new User(req.username(), req.email());
    user.setRole("USER");  // server-side assignment, not from request
    userRepository.save(user);
    return ResponseEntity.status(201).body(user);
}
```
- For JSON, use `@JsonIgnoreProperties(ignoreUnknown = true)` or `FAIL_ON_UNKNOWN_PROPERTIES` to reject unexpected fields.

---

## CWE-20 — Insufficient Input Validation

**Why it matters:** Without bounds on input size, format, or content, an application can process malicious or malformed data that leads to unexpected behavior, crashes, or injection attacks. This is a catch-all CWE for any validation that should happen at the trust boundary but doesn't.

**Attack vector in Spring:**
```java
// VULNERABLE — no validation on note field
@PostMapping("/notes")
public ResponseEntity<?> createNote(@RequestBody NoteRequest req) {
    // Attacker can send a 50MB string, or a regex payload, or SQL
    noteService.save(req.getContent());
    return ResponseEntity.ok("saved");
}
```
No `@Size`, no `@Pattern`, no length check. An attacker can flood storage or inject content.

**How to prevent:**
- Apply explicit validation annotations to all input fields:
```java
// SAFE
public record NoteRequest(
    @NotBlank @Size(max = 1000) String content,
    @Size(max = 200) String title
) {}

@PostMapping("/notes")
public ResponseEntity<?> createNote(@Valid @RequestBody NoteRequest req) {
    // Validation fails with 400 if constraints are violated
    noteService.save(req.content());
    return ResponseEntity.ok("saved");
}
```
- Use `@Pattern` for format constraints, `@Min`/`@Max` for numeric ranges.

---

## CWE-89 — SQL Injection (ORDER BY Injection)

**Why it matters:** While `?` parameter binding prevents SQL injection for `WHERE` clauses, `ORDER BY` and `GROUP BY` clauses cannot use bound parameters. If user input is concatenated directly into the SQL string for sorting, an attacker can inject arbitrary SQL, including `DROP TABLE`, `UNION SELECT`, or boolean-based extraction.

**Attack vector in Spring:**
```java
// VULNERABLE — sort parameter concatenated into SQL
@GetMapping("/subscriptions")
public ResponseEntity<?> list(@RequestParam String sort) {
    String sql = "SELECT * FROM subscriptions ORDER BY " + sort;
    // Attacker sends: sort=id; DROP TABLE subscriptions--
    return ResponseEntity.ok(jdbcTemplate.queryForList(sql));
}
```

**How to prevent:**
- Resolve sort columns from a server-side allow-list:
```java
// SAFE
private static final Set<String> SAFE_SORTABLE = Set.of("id", "plan", "createdAt", "status");

@GetMapping("/subscriptions")
public ResponseEntity<?> list(@RequestParam(defaultValue = "id") String sort) {
    if (!SAFE_SORTABLE.contains(sort)) {
        return ResponseEntity.badRequest().body("Invalid sort column");
    }
    String sql = "SELECT * FROM subscriptions ORDER BY " + sort;  // safe: allow-listed
    return ResponseEntity.ok(jdbcTemplate.queryForList(sql));
}
```
- Return 400 for any sort column not in the allow-list.

---

## CWE-22 — Path Traversal

**Why it matters:** If a user-supplied filename or path is used to access files on the server without validation, an attacker can read arbitrary files (e.g., `/etc/passwd`, application source code, configuration files with secrets) or write files to arbitrary locations.

**Attack vector in Spring:**
```java
// VULNERABLE — user-controlled path
@GetMapping("/files/{name}")
public ResponseEntity<?> readFile(@PathVariable String name) {
    Path file = Path.of("/var/data", name);  // ../../etc/passwd escapes the base dir
    return ResponseEntity.ok(Files.readString(file));
}
```
`GET /vuln4/files/../../etc/passwd` reads the system password file.

**How to prevent:**
- Normalize the path and verify it stays within the allowed base directory:
```java
// SAFE
@GetMapping("/files/{name}")
public ResponseEntity<?> readFile(@PathVariable String name) {
    Path baseDir = Path.of("/var/data").toAbsolutePath().normalize();
    Path file = baseDir.resolve(name).toAbsolutePath().normalize();
    
    if (!file.startsWith(baseDir)) {
        return ResponseEntity.status(403).body("Access denied");
    }
    if (!Files.isRegularFile(file)) {
        return ResponseEntity.status(404).body("Not found");
    }
    return ResponseEntity.ok(Files.readString(file));
}
```

---

## CWE-434 — Unrestricted Upload of File with Dangerous Type

**Why it matters:** Allowing users to upload files without validating the file type, size, or content enables attackers to upload malicious files (JSP shells, JARs, scripts) that can be executed on the server. This is a direct path to Remote Code Execution (RCE).

**Attack vector in Spring:**
```java
// VULNERABLE — no upload validation
@PostMapping("/upload")
public ResponseEntity<?> upload(@RequestParam("file") MultipartFile file) {
    // Attacker uploads a JSP shell: shell.jsp
    // Then accesses it via http://app/uploads/shell.jsp -> RCE
    Path target = Path.of("/var/uploads", file.getOriginalFilename());
    Files.copy(file.getInputStream(), target, StandardCopyOption.REPLACE_EXISTING);
    return ResponseEntity.ok("uploaded");
}
```

**How to prevent:**
- Implement multiple layers of validation:
```java
// SAFE
@PostMapping("/upload")
public ResponseEntity<?> upload(@RequestParam("file") MultipartFile file) {
    // 1. Size cap
    if (file.getSize() > 2 * 1024 * 1024) {  // 2 MB
        return ResponseEntity.status(413).body("File too large");
    }
    
    // 2. Extension allow-list
    String ext = getExtension(file.getOriginalFilename());
    if (!Set.of("jpg", "png", "pdf").contains(ext)) {
        return ResponseEntity.status(400).body("Invalid file type");
    }
    
    // 3. Magic bytes validation (don't trust the filename)
    byte[] header = file.getInputStream().readNBytes(4);
    if (!isValidMagicBytes(header, ext)) {
        return ResponseEntity.status(400).body("Invalid file content");
    }
    
    // 4. Use a generated filename, not the user-supplied one
    String safeName = UUID.randomUUID() + "." + ext;
    Path target = Path.of("/var/uploads", safeName);
    Files.copy(file.getInputStream(), target, StandardCopyOption.REPLACE_EXISTING);
    
    return ResponseEntity.ok("uploaded");
}
```

---

## CWE-1333 — Regular Expression Denial of Service (ReDoS)

**Why it matters:** A user-supplied regular expression can be crafted to cause catastrophic backtracking, consuming 100% of a CPU core for seconds or minutes. This is a denial-of-service attack that doesn't require network bandwidth — just a single request with a malicious regex pattern.

**Attack vector in Spring:**
```java
// VULNERABLE — user regex used directly in Pattern.compile
@PostMapping("/search/regex")
public ResponseEntity<?> search(@RequestParam String regex, @RequestParam String input) {
    Pattern p = Pattern.compile(regex);  // attacker sends: (((a+)+)+)+$
    Matcher m = p.matcher(input);
    return ResponseEntity.ok(m.matches());
}
```
Pattern `((((a+)+)+)+)+$` causes exponential backtracking on input `aaaaaaaaaaaaaaaaX`.

**How to prevent:**
- Avoid user-supplied regex entirely. Use literal string search when possible:
```java
// SAFE — literal search
@PostMapping("/search")
public ResponseEntity<?> search(@RequestParam String query, @RequestParam String input) {
    boolean found = input.contains(query);  // no regex, no ReDoS
    return ResponseEntity.ok(found);
}
```
- If regex is required, bound the input length and use a timeout:
```java
// SAFE — bounded input + timeout
public boolean safeMatches(String regex, String input) {
    if (input.length() > 100) return false;  // bound input
    Pattern p = Pattern.compile(regex);
    Matcher m = p.matcher(input);
    return m.find();
}
```

---

## CWE-601 — Open URL Redirection

**Why it matters:** If an application redirects to a URL provided by the user without validation, an attacker can craft a link that appears to come from the trusted domain but redirects to a phishing site. This undermines user trust and can be used for phishing attacks.

**Attack vector in Spring:**
```java
// VULNERABLE — redirect to user-supplied URL
@GetMapping("/redirect")
public String redirect(@RequestParam String url) {
    return "redirect:" + url;  // ?url=http://evil.com
}
```
User clicks `https://trusted-app.com/redirect?url=http://evil.com` — looks legitimate, but redirects to attacker's site.

**How to prevent:**
- Map logical names to allow-listed targets:
```java
// SAFE — logical name to allow-listed target
@GetMapping("/redirect")
public String redirect(@RequestParam String destination) {
    Map<String, String> ALLOWED = Map.of(
        "home", "/",
        "profile", "/profile",
        "settings", "/settings"
    );
    String target = ALLOWED.get(destination);
    if (target == null) {
        return "redirect:/";  // default to home
    }
    return "redirect:" + target;
}
```

---

## CWE-770 — Allocation of Resources Without Limits or Throttling

**Why it matters:** Without limits on memory allocation, page size, or export volume, an attacker can trigger operations that consume excessive memory or CPU, causing a denial of service. A request with `?size=1000000` can load millions of records into memory, crashing the JVM.

**Attack vector in Spring:**
```java
// VULNERABLE — unbounded export size
@GetMapping("/export")
public ResponseEntity<?> export(@RequestParam(defaultValue = "1000000") int size) {
    // Loads up to 1,000,000 records into memory
    List<Data> all = dataRepository.findAll();
    return ResponseEntity.ok(all.subList(0, Math.min(size, all.size())));
}
```
`GET /vuln4/export?size=1000000` loads all records into memory — OOM crash.

**How to prevent:**
- Cap the page size server-side:
```java
// SAFE
private static final int MAX_PAGE_SIZE = 100;

@GetMapping("/export")
public ResponseEntity<?> export(@RequestParam(defaultValue = "100") int size) {
    int capped = Math.min(size, MAX_PAGE_SIZE);
    List<Data> results = dataRepository.findAll(PageRequest.of(0, capped));
    return ResponseEntity.ok(results);
}
```

---

## CWE-650 — Improper Privilege Management (Binder Exposure / Spring4Shell Shape)

**Why it matters:** Spring's data binder can modify arbitrary properties of objects, including internal framework classes. If the binder is not restricted, an attacker can manipulate class loaders, bean factories, or other internal objects to achieve Remote Code Execution. This is the shape of the Spring4Shell (CVE-2022-22965) vulnerability.

**Attack vector in Spring:**
```java
// VULNERABLE — binder allows class.* properties
@PostMapping("/binder-probe")
public ResponseEntity<?> binderProbe(@RequestBody Map<String, String> data) {
    // Attacker sends: {"class.classLoader": "..."}
    // The binder modifies the class loader of the target object
    return ResponseEntity.ok("processed");
}
```
Even if the endpoint doesn't use the data, the binding phase itself can trigger class loader manipulation.

**How to prevent:**
- Use `@InitBinder` to disallow dangerous properties:
```java
// SAFE — disallow class.* properties
@InitBinder
public void initBinder(WebDataBinder binder) {
    binder.setDisallowedFields("class.*", "getClass.*", "classLoader.*");
}
```
- Use DTOs as the boundary — a field that doesn't exist on the DTO cannot be assigned.
