# Spring Security: How to Prevent Deserialization, XML & Polymorphic JSON Vulnerabilities

A practical guide to securing Spring Boot against deserialization attacks, XXE, polymorphic JSON, and resource exhaustion — covering 4 CWEs found in real Spring applications.

---

## Table of Contents

1. [Never Deserialize Untrusted Data](#1-never-deserialize-untrusted-data)
2. [ObjectInputFilter Limits](#2-objectinputfilter-limits)
3. [XXE Prevention](#3-xxe-prevention)
4. [SSRF via XXE Prevention](#4-ssrf-via-xxe-prevention)

---

## 1. Never Deserialize Untrusted Data

**CWE-502** — *Deserialization of Untrusted Data*

### The Problem

This is the most critical deserialization vulnerability. When an application deserializes attacker-controlled bytes, the deserialization process instantiates classes and calls their methods (constructors, setters, `hashCode`, `equals`, `readObject`). An attacker can choose which classes are instantiated and which methods are called — this is the fundamental primitive for Remote Code Execution (RCE). By chaining these method calls through library classes (commons-collections, spring-beans, jackson-databind), an attacker achieves arbitrary code execution.

```java
// ❌ VULNERABLE — Java serialization without any filter
@PostMapping("/session/import")
public ResponseEntity<?> importSession(@RequestBody Map<String, String> body) {
    String payload = body.get("base64");
    byte[] bytes = Base64.getDecoder().decode(payload);
    try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
        Object restored = in.readObject();  // NO filter, NO limits
        // Attacker sends bytes containing: HashMap<Probe, "cart">
        // Probe.<init>() runs → side-effect recorded
        // Probe.setNote() runs → side-effect recorded
        // Probe.hashCode() runs → side-effect recorded
        // In a real app: TemplatesImpl.newTransformer() → RCE
        return ResponseEntity.ok(Map.of("restoredClass", restored.getClass().getName()));
    }
}

// ❌ VULNERABLE — Jackson polymorphic typing with lax validator
// Attacker sends: {"@class":"java.util.HashMap","note":"typed-by-payload"}
// The @class field tells Jackson to instantiate HashMap (or any class)
// In a real app: @class points to a gadget class → RCE

// ❌ VULNERABLE — XStream with AnyTypePermission
// Attacker sends XML: <java.util.HashMap>...</java.util.HashMap>
// XStream reads root element as class name → instantiates HashMap
```

The Python PoC generates raw Java serialization bytes **without any Java code** — just `struct.pack` and byte manipulation. The server has no way to distinguish them from a legitimate serialized stream.

### The Fix

**Best:** Do not deserialize object graphs from the network at all. Use JSON with a concrete DTO, Protobuf, or Avro.

```java
// ✅ BEST — concrete DTO, no polymorphism, no class chosen by attacker
public record SessionSnapshot(
    @NotBlank String userId,
    @Size(max = 1000) String sessionData,
    Instant createdAt
) {}

@PostMapping("/session/import")
public ResponseEntity<?> importSession(@Valid @RequestBody SessionSnapshot snapshot) {
    // Jackson binds to SessionSnapshot.class — no polymorphic typing,
    // no class chosen by the attacker, no gadget chains
    sessionService.restore(snapshot);
    return ResponseEntity.ok(Map.of("restored", snapshot.userId()));
}
```

**If binary deserialization is unavoidable (legacy system):**

```java
// ✅ COMPENSATING — ObjectInputFilter allow-list + resource limits
private static final ObjectInputFilter ALLOW_LIST = info -> {
    // Resource limits (checked before type allow-list)
    if (info.serialClass() == null) {
        if (info.depth() > 8) return ObjectInputFilter.Status.REJECTED;
        if (info.arrayLength() > 256) return ObjectInputFilter.Status.REJECTED;
        if (info.streamBytes() > 64 * 1024) return ObjectInputFilter.Status.REJECTED;
        if (info.references() > 1_000) return ObjectInputFilter.Status.REJECTED;
        return ObjectInputFilter.Status.UNDECIDED;
    }
    
    // Type allow-list — only known-safe classes
    Class<?> allowed = info.serialClass();
    if (allowed == SessionSnapshot.class || allowed == String.class
            || allowed == Long.class || allowed == Integer.class
            || allowed == Instant.class || allowed == Boolean.class) {
        return ObjectInputFilter.Status.ALLOWED;
    }
    
    // Reject everything else
    return ObjectInputFilter.Status.REJECTED;
};

@PostMapping("/session/import")
public ResponseEntity<?> importSession(@RequestBody Map<String, String> body) {
    String payload = body.get("base64");
    byte[] bytes = Base64.getDecoder().decode(payload);
    
    // Pre-check payload size before deserialization
    if (bytes.length > 64 * 1024) {
        log.warn("Rejected oversized deserialization attempt: {} bytes", bytes.length);
        return ResponseEntity.status(413).body("Payload too large");
    }
    
    try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
        in.setObjectInputFilter(ALLOW_LIST);
        Object restored = in.readObject();
        return ResponseEntity.ok(Map.of("restoredClass", restored.getClass().getName()));
    } catch (ObjectInputFilter.RejectedException e) {
        log.error("Deserialization rejected by filter: {}", e.getMessage());
        return ResponseEntity.status(400).body("Invalid payload");
    } catch (IOException | ClassNotFoundException e) {
        log.error("Deserialization failed", e);
        return ResponseEntity.status(500).body("Deserialization error");
    }
}
```

**Key rules:**
- **Never deserialize object graphs from the network** — use JSON with concrete DTOs, Protobuf, or Avro
- If binary deserialization is unavoidable, apply `ObjectInputFilter` with both **type allow-list** and **resource limits**
- Treat every filter rejection as an attack signal — log and alert
- Upgrade vulnerable libraries (commons-collections 3.x → 4.x, fastjson → newer version)
- Drop `enableDefaultTyping` / `activateDefaultTyping` from Jackson
- Never enable fastjson `autoType`
- Use `-Djdk.serialFilter=...` as a JVM-wide backstop

---

## 2. ObjectInputFilter Limits

**CWE-400** — *Uncontrolled Resource Consumption (Deserialization Depth/Size)*

### The Problem

Even without a full gadget chain, an attacker can cause denial of service through uncontrolled resource consumption during deserialization. A deeply nested object graph exhausts the call stack (`StackOverflowError`), an enormous array exhausts heap memory, or a stream with billions of references causes the deserializer to loop indefinitely.

```java
// ❌ VULNERABLE — no depth, array, or size limits on the stream
try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
    Object restored = in.readObject();  // No ObjectInputFilter
    // Attacker sends:
    // 1. Depth bomb: nested objects 10,000 levels deep → StackOverflowError
    // 2. Array bomb: int[2_147_483_647] → OutOfMemoryError
    // 3. Reference bomb: 1 billion references to same object → CPU exhaustion
}
```

### The Fix

Apply explicit resource limits in `ObjectInputFilter`.

```java
// ✅ SAFE — resource limits + type allow-list
public final class DeserializationFilter {
    private static final int MAX_DEPTH = 8;
    private static final int MAX_ARRAY_LENGTH = 256;
    private static final int MAX_SERIALIZED_BYTES = 64 * 1024;  // 64 KB
    private static final int MAX_REFERENCES = 1_000;

    public static ObjectInputFilter createAllowList(Set<Class<?>> allowedTypes) {
        return info -> {
            // 1. Resource limits (checked before type allow-list)
            if (info.serialClass() == null) {
                if (info.depth() > MAX_DEPTH) {
                    log.warn("Deserialization rejected: depth {} exceeds max {}", info.depth(), MAX_DEPTH);
                    return ObjectInputFilter.Status.REJECTED;
                }
                if (info.arrayLength() > MAX_ARRAY_LENGTH) {
                    log.warn("Deserialization rejected: array length {} exceeds max {}", info.arrayLength(), MAX_ARRAY_LENGTH);
                    return ObjectInputFilter.Status.REJECTED;
                }
                if (info.streamBytes() > MAX_SERIALIZED_BYTES) {
                    log.warn("Deserialization rejected: stream size {} exceeds max {}", info.streamBytes(), MAX_SERIALIZED_BYTES);
                    return ObjectInputFilter.Status.REJECTED;
                }
                if (info.references() > MAX_REFERENCES) {
                    log.warn("Deserialization rejected: references {} exceeds max {}", info.references(), MAX_REFERENCES);
                    return ObjectInputFilter.Status.REJECTED;
                }
                return ObjectInputFilter.Status.UNDECIDED;
            }
            
            // 2. Type allow-list
            Class<?> clazz = info.serialClass();
            String className = clazz.getName();
            
            // Allow explicitly registered types
            if (allowedTypes.contains(clazz)) {
                return ObjectInputFilter.Status.ALLOWED;
            }
            
            // Optionally allow primitive wrappers and collections
            if (clazz.isPrimitive() || Number.class.isAssignableFrom(clazz)
                    || String.class.isAssignableFrom(clazz)
                    || List.class.isAssignableFrom(clazz)
                    || Map.class.isAssignableFrom(clazz)) {
                return ObjectInputFilter.Status.ALLOWED;
            }
            
            // Reject everything else
            log.warn("Deserialization rejected: class {} not in allow-list", className);
            return ObjectInputFilter.Status.REJECTED;
        };
    }
}

// Usage
private static final Set<Class<?>> ALLOWED_TYPES = Set.of(
    SessionSnapshot.class,
    String.class,
    Long.class,
    Integer.class,
    Instant.class
);

try (ObjectInputStream in = new ObjectInputStream(bytes)) {
    in.setObjectInputFilter(DeserializationFilter.createAllowList(ALLOWED_TYPES));
    Object restored = in.readObject();
}
```

**JVM-wide backstop via system property:**

```bash
# Set in application startup (e.g., Docker entrypoint, systemd EnvironmentFile)
-Djdk.serialFilter=maxbytes=65536;maxarray=256;depth=8;*.SessionSnapshot;*.String;*.Long
```

```yaml
# application.yml — pass to JVM via environment
# JAVA_OPTS: -Djdk.serialFilter=maxbytes=65536;maxarray=256;depth=8;*.SessionSnapshot;*.String
```

**Resource limit reference:**

| Limit | Value | Impact |
|-------|-------|--------|
| Max depth | 8 | Prevents StackOverflowError from nested objects |
| Max array length | 256 | Prevents OutOfMemoryError from large arrays |
| Max stream bytes | 64 KB | Rejects oversized payloads before full deserialization |
| Max references | 1,000 | Prevents CPU exhaustion from reference loops |

**Key rules:**
- Always set **all four** limits (depth, array, bytes, references) — missing any one leaves a DoS vector
- Pre-check payload size before creating `ObjectInputStream` — reject immediately if too large
- Treat every rejection as an attack signal — log with context and alert
- Use JVM-wide `-Djdk.serialFilter` as a backstop for anything the code review missed

---

## 3. XXE Prevention

**CWE-611** — *Improper Restriction of XML External Entity Reference*

### The Problem

When an XML parser resolves external entities, an attacker can read arbitrary files from the server's filesystem (`file:///etc/passwd`), disclose internal data, or turn the parser into an SSRF origin (`http://internal-service/admin`). XXE can also cause denial of service through "Billion Laughs" entity expansion.

```java
// ❌ VULNERABLE — DocumentBuilderFactory with default (unsafe) configuration
@PostMapping("/xml/xxe")
public ResponseEntity<?> xxe(@RequestBody String xml) {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    // No hardening flags — uses default configuration which resolves external entities
    Document document = factory.newDocumentBuilder()
        .parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    
    // Attacker sends:
    String xxePayload = """
        <?xml version="1.0"?>
        <!DOCTYPE declaration [
          <!ENTITY xxe SYSTEM "file:///tmp/vulnrange-m06-marker.txt">
        ]>
        <declaration>&xxe;</declaration>
        """;
    // Returns the content of the marker file — arbitrary file read
    return ResponseEntity.ok(Map.of("text", document.getDocumentElement().getTextContent()));
}

// ❌ VULNERABLE — SAXParser with default settings
SAXParser parser = SAXParserFactory.newInstance().newSAXParser();
parser.parse(new ByteArrayInputStream(xmlBytes), handler);
// External entities resolved by default

// ❌ VULNERABLE — DOMParser with default settings
DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
Document doc = builder.parse(new InputSource(new StringReader(xml)));
// External entities resolved by default
```

Payload reads `/tmp/vulnrange-m06-marker.txt` and returns its content. An `http://` entity turns the parser into an outbound request to internal services (SSRF).

### The Fix

Hardened XML parser configuration. `disallow-doctype-decl=true` is the single most effective fix — no DTD means no entities.

```java
// ✅ SAFE — hardened XML parser configuration
public final class XmlParserFactory {
    private XmlParserFactory() {}

    public static DocumentBuilderFactory createHardenedFactory() throws ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        
        // 1. Disable DOCTYPE entirely (strongest protection — no DTD, no entities)
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        
        // 2. Disable external entity resolution (defense-in-depth if DTDs are somehow enabled)
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        
        // 3. Disable external DTD loading
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        
        // 4. Disable XInclude
        factory.setXIncludeAware(false);
        
        // 5. Disable entity reference expansion
        factory.setExpandEntityReferences(false);
        
        return factory;
    }
}

// Usage
@PostMapping("/xml/parse")
public ResponseEntity<?> parseXml(@RequestBody String xml) {
    try {
        DocumentBuilderFactory factory = XmlParserFactory.createHardenedFactory();
        Document document = factory.newDocumentBuilder()
            .parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        
        String result = document.getDocumentElement().getTextContent();
        return ResponseEntity.ok(Map.of("content", result));
        
    } catch (ParserConfigurationException e) {
        // Should never happen — these features are always supported
        throw new IllegalStateException("XML parser not configured correctly", e);
    } catch (SAXException | IOException e) {
        log.error("XML parsing failed", e);
        return ResponseEntity.status(400).body("Invalid XML");
    }
}

// ✅ SAFE — for SAX parsing
public void parseSax(String xml) throws Exception {
    SAXParserFactory factory = SAXParserFactory.newInstance();
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    
    SAXParser parser = factory.newSAXParser();
    parser.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)), handler);
}
```

**If you must parse untrusted XML, use a schema-validated JSON/XML library:**

```java
// ✅ SAFE — use Jackson XML with no external entity resolution
 ObjectMapper xmlMapper = XmlMapper.builder()
     .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
     .build();

// Deserializes to a concrete DTO — no entity resolution, no class instantiation
public record XmlData(String name, String value) {}

@PostMapping("/xml/dto")
public ResponseEntity<?> parseXmlDto(@RequestBody XmlData data) {
    return ResponseEntity.ok(Map.of("name", data.name(), "value", data.value()));
}
```

**Key rules:**
- **`disallow-doctype-decl=true` is the single most effective fix** — no DTD means no entities, period
- If DTDs are required (rare), disable external general and parameter entities explicitly
- **Never reuse a default `DocumentBuilderFactory`** — always configure it explicitly with security features enabled
- Set `XIncludeAware(false)` and `setExpandEntityReferences(false)` as defense-in-depth
- For new projects, prefer JSON over XML — XXE is an XML-specific attack surface

---

## 4. SSRF via XXE Prevention

**CWE-918** — *Server-Side Request Forgery (SSRF via XXE)*

### The Problem

When an XML parser resolves an `http://` external entity, it makes an outbound HTTP request on behalf of the server. The attacker can use the server's network position to reach internal services that are not exposed to the internet (metadata services, internal admin panels, other microservices). This is SSRF disguised as XXE.

```java
// ❌ VULNERABLE — same XXE parser used as SSRF origin
@PostMapping("/xml/xxe")
public ResponseEntity<?> xxe(@RequestBody String xml) {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    // No hardening — resolves http:// entities
    Document document = factory.newDocumentBuilder()
        .parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));

    // Attacker sends:
    String ssrfPayload = """
        <?xml version="1.0"?>
        <!DOCTYPE declaration [
          <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials">
        ]>
        <declaration>&xxe;</declaration>
        """;
    // The server makes an HTTP request to the AWS metadata service
    // Returns IAM credentials running on the server → cloud compromise
}

// Other SSRF targets via XXE:
// - http://169.254.169.254/ (AWS/GCP/Azure cloud metadata)
// - http://localhost:8080/admin (internal admin panel)
// - http://internal-service:9090/api (microservice API)
// - gopher://internal-smtp:25 (protocol exploitation)
```

The parser becomes an outbound request origin. An attacker can scan internal networks, access cloud metadata services, or probe internal microservices.

### The Fix

The same fix as CWE-611: disable DTDs and external entities. Additionally, apply network-level controls.

```java
// ✅ SAFE — same XXE hardening prevents SSRF via XXE
// (Same as CWE-611 fix — disallow-doctype-decl blocks all external entity resolution)

// ✅ ADDITIONAL — network-level controls
// In docker-compose.yml or Kubernetes NetworkPolicy:
# networkpolicy.yaml
# apiVersion: networking.k8s.io/v1
# kind: NetworkPolicy
# metadata:
#   name: app-no-egress
# spec:
#   podSelector:
#     matchLabels:
#       app: spring-app
#   policyTypes:
#   - Egress
#   egress:
#   - to:
#     - podSelector:
#         matchLabels:
#           app: postgres
#     ports:
#     - port: 5432
#   - to:
#     - ipBlock:
#         cidr: 0.0.0.0/0
#         except:
#         - 169.254.169.254/32    # Block cloud metadata
#         - 10.0.0.0/8            # Block internal ranges
#         - 172.16.0.0/12
#         - 192.168.0.0/16
#     ports:
#     - port: 443                 # Only HTTPS to known external services
```

**Cloud metadata protection:**

```java
// ✅ SAFE — validate URLs before making HTTP requests (for legitimate outbound calls)
public boolean isSafeUrl(URI uri) {
    String host = uri.getHost();
    
    if (host == null) return false;
    
    // Block cloud metadata endpoints
    if (host.equals("169.254.169.254") || host.equals("100.100.100.200")) {
        return false;  // AWS / Azure metadata
    }
    
    // Block internal/private IP ranges
    try {
        InetAddress address = InetAddress.getByName(host);
        if (address.isLoopbackAddress() || address.isAnyLocalAddress()
                || address.isLinkLocalAddress() || address.isSiteLocalAddress()) {
            return false;  // 10.x, 172.16-31.x, 192.168.x, 127.x
        }
    } catch (UnknownHostException e) {
        return false;  // Invalid host
    }
    
    // Block dangerous protocols
    String scheme = uri.getScheme();
    if (scheme == null || (!scheme.equals("http") && !scheme.equals("https"))) {
        return false;  // Allow only http/https, block gopher, file, ftp, etc.
    }
    
    return true;
}

// Usage for legitimate outbound HTTP
@GetMapping("/proxy/fetch")
public ResponseEntity<?> fetchUrl(@RequestParam String url) {
    try {
        URI uri = new URI(url);
        if (!isSafeUrl(uri)) {
            log.warn("Blocked unsafe URL: {}", url);
            return ResponseEntity.status(403).body("URL not allowed");
        }
        
        // Make the request through a configured HTTP client (with timeout)
        HttpResponse<String> response = HttpClient.newHttpClient()
            .send(HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(5))
                .build(),
                BodyHandlers.ofString());
        
        return ResponseEntity.status(response.statusCode())
            .body(response.body());
            
    } catch (URISyntaxException | InterruptedException | IOException e) {
        log.error("URL fetch failed for: {}", url, e);
        return ResponseEntity.status(500).body("Fetch failed");
    }
}
```

**Key rules:**
- **Same fix as XXE:** `disallow-doctype-decl=true` blocks all external entity resolution, including `http://` SSRF vectors
- **Network-level controls:** Use Kubernetes NetworkPolicy or Docker network policies to restrict outbound traffic
- **Block cloud metadata:** Always block `169.254.169.254` (AWS) and `100.100.100.200` (Azure) at the network level
- **Validate outbound URLs:** If your app makes legitimate outbound HTTP requests, validate the target URL against an allow-list of domains and block private/internal ranges
- **Block dangerous protocols:** Only allow `http` and `https` — block `gopher`, `file`, `ftp`, `jar`, `dict`, `ldap`, `tftp`

---

## Summary Checklist

| # | Control | CWE | Priority |
|---|---------|-----|----------|
| 1 | Concrete DTOs, never deserialize object graphs | CWE-502 | CRITICAL |
| 2 | `ObjectInputFilter` with type allow-list + resource limits | CWE-502, CWE-400 | CRITICAL |
| 3 | `disallow-doctype-decl=true` for all XML parsers | CWE-611 | CRITICAL |
| 4 | Network-level egress filtering + URL validation | CWE-611, CWE-918 | HIGH |

---

## Detection & Review Heuristics

| Check | Command / Pattern |
|-------|-------------------|
| Java deserialization | `grep -r 'readObject(' \| 'ObjectInputStream'` → should have `setObjectInputFilter` |
| Jackson default typing | `grep -r 'activateDefaultTyping\|enableDefaultTyping'` → should not exist |
| XStream without permissions | `grep -r 'XStream('` → should use `processAnnotations` + `NoTypePermission` |
| Default XML parser | `grep -r 'DocumentBuilderFactory.newInstance()'` → should configure features explicitly |
| `disallow-doctype-decl` missing | `grep -r 'disallow-doctype-decl'` → should exist in all XML parsing code |
| JVM serial filter | Check Dockerfile / systemd for `-Djdk.serialFilter=...` |

---

## References

- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [OWASP XXE Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [Java ObjectInputFilter API](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/io/ObjectInputFilter.html)
- [CVE-2015-7501 (Apache Commons Collections)](https://nvd.nist.gov/vuln/detail/CVE-2015-7501)
- [Cloud Security Alliance: Cloud Metadata Threats](https://cloudsecurityalliance.org/artifacts/cloud-metadata-service-threats/)
