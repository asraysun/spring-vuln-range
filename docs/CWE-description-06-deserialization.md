# CWE Reference — §06 Deserialization, XML and Polymorphic JSON

CWEs extracted from `docs/06-deserialization.md` with developer-focused comments.

---

## CWE-502 — Deserialization of Untrusted Data

**Why it matters:** This is the most critical deserialization vulnerability. When an application deserializes attacker-controlled bytes, the deserialization process instantiates classes and calls their methods (constructors, setters, `hashCode`, `equals`, `readObject`). An attacker can choose which classes are instantiated and which methods are called — this is the fundamental primitive for Remote Code Execution (RCE). By chaining these method calls through library classes (commons-collections, spring-beans, jackson-databind), an attacker achieves arbitrary code execution.

**Attack vector in Spring:**
```java
// VULNERABLE — Java serialization without any filter
@PostMapping("/session/import")
public ResponseEntity<?> importSession(@RequestBody Map<String, String> body) {
    String payload = body.get("base64");
    byte[] bytes = Base64.getDecoder().decode(payload);
    try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
        Object restored = in.readObject();  // NO filter, NO limits
        // Attacker sends bytes containing: HashMap<Probe, "cart">
        // Probe.<init>() runs -> side-effect recorded
        // Probe.setNote() runs -> side-effect recorded
        // Probe.hashCode() runs -> side-effect recorded
        // In a real app: TemplatesImpl.newTransformer() -> RCE
        return ResponseEntity.ok(Map.of("restoredClass", restored.getClass().getName()));
    }
}

// VULNERABLE — Jackson polymorphic typing with lax validator
// Attacker sends: {"@class":"java.util.HashMap","note":"typed-by-payload"}
// The @class field tells Jackson to instantiate HashMap (or any class)
// In a real app: @class points to a gadget class -> RCE

// VULNERABLE — XStream with AnyTypePermission
// Attacker sends XML: <java.util.HashMap>...</java.util.HashMap>
// XStream reads root element as class name -> instantiates HashMap
// Nested elements instantiate Probe, String, etc.
```
The Python PoC generates raw Java serialization bytes **without any Java code** — just `struct.pack` and byte manipulation. The server has no way to distinguish them from a legitimate serialized stream.

**How to prevent:**
```java
// SAFE — ObjectInputFilter allow-list + resource limits
private static final ObjectInputFilter ALLOW_LIST = info -> {
    if (info.serialClass() == null) {
        // Resource limits
        if (info.depth() > 8) return ObjectInputFilter.Status.REJECTED;
        if (info.arrayLength() > 256) return ObjectInputFilter.Status.REJECTED;
        if (info.streamBytes() > 64 * 1024) return ObjectInputFilter.Status.REJECTED;
        if (info.references() > 1_000) return ObjectInputFilter.Status.REJECTED;
        return ObjectInputFilter.Status.UNDECIDED;
    }
    // Type allow-list
    Class<?> allowed = info.serialClass();
    if (allowed == SessionSnapshot.class || allowed == String.class
            || allowed == Long.class || allowed == Integer.class) {
        return ObjectInputFilter.Status.ALLOWED;
    }
    return ObjectInputFilter.Status.REJECTED;  // everything else
};

// Apply the filter
try (ObjectInputStream in = new ObjectInputStream(bytes)) {
    in.setObjectInputFilter(ALLOW_LIST);
    Object restored = in.readObject();
}

// BEST — Do not deserialize object graphs from the network at all.
// Use JSON with a concrete DTO, Protobuf, or Avro.
@PostMapping("/session/import")
public ResponseEntity<?> importSession(@Valid @RequestBody SessionSnapshot snapshot) {
    // Jackson binds to SessionSnapshot.class — no polymorphic typing,
    // no class chosen by the attacker, no gadget chains
    return ResponseEntity.ok(Map.of("restored", snapshot));
}
```
- Upgrade vulnerable libraries (commons-collections 3.x → 4.x, fastjson → newer version).
- Drop `enableDefaultTyping`/`activateDefaultTyping` from Jackson.
- Never enable fastjson `autoType`.
- Use `-Djdk.serialFilter=...` as a JVM-wide backstop.

---

## CWE-400 — Uncontrolled Resource Consumption (Deserialization Depth/Size)

**Why it matters:** Even without a full gadget chain, an attacker can cause denial of service through uncontrolled resource consumption during deserialization. A deeply nested object graph exhausts the call stack (StackOverflowError), an enormous array exhausts heap memory, or a stream with billions of references causes the deserializer to loop indefinitely.

**Attack vector in Spring:**
```java
// VULNERABLE — no depth, array, or size limits on the stream
try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
    Object restored = in.readObject();  // No ObjectInputFilter
    // Attacker sends:
    // 1. Depth bomb: nested objects 10,000 levels deep -> StackOverflowError
    // 2. Array bomb: int[2_147_483_647] -> OutOfMemoryError
    // 3. Reference bomb: 1 billion references to same object -> CPU exhaustion
}
```

**How to prevent:**
```java
// SAFE — resource limits in ObjectInputFilter
private static final int MAX_DEPTH = 8;
private static final int MAX_ARRAY_LENGTH = 256;
private static final int MAX_SERIALIZED_BYTES = 64 * 1024;
private static final int MAX_REFS = 1_000;

private static final ObjectInputFilter FILTER = info -> {
    if (info.serialClass() == null) {
        if (info.depth() > MAX_DEPTH) return ObjectInputFilter.Status.REJECTED;
        if (info.arrayLength() > MAX_ARRAY_LENGTH) return ObjectInputFilter.Status.REJECTED;
        if (info.streamBytes() > MAX_SERIALIZED_BYTES) return ObjectInputFilter.Status.REJECTED;
        if (info.references() > MAX_REFS) return ObjectInputFilter.Status.REJECTED;
        return ObjectInputFilter.Status.UNDECIDED;
    }
    // ... type allow-list ...
};
```
- Pre-check payload size before deserialization: reject anything over 64 KB.
- Treat every rejection as an attack signal — log and alert.

---

## CWE-611 — Improper Restriction of XML External Entity Reference (XXE)

**Why it matters:** When an XML parser resolves external entities, an attacker can read arbitrary files from the server's filesystem (`file:///etc/passwd`), disclose internal data, or turn the parser into an SSRF origin (`http://internal-service/admin`). XXE can also cause denial of service through "Billion Laughs" entity expansion.

**Attack vector in Spring:**
```java
// VULNERABLE — DocumentBuilderFactory with default (unsafe) configuration
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
    // Returns the content of the marker file
    return ResponseEntity.ok(Map.of("text", document.getDocumentElement().getTextContent()));
}
```
Payload reads `/tmp/vulnrange-m06-marker.txt` and returns its content. An `http://` entity turns the parser into an outbound request to internal services (SSRF).

**How to prevent:**
```java
// SAFE — hardened XML parser configuration
static DocumentBuilderFactory hardenedFactory() throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    factory.setXIncludeAware(false);
    factory.setExpandEntityReferences(false);
    return factory;
}
```
- `disallow-doctype-decl=true` is the single most effective fix — no DTD means no entities.
- If DTDs are required, disable external general and parameter entities.
- Never reuse a default `DocumentBuilderFactory` — always configure it explicitly.

---

## CWE-918 — Server-Side Request Forgery (SSRF via XXE)

**Why it matters:** When an XML parser resolves an `http://` external entity, it makes an outbound HTTP request on behalf of the server. The attacker can use the server's network position to reach internal services that are not exposed to the internet (metadata services, internal admin panels, other microservices). This is SSRF disguised as XXE.

**Attack vector in Spring:**
```java
// VULNERABLE — same XXE parser can be used as SSRF
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
    // Returns IAM credentials running on the server
}
```
The parser becomes an outbound request origin. An attacker can scan internal networks, access cloud metadata services, or probe internal microservices.

**How to prevent:**
- Same fix as CWE-611: disable DTDs and external entities.
- Additionally, if external entities are unavoidable, use an egress firewall or network policies to block outbound requests from the application server.
- Never use a default XML parser — always configure it explicitly with security features enabled.
