# CWE Reference — §13 Dependencies and Supply Chain

CWEs extracted from `docs/13-supply-chain.md` with developer-focused comments.

---

## CWE-1104 — Use of Unmaintained or Vulnerable Third-Party Component

**Why it matters:** A vulnerable library shipped on the classpath and never flagged by scanners means the application carries known attack surfaces that have been publicly disclosed. The vulnerability is not in the application code — it is in a dependency that the developer did not write. This is the supply chain attack vector: an attacker does not need to find a bug in your code when a vulnerable library is already doing the work for them.

**Attack vector in Spring:**
```xml
<!-- VULNERABLE — parent pom.xml pins vulnerable versions -->
<properties>
    <vulnerable.commons-collections.version>3.2.1</vulnerable.commons-collections.version>
    <vulnerable.fastjson.version>1.2.24</vulnerable.fastjson.version>
</properties>

<dependencies>
    <!-- commons-collections 3.2.1 — ysoserial gadget carrier -->
    <dependency>
        <groupId>commons-collections</groupId>
        <artifactId>commons-collections</artifactId>
        <version>${vulnerable.commons-collections.version}</version>
    </dependency>
    
    <!-- fastjson 1.2.24 — autoType CVE range -->
    <dependency>
        <groupId>com.alibaba</groupId>
        <artifactId>fastjson</artifactId>
        <version>${vulnerable.fastjson.version}</version>
    </dependency>
</dependencies>
```
`GET /vuln13/dependency-inventory` returns the actual dependency versions shipped in the JAR. Both `commons-collections` 3.2.1 and `fastjson` 1.2.24 are known gadget carriers. A scanner that reports this module as clean is not looking.

**How to prevent:**
```xml
<!-- SAFE — baseline-upgrades profile replaces vulnerable libraries -->
<profile>
    <id>baseline-upgrades</id>
    <dependencies>
        <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-collections4</artifactId>
            <version>4.4</version>  <!-- No ysoserial gadgets -->
        </dependency>
        <!-- fastjson 1.2.x is replaced entirely, not configured -->
    </dependencies>
</profile>

<!-- SAFE — OWASP dependency-check gate in CI -->
<plugin>
    <groupId>org.owasp</groupId>
    <artifactId>dependency-check-maven</artifactId>
    <version>10.0.4</version>
    <configuration>
        <failBuildOnCVSS>7</failBuildOnCVSS>
    </configuration>
</plugin>
```
- Pin every dependency through the BOM, no range versions.
- `dependency-check-maven` with `failBuildOnCVSS` 7, bound to a CI profile.
- Nightly rescan with Trivy or Snyk so new CVEs in old dependencies resurface.
- Transitive dependencies are your CVEs — scan everything you did not write.

---

## CWE-1395 — Supply Chain Dependency on Weak or Unverified Component

**Why it matters:** CWE-1395 covers the broader supply chain risk: a vulnerable library is not just about the direct dependency, but about the entire dependency graph and the upgrade process. An "upgrade" that moves one artifact but leaves the gadget family on the classpath is an incomplete fix. A suppression file with `exclude all of org.apache.*` is a mute button, not a review. An unreviewed upgrade without testing is a regression waiting to happen.

**Attack vector in Spring:**
```xml
<!-- VULNERABLE — "upgrade" that is incomplete -->
<!-- Old: commons-collections 3.2.1 -->
<!-- "Upgrade": commons-collections 3.2.2 (fixes CVE-2015-6420 but gadget family still present) -->
<!-- The real fix: commons-collections4 4.4 (completely different package, no gadgets) -->

<!-- VULNERABLE — suppression used as a mute button -->
<!-- tools/owasp/suppressions.xml -->
<suppressions>
    <suppress>
        <notes>exclude all of org.apache.*</notes>  <!-- MUTE BUTTON -->
        <packageUrl regex="true">^pkg:maven/org\.apache\..*</packageUrl>
    </suppress>
</suppressions>
<!-- Scanner reports green, but vulnerable libraries are still on the classpath -->
```
An "upgrade" from commons-collections 3.2.1 to 3.2.2 fixes one CVE but leaves the entire gadget family on the classpath. The real fix is `commons-collections4` 4.4 — a completely different artifact.

**How to prevent:**
```xml
<!-- SAFE — upgrade the library, do not filter around it -->
<!-- commons-collections 3.x → commons-collections4 4.4 (different package: org.apache.commons.collections4) -->
<!-- fastjson 1.2.x → replaced entirely (use Jackson or Gson with concrete types) -->

<!-- SAFE — suppression with why, who, and expiry -->
<suppressions>
    <suppress>
        <notes>False positive: Jackson polymorphic typing is disabled in production</notes>
        <packageUrl regex="true">^pkg:maven/com\.fasterxml\.jackson\..*</packageUrl>
        <vulnerabilityName>CVE-2022-42003</vulnerabilityName>
        <justification>activateDefaultTyping is not called in any production profile</justification>
        <owner>security-team</owner>
        <expires>2026-06-01</expires>  <!-- Expired entry fails the build -->
    </suppress>
</suppressions>
```
- Upgrade the library, do not filter around it. `ObjectInputFilter` is a compensating control for formats you cannot remove today.
- Suppressions must have: why, who, and an expiry date. An expired entry should fail the build.
- Review every `<artifactId>` added to `pom.xml` as a security-relevant change.

---

## CWE-502 — Deserialization of Untrusted Data (Gadget Chains via Dependencies)

**Why it matters:** CWE-502 in the context of supply chain refers to vulnerable libraries that turn a parser or serializer into an object factory. When a library on the classpath has known gadget chains (commons-collections `InvokerTransformer`, fastjson `autoType`, Jackson `activateDefaultTyping`), an attacker can craft payloads that instantiate arbitrary classes and execute arbitrary code — without writing any Java code themselves. The vulnerability is in the dependency, not in the application code.

**Attack vector in Spring:**
```java
// VULNERABLE — commons-collections 3.2.1 gadget chain
// Attacker sends JSON with method and target:
// {"method":"toUpperCase","target":"deserialization-primitive"}
// The server round-trips through ObjectInputStream with no filter
// Commons-collections InvokerTransformer gadget chain executes:
//   "deserialization-primitive".toUpperCase()  → "DESERIALIZATION-PRIMITIVE"
// In a real app: TemplatesImpl.newTransformer() → RCE

// VULNERABLE — fastjson autoType
@PostMapping("/parse-json")
public ResponseEntity<?> parseJson(@RequestBody String json) {
    // fastjson with autoTypeSupport=true
    JSONObject obj = (JSONObject) JSON.parse(json);
    // Attacker sends: {"@type":"com.example.AutotypeProbe","note":"chosen-by-payload"}
    // fastjson instantiates AutotypeProbe and calls setNote()
    // In a real app: @type points to a gadget class → RCE
}

// VULNERABLE — no size limit before parsing
@PostMapping("/gadget/round-trip")
public ResponseEntity<?> gadgetRoundTrip(@RequestBody Map<String, String> body) {
    String payload = body.get("base64");
    byte[] bytes = Base64.getDecoder().decode(payload);
    try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
        Object restored = in.readObject();  // No ObjectInputFilter, no size cap
        // Attacker sends: 64 KB of nested gadget objects → heap exhaustion
    }
}
```
The `commons-collections` 3.2.1 gadget chain is the ysoserial payload carrier. The `fastjson` 1.2.24 `autoType` CVE range (CVE-2022-25845) allows class instantiation from JSON. Both are in the dependency inventory returned by `GET /vuln13/dependency-inventory`.

**How to prevent:**
```java
// SAFE — ObjectInputFilter allow-list + size cap (compensating control)
private static final ObjectInputFilter FILTER = info -> {
    if (info.serialClass() == null) {
        if (info.depth() > 8) return ObjectInputFilter.Status.REJECTED;
        if (info.streamBytes() > 64 * 1024) return ObjectInputFilter.Status.REJECTED;
        return ObjectInputFilter.Status.UNDECIDED;
    }
    // Allow only the types you actually deserialize
    if (info.serialClass() == OrderDocument.class || info.serialClass() == String.class) {
        return ObjectInputFilter.Status.ALLOWED;
    }
    return ObjectInputFilter.Status.REJECTED;  // Default deny
};

// SAFE — remove the parser that names classes
// Don't use fastjson with autoType. Don't use Jackson with activateDefaultTyping.
// Bind to a concrete type:
@PostMapping("/parse-json")
public ResponseEntity<?> parseJson(@Valid @RequestBody OrderDocument doc) {
    // Jackson binds to OrderDocument.class — no @type, no polymorphic typing,
    // unknown properties rejected
    return ResponseEntity.ok(Map.of("processed", doc.getSubscriptionId()));
}
```
- Remove the parser that names classes (fastjson `autoType`, Jackson default typing).
- Upgrade the library (commons-collections 3.x → commons-collections4 4.4).
- `ObjectInputFilter` is a compensating control — the upgrade is the fix.
- Bind to a concrete type, reject unknown properties.

---

## CWE-770 — Allocation of Resources Without Limits (Unbounded Parsing)

**Why it matters:** Without a size limit before parsing attacker-controlled bytes, a deserialization or JSON parsing endpoint can be used to exhaust server resources. An attacker sends a payload that decodes to a large object graph, causing heap exhaustion, GC pressure, or CPU saturation. This is a denial-of-service attack through unbounded resource allocation during parsing.

**Attack vector in Spring:**
```java
// VULNERABLE — no size limit before decoding and parsing
@PostMapping("/gadget/round-trip")
public ResponseEntity<?> gadgetRoundTrip(@RequestBody Map<String, String> body) {
    String payload = body.get("base64");
    byte[] bytes = Base64.getDecoder().decode(payload);  // No size check
    try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
        Object restored = in.readObject();  // No depth/array/byte limits
        // Attacker sends: base64-encoded 64 MB object graph → OOM
        // Or: deeply nested 10,000-level object graph → StackOverflowError
    }
}
```
No `MAX_PAYLOAD_BYTES` cap means the attacker controls how much memory the server allocates during parsing.

**How to prevent:**
```java
// SAFE — size cap before parsing
private static final int MAX_PAYLOAD_BYTES = 64 * 1024;  // 64 KB

@PostMapping("/deserialize")
public ResponseEntity<?> deserialize(@RequestBody Map<String, String> body) {
    String payload = body.get("base64");
    byte[] bytes = Base64.getDecoder().decode(payload);
    
    if (bytes.length > MAX_PAYLOAD_BYTES) {
        return ResponseEntity.status(413).body("Payload too large");
    }
    
    try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
        in.setObjectInputFilter(info -> {
            if (info.serialClass() == null) {
                if (info.streamBytes() > MAX_PAYLOAD_BYTES) return ObjectInputFilter.Status.REJECTED;
                if (info.depth() > 8) return ObjectInputFilter.Status.REJECTED;
                return ObjectInputFilter.Status.UNDECIDED;
            }
            // ... type allow-list ...
        });
        Object restored = in.readObject();
        return ResponseEntity.ok(Map.of("restored", restored.getClass().getName()));
    }
}
```
- `MAX_PAYLOAD_BYTES` (64 KB) → reject with 413 before parsing.
- Depth limit (8), array length limit (256), reference limit (1,000).
- Every rejection is an attack signal — log and alert.
