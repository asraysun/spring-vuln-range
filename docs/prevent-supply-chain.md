# Spring Security: How to Prevent Supply Chain & Dependency Vulnerabilities

A practical guide to securing Spring Boot against vulnerable dependencies, unpatched libraries, deserialization gadget chains, and build integrity failures — covering 4 CWEs found in real Spring applications.

---

## Table of Contents

1. [Vulnerable Third-Party Components](#1-vulnerable-third-party-components)
2. [Complete Library Upgrades](#2-complete-library-upgrades)
3. [Deserialization Gadget Chain Prevention](#3-deserialization-gadget-chain-prevention)
4. [Unbounded Parsing Protection](#4-unbounded-parsing-protection)

---

## 1. Vulnerable Third-Party Components

**CWE-1104** — *Use of Unmaintained or Vulnerable Third-Party Component*

### The Problem

A vulnerable library shipped on the classpath and never flagged by scanners means the application carries known attack surfaces that have been publicly disclosed. The vulnerability is not in the application code — it is in a dependency that the developer did not write. This is the supply chain attack vector: an attacker does not need to find a bug in your code when a vulnerable library is already doing the work for them.

```xml
<!-- ❌ VULNERABLE — parent pom.xml pins vulnerable versions -->
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

### The Fix

Pin every dependency through the BOM. Run OWASP dependency-check with a build gate. Nightly rescans catch new CVEs in old dependencies.

```xml
<!-- ✅ SAFE — baseline-upgrades profile replaces vulnerable libraries -->
<profiles>
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
</profiles>

<!-- ✅ SAFE — OWASP dependency-check gate in CI -->
<build>
    <plugins>
        <plugin>
            <groupId>org.owasp</groupId>
            <artifactId>dependency-check-maven</artifactId>
            <version>10.0.4</version>
            <executions>
                <execution>
                    <phase>verify</phase>
                    <goals>
                        <goal>check</goal>
                    </goals>
                </execution>
            </executions>
            <configuration>
                <failBuildOnCVSS>7</failBuildOnCVSS>
                <suppressionFile>tools/owasp/suppressions.xml</suppressionFile>
            </configuration>
        </plugin>
    </plugins>
</build>
```

**CI wiring:**

```yaml
# ✅ SAFE — GitHub Actions example
# .github/workflows/security.yml
name: SCA Scan
on:
  pull_request:
  push:
    branches: [main]
jobs:
  dependency-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-java@v4
        with:
          java-version: '21'
          distribution: 'temurin'
      - name: OWASP Dependency Check
        run: ./mvnw -B -P sca org.owasp:dependency-check-maven:check -DfailBuildOnCVSS=7
      - name: Trivy FS
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'
```

**Key rules:**
- **Pin every dependency** through the BOM (Bill of Materials), no range versions (`[1.0,)`)
- `dependency-check-maven` with `failBuildOnCVSS` 7, bound to a CI profile
- **Nightly rescan** with Trivy, Snyk, or Anchore so new CVEs in old dependencies resurface
- **Transitive dependencies are your CVEs** — scan everything you did not write
- Versions belong in `dependencyManagement`, not in individual module POMs
- Review every `<artifactId>` added to `pom.xml` as a **security-relevant change**, not housekeeping

---

## 2. Complete Library Upgrades

**CWE-1395** — *Supply Chain Dependency on Weak or Unverified Component*

### The Problem

CWE-1395 covers the broader supply chain risk: a vulnerable library is not just about the direct dependency, but about the entire dependency graph and the upgrade process. An "upgrade" that moves one artifact but leaves the gadget family on the classpath is an incomplete fix. A suppression file with `exclude all of org.apache.*` is a mute button, not a review. An unreviewed upgrade without testing is a regression waiting to happen.

```xml
<!-- ❌ VULNERABLE — "upgrade" that is incomplete -->
<!-- Old: commons-collections 3.2.1 -->
<!-- "Upgrade": commons-collections 3.2.2 (fixes CVE-2015-6420 but gadget family still present) -->
<!-- The real fix: commons-collections4 4.4 (completely different package, no gadgets) -->

<!-- ❌ VULNERABLE — suppression used as a mute button -->
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

### The Fix

Upgrade the library, do not filter around it. Suppressions must have: why, who, and an expiry date.

```xml
<!-- ✅ SAFE — upgrade the library, do not filter around it -->
<!-- commons-collections 3.x → commons-collections4 4.4 (different package: org.apache.commons.collections4) -->
<!-- fastjson 1.2.x → replaced entirely (use Jackson or Gson with concrete types) -->

<!-- ✅ SAFE — suppression with why, who, and expiry -->
<suppressions>
    <suppress>
        <notes>False positive: Jackson polymorphic typing is disabled in production</notes>
        <packageUrl regex="true">^pkg:maven/com\.fasterxml\.jackson\..*</packageUrl>
        <vulnerabilityName>CVE-2022-42003</vulnerabilityName>
        <justification>activateDefaultTyping is not called in any production profile</justification>
        <owner>security-team</owner>
        <expires>2026-06-01</expires>  <!-- Expired entries fail the build -->
    </suppress>
</suppressions>
```

**Upgrade decision matrix:**

| Vulnerable Library | Incomplete "Fix" | Complete Fix |
|-------------------|------------------|--------------|
| `commons-collections` 3.x | Bump to 3.2.2 | Replace with `commons-collections4` 4.4 |
| `fastjson` 1.2.x | Disable `autoType` | Replace with Jackson/Gson + concrete DTOs |
| `jackson-databind` (polymorphic typing) | Suppress CVE | Drop `activateDefaultTyping`, use `SimpleEvaluationContext` |
| `log4j` 2.14.x | Suppress CVE | Upgrade to `log4j` 2.17.1+ |
| `spring-framework` (Spring4Shell) | Suppress CVE | Upgrade to `6.0.9+` or `5.3.25+` |

**Suppression lifecycle:**

```xml
<!-- ❌ NEVER use blanket suppressions -->
<suppress>
    <notes>suppress all apache libs</notes>
    <packageUrl regex="true">^pkg:maven/org\.apache\..*</packageUrl>
</suppress>

<!-- ✅ ALWAYS use targeted suppressions with metadata -->
<suppress>
    <notes>CVE-202X-XXXX: false positive — library is not used, only transitively included by X</notes>
    <packageUrl regex="true">^pkg:maven/com\.example\.vuln-lib@1\.0\.0</packageUrl>
    <vulnerabilityName>CVE-202X-XXXX</vulnerabilityName>
    <justification>Not in classpath — excluded by scope/test or managed dependency</justification>
    <owner>security-team</owner>
    <expires>2026-06-01</expires>
</suppress>
```

**Key rules:**
- **Upgrade the library**, do not filter around it
- `ObjectInputFilter` is a **compensating control** — the upgrade is the fix
- Suppressions must have: **why, who, and an expiry date**
- An expired suppression entry **should fail the build**
- Never use blanket suppressions (`exclude all of org.apache.*`)
- Test upgrades in CI before merging — an unreviewed upgrade is a regression waiting to happen
- Review every `<artifactId>` added to `pom.xml` as security-relevant

---

## 3. Deserialization Gadget Chain Prevention

**CWE-502** — *Deserialization of Untrusted Data (Gadget Chains via Dependencies)*

### The Problem

CWE-502 in the context of supply chain refers to vulnerable libraries that turn a parser or serializer into an object factory. When a library on the classpath has known gadget chains (commons-collections `InvokerTransformer`, fastjson `autoType`, Jackson `activateDefaultTyping`), an attacker can craft payloads that instantiate arbitrary classes and execute arbitrary code — without writing any Java code themselves.

```java
// ❌ VULNERABLE — commons-collections 3.2.1 gadget chain
// Attacker sends: {"method":"toUpperCase","target":"deserialization-primitive"}
// The server round-trips through ObjectInputStream with no filter
// Commons-collections InvokerTransformer gadget chain executes:
//   "deserialization-primitive".toUpperCase()  → "DESERIALIZATION-PRIMITIVE"
// In a real app: TemplatesImpl.newTransformer() → RCE

// ❌ VULNERABLE — fastjson autoType
@PostMapping("/parse-json")
public ResponseEntity<?> parseJson(@RequestBody String json) {
    // fastjson with autoTypeSupport=true
    JSONObject obj = (JSONObject) JSON.parse(json);
    // Attacker sends: {"@type":"com.example.AutotypeProbe","note":"chosen-by-payload"}
    // fastjson instantiates AutotypeProbe and calls setNote()
    // In a real app: @type points to a gadget class → RCE
}

// ❌ VULNERABLE — Jackson with activateDefaultTyping
ObjectMapper mapper = new ObjectMapper();
mapper.activateDefaultTyping(...);  // Turns JSON parser into object factory
```

The `commons-collections` 3.2.1 gadget chain is the ysoserial payload carrier. The `fastjson` 1.2.24 `autoType` CVE range (CVE-2022-25845) allows class instantiation from JSON. Both are in the dependency inventory returned by `GET /vuln13/dependency-inventory`.

### The Fix

Remove the parser that names classes. Upgrade vulnerable libraries. Apply `ObjectInputFilter` as a compensating control.

```java
// ✅ SAFE — remove fastjson autoType, use Jackson with concrete DTO
public record OrderDocument(
    @NotBlank String subscriptionId,
    @Size(max = 1000) String payload
) {}

@PostMapping("/parse-json")
public ResponseEntity<?> parseJson(@Valid @RequestBody OrderDocument doc) {
    // Jackson binds to OrderDocument.class — no @type, no polymorphic typing,
    // unknown properties rejected (FAIL_ON_UNKNOWN_PROPERTIES = true)
    return ResponseEntity.ok(Map.of("processed", doc.subscriptionId()));
}

// ✅ SAFE — ObjectInputFilter allow-list (compensating control)
private static final ObjectInputFilter FILTER = info -> {
    // Resource limits
    if (info.serialClass() == null) {
        if (info.depth() > 8) return ObjectInputFilter.Status.REJECTED;
        if (info.arrayLength() > 256) return ObjectInputFilter.Status.REJECTED;
        if (info.streamBytes() > 64 * 1024) return ObjectInputFilter.Status.REJECTED;
        return ObjectInputFilter.Status.UNDECIDED;
    }
    
    // Type allow-list — only known-safe classes
    Class<?> clazz = info.serialClass();
    if (clazz == OrderDocument.class || clazz == String.class
            || clazz == Long.class || clazz == Integer.class) {
        return ObjectInputFilter.Status.ALLOWED;
    }
    
    // Reject everything else
    return ObjectInputFilter.Status.REJECTED;
};

try (ObjectInputStream in = new ObjectInputStream(bytes)) {
    in.setObjectInputFilter(FILTER);
    Object restored = in.readObject();
}
```

**Gadget family reference:**

| Library | Gadget | Mechanism | Fix |
|---------|--------|-----------|-----|
| `commons-collections` 3.x | `InvokerTransformer` | Method invocation via reflection | Upgrade to `commons-collections4` 4.4 |
| `fastjson` 1.2.x | `autoType` | `@type` field triggers class instantiation | Replace with Jackson/Gson |
| `jackson-databind` | `activateDefaultTyping` | `@class` field triggers polymorphic deserialization | Drop `activateDefaultTyping`, use `SimpleEvaluationContext` |
| `spring-beans` | `BeanWrapper` | Property path traversal | Use `SimpleEvaluationContext` |
| `groovy` | `MetaClass` | Method invocation via GroovyShell | Remove dependency or use `@ASTTest` restrictions |

**Key rules:**
- **Remove the parser that names classes** — fastjson `autoType`, Jackson `activateDefaultTyping`
- Bind to a **concrete type** (DTO), reject unknown properties
- Upgrade the library (`commons-collections` 3.x → `commons-collections4` 4.4)
- `ObjectInputFilter` is a **compensating control** — the upgrade is the fix
- If binary deserialization is unavoidable, apply `ObjectInputFilter` with both **type allow-list** and **resource limits**

---

## 4. Unbounded Parsing Protection

**CWE-770** — *Allocation of Resources Without Limits (Unbounded Parsing)*

### The Problem

Without a size limit before parsing attacker-controlled bytes, a deserialization or JSON parsing endpoint can be used to exhaust server resources. An attacker sends a payload that decodes to a large object graph, causing heap exhaustion, GC pressure, or CPU saturation. This is a denial-of-service attack through unbounded resource allocation during parsing.

```java
// ❌ VULNERABLE — no size limit before decoding and parsing
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

### The Fix

Cap payload size **before** parsing. Apply depth/array/reference limits in `ObjectInputFilter`.

```java
// ✅ SAFE — size cap before parsing + filter
private static final int MAX_PAYLOAD_BYTES = 64 * 1024;  // 64 KB

@PostMapping("/deserialize")
public ResponseEntity<?> deserialize(@RequestBody Map<String, String> body) {
    String payload = body.get("base64");
    byte[] bytes = Base64.getDecoder().decode(payload);

    // 1. Pre-check payload size
    if (bytes.length > MAX_PAYLOAD_BYTES) {
        log.warn("Rejected oversized deserialization: {} bytes", bytes.length);
        return ResponseEntity.status(413).body("Payload too large");
    }

    // 2. Apply filter with depth/array/byte limits
    ObjectInputFilter filter = info -> {
        if (info.serialClass() == null) {
            if (info.depth() > 8) return ObjectInputFilter.Status.REJECTED;
            if (info.arrayLength() > 256) return ObjectInputFilter.Status.REJECTED;
            if (info.streamBytes() > MAX_PAYLOAD_BYTES) return ObjectInputFilter.Status.REJECTED;
            if (info.references() > 1_000) return ObjectInputFilter.Status.REJECTED;
            return ObjectInputFilter.Status.UNDECIDED;
        }
        
        // Type allow-list
        Class<?> clazz = info.serialClass();
        if (clazz == OrderDocument.class || clazz == String.class) {
            return ObjectInputFilter.Status.ALLOWED;
        }
        return ObjectInputFilter.Status.REJECTED;
    };

    try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
        in.setObjectInputFilter(filter);
        Object restored = in.readObject();
        return ResponseEntity.ok(Map.of("restored", restored.getClass().getName()));
    } catch (ObjectInputFilter.RejectedException e) {
        log.error("Deserialization rejected by filter: {}", e.getMessage());
        return ResponseEntity.status(400).body("Invalid payload");
    }
}
```

**Resource limit reference:**

| Limit | Value | Purpose |
|-------|-------|---------|
| Max depth | 8 | Prevents `StackOverflowError` from nested objects |
| Max array length | 256 | Prevents `OutOfMemoryError` from large arrays |
| Max stream bytes | 64 KB | Rejects oversized payloads before full deserialization |
| Max references | 1,000 | Prevents CPU exhaustion from reference loops |

**Key rules:**
- **`MAX_PAYLOAD_BYTES` (64 KB)** → reject with `413` before parsing
- Set **depth** (8), **array length** (256), and **reference** (1,000) limits in the filter
- Every rejection is an **attack signal** — log and alert
- Pre-check payload size **before** creating `ObjectInputStream`
- For JSON parsing, set `JsonParser` size limits (e.g., `JsonParser.setMaxNumberOfChars(100000)`)
- Monitor heap usage during parsing — set GC logging to detect parsing-related pressure

---

## Summary Checklist

| # | Control | CWE | Priority |
|---|---------|-----|----------|
| 1 | Pin deps via BOM, `dependency-check` gate (`failBuildOnCVSS=7`) | CWE-1104 | CRITICAL |
| 2 | Complete upgrades, not blanket suppressions | CWE-1395 | CRITICAL |
| 3 | Remove autoType/activateDefaultTyping, upgrade libraries | CWE-502 | CRITICAL |
| 4 | `ObjectInputFilter` with type allow-list + resource limits | CWE-502 | HIGH |
| 5 | `MAX_PAYLOAD_BYTES` cap before parsing | CWE-770 | HIGH |

---

## Detection & Review Heuristics

| Check | Command / Pattern |
|-------|-------------------|
| Vulnerable dependencies | `./mvnw dependency:tree` → should have no known CVEs |
| Missing SCA gate | `grep -r 'dependency-check-maven'` in `pom.xml` → should exist with `failBuildOnCVSS` |
| Blanket suppressions | `grep -r 'exclude all' \| 'regex.*\*'` in `suppressions.xml` → should not exist |
| `activateDefaultTyping` | `grep -r 'activateDefaultTyping' \| 'enableDefaultTyping'` → should not exist |
| `setAutoTypeSupport` | `grep -r 'setAutoTypeSupport(true)'` → should not exist |
| Version in module POM | `grep -r '<version>' --include='pom.xml'` in module dirs → should only be in `dependencyManagement` |
| Unreviewed artifact addition | `git diff -U0 -- 'pom.xml' \| grep -n '<artifactId>'` → review every new artifact as security-relevant |
| Container image scan | `trivy fs --severity CRITICAL,HIGH --exit-code 1` → should pass nightly |

---

## References

- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
- [Trivy - Open Source Container Scanner](https://github.com/aquasecurity/trivy)
- [Snyk Open Source](https://snyk.io/product/snyk-open-source/)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [CVE-2022-25845 (fastjson autoType)](https://nvd.nist.gov/vuln/detail/CVE-2022-25845)
- [CVE-2015-7501 (commons-collections)](https://nvd.nist.gov/vuln/detail/CVE-2015-7501)
- [Spring Boot Dependency Management](https://docs.spring.io/spring-boot/reference/using/maven.html#using.maven.dependency-management)
