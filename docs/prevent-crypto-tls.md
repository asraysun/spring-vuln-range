# Spring Security: How to Prevent Cryptography & TLS Vulnerabilities

A practical guide to securing Spring Boot against weak cryptography, broken encryption modes, hardcoded keys, TLS misconfiguration, and PRNG flaws — covering 10 CWEs found in real Spring applications.

---

## Table of Contents

1. [Password Hashing](#1-password-hashing)
2. [Authenticated Encryption (AES-GCM)](#2-authenticated-encryption-aes-gcm)
3. [Random IV Generation](#3-random-iv-generation)
4. [Padding Oracle Prevention](#4-padding-oracle-prevention)
5. [Secure Random Number Generation](#5-secure-random-number-generation)
6. [Key Management](#6-key-management)
7. [TLS Certificate Validation](#7-tls-certificate-validation)
8. [Constant-Time Comparison](#8-constant-time-comparison)
9. [TLS Protocol Floor](#9-tls-protocol-floor)

---

## 1. Password Hashing

**CWE-916** — *Use of One-Way Hash without a Salt*  
**CWE-327** — *Use of a Broken or Risky Cryptographic Algorithm*

### The Problem

MD5 and SHA-1 are fast, single-pass cryptographic hash functions designed for data integrity, not for password storage. When used without a per-password salt, identical passwords produce identical hashes, enabling rainbow table attacks. Even with salt, MD5 and SHA-1 are too fast — an attacker can brute-force billions of guesses per second on modern hardware.

```java
// ❌ VULNERABLE — MD5 as password hash
@PostMapping("/hash")
public ResponseEntity<?> hash(@RequestBody HashRequest req) {
    String hash = DigestUtils.md5Hex(req.getPassword());  // No salt, fast, crackable
    return ResponseEntity.ok(Map.of("hash", hash));
}

// Also vulnerable — SHA-1
String hash = DigestUtils.sha1Hex(password);  // Same problems as MD5
```

`POST /vuln8/hash` with `{"password":"password123"}` returns `482c115077280399c283fd8e34e27f3c` — crackable instantly via rainbow tables.

### The Fix

Use **Argon2id** (preferred) or **BCrypt** with a tuned work factor.

```java
// ✅ BEST — Argon2id (won the Password Hashing Competition)
@Bean
PasswordEncoder passwordEncoder() {
    // memory=65536 KB (64 MB), parallelism=4, iterations=3, hashLength=32, saltLength=16
    return new Argon2PasswordEncoder(16, 32, 3, 65536, 4);
}

// ✅ ACCEPTABLE — BCrypt with cost ≥ 12
@Bean
PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(12);  // cost factor 12 → ~100ms per hash
}

// Usage — always use the encoder bean, never DigestUtils
User user = new User(username, passwordEncoder().encode(rawPassword));
boolean matches = passwordEncoder().matches(rawPassword, storedHash);
```

**Work factor tuning:**

| Algorithm | Parameter | Target |
|-----------|-----------|--------|
| Argon2id | `memory=65536`, `iterations=3`, `parallelism=4` | ~100ms on production hardware |
| BCrypt | `cost = 12` | ~100ms on production hardware |
| scrypt | `N=16384`, `r=8`, `p=1` | ~100ms on production hardware |

**How to tune:**

```bash
# Run this benchmark and adjust cost until hashing takes ~100ms
java -cp spring-security-crypto-*.jar org.springframework.security.crypto.bcrypt.BCryptBenchmark
```

**Key rules:**
- **Argon2id is the current best practice** — memory-hard, resistant to GPU and ASIC attacks
- BCrypt with cost ≥ 12 is acceptable if Argon2 is unavailable
- **Never use MD5, SHA-1, or SHA-256 for passwords** — these are for integrity checks, not secrets
- Always use Spring Security's `PasswordEncoder` beans — never `DigestUtils` directly
- Re-hash passwords on successful login if you increase the work factor

---

## 2. Authenticated Encryption (AES-GCM)

**CWE-327** — *Use of a Broken or Risky Cryptographic Algorithm*

### The Problem

ECB mode encryption preserves the structure of the plaintext — identical blocks produce identical ciphertext blocks. This leaks patterns in the data (e.g., image structures, repeated fields) and makes cryptographic analysis trivial. ECB provides confidentiality but no integrity or authenticity.

```java
// ❌ VULNERABLE — AES/ECB mode
@PostMapping("/encrypt")
public ResponseEntity<?> encrypt(@RequestBody EncryptRequest req) {
    SecretKeySpec key = new SecretKeySpec("0verview-key-2020".getBytes(), "AES");
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");  // ECB mode!
    cipher.init(Cipher.ENCRYPT_MODE, key);
    byte[] encrypted = cipher.doFinal(req.getPlain().getBytes());
    return ResponseEntity.ok(Map.of("encrypted", Base64.getEncoder().encodeToString(encrypted)));
}
```

Input `"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"` (32 A's = 2 identical 16-byte blocks) produces ciphertext with a visible repeating pattern. An attacker can identify field boundaries, detect repeated values, and perform block substitution attacks.

### The Fix

Use **authenticated encryption**: AES-GCM or ChaCha20-Poly1305. These modes provide both confidentiality and integrity.

```java
// ✅ SAFE — AES-GCM with random IV and authenticated tag
private static final String ALGORITHM = "AES/GCM/NoPadding";
private static final int GCM_TAG_LENGTH = 128;  // bits
private static final int GCM_IV_LENGTH = 12;    // bytes (96 bits)

@PostMapping("/encrypt")
public ResponseEntity<?> encrypt(@RequestBody EncryptRequest req) {
    // 1. Load key from secure storage (Vault, env, KMS) — not hardcoded
    byte[] keyBytes = loadKeyFromSecureStorage();
    SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

    // 2. Generate random IV
    byte[] iv = new byte[GCM_IV_LENGTH];
    new SecureRandom().nextBytes(iv);

    // 3. Initialize cipher
    GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
    Cipher cipher = Cipher.getInstance(ALGORITHM);
    cipher.init(Cipher.ENCRYPT_MODE, key, spec);

    // 4. Encrypt
    byte[] ciphertext = cipher.doFinal(req.getPlain().getBytes(StandardCharsets.UTF_8));

    // 5. Store IV + ciphertext + tag together (GCM appends tag automatically)
    byte[] output = new byte[iv.length + ciphertext.length];
    System.arraycopy(iv, 0, output, 0, iv.length);
    System.arraycopy(ciphertext, 0, output, iv.length, ciphertext.length);

    return ResponseEntity.ok(Map.of(
        "encrypted", Base64.getEncoder().encodeToString(output)
    ));
}

// ✅ SAFE — decrypt
@PostMapping("/decrypt")
public ResponseEntity<?> decrypt(@RequestBody DecryptRequest req) {
    byte[] keyBytes = loadKeyFromSecureStorage();
    SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

    byte[] input = Base64.getDecoder().decode(req.getEncrypted());

    // 6. Extract IV (first 12 bytes)
    byte[] iv = Arrays.copyOfRange(input, 0, GCM_IV_LENGTH);
    byte[] ciphertext = Arrays.copyOfRange(input, GCM_IV_LENGTH, input.length);

    // 7. Decrypt
    GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
    Cipher cipher = Cipher.getInstance(ALGORITHM);
    cipher.init(Cipher.DECRYPT_MODE, key, spec);

    byte[] plaintext = cipher.doFinal(ciphertext);
    return ResponseEntity.ok(Map.of("decrypted", new String(plaintext, StandardCharsets.UTF_8)));
}

// Key loading from secure storage
private byte[] loadKeyFromSecureStorage() {
    String encodedKey = System.getenv("ENCRYPTION_KEY");
    if (encodedKey == null || encodedKey.isBlank()) {
        throw new IllegalStateException("ENCRYPTION_KEY environment variable is required");
    }
    return Base64.getDecoder().decode(encodedKey);
}
```

**AES-GCM vs ChaCha20-Poly1305:**

| Feature | AES-GCM | ChaCha20-Poly1305 |
|---------|---------|-------------------|
| IV length | 96 bits (12 bytes) | 96 bits (12 bytes) |
| Tag length | 128 bits (configurable 64-128) | 128 bits |
| Hardware acceleration | Yes (AES-NI on x86) | Yes (modern CPUs) |
| Software performance | Good | Excellent |
| Key length | 128, 192, or 256 bits | 256 bits |
| Parallel encryption | Yes | No |

**Key rules:**
- Use **authenticated encryption only** — AES-GCM or ChaCha20-Poly1305
- Generate a **random 96-bit IV per record** using `SecureRandom`
- Store the IV with the ciphertext — it is not secret but must be unique
- Never use ECB mode — it leaks plaintext structure
- Never use CBC without MAC (encrypt-then-MAC is complex; prefer GCM)
- Key must come from secure storage (Vault, KMS, env var) — never hardcoded

---

## 3. Random IV Generation

**CWE-329** — *Not Using a Random IV with CBC Mode*

### The Problem

A static (hardcoded or derived) initialization vector in CBC mode means that plaintexts with identical prefixes produce ciphertexts with identical prefixes. This leaks information about the data structure and enables differential cryptanalysis — an attacker can detect when two encrypted records share common data.

```java
// ❌ VULNERABLE — static IV in CBC mode
@PostMapping("/encrypt-cbc")
public ResponseEntity<?> encryptCbc(@RequestBody EncryptRequest req) {
    SecretKeySpec key = new SecretKeySpec("0verview-key-2020".getBytes(), "AES");
    // Static IV — same for every encryption
    IvParameterSpec iv = new IvParameterSpec(new byte[16]);  // all zeros!
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    return ResponseEntity.ok(Map.of("encrypted",
        Base64.getEncoder().encodeToString(cipher.doFinal(req.getPlain().getBytes()))));
}
```

Two records with the same first 16 bytes produce ciphertexts with the same first 16 bytes. An attacker comparing encrypted database rows can identify records with matching prefixes.

### The Fix

Generate a fresh random IV for **every** encryption operation. Prefer GCM over CBC.

```java
// ✅ SAFE — random IV per record (GCM recommended)
private static final int GCM_IV_LENGTH = 12;  // 96 bits

Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
byte[] iv = new byte[GCM_IV_LENGTH];
new SecureRandom().nextBytes(iv);  // OS entropy pool
GCMParameterSpec spec = new GCMParameterSpec(128, iv);
cipher.init(Cipher.ENCRYPT_MODE, key, spec);
```

**IV generation best practices:**

```java
// ✅ SAFE — IV generation utility
public final class IvGenerator {
    private IvGenerator() {}

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static byte[] generateGcmIv() {
        byte[] iv = new byte[12];  // 96 bits for GCM
        SECURE_RANDOM.nextBytes(iv);
        return iv;
    }

    public static byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        SECURE_RANDOM.nextBytes(bytes);
        return bytes;
    }
}

// ✅ SAFE — if you must use CBC (not recommended), random IV still required
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
byte[] iv = new byte[16];  // 128 bits for CBC
new SecureRandom().nextBytes(iv);
IvParameterSpec paramSpec = new IvParameterSpec(iv);
cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);

// Store IV || ciphertext || MAC
```

**Key rules:**
- Generate a **fresh random IV for every encryption** — never reuse IVs with the same key
- Use `SecureRandom`, not `new Random()`
- Prefer GCM over CBC — GCM is not vulnerable to padding oracle attacks
- The IV is **not secret** but must be **unique** per encryption with the same key
- Store the IV alongside the ciphertext (prepend or include in the stored value)
- Never derive the IV from data that the attacker can influence (e.g., record ID, timestamp)

---

## 4. Padding Oracle Prevention

**CWE-209** — *Information Exposure Through Error Messages (Padding Oracle)*  
**CWE-347** — *Improper Verification of Cryptographic Signature*

### The Problem

When an application returns different error messages or response codes for "bad padding" vs "bad authentication tag", it creates a **padding oracle**. An attacker can exploit this oracle byte-by-byte to decrypt any ciphertext without knowing the encryption key, or forge valid ciphertexts. This completely breaks the confidentiality and integrity guarantees of encryption.

```java
// ❌ VULNERABLE — distinct error messages for different failures
@PostMapping("/decrypt")
public ResponseEntity<?> decrypt(@RequestBody DecryptRequest req) {
    try {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decrypted = cipher.doFinal(req.getCiphertext());
        return ResponseEntity.ok(Map.of("plaintext", new String(decrypted)));
    } catch (BadPaddingException e) {
        // "Bad padding" — tells attacker the padding was correct
        return ResponseEntity.status(400).body(Map.of("error", "Bad padding"));
    } catch (AEADBadTagException e) {
        // "Bad tag" — tells attacker the padding was wrong but auth failed
        return ResponseEntity.status(400).body(Map.of("error", "Bad authentication tag"));
    }
}
```

The attacker sends millions of crafted ciphertexts and observes whether the error is "bad padding" or "bad tag". This **1-bit oracle** allows full decryption of any ciphertext encrypted with the same key.

The padding oracle is essentially a "signature verifier" for the padding structure. Each oracle query recovers one byte of plaintext.

### The Fix

Use authenticated encryption (GCM) and return **one generic error** for ALL decryption failures.

```java
// ✅ SAFE — authenticated encryption (GCM) + one generic error
@PostMapping("/decrypt")
public ResponseEntity<?> decrypt(@RequestBody DecryptRequest req) {
    try {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decrypted = cipher.doFinal(req.getCiphertext());
        return ResponseEntity.ok(Map.of("plaintext", new String(decrypted, StandardCharsets.UTF_8)));
    } catch (Exception e) {
        // One generic error — no distinction between padding, tag, or any other failure
        log.error("Decryption failed", e);
        return ResponseEntity.status(400).body(Map.of("error", "Invalid payload"));
    }
}

// ✅ SAFE — if you must support legacy CBC, still use one generic error
@PostMapping("/decrypt-legacy")
public ResponseEntity<?> decryptLegacy(@RequestBody DecryptRequest req) {
    try {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decrypted = cipher.doFinal(req.getCiphertext());
        return ResponseEntity.ok(Map.of("plaintext", new String(decrypted, StandardCharsets.UTF_8)));
    } catch (Exception e) {
        // Same generic error — no oracle
        log.error("Decryption failed", e);
        return ResponseEntity.status(400).body(Map.of("error", "Invalid payload"));
    }
}
```

**Error response standardization:**

```java
// ✅ SAFE — centralized error handling for cryptographic operations
@RestControllerAdvice
public class CryptoExceptionHandler {

    @ExceptionHandler(CryptographicException.class)
    public ResponseEntity<ProblemDetail> handleCrypto(CryptographicException e) {
        log.error("Cryptographic operation failed", e);
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
            HttpStatus.BAD_REQUEST,
            "Invalid payload"
        );
        return ResponseEntity.status(400).body(problem);
    }

    @ExceptionHandler(GeneralSecurityException.class)
    public ResponseEntity<ProblemDetail> handleSecurity(GeneralSecurityException e) {
        log.error("Security operation failed", e);
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
            HttpStatus.INTERNAL_SERVER_ERROR,
            "An internal error occurred"
        );
        return ResponseEntity.status(500).body(problem);
    }
}
```

**Key rules:**
- **Always use authenticated encryption** (AES-GCM, ChaCha20-Poly1305) — tag verification is built-in
- Return **one generic error message** for ALL decryption failures
- **Any distinction between failure types is an oracle** — "bad padding" vs "bad tag" vs "wrong key"
- Log the full exception server-side with context; never expose internals to the caller
- Never expose different HTTP status codes for different failure types (400 vs 422)
- Treat every decryption failure as a potential attack signal — log and alert

---

## 5. Secure Random Number Generation

**CWE-330** — *Use of Insufficiently Random Values*  
**CWE-338** — *Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)*

### The Problem

`java.util.Random` is a Linear Congruential Generator seeded by `System.nanoTime()`. The seed is deterministic and reproducible — observing one output lets an attacker compute the seed and predict all future (and past) outputs. Tokens, codes, and IDs generated with `Random` are not random at all; they are a reproducible sequence.

```java
// ❌ VULNERABLE — tokens from java.util.Random
@GetMapping("/token/random")
public ResponseEntity<?> generateToken() {
    Random rand = new Random();  // Seeded by System.nanoTime()
    long seed = rand.nextLong();
    String token = String.valueOf(rand.nextInt(9_000_000) + 1_000_000);
    return ResponseEntity.ok(Map.of("token", token, "seedUsed", seed));
}

// ❌ VULNERABLE — predict tokens from seed
@GetMapping("/token/predict")
public ResponseEntity<?> predict(@RequestParam long seed) {
    Random rand = new Random(seed);
    String predicted = String.valueOf(rand.nextInt(9_000_000) + 1_000_000);
    return ResponseEntity.ok(Map.of("predicted", predicted));
}

// All of these are predictable:
String resetCode = String.valueOf(new Random().nextInt(1000000));
String sessionId = String.valueOf(new Random().nextLong());
String apiKey = Long.toHexString(new Random().nextLong());
```

`GET /vuln8/token/random` returns the seed used. `GET /vuln8/token/predict?seed=<seed>` returns the same token. Password reset codes, session tokens, and API keys generated this way are trivially predictable.

### The Fix

Use `SecureRandom` for every token, code, ID, salt, and key.

```java
// ✅ SAFE — SecureRandom reads from OS entropy pool
@GetMapping("/token")
public ResponseEntity<?> generateToken() {
    SecureRandom rand = new SecureRandom();
    byte[] bytes = new byte[32];  // 256 bits of entropy
    rand.nextBytes(bytes);
    String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    return ResponseEntity.ok(Map.of("token", token));
}

// ✅ SAFE — secure reset code generation
public String generateResetCode() {
    byte[] bytes = new byte[12];  // 96 bits of entropy
    new SecureRandom().nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
}

// ✅ SAFE — secure API key generation
public String generateApiKey() {
    byte[] key = new byte[32];  // 256 bits
    new SecureRandom().nextBytes(key);
    return "sk_" + Base64.getUrlEncoder().withoutPadding().encodeToString(key);
}
```

**SecureRandom vs Random:**

| Feature | `java.util.Random` | `SecureRandom` |
|---------|-------------------|----------------|
| Algorithm | Linear Congruential Generator | OS entropy pool (`/dev/urandom` on Linux, `CryptGenRandom` on Windows) |
| Seed | `System.nanoTime()` (deterministic) | Mixed entropy sources |
| Predictable | Yes — from a few outputs | No |
| Use for simulations | ✅ Yes | ⚠️ Overkill |
| Use for security tokens | ❌ Never | ✅ Always |
| Use for salts | ❌ Never | ✅ Always |
| Use for IVs | ❌ Never | ✅ Always |

**Key rules:**
- **Use `SecureRandom` for every security-sensitive value**: tokens, reset codes, API keys, session IDs, salts, IVs
- Generate **≥ 128 bits of entropy** for security tokens (16 bytes), 256 bits for keys (32 bytes)
- **Never use `new Random()` for security values** — it is a reproducible sequence
- Never expose the seed or internal state of the random generator
- On Linux, `SecureRandom` reads from `/dev/urandom` and `/dev/random`

---

## 6. Key Management

**CWE-321** — *Use of Hard-coded Cryptographic Key*  
**CWE-798** — *Use of Hard-coded Credentials (Cryptographic Key)*

### The Problem

A cryptographic key embedded in source code, configuration files, or JAR artifacts is visible to anyone with access to the repository or the compiled code. Anyone can extract the key, decrypt all encrypted data, forge authentication tokens, or impersonate the service.

```java
// ❌ VULNERABLE — hardcoded key in source code
public class DataKeyProvider {
    private static final byte[] KEY = "0verview-key-2020".getBytes();  // In source!
}

// ❌ VULNERABLE — hardcoded key in configuration with fallback
@Value("${encryption.key:0verview-key-2020}")
private byte[] key;  // Fallback in config file

// ❌ VULNERABLE — key material visible in the JAR
private static final SecretKey KEY = new SecretKeySpec(
    "0verview-key-2020".getBytes(), "AES"
);
// Anyone decompiling the JAR gets the key
```

`GET /vuln8/key-info` returns the key. Anyone can decrypt all data encrypted with this key.

### The Fix

Load keys from environment variables, Vault, or KMS. Validate key strength at startup.

```java
// ✅ SAFE — key from environment variable, no fallback
@Value("${ENCRYPTION_KEY}")
private String encodedKey;

private SecretKey key;

@PostConstruct
void init() {
    if (encodedKey == null || encodedKey.isBlank()) {
        throw new IllegalStateException("ENCRYPTION_KEY environment variable is required");
    }
    
    byte[] keyBytes = Base64.getDecoder().decode(encodedKey);
    if (keyBytes.length < 32) {
        throw new IllegalStateException("ENCRYPTION_KEY must be ≥ 256 bits (got " + (keyBytes.length * 8) + " bits)");
    }
    
    this.key = new SecretKeySpec(keyBytes, "AES");
}

// ✅ SAFE — envelope encryption with key rotation
@Component
class EnvelopeEncryptionService {
    private final Map<String, SecretKey> cache = new ConcurrentHashMap<>();
    
    // Encrypt with a data encryption key (DEK), wrap DEK with key encryption key (KEK)
    public byte[] encrypt(byte[] plaintext, String keyId) {
        // 1. Get or generate DEK
        SecretKey dek = cache.computeIfAbsent(keyId, this::loadOrGenerateDek);
        
        // 2. Encrypt plaintext with DEK using GCM
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, dek, spec);
            byte[] ciphertext = cipher.doFinal(plaintext);
            
            // 3. Return IV + ciphertext + keyId (for rotation support)
            byte[] output = new byte[iv.length + ciphertext.length + keyId.length() + 16];
            System.arraycopy(iv, 0, output, 0, iv.length);
            System.arraycopy(ciphertext, 0, output, iv.length, ciphertext.length);
            // Store keyId separately or encoded in output
            
            return output;
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Encryption failed", e);
        }
    }
}
```

**Generate a secure key:**

```bash
# Generate a 256-bit key in base64
openssl rand -base64 32

# Or in Java
java -e 'System.out.println(java.util.Base64.getEncoder().encodeToString(new byte[32]));'
# Better: use the application itself during secure setup
```

**Key storage options:**

| Storage | Security | Rotation | Use Case |
|---------|----------|----------|----------|
| Environment variable | Medium | Manual | Development, simple deployments |
| HashiCorp Vault | High | Automated | Production, multi-env |
| AWS KMS | High | Automated | AWS deployments |
| Azure Key Vault | High | Automated | Azure deployments |
| Google Cloud KMS | High | Automated | GCP deployments |
| Kubernetes Secrets | Medium | Manual | K8s clusters |

**Key rules:**
- **Never embed keys in source code, config files, or JAR artifacts**
- Load keys from environment variables, Vault, KMS, or secret volumes
- Validate key strength at startup (AES-256 = 32 bytes, HMAC-SHA256 = 32 bytes)
- Use **envelope encryption**: a KEK (stored securely) encrypts DEKs (stored with data)
- Include a **key ID** with encrypted data to support gradual key rotation
- Never commit keys to repositories
- Use `SecretHandle` or a wrapper that never reveals material in `toString()`

---

## 7. TLS Certificate Validation

**CWE-295** — *Improper Validation of Certificate Trust*

### The Problem

A trust-all `TrustManager` accepts any certificate, including self-signed, expired, or forged certificates. This completely disables TLS authentication, allowing a man-in-the-middle (MITM) attacker to intercept and modify all encrypted traffic. The attacker can read, modify, and inject data in transit.

```java
// ❌ VULNERABLE — trust-all TrustManager
@PostMapping("/fetch-https")
public ResponseEntity<?> fetch(@RequestBody FetchRequest req) {
    TrustManager[] trustAll = new TrustManager[]{
        new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            public void checkClientTrusted(X509Certificate[] certs, String authType) {}
            public void checkServerTrusted(X509Certificate[] certs, String authType) {}
        }
    };

    SSLContext ctx = SSLContext.getInstance("TLS");
    ctx.init(null, trustAll, new SecureRandom());

    // Trust-all hostname verifier
    HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);

    URL url = new URL(req.getUrl());
    HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
    conn.setSSLSocketFactory(ctx.getSocketFactory());
    // Returns the body — but certificate was never verified
    // A MITM attacker can intercept and modify all data
    return ResponseEntity.ok(Map.of(
        "body", new String(conn.getInputStream().readAllBytes()),
        "certificateVerified", false
    ));
}
```

### The Fix

Use the **default trust store** with hostname verification enabled. Never create a custom trust-all `TrustManager`.

```java
// ✅ SAFE — default trust store, hostname verification on
@PostMapping("/fetch-https")
public ResponseEntity<?> fetch(@RequestBody FetchRequest req) {
    URL url = new URL(req.getUrl());
    HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
    
    // Default trust manager validates certificates against the system trust store
    // Default hostname verifier checks that the certificate matches the hostname
    // No custom SSL context needed — use the defaults
    
    // Optional: set timeouts
    conn.setConnectTimeout(5000);
    conn.setReadTimeout(10000);
    
    int responseCode = conn.getResponseCode();
    if (responseCode != 200) {
        return ResponseEntity.status(responseCode).body("Request failed");
    }
    
    return ResponseEntity.ok(Map.of(
        "body", new String(conn.getInputStream().readAllBytes())
    ));
}

// ✅ SAFE — if you MUST use an internal CA, import it into the trust store
// Do NOT disable verification. Add the CA certificate to the trust store:
// keytool -import -trustcacerts -alias internal-ca -file internal-ca.pem -keystore $JAVA_HOME/lib/security/cacerts
```

**For Spring WebClient / RestTemplate:**

```java
// ✅ SAFE — default SSL socket factory (uses system trust store)
@Bean
public WebClient webClient() {
    return WebClient.builder()
        .baseUrl("https://api.example.com")
        // Default HttpClient uses system trust store
        .build();
}

// ✅ SAFE — if you need a custom trust store (internal CA)
@Bean
public WebClient webClientWithInternalCa() throws GeneralSecurityException, IOException {
    // Load custom trust store
    KeyStore trustStore = KeyStore.getInstance("JKS");
    try (InputStream is = new FileInputStream("/path/to/truststore.jks")) {
        trustStore.load(is, "changeit".toCharArray());
    }
    
    SSLContext sslContext = SSLContextBuilder.create()
        .loadTrustMaterial(trustStore, null)
        .build();
    
    HttpClient httpClient = HttpClient.createBuilder()
        .secure(spec -> spec.sslContext(sslContext))
        .build();
    
    return WebClient.builder()
        .baseUrl("https://internal-api.example.com")
        .clientHttpConnector(new ReactorClientHttpConnector(httpClient))
        .build();
}
```

**Key rules:**
- **Never create a custom `X509TrustManager` that accepts everything**
- Use the **default trust store** — it validates certificates against the system CA store
- **Always leave hostname verification enabled** — never use `(hostname, session) -> true`
- If an internal CA is needed, **import the CA certificate into the trust store** — do not disable verification
- Set connection and read timeouts on all outbound HTTPS calls
- Log certificate validation failures for security monitoring

---

## 8. Constant-Time Comparison

**CWE-208** — *Observable Timing Discrepancy*

### The Problem

String comparison using `equals()` returns as soon as the first mismatching character is found. An attacker can measure response times to determine how many leading characters of a secret match. A 32-byte HMAC can be recovered in approximately 800 requests (256 characters × ~3 guesses per character).

```java
// ❌ VULNERABLE — String.equals() has timing leak
public boolean verifyToken(String provided, String expected) {
    return provided.equals(expected);  // Returns early on first mismatch
}

// Response time for "abc..." vs "xyz..." is shorter than "abc..." vs "abd..."
// Attacker measures timing and recovers the correct value byte by byte
```

### The Fix

Use `MessageDigest.isEqual()` which compares **all bytes** regardless of where they differ.

```java
// ✅ SAFE — constant-time comparison for byte arrays
public boolean verifyToken(byte[] provided, byte[] expected) {
    return MessageDigest.isEqual(provided, expected);
    // Compares ALL bytes regardless of where they differ — fixed time
}

// ✅ SAFE — for strings, convert to bytes first
public boolean verifyTokenString(String provided, String expected) {
    if (provided == null || expected == null) return false;
    return MessageDigest.isEqual(
        provided.getBytes(StandardCharsets.UTF_8),
        expected.getBytes(StandardCharsets.UTF_8)
    );
}

// ✅ SAFE — Spring Security utility
import org.springframework.security.crypto.codec.Base64;

public boolean verifyMac(String providedMac, String expectedMac, byte[] data) {
    byte[] provided = Base64.decode(providedMac);
    byte[] expected = Base64.decode(expectedMac);
    byte[] computed = hmacSha256(key, data);
    return MessageDigest.isEqual(computed, expected);
}
```

**Key rules:**
- **Always use `MessageDigest.isEqual()`** for comparing secrets, tokens, MACs, or signatures
- Or use Spring Security's utilities for common patterns
- **Never use `String.equals()`, `==`, or `Objects.equals()`** for cryptographic comparisons
- Apply to all secret comparisons: JWT MAC verification, API key matching, HMAC validation, token comparison

---

## 9. TLS Protocol Floor

**CWE-326** — *Weak Encryption Strength (Insecure TLS Version)*

### The Problem

TLS 1.0 and TLS 1.1 have known cryptographic weaknesses (BEAST, POODLE, RC4 attacks) and are deprecated by RFC 8996. Allowing these versions exposes traffic to downgrade attacks where an attacker forces the connection to use a weaker protocol version with broken cryptography.

### The Fix

Restrict to TLS 1.2+ in both server configuration and outbound client code.

```yaml
# ✅ SAFE — application.yml / application-prod.yml
server:
  ssl:
    enabled-protocols:
      - TLSv1.2
      - TLSv1.3
```

```java
// ✅ SAFE — programmatic SSL configuration (outbound clients)
SSLParameters params = new SSLParameters();
params.setProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
params.setCipherSuites(new String[]{
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
});

SSLSocketFactory factory = SSLContext.getInstance("TLS").getSocketFactory();
// Apply params to HttpsURLConnection or Apache HttpClient
```

```java
// ✅ SAFE — Spring RestTemplate with TLS 1.2+
@Bean
public RestTemplate restTemplate() throws GeneralSecurityException {
    SSLContext sslContext = SSLContextBuilder.create()
        .useTLS()
        .build();
    
    Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
        .register("https", new SSLConnectionSocketFactory(sslContext, 
            new String[]{"TLSv1.2", "TLSv1.3"}, 
            null, 
            SSLConnectionSocketFactory.getDefaultHostnameVerifier()))
        .build();
    
    CloseableHttpClient httpClient = HttpClients.custom()
        .setConnectionManager(new PoolingHttpClientConnectionManager(socketFactoryRegistry))
        .build();
    
    return new RestTemplateBuilder()
        .requestFactory(() -> new HttpComponentsClientHttpRequestFactory(httpClient))
        .build();
}
```

**TLS version comparison:**

| Version | Status | Weaknesses | Recommendation |
|---------|--------|------------|----------------|
| TLS 1.0 | ❌ Deprecated (RFC 8996) | BEAST, POODLE, RC4 | Never use |
| TLS 1.1 | ❌ Deprecated (RFC 8996) | BEAST, CBC vulnerabilities | Never use |
| TLS 1.2 | ✅ Secure | None critical | Minimum acceptable |
| TLS 1.3 | ✅ Best | None | Preferred |

**Recommended cipher suites (TLS 1.2):**

```
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
```

**Key rules:**
- **TLS 1.2 is the minimum acceptable version**
- **TLS 1.3 is preferred** — stronger cryptography, faster handshakes
- **Never enable TLS 1.0 or 1.1 in production**
- Set `enabled-protocols` in `application.yml` for the embedded server
- Configure outbound HTTP clients explicitly with TLS 1.2+
- Use only AEAD cipher suites (GCM, ChaCha20-Poly1305) — disable CBC suites

---

## Summary Checklist

| # | Control | CWE | Priority |
|---|---------|-----|----------|
| 1 | Argon2id or BCrypt ≥ 12 for passwords | CWE-916, CWE-327 | CRITICAL |
| 2 | AES-GCM with random IV (not ECB) | CWE-327 | CRITICAL |
| 3 | `SecureRandom` for every IV | CWE-329 | CRITICAL |
| 4 | One generic error for all decryption failures | CWE-209, CWE-347 | CRITICAL |
| 5 | `SecureRandom` for all security tokens | CWE-330, CWE-338 | CRITICAL |
| 6 | Keys from Vault/env, validate ≥ 256 bits | CWE-321, CWE-798 | CRITICAL |
| 7 | Default trust store, no trust-all TrustManager | CWE-295 | CRITICAL |
| 8 | `MessageDigest.isEqual()` for all secret comparisons | CWE-208 | HIGH |
| 9 | TLS 1.2+ minimum | CWE-326 | HIGH |

---

## Detection & Review Heuristics

| Check | Command / Pattern |
|-------|-------------------|
| Weak password hashing | `grep -r 'DigestUtils\|md5Hex\|sha1Hex'` → should use `PasswordEncoder` |
| ECB mode | `grep -r 'AES/ECB'` → should use `AES/GCM` |
| Static IV | `grep -r 'new byte\[16\].*IvParameterSpec\|new byte\[12\].*GCM'` → should use `SecureRandom.nextBytes()` |
| Padding oracle | `grep -r 'BadPaddingException\|AEADBadTagException'` → should catch generic `Exception` |
| Weak Random | `grep -r 'new Random()'` near `token\|code\|secret\|salt` → should use `SecureRandom` |
| Hardcoded keys | `grep -r 'static.*KEY\|KEY = "'` → should load from env/Vault |
| Trust-all TM | `grep -r 'X509TrustManager'` → should not override `checkServerTrusted` |
| Non-constant-time | `grep -r '\.equals(.*secret\|\.equals(.*token\|\.equals(.*mac'` → should use `MessageDigest.isEqual()` |
| TLS versions | `grep -r 'TLSv1\.0\|TLSv1\.1'` → should only allow TLSv1.2, TLSv1.3 |

---

## References

- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP TLS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/TLS_Cheat_Sheet.html)
- [OWASP Padding Oracle Attack](https://cheatsheetseries.owasp.org/cheatsheets/Padding_Oracle_Attack_Cheat_Sheet.html)
- [NIST SP 800-38D: GCM Recommendation](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- [RFC 8996: Deprecating TLS 1.0 and TLS 1.1](https://datatracker.ietf.org/doc/rfc8996/)
- [PHC: Password Hashing Competition](https://www.password-hashing.net/)
- [OWASP Java Encoder](https://owasp.org/www-project-java-encoder/)
