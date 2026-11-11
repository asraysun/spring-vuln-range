# CWE Reference — §08 Cryptography and TLS

CWEs extracted from `docs/08-crypto-tls.md` with developer-focused comments.

---

## CWE-916 — Use of One-Way Hash without a Salt (MD5/SHA-1 for Passwords)

**Why it matters:** MD5 and SHA-1 are fast, single-pass cryptographic hash functions designed for data integrity, not for password storage. When used without a per-password salt, identical passwords produce identical hashes, enabling rainbow table attacks. Even with salt, MD5 and SHA-1 are too fast — an attacker can brute-force billions of guesses per second on modern hardware.

**Attack vector in Spring:**
```java
// VULNERABLE — MD5 as password hash
@PostMapping("/hash")
public ResponseEntity<?> hash(@RequestBody HashRequest req) {
    String hash = DigestUtils.md5Hex(req.getPassword());  // No salt, fast, crackable
    return ResponseEntity.ok(Map.of("hash", hash));
}

// Also vulnerable — SHA-1
String hash = DigestUtils.sha1Hex(password);  // Same problems as MD5
```
`POST /vuln8/hash` with `{"password":"password123"}` returns `482c115077280399c283fd8e34e27f3c` — crackable instantly via rainbow tables.

**How to prevent:**
```java
// SAFE — Argon2id (preferred) or BCrypt with tuned cost
@Bean
PasswordEncoder passwordEncoder() {
    return new Argon2PasswordEncoder(16, 32, 1, 65536, 4);  // memory, parallelism, iterations
    // Or: return new BCryptPasswordEncoder(12);  // cost factor 12
}
```
- Argon2id won the Password Hashing Competition and is the current best practice.
- BCrypt with cost ≥ 12 is acceptable if Argon2 is unavailable.
- Never use MD5/SHA-1/SHA-256 for passwords — these are for integrity checks, not secrets.

---

## CWE-327 — Use of a Broken or Risky Cryptographic Algorithm

**Why it matters:** ECB mode encryption preserves the structure of the plaintext — identical blocks produce identical ciphertext blocks. This leaks patterns in the data (e.g., image structures, repeated fields) and makes cryptographic analysis trivial. ECB provides confidentiality but no integrity or authenticity.

**Attack vector in Spring:**
```java
// VULNERABLE — AES/ECB mode
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

**How to prevent:**
```java
// SAFE — AES-GCM with random IV
@PostMapping("/encrypt")
public ResponseEntity<?> encrypt(@RequestBody EncryptRequest req) {
    // Key from Vault/env, not hardcoded
    SecretKeySpec key = new SecretKeySpec(loadKeyFromVault(), "AES");
    
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    GCMParameterSpec spec = new GCMParameterSpec(128, generateRandomIv(12));  // 96-bit IV
    cipher.init(Cipher.ENCRYPT_MODE, key, spec);
    byte[] encrypted = cipher.doFinal(req.getPlain().getBytes());
    
    // Store IV with ciphertext: IV || ciphertext || tag
    return ResponseEntity.ok(Map.of("encrypted", Base64.getEncoder().encodeToString(
        spec.getIV()  // 12 bytes IV prepended
    )));
}
```
- Use authenticated encryption: AES-GCM or ChaCha20-Poly1305.
- Generate a random 96-bit IV (GCM) or 12-byte nonce (ChaCha20) per record.
- Store the IV with the ciphertext — it is not secret, but must be unique.

---

## CWE-329 — Not Using a Random IV with CBC Mode

**Why it matters:** A static (hardcoded or derived) initialization vector in CBC mode means that plaintexts with identical prefixes produce ciphertexts with identical prefixes. This leaks information about the data structure and enables differential cryptanalysis — an attacker can detect when two encrypted records share common data.

**Attack vector in Spring:**
```java
// VULNERABLE — static IV in CBC mode
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

**How to prevent:**
```java
// SAFE — random IV per record
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
byte[] iv = new byte[12];  // 96 bits for GCM
new SecureRandom().nextBytes(iv);
GCMParameterSpec spec = new GCMParameterSpec(128, iv);
cipher.init(Cipher.ENCRYPT_MODE, key, spec);
```
- Generate a fresh random IV for every encryption operation.
- Use `SecureRandom`, not `new Random()`.
- Prefer GCM over CBC — GCM is not vulnerable to padding oracle attacks (CWE-209).

---

## CWE-209 — Information Exposure Through Error Messages (Padding Oracle)

**Why it matters:** When an application returns different error messages or response codes for "bad padding" vs "bad authentication tag", it creates a padding oracle. An attacker can exploit this oracle byte-by-byte to decrypt any ciphertext without knowing the encryption key, or forge valid ciphertexts. This completely breaks the confidentiality and integrity guarantees of encryption.

**Attack vector in Spring:**
```java
// VULNERABLE — distinct error messages for different failures
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
The attacker sends millions of crafted ciphertexts and observes whether the error is "bad padding" or "bad tag". This 1-bit oracle allows full decryption of any ciphertext encrypted with the same key.

**How to prevent:**
```java
// SAFE — one generic error for all failures
@PostMapping("/decrypt")
public ResponseEntity<?> decrypt(@RequestBody DecryptRequest req) {
    try {
        // Use authenticated encryption (GCM) — tag verification is built-in
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decrypted = cipher.doFinal(req.getCiphertext());
        return ResponseEntity.ok(Map.of("plaintext", new String(decrypted)));
    } catch (Exception e) {
        // One generic error — no distinction between padding, tag, or any other failure
        log.error("Decryption failed", e);
        return ResponseEntity.status(400).body(Map.of("error", "Invalid payload"));
    }
}
```
- Always use authenticated encryption (AES-GCM, ChaCha20-Poly1305).
- Return one generic error message for ALL decryption failures.
- Any distinction between failure types is an oracle.

---

## CWE-347 — Improper Verification of Cryptographic Signature (Padding Oracle Variant)

**Why it matters:** CWE-347 in the context of encryption refers to any mechanism that allows an attacker to verify whether a cryptographic operation succeeded partially or fully. A padding oracle is a form of cryptographic signature verification where the "signature" is the server's response to malformed ciphertext.

**Attack vector in Spring:**
```java
// VULNERABLE — the server verifies padding and reveals the result
// This is CWE-347: the padding check acts as a signature verifier
// Attacker crafts ciphertext blocks and uses the server's response
// to verify guesses about the plaintext
```
The padding oracle is essentially a "signature verifier" for the padding structure. Each oracle query is one byte of plaintext recovered.

**How to prevent:**
- Same as CWE-209: use authenticated encryption and return generic errors.
- Never expose the result of cryptographic verification steps to the caller.

---

## CWE-330 — Use of Insufficiently Random Values

**Why it matters:** `java.util.Random` is a Linear Congruential Generator seeded by `System.nanoTime()`. The seed is deterministic and reproducible — observing one output lets an attacker compute the seed and predict all future (and past) outputs. Tokens, codes, and IDs generated with `Random` are not random at all; they are a reproducible sequence.

**Attack vector in Spring:**
```java
// VULNERABLE — tokens from java.util.Random
@GetMapping("/token/random")
public ResponseEntity<?> generateToken() {
    Random rand = new Random();  // Seeded by System.nanoTime()
    long seed = rand.nextLong();
    String token = String.valueOf(rand.nextInt(9_000_000) + 1_000_000);
    return ResponseEntity.ok(Map.of("token", token, "seedUsed", seed));
}

// VULNERABLE — predict tokens from seed
@GetMapping("/token/predict")
public ResponseEntity<?> predict(@RequestParam long seed) {
    Random rand = new Random(seed);
    String predicted = String.valueOf(rand.nextInt(9_000_000) + 1_000_000);
    return ResponseEntity.ok(Map.of("predicted", predicted));
}
```
`GET /vuln8/token/random` returns the seed used. `GET /vuln8/token/predict?seed=<seed>` returns the same token. Password reset codes, session tokens, and API keys generated this way are trivially predictable.

**How to prevent:**
```java
// SAFE — SecureRandom reads from OS entropy pool
@GetMapping("/token")
public ResponseEntity<?> generateToken() {
    SecureRandom rand = new SecureRandom();
    byte[] bytes = new byte[16];  // 128 bits of entropy
    rand.nextBytes(bytes);
    String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    return ResponseEntity.ok(Map.of("token", token));
}
```
- Use `SecureRandom` for every token, code, ID, salt, and key.
- Generate ≥ 128 bits of entropy for security tokens.
- Never expose the seed or internal state of the random generator.

---

## CWE-338 — Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)

**Why it matters:** CWE-338 is the broader category for CWE-330 — any use of a PRNG that lacks sufficient entropy for cryptographic purposes. `java.util.Random` is designed for simulations and games, not security. Its internal state (64 bits) can be reconstructed from a few outputs.

**Attack vector in Spring:**
```java
// VULNERABLE — Random used for security-sensitive values
String resetCode = String.valueOf(new Random().nextInt(1000000));
String sessionId = String.valueOf(new Random().nextLong());
String apiKey = Long.toHexString(new Random().nextLong());
```
All of these are predictable given enough observations.

**How to prevent:**
- Same as CWE-330: use `SecureRandom` everywhere security-sensitive random values are needed.
- `SecureRandom` on Linux reads from `/dev/random` and `/dev/urandom`.

---

## CWE-321 — Use of Hard-coded Cryptographic Key

**Why it matters:** A cryptographic key embedded in source code, configuration files, or JAR artifacts is visible to anyone with access to the repository or the compiled code. Anyone can extract the key, decrypt all encrypted data, forge authentication tokens, or impersonate the service.

**Attack vector in Spring:**
```java
// VULNERABLE — hardcoded key in source code
public class DataKeyProvider {
    private static final byte[] KEY = "0verview-key-2020".getBytes();  // In source!
}

// VULNERABLE — hardcoded key in configuration
@Value("${encryption.key:0verview-key-2020}")
private byte[] key;  // Fallback in config file
```
`GET /vuln8/key-info` returns the key. Anyone can decrypt all data encrypted with this key.

**How to prevent:**
```java
// SAFE — key from environment or secret manager
@Value("${ENCRYPTION_KEY}")
private byte[] key;

@PostConstruct
void validate() {
    if (key == null || key.length < 32) {
        throw new IllegalStateException("ENCRYPTION_KEY must be ≥ 256 bits");
    }
}
```
- Store keys in Vault, AWS KMS, Azure Key Vault, or environment variables.
- Use envelope encryption: a key encryption key (KEK) stored securely encrypts data encryption keys (DEKs).
- Include a key ID with encrypted data so rotation can be gradual.
- Never commit keys to repositories.

---

## CWE-798 — Use of Hard-coded Credentials (Cryptographic Key)

**Why it matters:** CWE-798 covers any hard-coded secret, including cryptographic keys. A key in source code is equivalent to a password in source code — it provides no security and turns the application into a credential distributor.

**Attack vector in Spring:**
```java
// VULNERABLE — key material visible in the JAR
private static final SecretKey KEY = new SecretKeySpec(
    "0verview-key-2020".getBytes(), "AES"
);
// Anyone decompiling the JAR gets the key
```

**How to prevent:**
- Same as CWE-321: load keys from secure storage at runtime.
- Use `SecretHandle` or similar wrapper that never reveals material in `toString()`.

---

## CWE-295 — Improper Validation of Certificate Trust

**Why it matters:** A trust-all `TrustManager` accepts any certificate, including self-signed, expired, or forged certificates. This completely disables TLS authentication, allowing a man-in-the-middle (MITM) attacker to intercept and modify all encrypted traffic. The attacker can read, modify, and inject data in transit.

**Attack vector in Spring:**
```java
// VULNERABLE — trust-all TrustManager
@PostMapping("/fetch-https")
public ResponseEntity<?> fetch(@RequestBody FetchRequest req) {
    // Trust-all TrustManager
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
    
    // Now connects to any server with any certificate
    URL url = new URL(req.getUrl());
    HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
    conn.setSSLSocketFactory(ctx.getSocketFactory());
    // Returns the body of https://127.0.0.1:8443/vuln8/hash-info
    // Even though the certificate is self-signed and not in any trust store
    return ResponseEntity.ok(Map.of("body", new String(conn.getInputStream().readAllBytes()),
                                    "certificateVerified", false));
}
```
The vulnerable client accepts a self-signed certificate and returns `certificateVerified: false` — the body is retrieved but the certificate was never verified. A MITM attacker can intercept this connection and read/modify all data.

**How to prevent:**
```java
// SAFE — default trust store, hostname verification on
@PostMapping("/fetch-https")
public ResponseEntity<?> fetch(@RequestBody FetchRequest req) {
    // Use the default SSLContext — uses the system trust store
    URL url = new URL(req.getUrl());
    HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
    // Default trust manager validates certificates against the system trust store
    // Default hostname verifier checks that the certificate matches the hostname
    return ResponseEntity.ok(Map.of("body", new String(conn.getInputStream().readAllBytes())));
}
```
- Never create a custom `X509TrustManager` that accepts everything.
- If an internal CA is needed, import the CA certificate into the trust store — do not disable verification.
- Always leave hostname verification enabled.

---

## CWE-208 — Observable Timing Discrepancy (Non-constant-time Comparison)

**Why it matters:** String comparison using `equals()` returns as soon as the first mismatching character is found. An attacker can measure response times to determine how many leading characters of a secret match. A 32-byte HMAC can be recovered in approximately 800 requests (256 characters × ~3 guesses per character).

**Attack vector in Spring:**
```java
// VULNERABLE — String.equals() has timing leak
public boolean verifyToken(String provided, String expected) {
    return provided.equals(expected);  // Returns early on first mismatch
}

// Response time for "abc..." vs "xyz..." is shorter than "abc..." vs "abd..."
// Attacker measures timing and recovers the correct value byte by byte
```

**How to prevent:**
```java
// SAFE — constant-time comparison
public boolean verifyToken(byte[] provided, byte[] expected) {
    return MessageDigest.isEqual(provided, expected);
    // Compares ALL bytes regardless of where they differ
}
```
- Use `MessageDigest.isEqual()` for byte array comparison.
- Or use Spring Security's `ConstantTimeEquals` utility.
- Never use `String.equals()` to compare secrets, tokens, or MACs.

---

## CWE-326 — Weak Encryption Strength (Insecure TLS Version)

**Why it matters:** TLS 1.0 and TLS 1.1 have known cryptographic weaknesses (BEAST, POODLE, RC4 attacks) and are deprecated by RFC 8996. Allowing these versions exposes traffic to downgrade attacks where an attacker forces the connection to use a weaker protocol version with broken cryptography.

**Attack vector in Spring:**
```java
// VULNERABLE — no TLS protocol floor configured
// Default SSL/TLS configuration may allow TLS 1.0, TLS 1.1
// Attacker performs a protocol downgrade attack
```

**How to prevent:**
```java
// SAFE — restrict to TLS 1.2+
server:
  ssl:
    enabled-protocols:
      - TLSv1.2
      - TLSv1.3
```
```java
// Or programmatically:
SSLParameters params = new SSLParameters();
params.setProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
```
- TLS 1.2 is the minimum acceptable version.
- TLS 1.3 is preferred — it has stronger cryptography and faster handshakes.
- Never enable TLS 1.0 or 1.1 in production.
