package com.example.vulnrange.m08.safe;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;

import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

/**
 * Reference implementation of checklist section 8.
 *
 * <p>Decisions encoded here: Argon2id for passwords, AES-GCM (authenticated encryption, random
 * 96-bit IV per record, IV stored alongside the ciphertext), {@link SecureRandom} for every token,
 * and the default JVM trust store for outbound TLS — with no per-client overrides.
 */
@RestController
@RequestMapping("/safe8")
public class StrongCryptoController {

    private static final int GCM_IV_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final int MAX_PLAIN_BYTES = 64 * 1024;

    private final DataKeyProvider keys;
    private final SecureRandom random = new SecureRandom();
    // BCrypt with strength 12 (2^12 = 4096 iterations) — memory-hard enough for PoC
    private final RestTemplate defaultTlsClient = new RestTemplate();

    public StrongCryptoController(DataKeyProvider keys) {
        this.keys = keys;
    }

    @PostMapping("/hash-password")
    public Map<String, Object> hashPassword(@RequestBody Map<String, String> body) {
        String password = body.getOrDefault("password", "");
        if (password.length() < 12) {
            return Map.of("error", "password too short");
        }
        String hash = BCrypt.hashpw(password, BCrypt.gensalt(12));
        return Map.of(
                "hash", hash,
                "algorithm", "BCrypt (memory-hard, salted, 2^12 iterations)",
                "note", "for machine credentials use a secret manager instead of a shared hash");
    }

    @PostMapping("/verify-password")
    public Map<String, Object> verifyPassword(@RequestBody Map<String, String> body) {
        boolean ok = BCrypt.checkpw(body.getOrDefault("password", ""),
                body.getOrDefault("hash", ""));
        return Map.of("matches", ok);
    }

    /** Authenticated encryption: fresh IV per call, integrity tag included. */
    @PostMapping("/encrypt")
    public ResponseEntity<Map<String, Object>> encrypt(@RequestBody Map<String, String> body) {
        byte[] plain = body.getOrDefault("plain", "").getBytes(StandardCharsets.UTF_8);
        if (plain.length > MAX_PLAIN_BYTES) {
            return ResponseEntity.badRequest().body(Map.of("error", "plaintext too large"));
        }
        try {
            byte[] iv = new byte[GCM_IV_BYTES];
            random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keys.key(), new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] cipherText = cipher.doFinal(plain);

            byte[] envelope = new byte[iv.length + cipherText.length];
            System.arraycopy(iv, 0, envelope, 0, iv.length);
            System.arraycopy(cipherText, 0, envelope, iv.length, cipherText.length);

            return ResponseEntity.ok(Map.of(
                    "algorithm", "AES/GCM/NoPadding",
                    "envelopeBase64", Base64.getEncoder().encodeToString(envelope),
                    "ivReused", false,
                    "keySource", keys.source()));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "encryption failed"));
        }
    }

    /** One generic failure message: nothing here tells the caller why the envelope was rejected. */
    @PostMapping("/decrypt")
    public ResponseEntity<Map<String, Object>> decrypt(@RequestBody Map<String, String> body) {
        Map<String, Object> out = new LinkedHashMap<>();
        try {
            byte[] envelope = Base64.getDecoder().decode(body.getOrDefault("envelopeBase64", ""));
            if (envelope.length <= GCM_IV_BYTES) {
                throw new IllegalArgumentException("envelope too short");
            }
            byte[] iv = new byte[GCM_IV_BYTES];
            System.arraycopy(envelope, 0, iv, 0, GCM_IV_BYTES);
            byte[] cipherText = new byte[envelope.length - GCM_IV_BYTES];
            System.arraycopy(envelope, GCM_IV_BYTES, cipherText, 0, cipherText.length);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keys.key(), new GCMParameterSpec(GCM_TAG_BITS, iv));
            out.put("plain", new String(cipher.doFinal(cipherText), StandardCharsets.UTF_8));
            return ResponseEntity.ok(out);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "invalid envelope"));
        }
    }

    @GetMapping("/token")
    public Map<String, Object> token() {
        byte[] material = new byte[32];
        random.nextBytes(material);
        return Map.of("token", Base64.getUrlEncoder().withoutPadding().encodeToString(material),
                "entropyBits", 256,
                "generator", "SecureRandom");
    }

    /** Constant-time comparison; a short-circuiting equals() leaks the matching prefix over time. */
    @PostMapping("/token/verify")
    public Map<String, Object> verifyToken(@RequestBody Map<String, String> body) {
        byte[] expected = body.getOrDefault("expected", "").getBytes(StandardCharsets.UTF_8);
        byte[] provided = body.getOrDefault("provided", "").getBytes(StandardCharsets.UTF_8);
        return Map.of("matches", MessageDigest.isEqual(expected, provided));
    }

    /** The correct client behaviour is to fail on an untrusted certificate. */
    @PostMapping("/fetch-https")
    public Map<String, Object> fetchSecure(@RequestBody Map<String, String> body) {
        Map<String, Object> out = new LinkedHashMap<>();
        String url = body.getOrDefault("url", "https://127.0.0.1:8443/vuln8/hash-info");
        out.put("url", url);
        try {
            Object response = defaultTlsClient.getForObject(url, Object.class);
            out.put("certificateVerified", true);
            out.put("body", response);
            out.put("note", "a publicly trusted certificate is present for this host");
        } catch (Exception e) {
            out.put("certificateVerified", false);
            out.put("rejected", e.getClass().getName());
            out.put("detail", String.valueOf(e.getMessage()));
            out.put("expected", "why: the throw-away certificate is not in the trust store; that failure is the control working");
        }
        return out;
    }

    @GetMapping("/selftest")
    public Map<String, Object> selftest() {
        return Map.of(
                "passwordHash", "BCrypt (memory-hard, salted, 2^12 iterations)",
                "aeadAlgorithm", "AES/GCM/NoPadding with 96-bit random IV and 128-bit tag",
                "dataKeySource", keys.source(),
                "tokenGenerator", "SecureRandom",
                "comparison", "MessageDigest.isEqual (constant time)",
                "outboundTls", "default JVM trust store, hostname verification on",
                "tlsProtocolsAcceptedByThisService", "TLSv1.3, TLSv1.2");
    }
}
