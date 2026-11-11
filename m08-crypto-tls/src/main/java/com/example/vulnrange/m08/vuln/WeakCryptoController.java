package com.example.vulnrange.m08.vuln;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

/**
 * VULNERABLE (intentional): weak hashes, unauthenticated/block-crypto leaks, predictable tokens,
 * compiled-in keys and a TLS client that trusts everything. PoC: {@code attacks/08-crypto-tls.sh}.
 */
@RestController
@RequestMapping("/vuln8")
public class WeakCryptoController {

    /** VULNERABLE: key material compiled into the artifact (and therefore into git history). */
    private static final byte[] HARDCODED_KEY = "0verview-key-2020".substring(0, 16).getBytes(StandardCharsets.UTF_8);

    /** VULNERABLE: a fixed IV makes CBC deterministic for equal prefixes. */
    private static final byte[] STATIC_IV = "0000000000000000".getBytes(StandardCharsets.UTF_8);

    @PostMapping("/hash")
    public Map<String, Object> hash(@RequestBody Map<String, String> body) throws Exception {
        String value = body.getOrDefault("value", "");
        // VULNERABLE: MD5/SHA-1 are collision-prone digests and useless as password hashes
        // (fast, unsalted). Rainbow tables and GPU cracking are measured in seconds per guess.
        return Map.of(
                "md5", hex(digest("MD5", value)),
                "sha1", hex(digest("SHA-1", value)),
                "unsalted", true,
                "guessesPerSecondGpu", "billions");
    }

    /** VULNERABLE: AES/ECB — equal plaintext blocks produce equal ciphertext blocks. */
    @PostMapping("/encrypt")
    public Map<String, Object> ecb(@RequestBody Map<String, String> body) throws Exception {
        byte[] plain = body.getOrDefault("plain", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").getBytes(StandardCharsets.UTF_8);
        byte[] cipherBytes = ecbCipher(Cipher.ENCRYPT_MODE).doFinal(plain);
        return Map.of(
                "mode", "AES/ECB/PKCS5Padding",
                "keySource", "compiled-in constant",
                "base64", Base64.getEncoder().encodeToString(cipherBytes),
                "identicalBlocksPresent", hasRepeatingBlock(cipherBytes),
                "note", "16-byte structure of the plaintext is visible in the ciphertext");
    }

    /** VULNERABLE: AES/CBC with a static IV — equal prefixes produce equal ciphertext prefixes. */
    @PostMapping("/encrypt-cbc")
    public Map<String, Object> cbc(@RequestBody Map<String, String> body) throws Exception {
        byte[] plain = body.getOrDefault("plain", "subscription=ESPD-BASIC;pad=").getBytes(StandardCharsets.UTF_8);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(HARDCODED_KEY, "AES"), new IvParameterSpec(STATIC_IV));
        byte[] cipherBytes = cipher.doFinal(plain);
        return Map.of(
                "mode", "AES/CBC/PKCS5Padding",
                "iv", Base64.getEncoder().encodeToString(STATIC_IV),
                "ivReused", true,
                "base64", Base64.getEncoder().encodeToString(cipherBytes));
    }

    /**
     * VULNERABLE: distinct error text for padding vs. MAC problems is a padding oracle: the caller
     * learns whether the ciphertext was well-formed, which is enough to decrypt.
     */
    @PostMapping("/decrypt")
    public Map<String, Object> decryptOracle(@RequestBody Map<String, String> body) {
        Map<String, Object> out = new LinkedHashMap<>();
        try {
            byte[] cipherBytes = Base64.getDecoder().decode(body.getOrDefault("base64", ""));
            byte[] plain = ecbCipher(Cipher.DECRYPT_MODE).doFinal(cipherBytes);
            out.put("plain", new String(plain, StandardCharsets.UTF_8));
        } catch (javax.crypto.BadPaddingException e) {
            out.put("error", "bad padding - ciphertext is malformed");
        } catch (javax.crypto.IllegalBlockSizeException e) {
            out.put("error", "illegal block size - length is wrong");
        } catch (Exception e) {
            out.put("error", "generic failure");
        }
        return out;
    }

    /**
     * VULNERABLE: tokens from {@link Random}. It is a linear congruential generator: observing output
     * (or the seed) lets an attacker reproduce every token — reset codes, invite links, API keys.
     */
    @GetMapping("/token/random")
    public Map<String, Object> weakToken(@RequestParam(required = false) Long seed) {
        long effectiveSeed = seed != null ? seed : System.currentTimeMillis() / 60_000L;
        Random random = new Random(effectiveSeed);
        StringBuilder token = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            token.append(String.format("%02x", random.nextInt(256)));
        }
        return Map.of("token", token.toString(), "seedUsed", effectiveSeed,
                "predictable", true, "why", "Random is seeded by time and is fully deterministic");
    }

    @GetMapping("/token/predict")
    public Map<String, String> predict(@RequestParam long seed) {
        Random random = new Random(seed);
        StringBuilder token = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            token.append(String.format("%02x", random.nextInt(256)));
        }
        return Map.of("predictedToken", token.toString());
    }

    /** VULNERABLE: an HTTPS client that does not verify the certificate or the hostname. */
    @PostMapping("/fetch-https")
    public Map<String, Object> fetchInsecure(@RequestBody Map<String, String> body) {
        Map<String, Object> out = new LinkedHashMap<>();
        String url = body.getOrDefault("url", "https://127.0.0.1:8443/vuln8/hash-info");
        try {
            RestTemplate restTemplate = InsecureTlsClients.trustEverythingRestTemplate();
            Object response = restTemplate.getForObject(url, Object.class);
            out.put("url", url);
            out.put("certificateVerified", false);
            out.put("hostnameVerified", false);
            out.put("body", response);
            out.put("note", "any attacker certificate would have been accepted too - this is plaintext with extra steps");
        } catch (Exception e) {
            out.put("error", String.valueOf(e.getMessage()));
        }
        return out;
    }

    @GetMapping("/key-info")
    public Map<String, Object> keyInfo() {
        return Map.of(
                "algorithm", "AES-128",
                "keyLengthBytes", HARDCODED_KEY.length,
                "storage", "static final field in the source",
                "rotation", "none",
                "fingerprint", hex(sha256(HARDCODED_KEY)));
    }

    @GetMapping("/hash-info")
    public Map<String, Object> hashInfo() {
        return Map.of("endpoint", "vuln8", "servedOver", "https", "certificateTrustedByClient", false);
    }

    // --- helpers -----------------------------------------------------------------------------

    private static Cipher ecbCipher(int mode) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(mode, new SecretKeySpec(HARDCODED_KEY, "AES"));
        return cipher;
    }

    private static boolean hasRepeatingBlock(byte[] data) {
        for (int i = 0; i + 32 <= data.length; i += 16) {
            if (Arrays.equals(Arrays.copyOfRange(data, i, i + 16), Arrays.copyOfRange(data, i + 16, i + 32))) {
                return true;
            }
        }
        return false;
    }

    private static byte[] digest(String algorithm, String value) throws Exception {
        return MessageDigest.getInstance(algorithm).digest(value.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String hex(byte[] bytes) {
        return java.util.HexFormat.of().formatHex(bytes);
    }

    /** Unused helper kept to document that even "random" keys here come from a static generator. */
    @SuppressWarnings("unused")
    private static SecretKey freshKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        return generator.generateKey();
    }
}
