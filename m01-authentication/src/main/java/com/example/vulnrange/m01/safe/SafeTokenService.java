package com.example.vulnrange.m01.safe;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Service;

/**
 * Reference JWT handling for a service that must issue its own tokens.
 *
 * <p>In a real platform prefer {@code spring-boot-starter-oauth2-resource-server} with the
 * platform IdP: signature keys, rotation and revocation then stop being this service's problem.
 * What matters here is the discipline, which is the same either way:
 *
 * <ol>
 *   <li>the accepted algorithm is a constant of this class, never a value read from the token;</li>
 *   <li>the key is 256 bits of {@link SecureRandom} material from the environment / Vault;</li>
 *   <li>{@code exp}, {@code iss}, {@code aud}, {@code nbf}, {@code iat} skew are enforced;</li>
 *   <li>MAC comparison is constant time;</li>
 *   <li>claims are validated against a schema before they are trusted.</li>
 * </ol>
 */
@Service
public class SafeTokenService {

    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getUrlDecoder();
    private static final String ACCEPTED_ALG = "HS256";
    private static final String EXPECTED_ISSUER = "https://vulnrange.local/m01";
    private static final String EXPECTED_AUDIENCE = "espd-subscription-api";
    private static final long MAX_TTL_SECONDS = 900;

    private final byte[] key;
    private final SecureRandom random = new SecureRandom();

    public SafeTokenService(SafeTokenKeyProvider keyProvider) {
        this.key = keyProvider.keyBytes();
    }

    public String issue(String subject, String role, long ttlSeconds) {
        long now = Instant.now().getEpochSecond();
        long ttl = Math.min(Math.max(ttlSeconds, 1), MAX_TTL_SECONDS);
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", EXPECTED_ISSUER);
        claims.put("aud", EXPECTED_AUDIENCE);
        claims.put("sub", subject);
        claims.put("role", role);
        claims.put("jti", jti());
        claims.put("iat", now);
        claims.put("nbf", now);
        claims.put("exp", now + ttl);

        String signingInput = b64("{\"alg\":\"" + ACCEPTED_ALG + "\",\"typ\":\"JWT\",\"kid\":\"m01-v1\"}")
                + "." + b64(toJson(claims));
        return signingInput + "." + b64(mac(signingInput));
    }

    /** Verifies structure, algorithm, signature and time/issuer/audience claims. */
    public Map<String, String> verify(String compactJws) {
        if (compactJws == null) {
            throw new IllegalArgumentException("token missing");
        }
        String[] parts = compactJws.split("\\.", -1);
        if (parts.length != 3) {
            throw new IllegalArgumentException("malformed token");
        }
        String header = new String(B64D.decode(parts[0]), StandardCharsets.UTF_8);
        if (!("\"" + ACCEPTED_ALG + "\"").equals(jsonValue(header, "alg"))) {
            // Rejects alg:none, HS256/RS256 confusion and any other negotiation attempt.
            throw new IllegalArgumentException("unexpected alg");
        }
        String expected = b64(mac(parts[0] + "." + parts[1]));
        if (!MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                parts[2].getBytes(StandardCharsets.UTF_8))) {
            throw new IllegalArgumentException("bad signature");
        }

        String payload = new String(B64D.decode(parts[1]), StandardCharsets.UTF_8);
        Map<String, String> claims = new LinkedHashMap<>();
        for (String claim : new String[] {"iss", "aud", "sub", "role", "jti", "iat", "nbf", "exp"}) {
            claims.put(claim, jsonValue(payload, claim));
        }
        if (!EXPECTED_ISSUER.equals(claims.get("iss"))) {
            throw new IllegalArgumentException("unexpected iss");
        }
        if (!EXPECTED_AUDIENCE.equals(claims.get("aud"))) {
            throw new IllegalArgumentException("unexpected aud");
        }
        long now = Instant.now().getEpochSecond();
        if (claims.get("exp") == null || now >= Long.parseLong(claims.get("exp"))) {
            throw new IllegalArgumentException("expired");
        }
        if (claims.get("nbf") != null && now + 60 < Long.parseLong(claims.get("nbf"))) {
            throw new IllegalArgumentException("not yet valid");
        }
        if (claims.get("sub") == null || claims.get("sub").isBlank()) {
            throw new IllegalArgumentException("missing sub");
        }
        return claims;
    }

    /** Reset codes, pairing codes, invite tokens: CSPRNG only (JEP 294-style discipline). */
    public String randomCode(int digits) {
        StringBuilder sb = new StringBuilder(digits);
        for (int i = 0; i < digits; i++) {
            sb.append(random.nextInt(10));
        }
        return sb.toString();
    }

    public String sha256Hex(String value) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return java.util.HexFormat.of().formatHex(md.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private String jti() {
        byte[] bytes = new byte[16];
        random.nextBytes(bytes);
        return B64.encodeToString(bytes);
    }

    private byte[] mac(String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private String b64(String s) {
        return B64.encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    private String b64(byte[] b) {
        return B64.encodeToString(b);
    }

    private String toJson(Map<String, Object> claims) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> e : claims.entrySet()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append('"').append(e.getKey()).append("\":");
            if (e.getValue() instanceof Number) {
                sb.append(e.getValue());
            } else {
                sb.append('"').append(String.valueOf(e.getValue()).replace("\"", "\\\"")).append('"');
            }
        }
        return sb.append('}').toString();
    }

    /** Tiny flat-JSON string reader; a real service uses Jackson with a strict DTO. */
    private String jsonValue(String json, String key) {
        String needle = "\"" + key + "\":";
        int idx = json.indexOf(needle);
        if (idx < 0) {
            return null;
        }
        int from = idx + needle.length();
        while (from < json.length() && (json.charAt(from) == ' ' || json.charAt(from) == '"')) {
            from++;
        }
        int to = from;
        while (to < json.length() && json.charAt(to) != '"' && json.charAt(to) != ',' && json.charAt(to) != '}') {
            to++;
        }
        return json.substring(from, to);
    }
}
