package com.example.vulnrange.m01.vuln;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * VULNERABLE (intentional): every token decision made here is broken.
 *
 * <ul>
 *   <li>HMAC key is a dictionary word from configuration (checklist §1, §3).</li>
 *   <li>{@code alg} is taken from the token itself, so {@code alg: none} and an
 *       RS256-&gt;HS256 downgrade are both accepted (CWE-347).</li>
 *   <li>{@code exp}, {@code iss}, {@code aud} are parsed but never enforced.</li>
 *   <li>MAC compared with {@code String.equals} (timing side channel, CWE-208).</li>
 * </ul>
 */
@Service
public class InsecureTokenService {

    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getUrlDecoder();

    private final String weakSecret;

    public InsecureTokenService(@Value("${vulnrange.m01.jwt-weak-secret}") String weakSecret) {
        this.weakSecret = weakSecret;
    }

    public String issueHs256(Map<String, Object> claims) {
        String header = b64("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        String payload = b64(toJson(claims));
        String signingInput = header + "." + payload;
        return signingInput + "." + b64(hmac(signingInput, weakSecret));
    }

    /** @return claims if the token "looks fine", throws otherwise. Accepts unsigned tokens. */
    public Map<String, Object> verify(String token) {
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) {
            throw new IllegalArgumentException("malformed token");
        }
        String header = new String(B64D.decode(parts[0]), StandardCharsets.UTF_8);
        Map<String, Object> claims = fromJson(new String(B64D.decode(parts[1]), StandardCharsets.UTF_8));

        // VULNERABLE: algorithm negotiation from attacker-controlled input.
        if (header.contains("\"none\"")) {
            return claims;
        }

        // VULNERABLE: no exp/iss/aud validation, non-constant-time comparison.
        String expected = b64(hmac(parts[0] + "." + parts[1], weakSecret));
        if (!expected.equals(parts[2])) {
            throw new IllegalArgumentException("bad signature");
        }
        return claims;
    }

    /**
     * VULNERABLE: remember-me style token from a key that is compiled into the artifact, so anyone
     * with the jar (or the sources) can mint "remember me" cookies offline.
     */
    public String rememberMe(String username) {
        return username + ":" + b64(hmac(username, "remember-me-static-key"));
    }

    public boolean rememberMeMatches(String cookieValue) {
        int idx = cookieValue.lastIndexOf(':');
        if (idx < 0) {
            return false;
        }
        String user = cookieValue.substring(0, idx);
        return b64(hmac(user, "remember-me-static-key")).equals(cookieValue.substring(idx + 1));
    }

    static String md5Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            return java.util.HexFormat.of().formatHex(md.digest(input.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private byte[] hmac(String data, String secret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
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

    /** Minimal JSON writer for flat string/number claims; keeps the demo dependency-free. */
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

    @SuppressWarnings("unchecked")
    private Map<String, Object> fromJson(String json) {
        Map<String, Object> out = new LinkedHashMap<>();
        String body = json.trim();
        if (body.startsWith("{")) {
            body = body.substring(1, body.length() - 1);
        }
        for (String pair : body.split(",(?=\")")) {
            String[] kv = pair.split(":", 2);
            if (kv.length == 2) {
                String key = kv[0].trim().replaceAll("^\"|\"$", "");
                String value = kv[1].trim().replaceAll("^\"|\"$", "");
                out.put(key, value);
            }
        }
        return out;
    }
}
