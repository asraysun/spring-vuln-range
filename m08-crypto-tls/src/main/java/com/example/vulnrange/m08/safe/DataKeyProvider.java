package com.example.vulnrange.m08.safe;

import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import org.springframework.stereotype.Component;

/**
 * Data-encryption key comes from the environment / Vault-mounted file; if neither is present the
 * provider generates an ephemeral key and says so loudly. There is no repository fallback, because a
 * repository fallback is what turns a missing secret into a silent cross-environment key reuse.
 *
 * <p>Format: base64 of a 256-bit key in {@code RANGE_M08_DATA_KEY}. A real deployment additionally
 * keeps the key in KMS with an audit trail of every use, and the ciphertext envelope carries a key id
 * so rotation can be gradual.
 */
@Component
public class DataKeyProvider {

    private static final int REQUIRED_BITS = 256;
    private final SecretKey key;
    private final String source;

    public DataKeyProvider(
            @org.springframework.beans.factory.annotation.Value("${vulnrange.safe.data-key:}") String configuredKey) {
        String material = configuredKey == null ? "" : configuredKey;
        if (!material.isBlank()) {
            byte[] decoded;
            try {
                decoded = Base64.getDecoder().decode(material);
            } catch (IllegalArgumentException e) {
                throw new IllegalStateException("RANGE_M08_DATA_KEY must be base64-encoded key material");
            }
            if (decoded.length * 8 < REQUIRED_BITS) {
                throw new IllegalStateException("RANGE_M08_DATA_KEY must hold at least 256 bits");
            }
            this.key = new javax.crypto.spec.SecretKeySpec(decoded, "AES");
            this.source = "env:RANGE_M08_DATA_KEY";
        } else {
            byte[] generated = new byte[REQUIRED_BITS / 8];
            new SecureRandom().nextBytes(generated);
            this.key = new javax.crypto.spec.SecretKeySpec(generated, "AES");
            this.source = "ephemeral-generated-at-startup";
        }
    }

    public SecretKey key() {
        return key;
    }

    public String source() {
        return source;
    }
}
