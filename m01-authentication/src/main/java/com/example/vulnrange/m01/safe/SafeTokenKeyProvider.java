package com.example.vulnrange.m01.safe;

import java.security.SecureRandom;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Key material comes from the environment / Vault injector — never from the repository, never a
 * compiled-in default. If nothing is injected the service still works, but with an ephemeral key
 * that disappears on restart: that is the intended fail-noisy behaviour for local development.
 */
@Component
public class SafeTokenKeyProvider {

    private static final Logger log = LoggerFactory.getLogger(SafeTokenKeyProvider.class);
    private static final int REQUIRED_BYTES = 32;

    private final byte[] key;

    public SafeTokenKeyProvider(@Value("${vulnrange.m01.token-key:}") String configuredKey) {
        byte[] candidate = null;
        if (!configuredKey.isBlank()) {
            try {
                candidate = Base64.getDecoder().decode(configuredKey);
            } catch (IllegalArgumentException e) {
                log.error("vulnrange.m01.token-key is not valid base64; generating an ephemeral key");
            }
        }
        if (candidate == null || candidate.length < REQUIRED_BYTES) {
            log.warn("no 256-bit token key injected (set RANGE_M01_TOKEN_KEY from Vault); "
                    + "using an ephemeral key, tokens will not survive a restart");
            byte[] generated = new byte[REQUIRED_BYTES];
            new SecureRandom().nextBytes(generated);
            candidate = generated;
        }
        this.key = candidate;
    }

    public byte[] keyBytes() {
        return key.clone();
    }
}
