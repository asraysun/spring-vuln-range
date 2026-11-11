package com.example.vulnrange.m03.vuln;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * VULNERABLE (intentional): the "legacy" way secrets reach an application.
 *
 * <p>Three distinct mistakes, all common in real Spring services:
 * <ol>
 *   <li>a credential is compiled into the artifact as a default value (it lives in git history and
 *       in the jar forever, even after the line is "fixed");</li>
 *   <li>the property has a working fallback, so a missing Vault entry silently degrades prod to a
 *       shared dev credential;</li>
 *   <li>the same value is reused across dev/ift/prod, so one leak is a prod leak.</li>
 * </ol>
 */
@Component
public class LegacyIntegrationProperties {

    /**
     * VULNERABLE: literal default. The value is a documentation placeholder (AWS's own example key),
     * never a real credential - but the <em>pattern</em> is exactly the one that leaks prod keys.
     */
    @Value("${vulnrange.legacy.espd-api-key:AKIAIOSFODNN7EXAMPLE}")
    private String espdApiKey;

    @Value("${vulnrange.legacy.db-password:postgres}")
    private String databasePassword;

    @Value("${vulnrange.legacy.db-url:jdbc:postgresql://postgres-dev:5432/espd}")
    private String databaseUrl;

    @Value("${vulnrange.legacy.encryption-key:0123456789abcdef}")
    private String encryptionKey;

    public String espdApiKey() {
        return espdApiKey;
    }

    public String databasePassword() {
        return databasePassword;
    }

    public String databaseUrl() {
        return databaseUrl;
    }

    public String encryptionKey() {
        return encryptionKey;
    }
}
