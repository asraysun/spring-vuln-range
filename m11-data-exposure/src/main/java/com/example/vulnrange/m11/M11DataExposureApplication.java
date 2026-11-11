package com.example.vulnrange.m11;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Checklist section 11 — data exposure and privacy.
 *
 * <p>Intentionally vulnerable. {@code /vuln11/**} answers with persistence entities and accepts PII in
 * query parameters; {@code /safe11/**} answers with explicit projections and keeps identifiers in
 * headers and path segments where they belong.
 */
@SpringBootApplication
public class M11DataExposureApplication {

    public static void main(String[] args) {
        System.out.println("""
                ===================================================================
                 m11-data-exposure — DELIBERATELY VULNERABLE, EDUCATIONAL ONLY
                 /vuln11/** serialises JPA entities (hashes, tokens, PII) by design.
                ===================================================================""");
        SpringApplication.run(M11DataExposureApplication.class, args);
    }
}
