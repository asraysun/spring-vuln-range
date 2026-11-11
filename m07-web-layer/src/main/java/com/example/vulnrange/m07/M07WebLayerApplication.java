package com.example.vulnrange.m07;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Checklist section 7 — browser-facing controls: CSRF, CORS, security headers, output encoding.
 *
 * <p>Intentionally vulnerable. {@code /vuln7/**} runs with CSRF off, headers off and a permissive
 * CORS source; {@code /safe7/**} is the same functionality with all three controls in place.
 */
@SpringBootApplication
public class M07WebLayerApplication {

    public static void main(String[] args) {
        System.out.println("""
                ===================================================================
                 m07-web-layer — DELIBERATELY VULNERABLE, EDUCATIONAL ONLY
                 /vuln7/** has CSRF, security headers and output encoding off.
                ===================================================================""");
        SpringApplication.run(M07WebLayerApplication.class, args);
    }
}
