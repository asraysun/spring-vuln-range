package com.example.vulnrange.m02;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

/**
 * Checklist section 2 — authorization and access control.
 *
 * <p>Intentionally vulnerable. Method security is enabled so that {@code @PreAuthorize} gaps are
 * visible; object-level checks are what the {@code /vuln2} endpoints skip.
 */
@SpringBootApplication
@EnableMethodSecurity
public class M02AuthorizationApplication {

    public static void main(String[] args) {
        System.out.println("""
                ===================================================================
                 m02-authorization — DELIBERATELY VULNERABLE, EDUCATIONAL ONLY
                 /vuln2/** skips object- and tenant-level checks by design.
                ===================================================================""");
        SpringApplication.run(M02AuthorizationApplication.class, args);
    }
}
