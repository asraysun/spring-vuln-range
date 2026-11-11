package com.example.vulnrange.m01;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Checklist section 1 — authentication, sessions and tokens.
 *
 * <p>Intentionally vulnerable. Loopback-only by {@code server.address} in application.yml.
 * Insecure code is under {@code /vuln1/**}, reference implementation under {@code /safe1/**}.
 */
@SpringBootApplication
public class M01AuthenticationApplication {

    public static void main(String[] args) {
        System.out.println("""
                ===================================================================
                 m01-authentication — DELIBERATELY VULNERABLE, EDUCATIONAL ONLY
                 /vuln1/** is insecure by design. Never deploy this service.
                ===================================================================""");
        SpringApplication.run(M01AuthenticationApplication.class, args);
    }
}
