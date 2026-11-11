package com.example.vulnrange.m10;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Checklist section 10 — outbound calls and webhooks.
 *
 * <p>Intentionally vulnerable. "Internal" services and the cloud instance metadata endpoint are
 * <em>simulated inside this module</em>: the PoC proves the SSRF primitive (the server makes a request
 * the caller chose) without touching anything outside the loopback interface.
 */
@SpringBootApplication
public class M10SsrfWebhooksApplication {

    public static void main(String[] args) {
        System.out.println("""
                ===================================================================
                 m10-ssrf-webhooks — DELIBERATELY VULNERABLE, EDUCATIONAL ONLY
                 /vuln10/** fetches arbitrary URLs; the payment webhook is unsigned.
                ===================================================================""");
        SpringApplication.run(M10SsrfWebhooksApplication.class, args);
    }
}
