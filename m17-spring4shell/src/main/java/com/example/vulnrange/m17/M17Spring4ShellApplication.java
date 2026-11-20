package com.example.vulnrange.m17;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Checklist section 17 — Spring4Shell (CVE-2022-22965).
 *
 * <p>Demonstrates the Spring Data Binding vulnerability that allows Remote Code Execution (RCE)
 * through malicious request parameters.
 *
 * <p><b>EDUCATIONAL ONLY:</b> This module is deliberately vulnerable. Never deploy this in production.
 */
@SpringBootApplication
public class M17Spring4ShellApplication {

    public static void main(String[] args) {
        System.out.println("""
                ===================================================================
                 m17-spring4shell — DELIBERATELY VULNERABLE, EDUCATIONAL ONLY
                 CVE-2022-22965: Spring Data Binding RCE
                 /vuln17/** demonstrates the vulnerable pattern
                ===================================================================""");
        SpringApplication.run(M17Spring4ShellApplication.class, args);
    }
}
