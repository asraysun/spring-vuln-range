package com.example.vulnrange.m04;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Checklist section 4 — input validation and data binding.
 *
 * <p>Intentionally vulnerable. This module is also where the Spring4Shell (CVE-2022-22965) class
 * binding surface is demonstrated: the patched framework blocks the known chain, the DTO boundary is
 * what actually removes the risk.
 */
@SpringBootApplication
public class M04ValidationBindingApplication {

    public static void main(String[] args) {
        System.out.println("""
                ===================================================================
                 m04-validation-binding — DELIBERATELY VULNERABLE, EDUCATIONAL ONLY
                 Request data is bound straight into server-side objects by design.
                ===================================================================""");
        SpringApplication.run(M04ValidationBindingApplication.class, args);
    }
}
