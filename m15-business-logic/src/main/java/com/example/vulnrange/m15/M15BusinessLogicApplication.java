package com.example.vulnrange.m15;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Checklist section 15 — subscription and ESPD business logic.
 *
 * <p>This is where the money is: the vulnerabilities here are not exotic code, they are places where
 * the server let the client decide what is true. {@code /vuln15/**} does that; {@code /safe15/**}
 * derives the same facts from server-side state.
 */
@SpringBootApplication
public class M15BusinessLogicApplication {

    public static void main(String[] args) {
        System.out.println("""
                ===================================================================
                 m15-business-logic — DELIBERATELY VULNERABLE, EDUCATIONAL ONLY
                 /vuln15/** trusts client-supplied price, state and entitlements.
                ===================================================================""");
        SpringApplication.run(M15BusinessLogicApplication.class, args);
    }
}
