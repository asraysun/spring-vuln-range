package com.example.vulnrange.m09;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Checklist section 9 — error handling, logging and security events.
 *
 * <p>Intentionally vulnerable: {@code /vuln9/**} leaks internals to callers and writes sensitive
 * values into the log pipeline; {@code /safe9/**} shows the correlation-id + masking + audit-event
 * pattern that replaces it.
 */
@SpringBootApplication
public class M09LoggingErrorsApplication {

    public static void main(String[] args) {
        System.out.println("""
                ===================================================================
                 m09-logging-errors — DELIBERATELY VULNERABLE, EDUCATIONAL ONLY
                 /vuln9/** leaks stack traces and logs PII by design.
                ===================================================================""");
        SpringApplication.run(M09LoggingErrorsApplication.class, args);
    }
}
