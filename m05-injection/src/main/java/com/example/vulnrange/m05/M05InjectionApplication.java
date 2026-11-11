package com.example.vulnrange.m05;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Checklist section 5 — injection.
 *
 * <p>Intentionally vulnerable. Two endpoints here can execute code/commands on the host process and
 * are therefore <strong>disabled unless explicitly enabled</strong>:
 * set {@code VULNRANGE_ALLOW_EXEC=true} (OS command demo) and {@code VULNRANGE_ALLOW_SPEL_TYPES=true}
 * (SpEL type-reference demo) before starting the module. Everything else (SQL, LIKE, ORDER BY, CRLF)
 * works out of the box.
 */
@SpringBootApplication
public class M05InjectionApplication {

    public static void main(String[] args) {
        System.out.println("""
                ===================================================================
                 m05-injection — DELIBERATELY VULNERABLE, EDUCATIONAL ONLY
                 SQL/LIKE/ORDER BY/SpEL sinks are reachable on purpose.
                 OS-command sink requires VULNRANGE_ALLOW_EXEC=true.
                ===================================================================""");
        SpringApplication.run(M05InjectionApplication.class, args);
    }
}
