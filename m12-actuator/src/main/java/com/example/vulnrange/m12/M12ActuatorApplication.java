package com.example.vulnrange.m12;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.env.Environment;

/**
 * Checklist section 12 — management endpoints, API descriptions and debug surfaces.
 *
 * <p>Default profile is deliberately over-exposed (everything on the web port, unauthenticated).
 * Start with {@code --spring.profiles.active=safe} to get the hardened configuration: only
 * {@code health} and {@code info}, on a separate loopback management port, behind authentication,
 * with values and details hidden. Compare the two runs side by side.
 */
@SpringBootApplication
public class M12ActuatorApplication {

    public static void main(String[] args) {
        Environment environment = new org.springframework.core.env.StandardEnvironment();
        String profiles = String.join(",", environment.getActiveProfiles());
        System.out.printf("""
                ===================================================================
                 m12-actuator — DELIBERATELY VULNERABLE BY DEFAULT
                 active profiles: %s
                 vulnerable run : java -jar m12-actuator-*.jar
                 hardened run   : java -jar m12-actuator-*.jar --spring.profiles.active=safe
                ===================================================================%n""",
                profiles.isEmpty() ? "none (vulnerable)" : profiles);
        SpringApplication.run(M12ActuatorApplication.class, args);
    }
}
