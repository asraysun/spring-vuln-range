package com.example.vulnrange.m03;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * Checklist section 3 — secrets and configuration.
 *
 * <p>All "secrets" in this module are synthetic placeholders with no value outside this repository.
 * They exist so that secret scanners, log scrubbing and review practices can be exercised for real.
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class M03SecretsConfigApplication {

    public static void main(String[] args) {
        System.out.println("""
                ===================================================================
                 m03-secrets-config — DELIBERATELY VULNERABLE, EDUCATIONAL ONLY
                 The credentials below are fake placeholders, never real secrets.
                ===================================================================""");
        SpringApplication.run(M03SecretsConfigApplication.class, args);
    }
}
