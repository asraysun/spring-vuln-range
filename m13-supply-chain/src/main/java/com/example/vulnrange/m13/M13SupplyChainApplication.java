package com.example.vulnrange.m13;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Checklist section 13 — dependencies, transitive risk and build integrity.
 *
 * <p>This module pins two libraries with known vulnerable versions on purpose. It is the negative
 * test for your SCA gate: if dependency-check / Trivy / Snyk / Gradle audit report a clean build
 * here, the gate is not working and no other finding from this range should be trusted.
 */
@SpringBootApplication
public class M13SupplyChainApplication {

    public static void main(String[] args) {
        System.out.println("""
                ===================================================================
                 m13-supply-chain — carries INTENTIONALLY VULNERABLE dependencies
                 Run the gate: ./mvnw -Psca -pl m13-supply-chain verify
                 or:           scripts/run_sca.sh
                ===================================================================""");
        SpringApplication.run(M13SupplyChainApplication.class, args);
    }
}
