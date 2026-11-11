package com.example.vulnrange.m14;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Checklist section 14 — runtime, container and platform hardening.
 *
 * <p>Nothing in the {@code /vuln14} endpoints is a remote-code bug; they answer a different question:
 * "once an attacker has <em>any</em> request-level primitive inside this pod, what do they get?".
 * Compare {@code deploy/k8s/vulnerable-deployment.yaml} with
 * {@code deploy/k8s/hardened-deployment.yaml}, and run {@code scripts/check_k8s_manifests.sh}.
 */
@SpringBootApplication
public class M14RuntimeHardeningApplication {

    public static void main(String[] args) {
        System.out.println("""
                ===================================================================
                 m14-runtime-hardening — DELIBERATELY VULNERABLE, EDUCATIONAL ONLY
                 Manifest audit: scripts/check_k8s_manifests.sh
                ===================================================================""");
        SpringApplication.run(M14RuntimeHardeningApplication.class, args);
    }
}
