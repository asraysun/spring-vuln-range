package com.example.vulnrange.m08;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Checklist section 8 — cryptography and TLS.
 *
 * <p>Intentionally vulnerable. On startup the module generates a throw-away self-signed keystore in
 * the OS temp directory (random password, never committed) and exposes an HTTPS listener on 8443 so
 * that the "trust-all client" and "default trust store" behaviours can be compared against a real
 * TLS handshake instead of a mock.
 */
@SpringBootApplication
public class M08CryptoTlsApplication {

    public static void main(String[] args) {
        System.out.println("""
                ===================================================================
                 m08-crypto-tls — DELIBERATELY VULNERABLE, EDUCATIONAL ONLY
                 HTTP 8088 / HTTPS 8443 (throw-away self-signed certificate).
                ===================================================================""");
        SpringApplication.run(M08CryptoTlsApplication.class, args);
    }
}
