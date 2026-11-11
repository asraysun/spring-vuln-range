package com.example.vulnrange.m06;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Checklist section 6 — deserialization, XML and polymorphic JSON.
 *
 * <p>Intentionally vulnerable. "Side effects" observed by the PoC scripts are <em>in-process</em>
 * bookkeeping only: the probe class records that attacker-controlled bytes caused application code
 * to run (constructor, setter, hashCode). That is exactly the primitive a gadget chain starts from;
 * the range stops there and does not provide an executable payload against any system.
 */
@SpringBootApplication
public class M06DeserializationApplication {

    public static void main(String[] args) {
        System.out.println("""
                ===================================================================
                 m06-deserialization — DELIBERATELY VULNERABLE, EDUCATIONAL ONLY
                 readObject / XStream / XXE sinks are reachable on purpose.
                ===================================================================""");
        SpringApplication.run(M06DeserializationApplication.class, args);
    }
}
