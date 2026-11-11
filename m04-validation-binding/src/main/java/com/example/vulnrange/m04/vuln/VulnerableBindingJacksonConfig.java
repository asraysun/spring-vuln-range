package com.example.vulnrange.m04.vuln;

import com.fasterxml.jackson.databind.DeserializationFeature;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * VULNERABLE (intentional): disables fail-on-unknown-properties for the vulnerable controller
 * so that extra JSON fields silently populate entity properties (mass assignment).
 */
@RestControllerAdvice(basePackages = "com.example.vulnrange.m04.vuln")
public class VulnerableBindingJacksonConfig {

    @org.springframework.beans.factory.annotation.Autowired
    public void customizeObjectMapper(Jackson2ObjectMapperBuilder builder) {
        builder.featuresToDisable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    }
}
