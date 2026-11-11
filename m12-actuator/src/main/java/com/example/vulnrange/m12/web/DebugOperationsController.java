package com.example.vulnrange.m12.web;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Operational/debug surface that was "only temporary" and ended up in production, documented in the
 * public OpenAPI file and reachable without authentication.
 *
 * <p>VULNERABLE (intentional): a state-changing operation with no authz check. The operation itself is
 * harmless (a counter reset), because the point is that an anonymous caller can invoke one at all.
 * Fix: remove the route from production builds, or require a dedicated admin authority and audit it.
 */
@RestController
@RequestMapping("/vuln12/debug")
public class DebugOperationsController {

    private final AtomicLong cacheGeneration = new AtomicLong(7);

    @PostMapping("/reset-cache")
    public Map<String, Object> resetCache() {
        long previous = cacheGeneration.incrementAndGet();
        return Map.of(
                "status", "ok",
                "cacheGeneration", (Object) previous,
                "performedBy", "anonymous",
                "at", Instant.now().toString());
    }
}
