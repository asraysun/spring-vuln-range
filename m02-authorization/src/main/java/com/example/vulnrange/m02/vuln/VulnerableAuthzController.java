package com.example.vulnrange.m02.vuln;

import java.security.Principal;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.example.vulnrange.m02.domain.Subscription;
import com.example.vulnrange.m02.domain.SubscriptionRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * VULNERABLE (intentional): every endpoint below is reachable for its HTTP method and nothing else —
 * the object and the tenant of the caller are never consulted.
 */
@RestController
@RequestMapping("/vuln2")
public class VulnerableAuthzController {

    private final SubscriptionRepository repository;
    private final Map<String, String> tenantDirectory;
    private final Map<String, String> statusOverrides = new ConcurrentHashMap<>();

    public VulnerableAuthzController(SubscriptionRepository repository, Map<String, String> tenantDirectory) {
        this.repository = repository;
        this.tenantDirectory = tenantDirectory;
    }

    /**
     * VULNERABLE: IDOR / BOLA. "Authenticated" is treated as "authorised for this row".
     * {@code bob} can read {@code alice}'s subscription simply by changing the id.
     */
    @GetMapping("/subscriptions/{id}")
    public ResponseEntity<?> subscription(@PathVariable String id) {
        return repository.findById(id)
                .<ResponseEntity<?>>map(s -> ResponseEntity.ok(Map.of(
                        "subscription", s,
                        "note", "no ownership check happened here")))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /**
     * VULNERABLE: the "public read" matcher covers a state-changing operation because it was written
     * for a read. Anyone (unauthenticated) can cancel someone else's subscription.
     */
    @GetMapping("/subscriptions/{id}/cancel")
    public Map<String, String> cancel(@PathVariable String id) {
        statusOverrides.put(id, "CANCELLED");
        return Map.of(id, "CANCELLED", "actor", "anonymous");
    }

    /** VULNERABLE: leftover {@code permitAll()} from a dashboard spike — full dump with PII. */
    @GetMapping("/admin/subscriptions")
    public List<Subscription> allSubscriptions() {
        return repository.findAll();
    }

    /** VULNERABLE: "internal" path used as a synonym for safe. */
    @GetMapping("/internal/metrics")
    public Map<String, Object> internalMetrics() {
        // Fully qualified on purpose: this demo module is not a place to add imports for a logger.
        org.slf4j.LoggerFactory.getLogger(VulnerableAuthzController.class)
                .info("anonymous caller read the internal metrics endpoint with {} subscriptions exposed",
                        repository.findAll().size());
        return Map.of("totalSubscriptions", repository.findAll().size(),
                "subscriptions", repository.findAll());
    }

    /** VULNERABLE: reached through {@code WebSecurityCustomizer.ignoring()} — no filters at all. */
    @GetMapping("/bypass/whoami")
    public Map<String, Object> bypass() {
        return Map.of("authenticated", false,
                "delivered", true,
                "note", "WebSecurityCustomizer.ignoring() removed the whole filter chain");
    }

    /**
     * VULNERABLE: the tenant boundary is taken from the request instead of the authenticated
     * principal, so horizontal privilege escalation across tenants is a query parameter away.
     */
    @GetMapping("/tenant/subscriptions")
    public ResponseEntity<?> tenantSubscriptions(@RequestParam String tenantId, Principal principal) {
        return ResponseEntity.ok(Map.of(
                "requestedTenant", tenantId,
                "callerTenant", tenantDirectory.getOrDefault(principal.getName(), "unknown"),
                "rows", repository.findByTenant(tenantId)));
    }

    /**
     * VULNERABLE: method security present but vacuous — {@code isAuthenticated()} says nothing about
     * <em>which</em> profile may be read.
     */
    @GetMapping("/profile/{username}")
    @PreAuthorize("isAuthenticated()")
    public Map<String, Object> profile(@PathVariable String username, Principal principal) {
        return Map.of("requested", username, "caller", principal.getName(),
                "email", username + "@example.invalid",
                "phone", "+7-000-000-" + Math.abs(username.hashCode() % 10000));
    }

    /** VULNERABLE: the client tells the server which authorities to grant. */
    @PostMapping("/register")
    public Map<String, Object> register(@RequestParam String username,
                                       @RequestParam(defaultValue = "USER") List<String> authorities) {
        return Map.of("username", username,
                "granted", authorities,
                "note", "in a real app these strings go straight into the user store");
    }

    /** VULNERABLE blast radius: an admin report gated only by hasRole, reachable by a self-granted role. */
    @GetMapping("/admin/report")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, Object> adminReport(Principal principal) {
        return Map.of("generatedFor", principal.getName(), "rows", repository.findAll());
    }
}
