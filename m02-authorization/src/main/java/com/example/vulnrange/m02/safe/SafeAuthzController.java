package com.example.vulnrange.m02.safe;

import java.security.Principal;
import java.util.List;
import java.util.Map;

import com.example.vulnrange.m02.domain.Subscription;
import com.example.vulnrange.m02.domain.SubscriptionRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Reference implementation of checklist section 2. Three rules do most of the work:
 *
 * <ol>
 *   <li>the tenant/owner always comes from the authenticated principal, never from the request;</li>
 *   <li>authorization is enforced where the row is read, not only in front of the controller;</li>
 *   <li>denials and not-founds are indistinguishable to the caller.</li>
 * </ol>
 */
@RestController
@RequestMapping("/safe2")
public class SafeAuthzController {

    private final SubscriptionRepository repository;
    private final Map<String, String> tenantDirectory;

    public SafeAuthzController(SubscriptionRepository repository, Map<String, String> tenantDirectory) {
        this.repository = repository;
        this.tenantDirectory = tenantDirectory;
    }

    /** Object-level check via repository ownership predicate; 404 for foreign rows to avoid enumeration.
     *  Note: we rely on the filter-chain authz (/safe2/** → authenticated) and the
     *  findByIdAndOwner query — using @PreAuthorize here would leak 403 (denied) instead
     *  of 404 (not found), which would reveal that the row exists but belongs to someone else. */
    @GetMapping("/subscriptions/{id}")
    public ResponseEntity<?> subscription(@PathVariable String id, Principal principal) {
        return repository.findByIdAndOwner(id, principal.getName())
                .<ResponseEntity<?>>map(ResponseEntity::ok)
                // Same answer as "does not exist": existence is not authorisation info.
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PostMapping("/subscriptions/{id}/cancel")
    @PreAuthorize("@subscriptionAccess.canModify(authentication, #id)")
    public ResponseEntity<?> cancel(@PathVariable String id, Principal principal) {
        // State change is POST-only, so a "public read" matcher can never reach it.
        return repository.findByIdAndOwner(id, principal.getName())
                .<ResponseEntity<?>>map(s -> ResponseEntity.ok(Map.of("id", s.id(), "status", "CANCELLED")))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping("/subscriptions")
    public List<Subscription> mySubscriptions(Principal principal) {
        return repository.findAll().stream()
                .filter(s -> s.ownerUsername().equals(principal.getName()))
                .toList();
    }

    /** Tenant id is derived from the caller, so cross-tenant reads require a real credential. */
    @GetMapping("/tenant/subscriptions")
    public List<Subscription> tenantSubscriptions(Principal principal) {
        return repository.findByTenant(tenantDirectory.getOrDefault(principal.getName(), "NONE"));
    }

    @GetMapping("/admin/subscriptions")
    public List<Subscription> adminSubscriptions() {
        // Role check lives in the filter chain (/safe2/admin/** -> hasRole('ADMIN')) and is repeated
        // here on purpose: defence in depth, because URL rules and code paths drift apart.
        return repository.findAll();
    }

    @GetMapping("/admin/report")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, Object> adminReport(Principal principal) {
        return Map.of("generatedFor", principal.getName(), "rows", repository.findAll());
    }

    /** Authorities are assigned by the server from a fixed policy; the client gets no vote. */
    @PostMapping("/register")
    public Map<String, Object> register(Principal principal) {
        return Map.of("username", principal == null ? "anonymous" : principal.getName(),
                "granted", List.of("USER"));
    }

    /**
     * Object-level policy. Keeping it in one bean (instead of ad-hoc {@code if}s in controllers)
     * makes the rules unit-testable and gives the negative-authorization matrix in m16 a single
     * place to assert against.
     */
    @Service("subscriptionAccess")
    public static class SubscriptionAccess {

        private final SubscriptionRepository repository;
        private final Map<String, String> tenantDirectory;

        public SubscriptionAccess(SubscriptionRepository repository, Map<String, String> tenantDirectory) {
            this.repository = repository;
            this.tenantDirectory = tenantDirectory;
        }

        public boolean canRead(org.springframework.security.core.Authentication auth, String id) {
            // Only ownership is checked here so that a denied read and a missing row
            // both collapse to 404 (existence is not authorisation info). Admin access
            // to all objects is handled by /safe2/admin/** which uses hasRole('ADMIN').
            return owns(auth, id);
        }

        public boolean canModify(org.springframework.security.core.Authentication auth, String id) {
            return owns(auth, id);
        }

        private boolean owns(org.springframework.security.core.Authentication auth, String id) {
            if (auth == null || auth.getName() == null) {
                return false;
            }
            return repository.findByIdAndOwner(id, auth.getName()).isPresent();
        }

        private boolean isAdmin(org.springframework.security.core.Authentication auth) {
            return auth != null && auth.getAuthorities().stream()
                    .anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()));
        }

        String tenantOf(org.springframework.security.core.Authentication auth) {
            return tenantDirectory.getOrDefault(auth == null ? "" : auth.getName(), "NONE");
        }
    }
}
