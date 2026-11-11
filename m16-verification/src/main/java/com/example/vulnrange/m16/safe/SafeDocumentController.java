package com.example.vulnrange.m16.safe;

import java.security.Principal;
import java.util.List;
import java.util.Map;

import com.example.vulnrange.m16.access.EspdDocumentStore;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Reference implementation of the ownership rule the matrix test asserts:
 * the caller is taken from the authenticated principal, ownership is checked on the row, and a foreign
 * row is indistinguishable from a missing one.
 */
@RestController
@RequestMapping("/safe16")
public class SafeDocumentController {

    private final EspdDocumentStore store;

    public SafeDocumentController(EspdDocumentStore store) {
        this.store = store;
    }

    @GetMapping("/documents/{id}")
    public ResponseEntity<?> document(@PathVariable String id, Principal principal) {
        if (principal == null || principal.getName() == null) {
            return ResponseEntity.status(401).body(Map.of("error", "authentication required"));
        }
        return store.find(id)
                .filter(document -> document.owner().equals(principal.getName()))
                .<ResponseEntity<?>>map(ResponseEntity::ok)
                // 404, not 403: the existence of the row is not the caller's to learn.
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /** The policy, stated in one place so the test matrix can be generated from it. */
    @GetMapping("/policy")
    public Map<String, Object> policy() {
        return Map.of(
                "identitySource", "java.security.Principal from the authenticated context",
                "ownershipRule", "document.owner == principal.name",
                "foreignResourceAnswer", 404,
                "unauthenticatedAnswer", 401,
                "matrix", List.of("unauthenticated", "owner", "other-user", "other-tenant", "deleted-row"));
    }
}
