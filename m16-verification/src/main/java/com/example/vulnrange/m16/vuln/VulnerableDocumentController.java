package com.example.vulnrange.m16.vuln;

import java.security.Principal;

import com.example.vulnrange.m16.access.EspdDocumentStore;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * VULNERABLE (intentional): "authenticated" is treated as "authorised for this row". This controller
 * exists so that the authorization matrix test has something it is <em>expected</em> to complain
 * about — a test that only asserts the good case cannot detect this class of regression.
 */
@RestController
@RequestMapping("/vuln16")
public class VulnerableDocumentController {

    private final EspdDocumentStore store;

    public VulnerableDocumentController(EspdDocumentStore store) {
        this.store = store;
    }

    @GetMapping("/documents/{id}")
    public ResponseEntity<?> document(@PathVariable String id, Principal principal) {
        return store.find(id)
                .<ResponseEntity<?>>map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }
}
