package com.example.vulnrange.m16.access;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import org.springframework.stereotype.Service;

/**
 * A tiny document store with an owner on every row: enough to write a meaningful authorization test
 * without dragging in a database. Synthetic data only.
 */
@Service
public class EspdDocumentStore {

    public record EspdDocument(String id, String owner, String tenantId, String registrationNumber, String content) {
    }

    private final Map<String, EspdDocument> documents = new LinkedHashMap<>();

    public EspdDocumentStore() {
        documents.put("DOC-0001", new EspdDocument("DOC-0001", "alice", "T-100", "0442-9-ESPD-0001", "declaration body A"));
        documents.put("DOC-0002", new EspdDocument("DOC-0002", "bob", "T-200", "0442-9-ESPD-0002", "declaration body B"));
        documents.put("DOC-0003", new EspdDocument("DOC-0003", "alice", "T-100", "0442-9-ESPD-0003", "declaration body C"));
    }

    public Optional<EspdDocument> find(String id) {
        return Optional.ofNullable(documents.get(id));
    }
}
