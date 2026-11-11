package com.example.vulnrange.m02.domain;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Repository;

/**
 * In-memory stand-in for a JPA repository.
 *
 * <p>Note how the <em>safe</em> lookups take the owner/tenant as a query argument: the isolation
 * check happens where the data is read, which is the only place an attacker cannot negotiate with.
 * A real implementation would use {@code @Query("... where s.owner = :principal")} plus
 * {@code @EntityGraph} / Hibernate filters for multi-tenancy.
 */
@Repository
public class SubscriptionRepository {

    private final List<Subscription> table = new ArrayList<>();

    public SubscriptionRepository() {
        table.add(new Subscription("SUB-1001", "alice", "T-100", "ESPD-BASIC", new BigDecimal("990.00"), "alice@example.invalid"));
        table.add(new Subscription("SUB-1002", "alice", "T-100", "ESPD-PRO", new BigDecimal("2490.00"), "alice@example.invalid"));
        table.add(new Subscription("SUB-2001", "bob", "T-200", "ESPD-BASIC", new BigDecimal("990.00"), "bob@example.invalid"));
        table.add(new Subscription("SUB-3001", "mallory", "T-300", "ESPD-TRIAL", new BigDecimal("0.00"), "mallory@example.invalid"));
    }

    /** UNSAFE accessor: no owner/tenant predicate. Kept to demonstrate the IDOR. */
    public Optional<Subscription> findById(String id) {
        return table.stream().filter(s -> s.id().equals(id)).findFirst();
    }

    /** SAFE accessor: the boundary is part of the query, not of the caller's good intentions. */
    public Optional<Subscription> findByIdAndOwner(String id, String owner) {
        return table.stream()
                .filter(s -> s.id().equals(id) && s.ownerUsername().equals(owner))
                .findFirst();
    }

    /** SAFE accessor: tenant-scoped read. */
    public List<Subscription> findByTenant(String tenantId) {
        return table.stream().filter(s -> s.tenantId().equals(tenantId)).toList();
    }

    public List<Subscription> findAll() {
        return List.copyOf(table);
    }
}
