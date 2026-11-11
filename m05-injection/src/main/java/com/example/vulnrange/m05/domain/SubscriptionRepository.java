package com.example.vulnrange.m05.domain;

import java.util.List;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

/**
 * Spring Data repository for the injection demos.
 *
 * <p>{@link #findByPlanAndTenant} is the <em>correct</em> form: named parameters, and a tenant
 * predicate that the caller cannot influence. {@code VulnerableInjectionController} shows the same
 * requirement built with string concatenation instead.
 */
@Repository
public interface SubscriptionRepository extends CrudRepository<SubscriptionEntity, String> {

    @Query("select s from SubscriptionEntity s where s.plan = :plan and s.tenantId = :tenantId order by s.createdAt desc")
    List<SubscriptionEntity> findByPlanAndTenant(@Param("plan") String plan, @Param("tenantId") String tenantId);

    List<SubscriptionEntity> findByOwnerUsername(String ownerUsername);
}
