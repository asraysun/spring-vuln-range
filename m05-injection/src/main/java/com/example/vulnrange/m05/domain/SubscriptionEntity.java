package com.example.vulnrange.m05.domain;

import java.math.BigDecimal;
import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** Row of the {@code subscription} table used by both the vulnerable and the safe query paths. */
@Entity
@Table(name = "subscription")
public class SubscriptionEntity {

    @Id
    @Column(name = "id", length = 32)
    private String id;

    @Column(name = "owner_username", length = 64)
    private String ownerUsername;

    @Column(name = "tenant_id", length = 16)
    private String tenantId;

    @Column(name = "plan", length = 32)
    private String plan;

    @Column(name = "customer_email", length = 254)
    private String customerEmail;

    @Column(name = "monthly_price")
    private BigDecimal monthlyPrice;

    @Column(name = "created_at")
    private Instant createdAt;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getOwnerUsername() {
        return ownerUsername;
    }

    public void setOwnerUsername(String ownerUsername) {
        this.ownerUsername = ownerUsername;
    }

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

    public String getPlan() {
        return plan;
    }

    public void setPlan(String plan) {
        this.plan = plan;
    }

    public String getCustomerEmail() {
        return customerEmail;
    }

    public void setCustomerEmail(String customerEmail) {
        this.customerEmail = customerEmail;
    }

    public BigDecimal getMonthlyPrice() {
        return monthlyPrice;
    }

    public void setMonthlyPrice(BigDecimal monthlyPrice) {
        this.monthlyPrice = monthlyPrice;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }
}
