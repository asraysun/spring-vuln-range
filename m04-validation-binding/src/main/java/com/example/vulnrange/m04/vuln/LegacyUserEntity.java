package com.example.vulnrange.m04.vuln;

import java.math.BigDecimal;

/**
 * VULNERABLE (intentional): the persistence object doubles as the request object.
 *
 * <p>Because Spring binds <em>every</em> writable property it can reach from the request, the fields
 * that only a human operator should control ({@code role}, {@code enabled}, {@code monthlyLimit},
 * {@code priceOverride}) become client input the moment this class is used as a controller argument.
 * This is CWE-915 (mass assignment) and it is invisible in a code review that only looks at the
 * controller body.
 */
public class LegacyUserEntity {

    private String username;
    private String email;
    private String role = "USER";
    private boolean enabled = true;
    private BigDecimal monthlyLimit = new BigDecimal("1000");
    private BigDecimal priceOverride = BigDecimal.ZERO;
    private String tenantId;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public BigDecimal getMonthlyLimit() {
        return monthlyLimit;
    }

    public void setMonthlyLimit(BigDecimal monthlyLimit) {
        this.monthlyLimit = monthlyLimit;
    }

    public BigDecimal getPriceOverride() {
        return priceOverride;
    }

    public void setPriceOverride(BigDecimal priceOverride) {
        this.priceOverride = priceOverride;
    }

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

    @Override
    public String toString() {
        return "LegacyUserEntity{username=" + username + ", email=" + email + ", role=" + role
                + ", enabled=" + enabled + ", monthlyLimit=" + monthlyLimit
                + ", priceOverride=" + priceOverride + ", tenantId=" + tenantId + "}";
    }
}
