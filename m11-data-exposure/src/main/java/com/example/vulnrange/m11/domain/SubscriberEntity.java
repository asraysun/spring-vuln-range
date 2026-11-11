package com.example.vulnrange.m11.domain;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;

/**
 * VULNERABLE (intentional) as soon as this object becomes a response body, which is exactly what the
 * {@code /vuln11} endpoints do: the persistence model and the wire model are the same thing, so every
 * column that somebody adds to the table is a column that is published by the API on the same day.
 */
@Entity
@Table(name = "subscriber")
public class SubscriberEntity {

    @Id
    @Column(name = "id", length = 32)
    private String id;

    @Column(name = "username", length = 64)
    private String username;

    @Column(name = "email", length = 254)
    private String email;

    @Column(name = "phone", length = 32)
    private String phone;

    /** VULNERABLE: published by {@code GET /vuln11/subscribers/{id}}. */
    @Column(name = "password_hash", length = 200)
    private String passwordHash;

    /** VULNERABLE: a long-lived refresh token in a read-model response is a session you cannot revoke. */
    @Column(name = "refresh_token", length = 200)
    private String refreshToken;

    /** VULNERABLE: internal risk/quota fields become public API surface. */
    @Column(name = "internal_risk_score")
    private Integer internalRiskScore;

    @Column(name = "gdpr_erasure_requested")
    private Boolean gdprErasureRequested;

    @Column(name = "inn", length = 12)
    private String inn;

    @Column(name = "snils", length = 14)
    private String snils;

    @Column(name = "espd_token_hash", length = 200)
    private String espdTokenHash;

    @OneToMany(mappedBy = "subscriber", fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    private List<SubscriptionRow> subscriptions = new ArrayList<>();

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

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

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public Integer getInternalRiskScore() {
        return internalRiskScore;
    }

    public void setInternalRiskScore(Integer internalRiskScore) {
        this.internalRiskScore = internalRiskScore;
    }

    public Boolean getGdprErasureRequested() {
        return gdprErasureRequested;
    }

    public void setGdprErasureRequested(Boolean gdprErasureRequested) {
        this.gdprErasureRequested = gdprErasureRequested;
    }

    public String getInn() {
        return inn;
    }

    public void setInn(String inn) {
        this.inn = inn;
    }

    public String getSnils() {
        return snils;
    }

    public void setSnils(String snils) {
        this.snils = snils;
    }

    public String getEspdTokenHash() {
        return espdTokenHash;
    }

    public void setEspdTokenHash(String espdTokenHash) {
        this.espdTokenHash = espdTokenHash;
    }

    public List<SubscriptionRow> getSubscriptions() {
        return subscriptions;
    }

    public void setSubscriptions(List<SubscriptionRow> subscriptions) {
        this.subscriptions = subscriptions;
    }
}
