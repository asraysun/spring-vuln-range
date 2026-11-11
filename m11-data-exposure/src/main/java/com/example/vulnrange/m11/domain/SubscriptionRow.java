package com.example.vulnrange.m11.domain;

import java.math.BigDecimal;
import java.time.Instant;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

/** Child rows of a subscriber; the back-reference is hidden to avoid a serialisation cycle. */
@Entity
@Table(name = "subscription_row")
public class SubscriptionRow {

    @Id
    @Column(name = "id", length = 32)
    private String id;

    @Column(name = "plan", length = 32)
    private String plan;

    @Column(name = "monthly_price")
    private BigDecimal monthlyPrice;

    @Column(name = "activated_at")
    private Instant activatedAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "subscriber_id")
    @JsonIgnore
    private SubscriberEntity subscriber;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getPlan() {
        return plan;
    }

    public void setPlan(String plan) {
        this.plan = plan;
    }

    public BigDecimal getMonthlyPrice() {
        return monthlyPrice;
    }

    public void setMonthlyPrice(BigDecimal monthlyPrice) {
        this.monthlyPrice = monthlyPrice;
    }

    public Instant getActivatedAt() {
        return activatedAt;
    }

    public void setActivatedAt(Instant activatedAt) {
        this.activatedAt = activatedAt;
    }

    public SubscriberEntity getSubscriber() {
        return subscriber;
    }

    public void setSubscriber(SubscriberEntity subscriber) {
        this.subscriber = subscriber;
    }
}
