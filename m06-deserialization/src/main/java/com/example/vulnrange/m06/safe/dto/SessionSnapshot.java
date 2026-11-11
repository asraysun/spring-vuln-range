package com.example.vulnrange.m06.safe.dto;

import java.io.Serial;
import java.io.Serializable;

/**
 * The only class a serialized session payload may contain. A concrete, final, DTO-shaped type:
 * no collections of interfaces, no polymorphic fields, nothing whose construction has effects.
 */
public final class SessionSnapshot implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private String subscriptionId;
    private String plan;
    private long asOfEpochSecond;

    public String getSubscriptionId() {
        return subscriptionId;
    }

    public void setSubscriptionId(String subscriptionId) {
        this.subscriptionId = subscriptionId;
    }

    public String getPlan() {
        return plan;
    }

    public void setPlan(String plan) {
        this.plan = plan;
    }

    public long getAsOfEpochSecond() {
        return asOfEpochSecond;
    }

    public void setAsOfEpochSecond(long asOfEpochSecond) {
        this.asOfEpochSecond = asOfEpochSecond;
    }
}
