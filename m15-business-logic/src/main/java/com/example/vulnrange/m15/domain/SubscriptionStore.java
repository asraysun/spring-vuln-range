package com.example.vulnrange.m15.domain;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.EnumSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The subscription aggregate: state, paid amount and an optimistic version.
 *
 * <p>{@link #ALLOWED_TRANSITIONS} is the state machine the vulnerable endpoints skip. Missing from a
 * map means "not allowed", which is the only safe default for a lifecycle that moves money.
 */
public final class SubscriptionStore {

    public enum State {
        TRIAL, ACTIVE, PAST_DUE, CANCELLED, EXPIRED
    }

    public static final Map<State, Set<State>> ALLOWED_TRANSITIONS = Map.of(
            State.TRIAL, EnumSet.of(State.ACTIVE, State.CANCELLED, State.EXPIRED),
            State.ACTIVE, EnumSet.of(State.PAST_DUE, State.CANCELLED, State.EXPIRED),
            State.PAST_DUE, EnumSet.of(State.ACTIVE, State.CANCELLED, State.EXPIRED),
            // Terminal states: nothing may leave them. Re-activation requires a new subscription.
            State.CANCELLED, EnumSet.noneOf(State.class),
            State.EXPIRED, EnumSet.noneOf(State.class));

    public static final class Subscription {
        public final String id;
        public final String owner;
        public volatile String tariffCode;
        public volatile BigDecimal amountPaid;
        public volatile State state;
        public volatile long version;
        public final AtomicLong documentsToday = new AtomicLong();
        public volatile Instant documentsQuotaDate;
        public volatile String grantedScopes;
        public volatile Instant consentExpiresAt;

        Subscription(String id, String owner, String tariffCode, BigDecimal amountPaid, State state) {
            this.id = id;
            this.owner = owner;
            this.tariffCode = tariffCode;
            this.amountPaid = amountPaid;
            this.state = state;
            this.version = 1L;
            this.documentsQuotaDate = Instant.now();
        }

        public Map<String, Object> asMap() {
            return Map.of(
                    "id", id,
                    "owner", owner,
                    "tariff", Objects.toString(tariffCode, ""),
                    "amountPaid", Objects.toString(amountPaid, ""),
                    "state", state.name(),
                    "version", version,
                    "documentsToday", documentsToday.get(),
                    "grantedScopes", Objects.toString(grantedScopes, ""),
                    "consentExpiresAt", Objects.toString(consentExpiresAt, "none"));
        }
    }

    private final Map<String, Subscription> subscriptions = new ConcurrentHashMap<>();

    public SubscriptionStore() {
        subscriptions.put("SUB-1001", new Subscription("SUB-1001", "alice", "ESPD-BASIC",
                new BigDecimal("990.00"), State.ACTIVE));
        subscriptions.put("SUB-1002", new Subscription("SUB-1002", "alice", "ESPD-PRO",
                new BigDecimal("2490.00"), State.TRIAL));
        subscriptions.put("SUB-2001", new Subscription("SUB-2001", "bob", "ESPD-TRIAL",
                BigDecimal.ZERO, State.TRIAL));
    }

    public Subscription get(String id) {
        return subscriptions.get(id);
    }

    public Map<String, Subscription> all() {
        return Map.copyOf(subscriptions);
    }

    public Subscription create(String id, String owner, String tariffCode, BigDecimal amountPaid, State state) {
        Subscription created = new Subscription(id, owner, tariffCode, amountPaid, state);
        subscriptions.put(id, created);
        return created;
    }

    /**
     * Compare-and-set on the version: the concurrency control that turns "click activate twice" into a
     * single state change plus one 409.
     */
    public synchronized boolean transition(String id, State target, long expectedVersion) {
        Subscription subscription = subscriptions.get(id);
        if (subscription == null || subscription.version != expectedVersion) {
            return false;
        }
        if (!ALLOWED_TRANSITIONS.getOrDefault(subscription.state, EnumSet.noneOf(State.class)).contains(target)) {
            return false;
        }
        subscription.state = target;
        subscription.version++;
        return true;
    }

    /** Unguarded transition used by the vulnerable endpoints: no allowed-set check, no version check. */
    public synchronized void forceTransition(String id, State target) {
        Subscription subscription = subscriptions.get(id);
        if (subscription != null) {
            subscription.state = target;
            subscription.version++;
        }
    }
}
