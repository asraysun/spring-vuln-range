# Spring Security: How to Prevent Business Logic & Revenue Integrity Vulnerabilities

A practical guide to securing Spring Boot against client-driven business decisions, state machine bypass, race conditions, replay attacks, and entitlement manipulation — covering 10 CWEs found in real Spring applications.

---

## Table of Contents

1. [Server-Driven Pricing & Discounts](#1-server-driven-pricing--discounts)
2. [Entitlements & Quotas as Lookups, Not Flags](#2-entitlements--quotas-as-lookups-not-flags)
3. [Explicit State Machine Enforcement](#3-explicit-state-machine-enforcement)
4. [Optimistic Concurrency Control](#4-optimistic-concurrency-control)
5. [Payment Callback Idempotency](#5-payment-callback-idempotency)
6. [Derived Renewal Periods](#6-derived-renewal-periods)
7. [Scope Allow-List for Consent](#7-scope-allow-list-for-consent)
8. [Bounded Consent Lifetime](#8-bounded-consent-lifetime)
9. [Audit Trail for Business Decisions](#9-audit-trail-for-business-decisions)

---

## 1. Server-Driven Pricing & Discounts

**CWE-472** — *External Control of Statement or Expression (Client-Driven Business Decisions)*

### The Problem

CWE-472 is the core business-logic vulnerability: when the client (request body, query parameter, header) decides business values that should be determined server-side. This includes price, discount, renewal period, and any other business rule. The server trusts the client's numbers, which means an attacker can set any price to zero, any discount to 100%, any renewal period to 10 years. This is not a code bug — it is an architectural failure where the client is treated as a trusted source of business truth.

```java
// ❌ VULNERABLE — price and currency chosen by the caller
@PostMapping("/orders")
public ResponseEntity<?> createOrder(@RequestBody OrderRequest req) {
    // Attacker sends: {"subscriptionId":"SUB-EVIL-1","plan":"ESPD-PRO","price":"1.00","currency":"RUB"}
    // The catalog exists but is never consulted
    // Attacker pays 1 RUB for a plan that should cost 10,000 RUB
    subscriptionService.createOrder(req.getSubscriptionId(), req.getPlan(), req.getPrice(), req.getCurrency());
    return ResponseEntity.ok("ordered");
}

// ❌ VULNERABLE — discount treated as a client string
// Attacker sends: {"discount":"100%"} — gets everything for free
// The discount is a client string, not a server-owned rule

// ❌ VULNERABLE — renewal length taken from the message
@PostMapping("/payment/callback")
public ResponseEntity<?> paymentCallback(@RequestBody PaymentCallback req) {
    // Attacker sends: {"subscriptionId":"SUB-2001","status":"PAID","days":3650}
    // 3650 days ≈ 10 years. The renewal period should come from the order, not the callback
    subscriptionService.renew(req.getSubscriptionId(), req.getDays());
    return ResponseEntity.ok("renewed");
}
```

### The Fix

The request names a plan; the amount, currency, features, and rules come from server-side state.

```java
// ✅ SAFE — the catalog is the only price
@PostMapping("/orders")
public ResponseEntity<?> createOrder(@Valid @RequestBody OrderRequest req) {
    // Request names a plan only — validate pattern
    if (!req.getPlan().matches("^ESPD-(TRIAL|BASIC|PRO)$")) {
        return ResponseEntity.badRequest().body("Invalid plan");
    }

    // Amount, currency, features come from TariffCatalog
    Tariff tariff = tariffCatalog.get(req.getPlan());
    BigDecimal price = tariff.price();
    String currency = tariff.currency();
    List<String> features = tariff.features();

    // If amount must be agreed with payment provider, compare with server's value
    if (req.getAmount() != null && !req.getAmount().equals(price)) {
        log.warn("Price mismatch for subscription {}: client={}, catalog={}",
            req.getSubscriptionId(), req.getAmount(), price);
        return ResponseEntity.status(400).body("Amount mismatch with catalog");
    }

    subscriptionService.createOrder(req.getSubscriptionId(), req.getPlan(), price, currency);
    return ResponseEntity.ok(Map.of("priceDecidedBy", "server-catalog"));
}

// ✅ SAFE — discounts are server-owned rules with eligibility
public BigDecimal discountedPrice(Tariff tariff, String discountCode, boolean firstYear) {
    return switch (discountCode) {
        case "FIRSTYEAR" -> firstYear
            ? tariff.price().multiply(new BigDecimal("0.85"))  // 15% discount
            : tariff.price();
        case "LOYALTY" -> tariff.price().multiply(new BigDecimal("0.90"));  // 10% discount
        default -> tariff.price();  // Unknown codes are simply not in the rule set
    };
}
```

**Key rules:**
- The request names a plan (`^ESPD-(TRIAL|BASIC|PRO)$`); the amount, currency and features come from `TariffCatalog`
- If an amount must be agreed with a payment provider, compare it with the server's own value and reject the mismatch
- **Never store the client's number** — re-derive everything from server-side state
- Discounts are server-owned rules with eligibility checks — a code the client invents is simply not in the rule set

---

## 2. Entitlements & Quotas as Lookups, Not Flags

**CWE-602** — *Client-Side Enforcement in a Trust-Unworthy Context*  
**CWE-285** — *Improper Authorization (Entitlement from Request Parameter)*

### The Problem

CWE-602 covers any business rule enforced on the client side (browser, mobile app) instead of the server. A UI that hides a button is not a control. A client-side validation that checks `if (user.isPro)` at login and never re-checks is trivially bypassed. Business logic enforced client-side is invisible to the server and can be bypassed by any HTTP tool.

CWE-285 in the context of business logic refers to entitlements and permissions decided by request parameters instead of server-side state. When `?entitled=true` grants access, any caller can enable any feature for any subscription.

```java
// ❌ VULNERABLE — entitlement decided by a request parameter
@GetMapping("/features/{key}")
public ResponseEntity<?> getFeature(@PathVariable String key,
                                     @RequestParam boolean entitled) {
    // Attacker sends: ?entitled=true
    // Gets access to espd.admin, espd.everything — features they don't have
    return ResponseEntity.ok(Map.of("entitled", entitled, "feature", key));
}

// ❌ VULNERABLE — quota from the request, no per-account accounting
@PostMapping("/documents/generate")
public ResponseEntity<?> generate(@RequestParam int limit) {
    // Attacker sends: ?limit=10000
    // Generates 10,000 documents — the "download limit" enforced in the browser is bypassed
    documentService.generate(limit);
    return ResponseEntity.ok("generated");
}
```

### The Fix

Entitlements and quotas are **lookups**, not flags from the request.

```java
// ✅ SAFE — entitlement is a lookup, not a flag
@GetMapping("/features/{key}")
public ResponseEntity<?> getFeature(@PathVariable String key,
                                     @RequestParam String subscriptionId) {
    Subscription sub = subscriptionStore.get(subscriptionId);
    boolean entitled = (sub.getState() == State.ACTIVE || sub.getState() == State.TRIAL)
            && tariffCatalog.get(sub.getPlan()).features().contains(key);
    return ResponseEntity.ok(Map.of("entitled", entitled));
}

// ✅ SAFE — quota is per account per day
@PostMapping("/documents/generate")
public ResponseEntity<?> generate(@RequestParam String subscriptionId) {
    Subscription sub = subscriptionStore.get(subscriptionId);
    Tariff tariff = tariffCatalog.get(sub.getPlan());
    int limit = tariff.dailyDocumentLimit();

    // Count used today
    int used = dailyDocumentCounter.count(sub.getId(), LocalDate.now());

    if (used >= limit) {
        log.info("quota_exceeded: subscription={}, used={}, limit={}", sub.getId(), used, limit);
        return ResponseEntity.status(429).body("Quota exceeded (daily limit: " + limit + ")");
    }

    dailyDocumentCounter.increment(sub.getId(), LocalDate.now());
    documentService.generate(sub.getId());
    return ResponseEntity.ok("generated");
}
```

**Key rules:**
- `feature(key)` = subscription is ACTIVE or TRIAL **and** the tariff's feature list contains the key
- `documents/generate` counts per subscription per day against `dailyDocumentLimit` and answers `429` past it
- A UI that hides a button is **not a control** — the server must enforce it
- Never trust `?entitled=true` or `?limit=10000` from the request

---

## 3. Explicit State Machine Enforcement

**CWE-841** — *Improper Enforcement of Behavioral Workflow (State Machine Bypass)*

### The Problem

CWE-841 covers subscription lifecycle bypass: when the state machine is not enforced, an attacker can transition a subscription from any state to any other state, including leaving a terminal state. `CANCELLED → ACTIVE` should be impossible — re-activation is a new subscription, not an edge in the graph. Without an explicit state machine, every state transition is reachable from every other state.

```java
// ❌ VULNERABLE — subscription state machine bypass
@PostMapping("/subscriptions/{id}/state")
public ResponseEntity<?> transition(@PathVariable String id,
                                     @RequestParam String to,
                                     @RequestParam boolean forceTransition) {
    // Attacker sends: ?to=CANCELLED (works)
    // Then: ?to=ACTIVE (also works! CANCELLED is not terminal)
    // forceTransition bypasses the state machine entirely
    subscriptionService.forceTransition(id, to);
    return ResponseEntity.ok("transitioned to " + to);
}
```

`POST /vuln15/subscriptions/SUB-1001/state?to=CANCELLED` cancels the subscription.
`POST /vuln15/subscriptions/SUB-1001/state?to=ACTIVE` reactivates it — `CANCELLED` is not terminal.

### The Fix

An explicit state machine with a default of "not allowed".

```java
// ✅ SAFE — explicit state machine with default of "not allowed"
private static final Map<State, Set<State>> ALLOWED_TRANSITIONS = Map.of(
    State.TRIAL, Set.of(State.ACTIVE, State.CANCELLED, State.EXPIRED),
    State.ACTIVE, Set.of(State.CANCELLED, State.SUSPENDED),
    State.SUSPENDED, Set.of(State.ACTIVE, State.CANCELLED),
    // CANCELLED and EXPIRED have NO edges — nothing may leave them
);

@PostMapping("/subscriptions/{id}/state")
public ResponseEntity<?> transition(@PathVariable String id,
                                     @RequestParam String to,
                                     @RequestParam String ifMatch) {
    Subscription sub = subscriptionStore.get(id);
    State current = sub.getState();
    State target;
    try {
        target = State.valueOf(to);
    } catch (IllegalArgumentException e) {
        return ResponseEntity.badRequest().body("Invalid target state: " + to);
    }

    // Check ALLOWED_TRANSITIONS
    Set<State> allowed = ALLOWED_TRANSITIONS.get(current);
    if (allowed == null || !allowed.contains(target)) {
        log.info("transition_rejected: subscription={}, from={}, to={}", id, current, target);
        return ResponseEntity.status(422).body(Map.of(
            "error", "transition rejected",
            "from", current,
            "to", target,
            "allowed", allowed
        ));
    }

    // Optimistic concurrency (see CWE-362)
    if (!String.valueOf(sub.getVersion()).equals(ifMatch)) {
        return ResponseEntity.status(409).body("Stale version — current: " + sub.getVersion());
    }

    subscriptionStore.transition(id, target, sub.getVersion());
    log.info("transition_accepted: subscription={}, from={}, to={}", id, current, target);
    return ResponseEntity.ok("transitioned to " + target);
}
```

**Key rules:**
- `ALLOWED_TRANSITIONS` maps each state to the set it may move to
- A missing entry (`CANCELLED`, `EXPIRED`) means **nothing may leave it**
- Re-activation is a new subscription, not an edge in the graph
- Anything outside the set is a `422` with the allowed set in the body
- Log `transition_rejected` and `transition_accepted` for every attempt

---

## 4. Optimistic Concurrency Control

**CWE-362** — *Concurrent Execution Using Shared Resource with Improper Synchronization (Race Condition)*

### The Problem

CWE-362 covers race conditions in business logic: when two clients race the same state transition, both succeed because there is no optimistic concurrency control. A double-click, a retried request, or two browser tabs all trigger separate state changes that are not serialized. This leads to duplicate applications, inconsistent state, and revenue loss.

```java
// ❌ VULNERABLE — no optimistic concurrency
@PostMapping("/subscriptions/{id}/state")
public ResponseEntity<?> transition(@PathVariable String id,
                                     @RequestParam String to) {
    // Client A reads version=1, sends ?to=ACTIVE
    // Client B reads version=1, sends ?to=CANCELLED
    // Both succeed — the second one should have been rejected (stale version)
    Subscription sub = subscriptionStore.get(id);
    sub.setState(State.valueOf(to));  // No version check
    subscriptionStore.save(sub);
    return ResponseEntity.ok("transitioned");
}
```

### The Fix

Optimistic concurrency on every transition using `ifMatch` (Etag-style).

```java
// ✅ SAFE — optimistic concurrency on every transition
// Client sends: POST /subscriptions/{id}/state?to=CANCELLED&ifMatch=3

@PostMapping("/subscriptions/{id}/state")
public ResponseEntity<?> transition(@PathVariable String id,
                                     @RequestParam String to,
                                     @RequestParam String ifMatch) {
    Subscription sub = subscriptionStore.get(id);

    // Compare-and-set under a lock
    if (!String.valueOf(sub.getVersion()).equals(ifMatch)) {
        log.warn("version_mismatch: subscription={}, client_version={}, current_version={}",
            id, ifMatch, sub.getVersion());
        return ResponseEntity.status(409).body(Map.of(
            "error", "Stale version",
            "expected", sub.getVersion(),
            "client", Integer.parseInt(ifMatch)
        ));
    }

    subscriptionStore.transition(id, State.valueOf(to), sub.getVersion());
    return ResponseEntity.ok("transitioned");
}

// SubscriptionStore.transition() does compare-and-set:
public void transition(String id, State target, int expectedVersion) {
    synchronized (this) {  // In production: database transaction with SELECT ... FOR UPDATE
        Subscription sub = store.get(id);
        if (sub.getVersion() != expectedVersion) {
            throw new OptimisticLockException("Version mismatch");
        }
        sub.setState(target);
        sub.setVersion(sub.getVersion() + 1);
        store.put(id, sub);
    }
}
```

**Key rules:**
- `ifMatch` carries the version the client last read
- `SubscriptionStore.transition(id, target, expectedVersion)` does compare-and-set
- Double-click, retried request and two tabs all collapse into one state change
- In production: use a database transaction with `SELECT ... FOR UPDATE` or a unique version index
- Return `409 Conflict` with the current version so the client can retry

---

## 5. Payment Callback Idempotency

**CWE-294** — *Authentication Bypass Using a Replay Attack (Payment Callback)*  
**CWE-837** — *Improper Enforcement of a Single Action Per Request (Duplicate Processing)*

### The Problem

CWE-294 in the context of webhooks/callbacks refers to replaying a valid payment callback multiple times. CWE-837 covers the lack of idempotency: when the same request is processed multiple times, each processing produces a new effect. A payment provider can resend a callback on timeout — the server must handle this gracefully.

```java
// ❌ VULNERABLE — replayed payment callback: no idempotency key
@PostMapping("/payment/callback")
public ResponseEntity<?> paymentCallback(@RequestBody PaymentCallback req) {
    // Attacker sends the same callback 3 times → 3 applications
    for (int i = 0; i < 3; i++) {
        subscriptionService.renew(req.getSubscriptionId(), req.getDays());
        // Each application extends the subscription by req.getDays()
        // 3 replays = 3 × 30 days = 90 days instead of 30
    }
    return ResponseEntity.ok("processed");
}
```

### The Fix

Idempotency key mandatory, stored with the outcome.

```java
// ✅ SAFE — Idempotency-Key mandatory, bounded, stored with outcome
private static final Set<String> PROCESSED_EVENTS = ConcurrentHashMap.newKeySet();
private static final Map<String, PaymentEvent> EVENT_STORE = new ConcurrentHashMap<>();

@PostMapping("/payment/callback")
public ResponseEntity<?> paymentCallback(@RequestBody PaymentCallback req,
                                          @RequestHeader("Idempotency-Key") String eventId) {
    // 1. Idempotency-Key is mandatory and bounded
    if (eventId == null || eventId.isBlank()) {
        return ResponseEntity.badRequest().body("Idempotency-Key header is required");
    }
    if (eventId.length() > 64) {
        return ResponseEntity.badRequest().body("Idempotency-Key must be ≤ 64 characters");
    }

    // 2. Check for duplicate
    PaymentEvent existing = EVENT_STORE.get(eventId);
    if (existing != null) {
        log.info("payment_duplicate: eventId={}, subscriptionId={}, originallyAppliedAt={}",
            eventId, req.getSubscriptionId(), existing.getAppliedAt());
        return ResponseEntity.ok(Map.of(
            "duplicate", true,
            "originallyAppliedAt", existing.getAppliedAt()
        ));
    }

    // 3. Process the payment
    subscriptionService.renew(req.getSubscriptionId(), req.getDays());

    // 4. Store the outcome
    PaymentEvent event = new PaymentEvent(req.getSubscriptionId(), req.getStatus(), Instant.now());
    EVENT_STORE.put(eventId, event);
    PROCESSED_EVENTS.add(eventId);

    return ResponseEntity.ok("processed");
}

// Production: use a database table with a unique index
// CREATE TABLE payment_events (
//     event_id VARCHAR(64) PRIMARY KEY,
//     subscription_id VARCHAR(50) NOT NULL,
//     status VARCHAR(20) NOT NULL,
//     applied_at TIMESTAMP NOT NULL
// );
```

**Key rules:**
- `Idempotency-Key` is **mandatory**, bounded (64 characters)
- Second delivery returns `duplicate: true`, `originallyAppliedAt` instead of applying again
- In production: use a **unique index** on the payment-event table, not a `ConcurrentHashMap`
- Payment providers can resend callbacks on timeout — design for this
- Log `payment_duplicate` for security monitoring

---

## 6. Derived Renewal Periods

**CWE-472** — *External Control of Statement or Expression (Client-Driven Business Decisions)*

### The Problem

The renewal period, charged amount, and resulting state are computed from the order and the subscription. A callback is a fact about a payment, not an instruction to the subscription. When the callback carries `days` or `amount`, the client controls business logic.

```java
// ❌ VULNERABLE — renewal length taken from the callback
@PostMapping("/payment/callback")
public ResponseEntity<?> paymentCallback(@RequestBody PaymentCallback req) {
    // Attacker sends: {"subscriptionId":"SUB-2001","status":"PAID","days":3650}
    // The callback extends the subscription by 3650 days (~10 years)
    // The renewal period should come from the order, not the callback
    subscriptionService.renew(req.getSubscriptionId(), req.getDays());
    return ResponseEntity.ok("renewed");
}
```

### The Fix

Derive everything from server-side state. The callback is a fact about a payment, not an instruction.

```java
// ✅ SAFE — renewal derived from the order
@PostMapping("/payment/callback")
public ResponseEntity<?> paymentCallback(@RequestBody PaymentCallback req,
                                          @RequestHeader("Idempotency-Key") String eventId) {
    // Validate event ID (see CWE-294 section above)
    // ...

    // Derive renewal from the order, not the callback
    Order order = orderRepository.findBySubscriptionId(req.getSubscriptionId());
    if (order == null) {
        return ResponseEntity.status(400).body("No order found for subscription");
    }

    // The order carries: renewalDays, amountCharged, plan
    int renewalDays = order.getRenewalDays();  // e.g., 30 days
    BigDecimal amountCharged = order.getAmountCharged();

    // Verify the payment amount matches the order
    if (req.getAmount() != null && !req.getAmount().compareTo(amountCharged) == 0) {
        log.warn("payment_amount_mismatch: subscription={}, order={}, callback={}",
            req.getSubscriptionId(), amountCharged, req.getAmount());
        return ResponseEntity.status(400).body("Payment amount mismatch");
    }

    subscriptionService.renew(req.getSubscriptionId(), renewalDays);
    return ResponseEntity.ok("renewed for " + renewalDays + " days");
}
```

**Key rules:**
- The callback is a **fact about a payment**, not an instruction
- Renewal period, charged amount, and resulting state are **computed from the order**
- If the callback carries `days` or `amount`, ignore them and derive from server-side state
- Verify payment amounts match the order — reject mismatches

---

## 7. Scope Allow-List for Consent

**CWE-863** — *Incorrect Authorization (Consent with Arbitrary Scopes)*

### The Problem

CWE-863 in the context of business logic refers to consent records written from whatever the OAuth client sends, including scopes that were never offered (like `espd.admin`) and expiry dates far in the future (like 2099). This turns consent into a no-op — the client decides what permissions it has and for how long.

```java
// ❌ VULNERABLE — consent with arbitrary scopes and no expiry validation
@PostMapping("/consent")
public ResponseEntity<?> consent(@RequestBody ConsentRequest req) {
    // Attacker sends: {"subscriptionId":"SUB-1001","scopes":"espd.read,espd.admin,espd.everything","expiresAt":"2099-01-01"}
    // espd.admin was never offered to this subscription
    // 2099 is 74 years in the future
    consentService.grant(req.getSubscriptionId(), req.getScopes(), req.getExpiresAt());
    return ResponseEntity.ok("consent granted");
}
```

### The Fix

Scope allow-list, bounded lifetime, rejected scopes returned in the response.

```java
// ✅ SAFE — scope allow-list, bounded lifetime
private static final Set<String> ALLOWED_SCOPES = Set.of("espd.read", "espd.export", "espd.webhook");
private static final int MAX_CONSENT_DAYS = 365;

@PostMapping("/consent")
public ResponseEntity<?> consent(@RequestBody ConsentRequest req) {
    // 1. Parse and validate scopes
    List<String> requested = parseScopes(req.getScopes());
    List<String> rejected = requested.stream()
        .filter(s -> !ALLOWED_SCOPES.contains(s))
        .toList();

    if (!rejected.isEmpty()) {
        log.warn("consent_rejected_scopes: subscription={}, rejected={}",
            req.getSubscriptionId(), rejected);
        return ResponseEntity.status(400).body(Map.of(
            "error", "Rejected scopes",
            "rejected", rejected,
            "allowed", new ArrayList<>(ALLOWED_SCOPES)
        ));
    }

    // 2. Validate expiry (see CWE-613)
    Instant expiresAt = req.getExpiresAt();
    Instant now = Instant.now();
    Instant maxExpiry = now.plusDays(MAX_CONSENT_DAYS);

    if (expiresAt.isBefore(now) || expiresAt.isAfter(maxExpiry)) {
        return ResponseEntity.badRequest().body("Expiry must be in the future and ≤ " + MAX_CONSENT_DAYS + " days");
    }

    // 3. Grant consent with validated values, not request body
    consentService.grant(req.getSubscriptionId(), requested, expiresAt);
    return ResponseEntity.ok("consent granted");
}
```

**Key rules:**
- Unknown scopes are rejected with the list of rejected names
- The stored grant is the **validated** one, not the request body
- Return `400` with `rejected` and `allowed` lists — visible in logs
- Never grant `espd.admin` or other admin scopes through consent endpoints

---

## 8. Bounded Consent Lifetime

**CWE-613** — *Insufficient Session Expiration (Consent Lifetime)*

### The Problem

CWE-613 in the context of consent refers to consent records with no expiry validation. A consent valid until 2099 is effectively permanent — it bypasses the principle of least privilege and means the attacker has long-lived access to features they should not have. Consent should have a bounded lifetime that is re-evaluated periodically.

```java
// ❌ VULNERABLE — consent valid until 2099
@PostMapping("/consent")
public ResponseEntity<?> consent(@RequestBody ConsentRequest req) {
    // No expiry validation — accepts "2099-01-01T00:00:00Z"
    consentService.grant(req.getSubscriptionId(), req.getScopes(), req.getExpiresAt());
    // Stored grant: scopes=espd.admin, expiresAt=2099
    // Effectively permanent access
}
```

### The Fix

Bound consent expiry to a maximum lifetime (e.g., 365 days). Re-evaluate periodically.

```java
// ✅ SAFE — expiry bounded to 365 days
Instant expiresAt = req.getExpiresAt();
Instant now = Instant.now();
Instant maxExpiry = now.plusDays(365);

if (expiresAt.isBefore(now) || expiresAt.isAfter(maxExpiry)) {
    return ResponseEntity.badRequest().body("Expiry must be in the future and ≤ 365 days");
}

consentService.grant(req.getSubscriptionId(), requestedScopes, expiresAt);
```

**Key rules:**
- `expiresAt` must be in the future and **at most 365 days out**
- Consent should be **re-evaluated periodically** (e.g., monthly cron job that checks expiring consents)
- Expired consents should be automatically revoked
- Log `consent_expired` for monitoring

---

## 9. Audit Trail for Business Decisions

**CWE-778** — *Insufficient Logging of Security Events (No Decision Trail)*

### The Problem

CWE-778 in the context of business logic refers to the absence of an audit trail for business decisions. Without logging every accept and every refusal (transition rejected, quota exceeded, feature denied), abuse shows up as a support ticket about a strange invoice — not as a sequence of 422/429s with a subscription ID. The audit trail is the detection signal that turns individual refusals into a recognizable abuse pattern.

```java
// ❌ VULNERABLE — no decision trail
// GET /vuln15/* — _abuseLog only, record() is never called
// Returns: {"events": []}
// An attacker can:
//   - Set price to 1.00 for ESPD-PRO → no log entry
//   - Transition CANCELLED → ACTIVE → no log entry
//   - Replay payment 100 times → no log entry
//   - Grant espd.admin to any subscription → no log entry
// All abuse is invisible
```

### The Fix

Every accept and every refusal goes to the audit trail.

```java
// ✅ SAFE — every accept and every refusal logged
@Component
public class BusinessAuditLogger {

    public void logTransitionAccepted(String subscriptionId, State from, State to) {
        log.info("transition_accepted: subscription={}, from={}, to={}", subscriptionId, from, to);
    }

    public void logTransitionRejected(String subscriptionId, State from, State to, String reason) {
        log.info("transition_rejected: subscription={}, from={}, to={}, reason={}",
            subscriptionId, from, to, reason);
    }

    public void logPriceMismatch(String subscriptionId, BigDecimal clientPrice, BigDecimal catalogPrice) {
        log.info("price_mismatch: subscription={}, client={}, catalog={}",
            subscriptionId, clientPrice, catalogPrice);
    }

    public void logQuotaExceeded(String subscriptionId, int used, int limit) {
        log.info("quota_exceeded: subscription={}, used={}, limit={}", subscriptionId, used, limit);
    }

    public void logFeatureDenied(String subscriptionId, String feature) {
        log.info("feature_denied: subscription={}, feature={}", subscriptionId, feature);
    }

    public void logConsentRejected(String subscriptionId, List<String> rejectedScopes) {
        log.info("consent_rejected: subscription={}, rejected={}", subscriptionId, rejectedScopes);
    }

    public void logPaymentDuplicate(String eventId, String subscriptionId, Instant originallyAppliedAt) {
        log.info("payment_duplicate: eventId={}, subscriptionId={}, originallyAppliedAt={}",
            eventId, subscriptionId, originallyAppliedAt);
    }
}
```

**Detection signal:**
- `authz_denied` in m02 + `transition_rejected` / `quota_exceeded` in m15 raised together from one subscription = **abuse before it is revenue loss**
- A sequence of 422/429s from a single subscription ID indicates a targeted attack
- Alert on: refusal spikes, duplicate payments, price mismatches

**Key rules:**
- Log every **accept** and every **refusal** with the reason
- Include: subscription ID, action, outcome, reason
- The audit trail (`GET /safe15/state`) is the detection signal
- `authz_denied` in m02 and `transition_rejected` in m15 raised together = attack pattern

---

## Summary Checklist

| # | Control | CWE | Priority |
|---|---------|-----|----------|
| 1 | Server-owned `TariffCatalog` for pricing | CWE-472 | CRITICAL |
| 2 | Entitlement/quota as lookups, not flags | CWE-602, CWE-285 | CRITICAL |
| 3 | `ALLOWED_TRANSITIONS` state machine | CWE-841 | CRITICAL |
| 4 | Optimistic concurrency (`ifMatch`) | CWE-362 | HIGH |
| 5 | `Idempotency-Key` mandatory for callbacks | CWE-294, CWE-837 | CRITICAL |
| 6 | Derive renewal from order, not callback | CWE-472 | HIGH |
| 7 | Scope allow-list for consent | CWE-863 | HIGH |
| 8 | Bounded consent expiry (≤ 365 days) | CWE-613 | HIGH |
| 9 | Audit trail of accepts + refusals | CWE-778 | HIGH |

---

## Detection & Review Heuristics

| Check | Command / Pattern |
|-------|-------------------|
| Client-driven price | `grep -r 'getPrice()\|getDiscount()\|getDays()' src/main/java` → should not be used for business logic |
| Entitlement from param | `grep -r '@RequestParam.*entitled\|@RequestParam.*access'` → should be state lookup |
| Missing state machine | `grep -r 'ALLOWED_TRANSITIONS\|State\s*->\s*Set'` → should exist on lifecycle endpoints |
| No optimistic concurrency | `grep -r 'setState(\|transition('` → should have `ifMatch`/version check |
| Missing idempotency | `grep -r 'payment.*callback\|webhook.*payment'` → should have `Idempotency-Key` |
| Consent without expiry | `grep -r 'consent.*grant'` → should validate `expiresAt` |
| No audit trail | `grep -r 'log.info.*transition_\|log.info.*quota_\|log.info.*feature_'` → should exist |
| `@RequestBody Map` on money endpoints | `grep -r 'Map<String, Object>' src/main/java` → review as security-relevant |

---

## References

- [OWASP Business Logic Security](https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html)
- [Idempotency Patterns in Distributed Systems](https://www.infoq.com/articles/idempotent-api-design/)
- [Optimistic Concurrency in JPA](https://docs.spring.io/spring-data/jpa/reference/jpa/entities.html#jpa.versioning)
- [State Machine Patterns in Spring](https://docs.spring.io/spring-framework/reference/integration/state-machine.html)
- [OWASP Idempotency](https://cheatsheetseries.owasp.org/cheatsheets/Idempotency_Cheat_Sheet.html)
- [Audit Logging Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
