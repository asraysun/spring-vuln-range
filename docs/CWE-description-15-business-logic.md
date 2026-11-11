# CWE Reference — §15 Business Logic: Subscription, ESPD and Revenue Integrity

CWEs extracted from `docs/15-business-logic.md` with developer-focused comments.

> **Key premise of this module:** Nothing in `/vuln15` is an exotic memory bug. Every endpoint answers one question: **did the server, or the client, decide what is true?** `VulnerableSubscriptionController` takes price, lifecycle, entitlement, quota and consent from the request; `SafeSubscriptionController` derives the same five facts from server-side state — a `TariffCatalog`, an `ALLOWED_TRANSITIONS` map, an optimistically versioned `SubscriptionStore`, a processed-callback index and a scope allow-list.

---

## CWE-472 — External Control of Statement or Expression (Client-Driven Business Decisions)

**Why it matters:** CWE-472 is the core business-logic vulnerability: when the client (request body, query parameter, header) decides business values that should be determined server-side. This includes price, discount, renewal period, and any other business rule. The server trusts the client's numbers, which means an attacker can set any price to zero, any discount to 100%, any renewal period to 10 years. This is not a code bug — it is an architectural failure where the client is treated as a trusted source of business truth.

**Attack vector in Spring:**
```java
// VULNERABLE — price and currency chosen by the caller
@PostMapping("/orders")
public ResponseEntity<?> createOrder(@RequestBody OrderRequest req) {
    // Attacker sends: {"subscriptionId":"SUB-EVIL-1","plan":"ESPD-PRO","price":"1.00","currency":"RUB"}
    // The catalog exists (GET /vuln15/catalog) but is never consulted
    // Attacker pays 1 RUB for a plan that should cost 10,000 RUB
    subscriptionService.createOrder(req.getSubscriptionId(), req.getPlan(), req.getPrice(), req.getCurrency());
    return ResponseEntity.ok("ordered");
}

// VULNERABLE — discount treated as a client string
// Attacker sends: {"discount":"100%"} — gets everything for free
// The discount is a client string, not a server-owned rule

// VULNERABLE — renewal length taken from the message
@PostMapping("/payment/callback")
public ResponseEntity<?> paymentCallback(@RequestBody PaymentCallback req) {
    // Attacker sends: {"subscriptionId":"SUB-2001","status":"PAID","days":3650}
    // 3650 days ≈ 10 years. The renewal period should come from the order, not the callback
    subscriptionService.renew(req.getSubscriptionId(), req.getDays());
    return ResponseEntity.ok("renewed");
}
```

**How to prevent:**
```java
// SAFE — the catalog is the only price
@PostMapping("/orders")
public ResponseEntity<?> createOrder(@Valid @RequestBody OrderRequest req) {
    // Request names a plan only
    if (!PlanPattern.matches(req.getPlan())) {
        return ResponseEntity.badRequest().body("Invalid plan");
    }
    
    // Amount, currency, features come from TariffCatalog
    Tariff tariff = tariffCatalog.get(req.getPlan());
    BigDecimal price = tariff.price();
    String currency = tariff.currency();
    List<String> features = tariff.features();
    
    // If amount must be agreed with payment provider, compare with server's value
    if (req.getAmount() != null && !req.getAmount().equals(price)) {
        return ResponseEntity.status(400).body("Amount mismatch");
    }
    
    subscriptionService.createOrder(req.getSubscriptionId(), req.getPlan(), price, currency);
    return ResponseEntity.ok(Map.of("priceDecidedBy", "server-catalog"));
}

// SAFE — discounts are server-owned rules
// TariffCatalog.discountedPrice(tariff, discountCode, firstYear)
// FIRSTYEAR applies only when firstYear is true (0.85 × catalog price)
// A code the client invents is simply not in the rule set
```
- The request names a plan (`^ESPD-(TRIAL|BASIC|PRO)$`); the amount, currency and features come from `TariffCatalog`.
- If an amount must be agreed with a payment provider, compare it with the server's own value and reject the mismatch.
- Never store the client's number.

---

## CWE-602 — Client-Side Enforcement in a Trust-Unworthy Context

**Why it matters:** CWE-602 covers any business rule enforced on the client side (browser, mobile app) instead of the server. A UI that hides a button is not a control. A client-side validation that checks `if (user.isPro)` at login and never re-checks is trivially bypassed. Business logic enforced client-side is invisible to the server and can be bypassed by any HTTP tool.

**Attack vector in Spring:**
```java
// VULNERABLE — entitlement decided by a request parameter
@GetMapping("/features/{key}")
public ResponseEntity<?> getFeature(@PathVariable String key,
                                     @RequestParam boolean entitled) {
    // Attacker sends: ?entitled=true
    // The server trusts the client's entitlement flag
    // A UI that hides a button is not a control
    return ResponseEntity.ok(Map.of("entitled", entitled));
}

// VULNERABLE — quota from the request, no per-account accounting
@PostMapping("/documents/generate")
public ResponseEntity<?> generate(@RequestParam int limit) {
    // Attacker sends: ?limit=10000
    // Generates 10,000 documents — the "download limit" enforced in the browser is bypassed
    documentService.generate(limit);
    return ResponseEntity.ok("generated");
}
```
`GET /vuln15/features/espd.tender.export?entitled=true` — the entitlement is a request parameter. `POST /vuln15/documents/generate?limit=10000` — the quota is client-controlled.

**How to prevent:**
```java
// SAFE — entitlement and quota are lookups, not flags
@GetMapping("/features/{key}")
public ResponseEntity<?> getFeature(@PathVariable String key,
                                     @RequestParam String subscriptionId) {
    // Entitlement = subscription is ACTIVE or TRIAL AND tariff's feature list contains the key
    Subscription sub = subscriptionStore.get(subscriptionId);
    boolean entitled = sub.getState() == State.ACTIVE || sub.getState() == State.TRIAL
            && tariffCatalog.get(sub.getPlan()).features().contains(key);
    return ResponseEntity.ok(Map.of("entitled", entitled));
}

// SAFE — quota is per account per day
@PostMapping("/documents/generate")
public ResponseEntity<?> generate(@RequestParam String subscriptionId) {
    Subscription sub = subscriptionStore.get(subscriptionId);
    int used = dailyDocumentCounter.count(sub.getId(), LocalDate.now());
    int limit = tariffCatalog.get(sub.getPlan()).dailyDocumentLimit();
    
    if (used >= limit) {
        return ResponseEntity.status(429).body("Quota exceeded");
    }
    
    dailyDocumentCounter.increment(sub.getId());
    documentService.generate();
    return ResponseEntity.ok("generated");
}
```
- `feature(key)` = subscription is ACTIVE or TRIAL **and** the tariff's feature list contains the key.
- `documents/generate` counts per subscription per day against `dailyDocumentLimit` and answers 429 past it.
- A UI that hides a button is not a control.

---

## CWE-841 — Improper Enforcement of Behavioral Workflow (State Machine Bypass)

**Why it matters:** CWE-842 covers subscription lifecycle bypass: when the state machine is not enforced, an attacker can transition a subscription from any state to any other state, including leaving a terminal state. `CANCELLED → ACTIVE` should be impossible — re-activation is a new subscription, not an edge in the graph. Without an explicit state machine, every state transition is reachable from every other state.

**Attack vector in Spring:**
```java
// VULNERABLE — subscription state machine bypass
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
The state machine has no edges defined; any state can transition to any other state.

**How to prevent:**
```java
// SAFE — explicit state machine with default of "not allowed"
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
    State target = State.valueOf(to);
    
    // Check ALLOWED_TRANSITIONS
    Set<State> allowed = ALLOWED_TRANSITIONS.get(current);
    if (allowed == null || !allowed.contains(target)) {
        // 422 with the allowed set in the body
        return ResponseEntity.status(422).body(Map.of(
            "error", "transition rejected",
            "from", current,
            "to", target,
            "allowed", allowed
        ));
    }
    
    // Optimistic concurrency (see CWE-362)
    if (!sub.getVersion().equals(Integer.parseInt(ifMatch))) {
        return ResponseEntity.status(409).body("Stale version");
    }
    
    subscriptionStore.transition(id, target, sub.getVersion());
    return ResponseEntity.ok("transitioned to " + target);
}
```
- `ALLOWED_TRANSITIONS` maps each state to the set it may move to.
- A missing entry (`CANCELLED`, `EXPIRED`) means nothing may leave it.
- Re-activation is a new subscription, not an edge in the graph.
- Anything outside the set is a 422 with the allowed set in the body.

---

## CWE-362 — Concurrent Execution Using Shared Resource with Improper Synchronization (Race Condition)

**Why it matters:** CWE-362 covers race conditions in business logic: when two clients race the same state transition, both succeed because there is no optimistic concurrency control. A double-click, a retried request, or two browser tabs all trigger separate state changes that are not serialized. This leads to duplicate applications, inconsistent state, and revenue loss.

**Attack vector in Spring:**
```java
// VULNERABLE — no optimistic concurrency
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
Two clients read the same version, both transition, both succeed. The second transition should have been rejected with a 409 (conflict).

**How to prevent:**
```java
// SAFE — optimistic concurrency on every transition
@PostMapping("/subscriptions/{id}/state")
public ResponseEntity<?> transition(@PathVariable String id,
                                     @RequestParam String to,
                                     @RequestParam String ifMatch) {
    Subscription sub = subscriptionStore.get(id);
    
    // Compare-and-set under a lock
    if (!sub.getVersion().equals(Integer.parseInt(ifMatch))) {
        return ResponseEntity.status(409).body("Stale version — expected " + sub.getVersion());
    }
    
    subscriptionStore.transition(id, State.valueOf(to), sub.getVersion());
    return ResponseEntity.ok("transitioned");
}

// SubscriptionStore.transition() does compare-and-set:
public void transition(String id, State target, int expectedVersion) {
    synchronized (this) {
        Subscription sub = store.get(id);
        if (sub.getVersion() != expectedVersion) {
            throw new OptimisticLockException("Version mismatch");
        }
        sub.setState(target);
        sub.setVersion(sub.getVersion() + 1);
    }
}
```
- `ifMatch` carries the version the client read.
- `SubscriptionStore.transition(id, target, expectedVersion)` does compare-and-set under a lock.
- Double-click, retried request and two tabs all collapse into one state change.

---

## CWE-294 — Authentication Bypass Using a Replay Attack (Payment Callback)

**Why it matters:** CWE-294 in the context of webhooks/callbacks refers to replaying a valid payment callback multiple times. Without an idempotency key, each replay is processed as a new event, leading to duplicate payments, extended subscriptions, or repeated benefit applications. A payment provider can resend a callback on timeout — the server must handle this gracefully.

**Attack vector in Spring:**
```java
// VULNERABLE — replayed payment callback: no idempotency key
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
`POST /vuln15/payment/callback` sent three times with the same body → three applications of the payment. The subscription expires in 90 days instead of 30.

**How to prevent:**
```java
// SAFE — Idempotency-Key mandatory, stored with the outcome
@PostMapping("/payment/callback")
public ResponseEntity<?> paymentCallback(@RequestBody PaymentCallback req,
                                          @RequestHeader("Idempotency-Key") String eventId) {
    // Idempotency-Key is mandatory, bounded (64 characters)
    if (eventId == null || eventId.length() > 64) {
        return ResponseEntity.badRequest().body("Idempotency-Key required");
    }
    
    // Stored with the outcome — in production: unique index on payment-event table
    if (processedEvents.contains(eventId)) {
        PaymentEvent original = processedEvents.get(eventId);
        return ResponseEntity.ok(Map.of(
            "duplicate", true,
            "originallyAppliedAt", original.getAppliedAt()
        ));
    }
    
    processedEvents.put(eventId, new PaymentEvent(req, Instant.now()));
    subscriptionService.renew(req.getSubscriptionId(), req.getDays());
    return ResponseEntity.ok("processed");
}
```
- `Idempotency-Key` is mandatory, bounded (64 characters).
- Second delivery returns `duplicate: true`, `originallyAppliedAt` instead of applying again.
- In production: a unique index on the payment-event table, not a `ConcurrentHashMap`.

---

## CWE-837 — Improper Enforcement of a Single Action Per Request (Duplicate Processing)

**Why it matters:** CWE-837 covers the lack of idempotency: when the same request is processed multiple times, each processing produces a new effect. This is the same vulnerability as CWE-294 but from a different angle — the server does not enforce "one action per request." A payment provider retry, a network timeout, or an attacker replaying the request all produce duplicate effects.

**Attack vector in Spring:**
```java
// VULNERABLE — no idempotency enforcement
@PostMapping("/payment/callback")
public ResponseEntity<?> paymentCallback(@RequestBody PaymentCallback req) {
    // Same request processed N times = N renewals applied
    // No Idempotency-Key, no deduplication
    subscriptionService.renew(req.getSubscriptionId(), req.getDays());
    return ResponseEntity.ok("processed");
}
```

**How to prevent:**
- Same as CWE-294: mandatory `Idempotency-Key`, stored with the outcome.
- A replay is answered with `duplicate: true`, `originallyAppliedAt` instead of applying again.

---

## CWE-285 — Improper Authorization (Entitlement from Request Parameter)

**Why it matters:** CWE-285 in the context of business logic refers to entitlements and permissions decided by request parameters instead of server-side state. When `?entitled=true` grants access, any caller can enable any feature for any subscription. This bypasses the tariff's feature list, the subscription's state, and all business rules.

**Attack vector in Spring:**
```java
// VULNERABLE — entitlement decided by a request parameter
@GetMapping("/features/{key}")
public ResponseEntity<?> getFeature(@PathVariable String key,
                                     @RequestParam boolean entitled) {
    // Attacker sends: ?entitled=true
    // Gets access to espd.admin, espd.everything — features they don't have
    return ResponseEntity.ok(Map.of("entitled", entitled, "feature", key));
}
```
`GET /vuln15/features/espd.tender.export?entitled=true` — the entitlement is a boolean from the request.

**How to prevent:**
```java
// SAFE — entitlement is a lookup, not a flag
@GetMapping("/features/{key}")
public ResponseEntity<?> getFeature(@PathVariable String key,
                                     @RequestParam String subscriptionId) {
    Subscription sub = subscriptionStore.get(subscriptionId);
    boolean entitled = sub.getState() == State.ACTIVE || sub.getState() == State.TRIAL
            && tariffCatalog.get(sub.getPlan()).features().contains(key);
    return ResponseEntity.ok(Map.of("entitled", entitled));
}
```
- `feature(key)` = subscription is ACTIVE or TRIAL **and** the tariff's feature list contains the key.
- Entitlement is a lookup, not a flag from the request.

---

## CWE-863 — Incorrect Authorization (Consent with Arbitrary Scopes)

**Why it matters:** CWE-863 in the context of business logic refers to consent records written from whatever the OAuth client sends, including scopes that were never offered (like `espd.admin`) and expiry dates far in the future (like 2099). This turns consent into a no-op — the client decides what permissions it has and for how long.

**Attack vector in Spring:**
```java
// VULNERABLE — consent with arbitrary scopes and no expiry validation
@PostMapping("/consent")
public ResponseEntity<?> consent(@RequestBody ConsentRequest req) {
    // Attacker sends: {"subscriptionId":"SUB-1001","scopes":"espd.read,espd.admin,espd.everything","expiresAt":"2099-01-01"}
    // espd.admin was never offered to this subscription
    // 2099 is 74 years in the future
    consentService.grant(req.getSubscriptionId(), req.getScopes(), req.getExpiresAt());
    return ResponseEntity.ok("consent granted");
}
```
`POST /vuln15/consent` with `{"scopes":"espd.read,espd.admin,espd.everything","expiresAt":"2099-01-01T00:00:00Z"}` — arbitrary scopes, arbitrary expiry.

**How to prevent:**
```java
// SAFE — scope allow-list, bounded lifetime
@PostMapping("/consent")
public ResponseEntity<?> consent(@RequestBody ConsentRequest req) {
    Set<String> ALLOWED_SCOPES = Set.of("espd.read", "espd.export", "espd.webhook");
    
    List<String> requested = parseScopes(req.getScopes());
    List<String> rejected = requested.stream()
        .filter(s -> !ALLOWED_SCOPES.contains(s))
        .toList();
    
    if (!rejected.isEmpty()) {
        return ResponseEntity.status(400).body(Map.of(
            "error", "Rejected scopes",
            "rejected", rejected,
            "allowed", new ArrayList<>(ALLOWED_SCOPES)
        ));
    }
    
    // Expiry must be in the future and ≤ 365 days
    Instant expiresAt = req.getExpiresAt();
    if (expiresAt.isBefore(Instant.now()) || expiresAt.isAfter(Instant.now().plusDays(365))) {
        return ResponseEntity.badRequest().body("Expiry must be in the future and ≤ 365 days");
    }
    
    consentService.grant(req.getSubscriptionId(), requested, expiresAt);
    return ResponseEntity.ok("consent granted");
}
```
- Unknown scopes are rejected with the list of rejected names.
- `expiresAt` must parse as an instant, be in the future and be at most 365 days out.
- The stored grant is the validated one, not the request body.

---

## CWE-613 — Insufficient Session Expiration (Consent Lifetime)

**Why it matters:** CWE-613 in the context of consent refers to consent records with no expiry validation. A consent valid until 2099 is effectively permanent — it bypasses the principle of least privilege and means the attacker has long-lived access to features they should not have. Consent should have a bounded lifetime that is re-evaluated periodically.

**Attack vector in Spring:**
```java
// VULNERABLE — consent valid until 2099
@PostMapping("/consent")
public ResponseEntity<?> consent(@RequestBody ConsentRequest req) {
    // No expiry validation — accepts "2099-01-01T00:00:00Z"
    consentService.grant(req.getSubscriptionId(), req.getScopes(), req.getExpiresAt());
    // Stored grant: scopes=espd.admin, expiresAt=2099
    // Effectively permanent access
}
```

**How to prevent:**
```java
// SAFE — expiry bounded to 365 days
Instant expiresAt = req.getExpiresAt();
if (expiresAt.isBefore(Instant.now()) || expiresAt.isAfter(Instant.now().plusDays(365))) {
    return ResponseEntity.badRequest().body("Expiry must be in the future and ≤ 365 days");
}
```
- `expiresAt` must be in the future and at most 365 days out.
- Re-evaluate consent periodically.

---

## CWE-778 — Insufficient Logging of Security Events (No Decision Trail)

**Why it matters:** CWE-778 in the context of business logic refers to the absence of an audit trail for business decisions. Without logging every accept and every refusal (transition rejected, quota exceeded, feature denied), abuse shows up as a support ticket about a strange invoice — not as a sequence of 422/429s with a subscription ID. The audit trail is the detection signal that turns individual refusals into a recognizable abuse pattern.

**Attack vector in Spring:**
```java
// VULNERABLE — no decision trail
// GET /vuln15/* — _abuseLog only, record() is never called
// Returns: {"events": []}
// An attacker can:
//   - Set price to 1.00 for ESPD-PRO → no log entry
//   - Transition CANCELLED → ACTIVE → no log entry
//   - Replay payment 100 times → no log entry
//   - Grant espd.admin to any subscription → no log entry
// All abuse is invisible
```
`GET /vuln15/state` returns nothing. There is no record of what was accepted, what was refused, and why.

**How to prevent:**
```java
// SAFE — every accept and every refusal goes to the audit trail
@Component
public class BusinessAuditLogger {
    
    public void logTransitionAccepted(String subscriptionId, State from, State to) {
        log.info("transition_accepted: subscription={}, from={}, to={}", subscriptionId, from, to);
    }
    
    public void logTransitionRejected(String subscriptionId, State from, State to, String reason) {
        log.info("transition_rejected: subscription={}, from={}, to={}, reason={}", 
            subscriptionId, from, to, reason);
    }
    
    public void logQuotaExceeded(String subscriptionId, int used, int limit) {
        log.info("quota_exceeded: subscription={}, used={}, limit={}", subscriptionId, used, limit);
    }
    
    public void logFeatureDenied(String subscriptionId, String feature) {
        log.info("feature_denied: subscription={}, feature={}", subscriptionId, feature);
    }
    
    public void logPriceMismatch(String subscriptionId, BigDecimal clientPrice, BigDecimal catalogPrice) {
        log.info("price_mismatch: subscription={}, client={}, catalog={}", 
            subscriptionId, clientPrice, catalogPrice);
    }
}
```
- Every accept and every refusal goes to the audit trail (`GET /safe15/state`).
- Include the reason: `transition rejected`, `quota exceeded`, `feature denied`.
- Abuse shows up as a sequence of 422/429s with a subscription ID, not as a support ticket.
- `authz_denied` in m02 and `transition rejected` / `quota exceeded` in m15 raised together from one subscription = abuse before it is revenue loss.
