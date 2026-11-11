package com.example.vulnrange.m15.safe;

import java.math.BigDecimal;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import com.example.vulnrange.m15.domain.SubscriptionStore;
import com.example.vulnrange.m15.domain.TariffCatalog;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Reference implementation of checklist section 15. One principle runs through it: the client asks,
 * the server decides, and every decision is recorded.
 */
@Validated
@RestController
@RequestMapping("/safe15")
public class SafeSubscriptionController {

    private static final Set<String> ALLOWED_SCOPES =
            Set.of("espd.read", "espd.subscription.create", "espd.tender.export", "espd.api");
    private static final Duration MAX_CONSENT_TTL = Duration.ofDays(365);

    public record OrderRequest(@NotBlank @Size(max = 64) String subscriptionId,
                              @NotBlank @Pattern(regexp = "^ESPD-(TRIAL|BASIC|PRO)$") String plan,
                              boolean firstYear,
                              @Size(max = 32) String discountCode) {
    }

    public record ConsentRequest(@NotBlank @Size(max = 64) String subscriptionId,
                                @Size(max = 256) String scopes,
                                @NotBlank String expiresAt) {
    }

    private final SubscriptionStore store = new SubscriptionStore();
    /** Idempotency store; in production this is a unique index on the payment-event table. */
    private final Map<String, Map<String, Object>> processedCallbacks = new ConcurrentHashMap<>();
    private final List<String> auditTrail = Collections.synchronizedList(new ArrayList<>());

    /** Price comes from the catalog; the request can only name a plan. */
    @PostMapping("/orders")
    public ResponseEntity<?> createOrder(@RequestBody @Validated OrderRequest request) {
        TariffCatalog.Tariff tariff = TariffCatalog.find(request.plan());
        if (tariff == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "unknown plan"));
        }
        BigDecimal price = TariffCatalog.discountedPrice(tariff, request.discountCode(), request.firstYear());
        SubscriptionStore.Subscription created = store.create(request.subscriptionId(), "current-user",
                tariff.code(), price, SubscriptionStore.State.TRIAL);
        audit("order created id=%s plan=%s price=%s %s".formatted(
                created.id, tariff.code(), price, tariff.currency()));
        return ResponseEntity.ok(Map.of(
                "subscription", created.asMap(),
                "priceDecidedBy", "server-catalog",
                "currency", tariff.currency(),
                "allowedTransitions", SubscriptionStore.ALLOWED_TRANSITIONS.get(SubscriptionStore.State.TRIAL).toString()));
    }

    /** Allowed-transition map plus optimistic version: invalid moves and lost races both fail loudly. */
    @PostMapping("/subscriptions/{id}/state")
    public ResponseEntity<Map<String, Object>> transition(@PathVariable String id,
                                                         @RequestParam String to,
                                                         @RequestParam long ifMatch) {
        SubscriptionStore.Subscription subscription = store.get(id);
        if (subscription == null) {
            return ResponseEntity.notFound().build();
        }
        SubscriptionStore.State target;
        try {
            target = SubscriptionStore.State.valueOf(to.toUpperCase());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", "unknown state"));
        }
        Set<SubscriptionStore.State> allowed =
                SubscriptionStore.ALLOWED_TRANSITIONS.getOrDefault(subscription.state, EnumSet.noneOf(SubscriptionStore.State.class));
        if (!allowed.contains(target)) {
            audit("transition rejected id=%s %s->%s not in allowed set", id, subscription.state, target);
            return ResponseEntity.status(422).body(Map.of(
                    "error", "transition is not allowed from the current state",
                    "from", subscription.state.name(),
                    "allowed", allowed.toString()));
        }
        if (!store.transition(id, target, ifMatch)) {
            audit("transition conflict id=%s expectedVersion=%d", id, ifMatch);
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
                    "error", "concurrent modification, re-read and retry",
                    "currentVersion", subscription.version));
        }
        audit("transition applied id=%s %s->%s", id, subscription.state, target);
        return ResponseEntity.ok(Map.of("subscription", subscription.asMap()));
    }

    /**
     * Payment callback: an idempotency key is mandatory, the key is stored with the outcome, and the
     * amount/period is re-derived from the order rather than read from the message.
     */
    @PostMapping("/payment/callback")
    public ResponseEntity<Map<String, Object>> paymentCallback(
            @RequestHeader(value = "Idempotency-Key", required = false) String idempotencyKey,
            @RequestBody Map<String, Object> body) {
        if (idempotencyKey == null || idempotencyKey.isBlank() || idempotencyKey.length() > 64) {
            return ResponseEntity.badRequest().body(Map.of("error", "Idempotency-Key header is required"));
        }
        Map<String, Object> previous = processedCallbacks.get(idempotencyKey);
        if (previous != null) {
            return ResponseEntity.ok(Map.of("duplicate", true, "originallyAppliedAt", previous.get("appliedAt")));
        }
        String id = String.valueOf(body.getOrDefault("subscriptionId", ""));
        SubscriptionStore.Subscription subscription = store.get(id);
        if (subscription == null) {
            return ResponseEntity.notFound().build();
        }
        if (subscription.state != SubscriptionStore.State.PAST_DUE && subscription.state != SubscriptionStore.State.TRIAL) {
            return ResponseEntity.status(422).body(Map.of("error", "subscription is not awaiting payment",
                    "state", subscription.state.name()));
        }
        long version = subscription.version;
        if (!store.transition(id, SubscriptionStore.State.ACTIVE, version)) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("error", "concurrent modification"));
        }
        Map<String, Object> outcome = Map.of("appliedAt", Instant.now().toString(),
                "subscription", subscription.asMap(),
                "renewalDays", 30,
                "amountCharged", String.valueOf(subscription.amountPaid));
        processedCallbacks.putIfAbsent(idempotencyKey, Map.of("appliedAt", Instant.now().toString()));
        audit("payment applied id=%s key=%s", id, idempotencyKey);
        return ResponseEntity.ok(outcome);
    }

    /** Entitlement is a server-side lookup against the subscription and its tariff. */
    @GetMapping("/features/{key}")
    public ResponseEntity<Map<String, Object>> feature(@PathVariable String key,
                                                      @RequestParam(defaultValue = "SUB-1001") String subscriptionId) {
        SubscriptionStore.Subscription subscription = store.get(subscriptionId);
        if (subscription == null) {
            return ResponseEntity.notFound().build();
        }
        TariffCatalog.Tariff tariff = TariffCatalog.find(subscription.tariffCode);
        boolean active = subscription.state == SubscriptionStore.State.ACTIVE
                || subscription.state == SubscriptionStore.State.TRIAL;
        boolean entitled = active && tariff != null && tariff.features().contains(key);
        if (!entitled) {
            audit("feature denied key=%s subscription=%s state=%s", key, subscriptionId, subscription.state);
            return ResponseEntity.status(403).body(Map.of("error", "not entitled", "state", subscription.state.name()));
        }
        return ResponseEntity.ok(Map.of("feature", key, "entitled", true,
                "entitlementSource", "server-side subscription + tariff",
                "data", Map.of("espdRegistrySnapshot", "privileged content")));
    }

    /** Quota is per account and per day, taken from the tariff, never from the request. */
    @PostMapping("/documents/generate")
    public ResponseEntity<Map<String, Object>> generate(@RequestParam(defaultValue = "SUB-1001") String subscriptionId) {
        SubscriptionStore.Subscription subscription = store.get(subscriptionId);
        if (subscription == null) {
            return ResponseEntity.notFound().build();
        }
        TariffCatalog.Tariff tariff = TariffCatalog.find(subscription.tariffCode);
        if (tariff == null) {
            return ResponseEntity.status(403).body(Map.of("error", "unknown tariff"));
        }
        if (Instant.now().isAfter(subscription.documentsQuotaDate.plus(Duration.ofDays(1)))) {
            subscription.documentsToday.set(0);
            subscription.documentsQuotaDate = Instant.now();
        }
        long used = subscription.documentsToday.incrementAndGet();
        if (used > tariff.dailyDocumentLimit()) {
            subscription.documentsToday.decrementAndGet();
            audit("quota exceeded id=%s used=%d limit=%d", subscriptionId, used, tariff.dailyDocumentLimit());
            return ResponseEntity.status(429).body(Map.of(
                    "error", "daily document quota exceeded",
                    "limit", tariff.dailyDocumentLimit(), "retryAfter", "next day"));
        }
        return ResponseEntity.ok(Map.of("generated", 1, "usedToday", used,
                "limit", tariff.dailyDocumentLimit()));
    }

    /** Scopes are checked against an allow-list, expiry must be in the future and bounded. */
    @PostMapping("/consent")
    public ResponseEntity<Map<String, Object>> consent(@RequestBody @Validated ConsentRequest request) {
        List<String> requested = List.of(request.scopes().split(","));
        List<String> unknown = requested.stream().map(String::trim).filter(s -> !s.isEmpty())
                .filter(scope -> !ALLOWED_SCOPES.contains(scope)).toList();
        if (!unknown.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "scope not recognised", "rejected", unknown));
        }
        Instant expiresAt;
        try {
            expiresAt = Instant.parse(request.expiresAt());
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "expiresAt must be an ISO-8601 instant"));
        }
        if (expiresAt.isBefore(Instant.now()) || expiresAt.isAfter(Instant.now().plus(MAX_CONSENT_TTL))) {
            return ResponseEntity.badRequest().body(Map.of("error", "consent expiry must be in the next 365 days"));
        }
        SubscriptionStore.Subscription subscription = store.get(request.subscriptionId());
        if (subscription == null) {
            return ResponseEntity.notFound().build();
        }
        subscription.grantedScopes = String.join(",", requested.stream().map(String::trim).toList());
        subscription.consentExpiresAt = expiresAt;
        audit("consent stored id=%s scopes=%s expiresAt=%s", subscription.id, subscription.grantedScopes, expiresAt);
        return ResponseEntity.ok(Map.of("stored", true, "scopes", subscription.grantedScopes,
                "expiresAt", expiresAt.toString()));
    }

    @GetMapping("/state")
    public Map<String, Object> state() {
        Map<String, Object> out = new LinkedHashMap<>();
        store.all().forEach((id, subscription) -> out.put(id, subscription.asMap()));
        out.put("_auditTrail", List.copyOf(auditTrail));
        return out;
    }

    @GetMapping("/policy")
    public Map<String, Object> policy() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("priceSource", "TariffCatalog only; the request may not carry an amount");
        out.put("allowedTransitions", SubscriptionStore.ALLOWED_TRANSITIONS.entrySet().stream()
                .map(entry -> entry.getKey() + " -> " + entry.getValue())
                .toList());
        out.put("concurrency", "optimistic version with ifMatch; conflicts answer 409");
        out.put("callbacks", "Idempotency-Key required and stored; renewal derived from the order");
        out.put("entitlement", "derived from subscription state + tariff features");
        out.put("quota", "per account per day, from the tariff");
        out.put("consent", "scope allow-list, expiry in the future and at most 365 days");
        out.put("audit", "every decision recorded with the reason");
        return out;
    }

    private void audit(String format, Object... args) {
        auditTrail.add(Instant.now() + " " + String.format(format, args));
    }
}
