package com.example.vulnrange.m15.vuln;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.example.vulnrange.m15.domain.SubscriptionStore;
import com.example.vulnrange.m15.domain.TariffCatalog;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * VULNERABLE (intentional): the client decides prices, lifecycle, entitlements, quotas and consent.
 * PoC: {@code attacks/15-business-logic.sh}.
 */
@RestController
@RequestMapping("/vuln15")
public class VulnerableSubscriptionController {

    private static final Logger log = LoggerFactory.getLogger(VulnerableSubscriptionController.class);

    private final SubscriptionStore store = new SubscriptionStore();
    private final List<String> abuseLog = Collections.synchronizedList(new ArrayList<>());

    /**
     * VULNERABLE: the order is built from what the caller sends — price, currency, even the tariff
     * features. Sending {@code "price": 1} buys ESPD-PRO; the catalog is never consulted.
     */
    @PostMapping("/orders")
    public Map<String, Object> createOrder(@RequestBody Map<String, Object> body) {
        String subscriptionId = String.valueOf(body.getOrDefault("subscriptionId", "SUB-" + System.nanoTime()));
        String plan = String.valueOf(body.getOrDefault("plan", "ESPD-BASIC"));
        BigDecimal price = new BigDecimal(String.valueOf(body.getOrDefault("price", "0")));
        String currency = String.valueOf(body.getOrDefault("currency", "RUB"));

        SubscriptionStore.Subscription created = store.create(subscriptionId, "caller", plan, price,
                SubscriptionStore.State.ACTIVE);
        abuseLog.add("order created with client-supplied price " + price + " " + currency + " for " + plan);
        return Map.of("subscription", created.asMap(), "priceDecidedBy", "client",
                "catalogConsulted", false);
    }

    /**
     * VULNERABLE: no state machine and no optimistic locking. {@code CANCELLED -> ACTIVE} (i.e. "keep
     * using it after cancelling") is a single query parameter, and the transition is idempotent-proof
     * only in the sense that nothing checks it at all.
     */
    @PostMapping("/subscriptions/{id}/state")
    public ResponseEntity<Map<String, Object>> transition(@PathVariable String id,
                                                         @RequestParam String to) {
        SubscriptionStore.Subscription subscription = store.get(id);
        if (subscription == null) {
            return ResponseEntity.notFound().build();
        }
        SubscriptionStore.State previous = subscription.state;
        try {
            store.forceTransition(id, SubscriptionStore.State.valueOf(to.toUpperCase()));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", "unknown state"));
        }
        abuseLog.add("state forced " + previous + " -> " + to + " without an allowed-transition check");
        return ResponseEntity.ok(Map.of("from", previous.name(), "to", to, "versionControlled", false));
    }

    /**
     * VULNERABLE: payment callback with no idempotency key. The same message replayed N times grants
     * N activations, N credit top-ups, or N renewal periods — the most common revenue-integrity bug.
     */
    @PostMapping("/payment/callback")
    public Map<String, Object> paymentCallback(@RequestBody Map<String, Object> body) {
        String id = String.valueOf(body.getOrDefault("subscriptionId", "SUB-1001"));
        SubscriptionStore.Subscription subscription = store.get(id);
        if (subscription == null) {
            return Map.of("ignored", true);
        }
        store.forceTransition(id, SubscriptionStore.State.ACTIVE);
        // Renewal length is taken from the message too, so a replay extends the period forever.
        int days = Integer.parseInt(String.valueOf(body.getOrDefault("days", "30")));
        abuseLog.add("payment callback applied to " + id + " (+" + days + " days), no idempotency key");
        return Map.of("applied", true, "subscription", subscription.asMap(), "idempotencyChecked", false);
    }

    /** VULNERABLE: the client reports whether it is entitled. This is a UI check, not access control. */
    @GetMapping("/features/{key}")
    public ResponseEntity<Map<String, Object>> feature(@PathVariable String key,
                                                      @RequestParam(defaultValue = "true") boolean entitled) {
        if (!entitled) {
            return ResponseEntity.status(403).body(Map.of("error", "not entitled"));
        }
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("feature", key);
        payload.put("entitled", entitled);
        payload.put("entitlementSource", "request parameter");
        payload.put("data", Map.of("espdRegistrySnapshot", "privileged content"));
        abuseLog.add("feature " + key + " granted because entitled=true was sent");
        return ResponseEntity.ok(payload);
    }

    /** VULNERABLE: quota from the request; no per-account or per-tariff accounting. */
    @PostMapping("/documents/generate")
    public Map<String, Object> generate(@RequestParam(defaultValue = "10000") int limit) {
        abuseLog.add("generated " + limit + " documents without a quota check");
        return Map.of("generated", limit, "quotaApplied", false,
                "cost", "shared worker pool and registry rate limits");
    }

    /**
     * VULNERABLE: consent record accepted with arbitrary scopes and no expiry validation; an expired or
     * over-scoped authorization is then used against the ESPD registry.
     */
    @PostMapping("/consent")
    public Map<String, Object> consent(@RequestBody Map<String, Object> body) {
        String scopes = String.valueOf(body.getOrDefault("scopes", "espd.read"));
        String expiresAt = String.valueOf(body.getOrDefault("expiresAt", "2099-01-01T00:00:00Z"));
        abuseLog.add("consent stored for scopes=" + scopes + " expiresAt=" + expiresAt + " (not validated)");
        return Map.of("stored", true, "scopes", scopes, "expiresAt", expiresAt,
                "scopeAllowListApplied", false, "expiryValidated", false);
    }

    @GetMapping("/state")
    public Map<String, Object> state() {
        Map<String, Object> out = new LinkedHashMap<>();
        store.all().forEach((id, subscription) -> out.put(id, subscription.asMap()));
        out.put("_abuseLog", List.copyOf(abuseLog));
        return out;
    }

    @GetMapping("/catalog")
    @SuppressWarnings("unchecked")
    public Map<String, Object> catalog() {
        // Present, and ignored by /vuln15/orders - which is the whole finding.
        return (Map) TariffCatalog.all();
    }

    /** Keeps the logger referenced so the abuse trail is also greppable in the log file. */
    private void record(String message) {
        abuseLog.add(message);
        log.warn("business rule skipped: {}", message);
    }
}
