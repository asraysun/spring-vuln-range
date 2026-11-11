package com.example.vulnrange.m02.domain;

import java.math.BigDecimal;

/**
 * Minimal subscription aggregate shared by the vulnerable and the safe endpoints.
 *
 * @param id             opaque-ish identifier; sequential ids make enumeration trivial on purpose
 * @param ownerUsername  the only principal allowed to read/modify it
 * @param tenantId       isolation boundary
 * @param plan           tariff code
 * @param monthlyPrice   price the server decided (see m15 for price tampering)
 * @param customerEmail  personal data, must never be exposed cross-owner
 */
public record Subscription(String id,
                           String ownerUsername,
                           String tenantId,
                           String plan,
                           BigDecimal monthlyPrice,
                           String customerEmail) {
}
