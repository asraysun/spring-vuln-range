package com.example.vulnrange.m15.domain;

import java.math.BigDecimal;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The tariff catalog is the server's only source of truth for what a plan costs and what it includes.
 *
 * <p>Compare with {@code /vuln15/orders}, where the client submits the price and the catalog is
 * consulted for nothing.
 */
public final class TariffCatalog {

    public record Tariff(String code, BigDecimal price, String currency, List<String> features,
                         int dailyDocumentLimit) {
    }

    private static final Map<String, Tariff> CATALOG = new LinkedHashMap<>();

    static {
        CATALOG.put("ESPD-TRIAL", new Tariff("ESPD-TRIAL", new BigDecimal("0.00"), "RUB",
                List.of("espd.read"), 2));
        CATALOG.put("ESPD-BASIC", new Tariff("ESPD-BASIC", new BigDecimal("990.00"), "RUB",
                List.of("espd.read", "espd.subscription.create"), 20));
        CATALOG.put("ESPD-PRO", new Tariff("ESPD-PRO", new BigDecimal("2490.00"), "RUB",
                List.of("espd.read", "espd.subscription.create", "espd.tender.export", "espd.api"), 100));
    }

    private TariffCatalog() {
    }

    public static Tariff find(String code) {
        return code == null ? null : CATALOG.get(code.toUpperCase());
    }

    public static Map<String, Tariff> all() {
        return Map.copyOf(CATALOG);
    }

    /** Discount codes are server-owned rules with eligibility, not strings the client may invent. */
    public static BigDecimal discountedPrice(Tariff tariff, String discountCode, boolean firstYear) {
        BigDecimal price = tariff.price();
        if (firstYear && "FIRSTYEAR".equals(discountCode)) {
            return price.multiply(new BigDecimal("0.85"));
        }
        return price;
    }
}
