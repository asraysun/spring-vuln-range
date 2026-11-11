#!/usr/bin/env bash
# Checklist section 15 — subscription and ESPD business logic.  Target: m15-business-logic (8095)
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
PORT=8095
banner "15 · business logic: price, state, entitlements, consent (port ${PORT})"
up "${PORT}" m15-business-logic

# -----------------------------------------------------------------------------------------------
title "1. The client decides the price"
note "The catalog exists at /vuln15/catalog and the order endpoint never looks at it."
req GET "${PORT}" "/vuln15/catalog"
req POST "${PORT}" "/vuln15/orders" \
  '{"subscriptionId":"SUB-EVIL-1","plan":"ESPD-PRO","price":"1.00","currency":"RUB"}'
note "Reference implementation takes a plan name and nothing else:"
req POST "${PORT}" "/safe15/orders" \
  '{"subscriptionId":"SUB-OK-1","plan":"ESPD-PRO","price":"1.00","currency":"RUB"}'
note "…and prices it from the catalog, applying only server-owned discount rules:"
req POST "${PORT}" "/safe15/orders" \
  '{"subscriptionId":"SUB-OK-2","plan":"ESPD-PRO","firstYear":true,"discountCode":"FIRSTYEAR"}'

# -----------------------------------------------------------------------------------------------
title "2. State-machine bypass: cancelled -> active"
req GET  "${PORT}" "/vuln15/state"
req POST "${PORT}" "/vuln15/subscriptions/SUB-1001/state?to=CANCELLED"
req POST "${PORT}" "/vuln15/subscriptions/SUB-1001/state?to=ACTIVE"
note "A terminal state is not terminal, and no version check prevents racing clients."
note "Reference implementation enforces the allowed set and an optimistic version:"
req POST "${PORT}" "/safe15/subscriptions/SUB-1003/state?to=ACTIVE&ifMatch=1"
req POST "${PORT}" "/safe15/subscriptions/SUB-1003/state?to=EXPIRED&ifMatch=1"
req POST "${PORT}" "/safe15/subscriptions/SUB-1003/state?to=CANCELLED&ifMatch=2"
req POST "${PORT}" "/safe15/subscriptions/SUB-1003/state?to=ACTIVE&ifMatch=3"
req GET  "${PORT}" "/safe15/policy"

# -----------------------------------------------------------------------------------------------
title "3. Replayed payment callback (no idempotency key)"
for i in 1 2 3; do
  req POST "${PORT}" "/vuln15/payment/callback" \
    '{"subscriptionId":"SUB-1001","status":"PAID","days":30}'
done
note "Three identical messages, three applications: renewal periods and credits accumulate."
note "Reference implementation requires an Idempotency-Key and applies it once:"
for i in 1 2; do
  curl -sS -m 8 -X POST -H 'Content-Type: application/json' -H "Idempotency-Key: pay-evt-0001" \
    --data-binary '{"subscriptionId":"SUB-1002","status":"PAID"}' \
    -w '\n<status:%{http_code}>\n' "$(BASE_FOR_PORT ${PORT})/safe15/payment/callback" | sed 's/^/    /' | head -8
done

# -----------------------------------------------------------------------------------------------
title "4. Entitlement from a request parameter is not access control"
req GET "${PORT}" "/vuln15/features/espd.tender.export?entitled=true"
note "Reference implementation derives entitlement from the subscription and its tariff:"
req GET "${PORT}" "/safe15/features/espd.tender.export?subscriptionId=SUB-1001"
req GET "${PORT}" "/safe15/features/espd.tender.export?subscriptionId=SUB-2001"

# -----------------------------------------------------------------------------------------------
title "5. Quota from the request"
req POST "${PORT}" "/vuln15/documents/generate?limit=10000"
note "One caller can consume the shared worker pool and the registry rate limit for everybody."
note "Reference implementation counts per account per day against the tariff:"
for i in 1 2 3; do
  curl -sS -m 8 -X POST "$(BASE_FOR_PORT ${PORT})/safe15/documents/generate?subscriptionId=SUB-2001" \
    -w ' <status:%{http_code}>\n' | sed 's/^/    /' | head -3
done

# -----------------------------------------------------------------------------------------------
title "6. Consent / authorization scope abuse"
req POST "${PORT}" "/vuln15/consent" \
  '{"subscriptionId":"SUB-1001","scopes":"espd.read,espd.admin,espd.everything","expiresAt":"2099-01-01T00:00:00Z"}'
note "Reference implementation: scope allow-list plus a bounded, future expiry:"
req POST "${PORT}" "/safe15/consent" \
  '{"subscriptionId":"SUB-1001","scopes":"espd.read,espd.admin","expiresAt":"2099-01-01T00:00:00Z"}'
req POST "${PORT}" "/safe15/consent" \
  '{"subscriptionId":"SUB-1001","scopes":"espd.read","expiresAt":"2099-01-01T00:00:00Z"}'
req POST "${PORT}" "/safe15/consent" \
  '{"subscriptionId":"SUB-1001","scopes":"espd.read","expiresAt":"2026-12-31T00:00:00Z"}'

# -----------------------------------------------------------------------------------------------
title "7. The abuse trail: every skipped rule is recorded"
req GET "${PORT}" "/vuln15/state"
echo
banner "done · details and fixes: docs/15-business-logic.md"
