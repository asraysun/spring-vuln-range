# 15 · Business logic: subscription, ESPD and revenue integrity

Checklist section: **§15 Business logic (subscription/ESPD)** · Module: `m15-business-logic` · Port: **8095**
PoC: [`attacks/15-business-logic.sh`](../attacks/15-business-logic.sh) · Run: `scripts/run-module.sh m15-business-logic`

Nothing in `/vuln15` is an exotic memory bug. Every endpoint answers one question: **did the server, or
the client, decide what is true?** `VulnerableSubscriptionController` takes price, lifecycle, entitlement,
quota and consent from the request; `SafeSubscriptionController` derives the same five facts from
server-side state — a `TariffCatalog`, an `ALLOWED_TRANSITIONS` map, an optimistically versioned
`SubscriptionStore`, a processed-callback index and a scope allow-list. The fixture data is
`SUB-1001` (alice, `ESPD-BASIC`, ACTIVE), `SUB-1002` (alice, `ESPD-PRO`, TRIAL) and `SUB-2001` (bob,
`ESPD-TRIAL`, TRIAL, daily limit 2).

## What this module demonstrates

| # | Vulnerability | CWE | Insecure | Hardened |
|---|---------------|-----|----------|----------|
| 1 | Price and currency chosen by the caller; the catalog is never consulted | CWE-472, CWE-602 | `POST /vuln15/orders` (`price`, `currency`); `GET /vuln15/catalog` exists and is ignored | `POST /safe15/orders` (plan name only, priced from `TariffCatalog`, `priceDecidedBy: server-catalog`) |
| 2 | Discount treated as a client string instead of a server-owned rule | CWE-472 | `POST /vuln15/orders` (`price`) | `TariffCatalog.discountedPrice` — `FIRSTYEAR` applies only when `firstYear` is true (0.85 × catalog price) |
| 3 | Subscription state machine bypass, including leaving a terminal state | CWE-841 | `POST /vuln15/subscriptions/{id}/state?to=CANCELLED` then `?to=ACTIVE` (`forceTransition`) | `POST /safe15/subscriptions/{id}/state?to=…&ifMatch=…` (422 outside `ALLOWED_TRANSITIONS`, 409 on version mismatch) |
| 4 | No optimistic concurrency: two clients race the same transition | CWE-362, CWE-841 | `POST /vuln15/subscriptions/{id}/state` (no version) | `SubscriptionStore.transition(id, target, expectedVersion)` compare-and-set; `ifMatch` required |
| 5 | Replayed payment callback: no idempotency key | CWE-294, CWE-837 | `POST /vuln15/payment/callback` (`subscriptionId`, `days`) — N replays, N applications | `POST /safe15/payment/callback` (`Idempotency-Key` mandatory, duplicate answered with `originalAppliedAt`) |
| 6 | Renewal length taken from the message | CWE-472 | `POST /vuln15/payment/callback` (`days`) | renewal derived from the order (`renewalDays: 30`, `amountCharged` from the subscription) |
| 7 | Entitlement decided by a request parameter | CWE-285, CWE-602 | `GET /vuln15/features/{key}?entitled=true` | `GET /safe15/features/{key}?subscriptionId=…` (state + tariff features) |
| 8 | Quota from the request, no per-account accounting | CWE-770 | `POST /vuln15/documents/generate?limit=10000` | `POST /safe15/documents/generate?subscriptionId=…` (per account per day, 429 past the tariff limit) |
| 9 | Consent with arbitrary scopes and no expiry validation | CWE-863, CWE-613 | `POST /vuln15/consent` (`scopes`, `expiresAt`) | `POST /safe15/consent` (scope allow-list, expiry in the future and ≤ 365 days) |
| 10 | No decision trail | CWE-778 | `/vuln15/*` — `_abuseLog` only, `record()` is never called | `GET /safe15/state` (`_auditTrail`), `GET /safe15/policy` |

## Reproduce

```bash
attacks/15-business-logic.sh

# the catalog exists and the order endpoint never looks at it
curl -s http://127.0.0.1:8095/vuln15/catalog
curl -s -X POST -H 'Content-Type: application/json' \
     -d '{"subscriptionId":"SUB-EVIL-1","plan":"ESPD-PRO","price":"1.00","currency":"RUB"}' \
     http://127.0.0.1:8095/vuln15/orders

# a terminal state is not terminal
curl -s -X POST 'http://127.0.0.1:8095/vuln15/subscriptions/SUB-1001/state?to=CANCELLED'
curl -s -X POST 'http://127.0.0.1:8095/vuln15/subscriptions/SUB-1001/state?to=ACTIVE'

# the same payment three times, three applications
for i in 1 2 3; do
  curl -s -X POST -H 'Content-Type: application/json' \
       -d '{"subscriptionId":"SUB-1001","status":"PAID","days":30}' \
       http://127.0.0.1:8095/vuln15/payment/callback; echo
done

# entitlement and quota from the request
curl -s 'http://127.0.0.1:8095/vuln15/features/espd.tender.export?entitled=true'
curl -s -X POST 'http://127.0.0.1:8095/vuln15/documents/generate?limit=10000'

# consent for scopes nobody offers, valid until 2099
curl -s -X POST -H 'Content-Type: application/json' \
     -d '{"subscriptionId":"SUB-1001","scopes":"espd.read,espd.admin,espd.everything","expiresAt":"2099-01-01T00:00:00Z"}' \
     http://127.0.0.1:8095/vuln15/consent
```

The hardened shape, where the same requests are answered from server-side state:

```bash
# the price is the catalog's, whatever the body says
curl -s -X POST -H 'Content-Type: application/json' \
     -d '{"subscriptionId":"SUB-OK-1","plan":"ESPD-PRO","price":"1.00","currency":"RUB"}' \
     http://127.0.0.1:8095/safe15/orders

# terminal state and stale version are refused, with the reason
curl -s -X POST 'http://127.0.0.1:8095/safe15/subscriptions/SUB-1003/state?to=ACTIVE&ifMatch=1'
curl -s -X POST 'http://127.0.0.1:8095/safe15/subscriptions/SUB-1003/state?to=CANCELLED&ifMatch=2'
curl -s -X POST 'http://127.0.0.1:8095/safe15/subscriptions/SUB-1003/state?to=ACTIVE&ifMatch=3'

# a replay is answered as a duplicate
curl -s -X POST -H 'Content-Type: application/json' -H 'Idempotency-Key: pay-evt-0001' \
     -d '{"subscriptionId":"SUB-1002","status":"PAID"}' \
     http://127.0.0.1:8095/safe15/payment/callback

# entitlement and quota are looked up per subscription
curl -s 'http://127.0.0.1:8095/safe15/features/espd.tender.export?subscriptionId=SUB-1001'
curl -s 'http://127.0.0.1:8095/safe15/features/espd.tender.export?subscriptionId=SUB-2001'
for i in 1 2 3; do
  curl -s -i -X POST 'http://127.0.0.1:8095/safe15/documents/generate?subscriptionId=SUB-2001' | head -1
done

# the policy and the trail, for the reviewer who asks "where is that written down"
curl -s http://127.0.0.1:8095/safe15/policy
curl -s http://127.0.0.1:8095/safe15/state
```

The safe module keeps state in memory, so `SUB-1003` only exists once `POST /safe15/orders` has created it;
run the order call from step 1 first, or the transition answers 404.

## Fix, in the order that matters

1. **The catalog is the only price.** The request names a plan (`^ESPD-(TRIAL|BASIC|PRO)$`); the amount,
   currency and features come from `TariffCatalog`. If an amount must be agreed with a payment provider,
   compare it with the server's own value and reject the mismatch — never store the client's number.
2. **Discounts are server-owned rules with eligibility.** `discountedPrice(tariff, discountCode,
   firstYear)` keeps the rule, its inputs and the rounding in one place; a code the client invents is
   simply not in the rule set.
3. **An explicit state machine, with a default of "not allowed".** `ALLOWED_TRANSITIONS` maps each state
   to the set it may move to, and a missing entry (`CANCELLED`, `EXPIRED`) means nothing may leave it.
   Re-activation is a new subscription, not an edge in the graph. Anything outside the set is a 422 with
   the allowed set in the body.
4. **Optimistic concurrency on every transition.** `ifMatch` carries the version the client read;
   `SubscriptionStore.transition` does a compare-and-set under a lock and answers 409 on a lost race.
   Double-click, retried request and two tabs all collapse into one state change.
5. **Idempotency on anything a payment provider can resend.** `Idempotency-Key` is mandatory, bounded
   (64 characters), stored with the outcome, and the second delivery returns the first outcome
   (`duplicate: true`, `originallyAppliedAt`) instead of applying it again. In production this is a
   unique index on the payment-event table, not a `ConcurrentHashMap`.
6. **Derive what the message should not carry.** Renewal period, charged amount and resulting state are
   computed from the order and the subscription; a callback is a fact about a payment, not an instruction
   to the subscription.
7. **Entitlement and quota are lookups, not flags.** `feature(key)` = subscription is ACTIVE or TRIAL
   **and** the tariff's feature list contains the key. `documents/generate` counts per subscription per
   day against `dailyDocumentLimit` and answers 429 past it. A UI that hides a button is not a control.
8. **Consent: allow-list the scopes, bound the lifetime.** Unknown scopes are rejected with the list of
   rejected names; `expiresAt` must parse as an instant, be in the future and be at most 365 days out;
   the stored grant is the validated one, not the request body.
9. **Record the decision.** Every accept and every refusal goes to the audit trail (`GET /safe15/state`)
   with the reason — `transition rejected`, `quota exceeded`, `feature denied` — so abuse shows up as a
   sequence of 422/429s with a subscription id, not as a support ticket about a strange invoice.

## Detection

* **The matrix test, not the demo.** Business-logic bugs are asserted, not scanned: the shape used by
  `m16-verification` (`SafeOwnershipMatrixTest`) applies directly — one row per `(endpoint, caller,
  input, expected status)`, here `(price=1.00, expected catalog price)`, `(CANCELLED → ACTIVE, 422)`,
  `(stale ifMatch, 409)`, `(replayed Idempotency-Key, duplicate)`, `(quota+1, 429)`,
  `(espd.admin, 400)`. `GET /safe15/policy` states every rule in one place so the test can be generated
  from it.
* `scripts/run_dast_zap.sh` sweeps ports 8081–8096, so a new self-inspection or catalog endpoint on 8095
  is seen by the DAST smoke run; `attacks/15-business-logic.sh` greps nothing and proves by status code.
* Static analysis does not understand price or lifecycle. The Semgrep rules in
  `tools/semgrep/spring-security-rules.yml` catch the neighbouring bug shapes — `spring-csrf-disabled`
  and `spring-security-ignoring-bypass` (`checklist: "2"`) on a state-changing endpoint — and
  `scripts/run_sast.sh` prints the review shortcut that finds them in a diff.
* Review heuristic: every `@RequestBody Map<String, Object>` on a money or lifecycle endpoint is a
  finding until the handler is shown to ignore the sensitive keys; `grep -rn "Map<String, Object>"
  src/main/java` on a payments service is a five-minute review.
* The audit trail is the detection signal: `authz_denied` in `m02` and `transition rejected` /
  `quota exceeded` in `m15` raised together, from one subscription, is abuse before it is revenue loss.

## Where this appears in real reviews

`{"plan":"ESPD-PRO","price":1}` accepted because "the frontend always sends the real price"; a
`cancel()` that sets a flag while `activate()` only checks `isAuthenticated()`; a status column updated
by an inbound webhook with no `payment_event_id` unique constraint, so a provider retry extends a
subscription by another year; `if (user.isPro)` populated from the session at login and never
re-checked after a downgrade; a "download limit" enforced in the browser and a generator endpoint that
accepts `limit`; and a consent record written from whatever the OAuth client sent, including
`espd.admin`, valid until 2099. None of these is visible to SAST or SCA, all of them are visible to a
negative test matrix — which is why this section is closed with a test, not with a comment.
