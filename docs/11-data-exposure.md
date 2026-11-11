# 11 · Data exposure and privacy

Checklist section: **§11 Data exposure and privacy** · Module: `m11-data-exposure` · Port: **8091**
PoC: [`attacks/11-data-exposure.sh`](../attacks/11-data-exposure.sh) · Run: `scripts/run-module.sh m11-data-exposure`

The database is H2 in memory, seeded from `data.sql` with two synthetic subscribers (`USR-0001`,
`USR-0002`) so the over-fetching has something to over-fetch. `spring.jpa.open-in-view` is deliberately
left at the Boot default: the lazy `subscriptions` association then serialises silently inside the
`/vuln11` endpoints, which is part of why "the entity is the response" survives in real codebases.

## What this module demonstrates

| # | Vulnerability | CWE | Insecure | Hardened |
|---|---------------|-----|----------|----------|
| 1 | JPA entity serialised as the API response (hash, token, risk score, INN, SNILS) | CWE-213, CWE-312 | `GET /vuln11/subscribers/{id}` | `GET /safe11/subscribers/{id}` (`SafeExposureController.SubscriberView`) |
| 2 | Whole table, no projection, no pagination | CWE-213, CWE-770 | `GET /vuln11/subscribers` | `GET /safe11/subscribers` (page, size, total, `maxPageSize`) |
| 3 | PII in the query string | CWE-598, CWE-532 | `GET /vuln11/subscribers/search?email=` | `POST /safe11/subscribers/search` (body, `SearchRequest`) |
| 4 | Access token as a query parameter, then echoed | CWE-598, CWE-532 | `GET /vuln11/reports/{id}?accessToken=` | `GET /safe11/reports/{id}` (`Authorization: Bearer`) |
| 5 | Field selection without an allow-list | CWE-213 | `GET /vuln11/subscribers/{id}/export?fields=passwordHash,refreshToken` | `GET /safe11/subscribers/{id}/export` (allow-list, 400 with the rejected fields) |
| 6 | Client-controlled page size | CWE-770 | `GET /vuln11/subscribers/page?size=1000000` | `GET /safe11/subscribers?size=` capped at `MAX_PAGE_SIZE` (100) |
| 7 | No stated response contract | CWE-213 | — | `GET /safe11/selftest` (`exposedFields`, `neverExposed`) |

## Reproduce

```bash
attacks/11-data-exposure.sh

# the entity is the response: passwordHash, refreshToken, internalRiskScore, inn, snils, espdTokenHash
curl -s http://127.0.0.1:8091/vuln11/subscribers/USR-0001

# whole table, every column, every row
curl -s http://127.0.0.1:8091/vuln11/subscribers

# PII in the query string: now in the access log and the Referer
curl -s 'http://127.0.0.1:8091/vuln11/subscribers/search?email=alice@example.invalid'

# credential in the URL, echoed into the body
curl -s 'http://127.0.0.1:8091/vuln11/reports/REP-1?accessToken=placeholder-token-0001'

# any field is exportable
curl -s 'http://127.0.0.1:8091/vuln11/subscribers/USR-0001/export?fields=passwordHash,refreshToken'

# the client decides how much memory the server spends
curl -s -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1:8091/vuln11/subscribers/page?size=1000000'
```

The hardened endpoints answer with the projection and reject the field names:

```bash
curl -s http://127.0.0.1:8091/safe11/subscribers/USR-0001
curl -s 'http://127.0.0.1:8091/safe11/subscribers?size=1000000'
curl -s 'http://127.0.0.1:8091/safe11/subscribers/USR-0001/export?fields=passwordHash'
curl -s http://127.0.0.1:8091/safe11/selftest
```

The `export` call above returns `400` with `rejected: ["passwordHash"]` and the `allowed` list: the
attempt is visible in logs instead of being silently filtered.

## Fix, in the order that matters

1. **A response contract, not an entity.** `SafeExposureController.SubscriberView` is the only shape a
   subscriber leaves the service in: `id`, `username`, `maskedEmail`, `primaryPlan`. A new entity column
   does not become API output by default.
2. **Mask before serialising.** `maskEmail` turns `alice@example.invalid` into `a***e@example.invalid`.
   Masking in a Jackson serialiser is a filter that someone can forget to register; masking in the
   projection is not.
3. **Identifiers stay out of URLs.** `POST /safe11/subscribers/search` takes the e-mail in a validated
   `SearchRequest` (`@Email`, `@Size(max = 254)`); `GET /safe11/reports/{id}` takes the token from the
   `Authorization` header and never echoes it.
4. **Field selection is a projection allow-list.** `/safe11/{id}/export` checks the requested names
   against a fixed list and builds the map itself; it does not pass the list to the repository.
5. **The server owns the page size.** `MAX_PAGE_SIZE` = 100, clamped with `Math.clamp`, reported back in
   the response and in `/safe11/selftest`.
6. **State the contract for CI.** `/safe11/selftest` lists `exposedFields` and `neverExposed`; a contract
   test fails the build when the two lists change, which is the moment a review should happen.
7. **Column-level protection in the database as a second layer:** the hash, the refresh token and the
   government identifiers are read by one narrow query on the authentication path, not by a generic
   `findAll`. Encrypt `inn`/`snils` at rest and keep them out of read models entirely.

## Detection

* Semgrep `unvalidated-redirect` and the path-containment rules do not cover this class; the check that
  does is a contract test asserting that `GET /safe11/subscribers/USR-0001` has exactly the keys in
  `/safe11/selftest` and that the body does not contain `passwordHash`, `refreshToken`, `inn` or `snils`.
* Grep the diff for entity types in controller signatures: `@RestController` methods returning
  `SubscriberEntity` or `List<SubscriberEntity>`, and `CrudRepository` interfaces exposed directly.
* Grep the diff for sensitive names in URLs: `accessToken`, `token`, `password`, `email=` inside mapping
  paths and `@RequestParam`.
* `scripts/run_secret_scan.sh` catches a hash, token or credential that leaks into a committed sample, a
  fixture or a log file — not one that leaks into a live response. The contract test above is the gate
  for the live case.
* `scripts/run_dast_zap.sh` already sweeps for unauthenticated `/api-docs/openapi.json`; add the
  `/safe11/selftest` comparison there if you want one place for both checks.

## Where this appears in real reviews

`public SubscriberEntity get(@PathVariable String id)` as a controller signature, because the DTO
"would be the same fields anyway"; `?email=` on a search endpoint that is also called from a browser;
`accessToken` in a report link that was pasted into a chat; and `@RequestParam(defaultValue = "1000000")
int size` added to make an export "complete". Each one is a one-line change, each one is invisible to a
functional test, and each one is a finding in a data-protection review long after the code shipped.
