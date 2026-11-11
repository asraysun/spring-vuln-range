# 10 · Outbound calls and webhooks

Checklist section: **§10 Outbound calls and webhooks** · Module: `m10-ssrf-webhooks` · Port: **8090**
PoC: [`attacks/10-ssrf-webhooks.sh`](../attacks/10-ssrf-webhooks.sh) · Run: `scripts/run-module.sh m10-ssrf-webhooks`

The "internal service" and the cloud instance metadata service are **simulated inside this module**
(`/vuln10/internal-admin/users`, `/vuln10/imds/**`). The PoC proves the SSRF primitive — the server makes
a request the caller chose — without a packet leaving the loopback interface.

## What this module demonstrates

| # | Vulnerability | CWE | Insecure | Hardened |
|---|---------------|-----|----------|----------|
| 1 | SSRF: caller-supplied URL fetched with the service's network position | CWE-918 | `POST /vuln10/fetch` (`{"url":"http://127.0.0.1:8090/vuln10/internal-admin/users"}`) | `POST /safe10/fetch` (`SafeFetchController`: scheme, host, port and path allow-lists) |
| 2 | Internal admin surface with no authentication ("it is internal, so it is safe") | CWE-306 | `GET /vuln10/internal-admin/users` | destination only reachable through the `/safe10` allow-list; no admin surface in `/safe10` |
| 3 | Metadata-service pattern reachable through the fetcher | CWE-918 | `POST /vuln10/fetch` → `http://127.0.0.1:8090/vuln10/imds/latest/meta-data/iam/security-credentials` | private-range and link-local refusal in `SafeFetchController` |
| 4 | Redirect-following defeats a naive allow-list | CWE-918 | `GET /vuln10/redirect-to-internal`, followed by `POST /vuln10/fetch` | `setInstanceFollowRedirects(false)` in the `SafeFetchController` client factory |
| 5 | Fetch-and-store without type or size checks | CWE-434, CWE-918 | `POST /vuln10/avatar` → `Files.write` of attacker-chosen bytes | `MAX_RESPONSE_BYTES` (256 KB) cap, no store endpoint in `/safe10` |
| 6 | Outbound client without timeouts | CWE-400, CWE-770 | `new RestTemplate()` + `GET /vuln10/slow` | connect 2 s / read 4 s in the `SimpleClientHttpRequestFactory` |
| 7 | Unsigned payment webhook | CWE-345, CWE-347 | `POST /vuln10/webhook/payment` (`signatureChecked: false`) | `POST /safe10/webhook/payment` (HMAC-SHA256 over timestamp + raw body) |
| 8 | Replayable webhook: no timestamp window, no idempotency key | CWE-294 | `POST /vuln10/webhook/payment` twice with the same body | 300 s window + `X-Webhook-Event-Id` idempotency store |

## Reproduce

```bash
attacks/10-ssrf-webhooks.sh

# the server reaches an admin surface the caller cannot
curl -s -X POST -H 'Content-Type: application/json' \
     -d '{"url":"http://127.0.0.1:8090/vuln10/internal-admin/users"}' \
     http://127.0.0.1:8090/vuln10/fetch

# the same primitive pointed at the simulated metadata service
curl -s -X POST -H 'Content-Type: application/json' \
     -d '{"url":"http://127.0.0.1:8090/vuln10/imds/latest/meta-data/iam/security-credentials"}' \
     http://127.0.0.1:8090/vuln10/fetch

# an "internal-looking" URL whose redirect target is not
curl -s -X POST -H 'Content-Type: application/json' \
     -d '{"url":"http://127.0.0.1:8090/vuln10/redirect-to-internal"}' \
     http://127.0.0.1:8090/vuln10/fetch

# unsigned payment webhook: anyone can mark anything paid, as often as they like
curl -s -X POST -H 'Content-Type: application/json' \
     -d '{"subscriptionId":"SUB-2001","status":"PAID","amount":"0.00","days":3650}' \
     http://127.0.0.1:8090/vuln10/webhook/payment
```

The reference implementation answers the same SSRF attempt with a 400 naming the refused leg of the
request, and refuses a webhook without headers:

```bash
curl -s -i -X POST -H 'Content-Type: application/json' \
     -d '{"url":"http://127.0.0.1:8090/vuln10/redirect-to-internal"}' \
     http://127.0.0.1:8090/safe10/fetch | head -12

curl -s -i -X POST -H 'Content-Type: application/json' \
     -d '{"subscriptionId":"SUB-2001","status":"PAID"}' \
     http://127.0.0.1:8090/safe10/webhook/payment | head -12

curl -s http://127.0.0.1:8090/safe10/egress-policy
```

## Fix, in the order that matters

1. **No unrestricted outbound URL.** In `SafeFetchController`, the destination is resolved before any
   connection: scheme in `http`/`https`, host in `ALLOWED_HOSTS`, port in `ALLOWED_PORTS`, path under an
   `ALLOWED_PATH_PREFIXES` entry. Anything else is a 400, not a best effort.
2. **Judge the resolved address, not the hostname.** `InetAddress.getAllByName` runs before the call; the
   metadata range, link-local, site-local and any-local addresses are refused. DNS pinning or an egress
   proxy closes the resolution gap that a re-resolving client leaves open.
3. **Redirects off.** `setInstanceFollowRedirects(false)` on the `SimpleClientHttpRequestFactory`. An
   allow-list checked once, on the first hop, is not a control.
4. **Timeouts and size caps.** Connect 2 s, read 4 s, `MAX_RESPONSE_BYTES` 256 KB. A downstream that
   never answers must not hold a request thread, and a downstream that answers with a gigabyte must not
   be written to disk.
5. **Webhook authentication over the raw body.** `sign(timestamp + "." + rawBody)` with HMAC-SHA256,
   compared with `MessageDigest.isEqual`. The secret comes from `vulnrange.safe.webhook-secret`
   (`RANGE_M10_WEBHOOK_SECRET`), not from a repository default.
6. **A bounded window and an idempotency key.** `REPLAY_WINDOW_SECONDS` (300) rejects stale messages;
   the `processedEvents` map keyed by `X-Webhook-Event-Id` turns a replay into a no-op. In a real
   deployment that key is a unique index in the database, not a `ConcurrentHashMap`.
7. **Signature proves origin, not correctness.** Prices and statuses are re-derived from the order
   record; a correctly signed message can still be a business-logic bug.

## Detection

* Semgrep rule `ssrf-url-from-request` (Java, path filter `*vuln*`) flags `$RT.getForObject($URL, …)`
  and `$RT.postForObject($URL, …)`, which matches both calls in `VulnerableFetchController`.
* `scripts/run_sast.sh` prints the manual review shortcut `git diff -U0 -- '*.java' | grep -n
  'RestTemplate\|WebClient\|HttpClient'`: every new outbound client in a diff is a review point.
* `scripts/run_dast_zap.sh` probes `/actuator` and `/api-docs/openapi.json` on every port; the same
  sweep is the place to add an SSRF canary fetch to a loopback listener that records connections.
* Grep for `new RestTemplate()` without a `ClientHttpRequestFactory`, and for `@RequestBody` maps whose
  field name is `url`/`uri`/`endpoint`.

## Where this appears in real reviews

A "preview avatar" or "import from URL" feature that takes the URL from the request body, a
`RestTemplate` built with `new RestTemplate()` because the default "just works", and a payment
webhook endpoint that parses `status` from the body without checking a signature because "the provider
only posts to this URL". Each is one request factory or one header check away from being correct, and
each is invisible in a functional test that only ever uses a valid URL and a valid message.
