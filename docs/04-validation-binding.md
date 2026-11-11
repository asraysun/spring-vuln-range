# 04 · Input validation and data binding

Checklist section: **§4 Input validation and data binding** · Module: `m04-validation-binding` · Port: **8084**
PoC: [`attacks/04-validation-binding.sh`](../attacks/04-validation-binding.sh) · Run: `scripts/run-module.sh m04-validation-binding`

## What this module demonstrates

| # | Vulnerability | CWE | Insecure | Hardened |
|---|---------------|-----|----------|----------|
| 1 | Mass assignment through form binding | CWE-915 | `POST /vuln4/users` (`role=ADMIN&priceOverride=0`) | `POST /safe4/users` (DTO, `@Valid`) |
| 2 | Mass assignment through JSON (unknown fields ignored) | CWE-915 | `POST /vuln4/users/json` | `@JsonIgnoreProperties(ignoreUnknown=false)` per DTO |
| 3 | No bounds on input | CWE-20 | `POST /vuln4/notes` | `@Size`, `@Pattern`, `@Email` with explicit ranges |
| 4 | `sort`/`direction` concatenated into SQL | CWE-89 | `GET /vuln4/subscriptions?sort=` | allow-list resolution, 400 on unknown column |
| 5 | Unvalidated file read path | CWE-22 | `GET /vuln4/files/{name}` | `normalize()` + `startsWith(base)` + `isRegularFile` |
| 6 | Upload without size/type/name checks | CWE-434, CWE-22 | `POST /vuln4/upload` | 2 MB cap, extension allow-list, magic bytes, generated name |
| 7 | Binder exposure (Spring4Shell shape) | CWE-915 | `POST /vuln4/binder-probe` | `@InitBinder` disallows `class.*`, DTO boundary |
| 8 | User-supplied regex (ReDoS) | CWE-1333 | `POST /vuln4/search/regex` | literal search, bounded input |
| 9 | Open redirect | CWE-601 | `GET /vuln4/redirect?url=` | logical name → allow-listed target |
| 10 | Unbounded in-memory export | CWE-770 | `GET /vuln4/export?size=` | capped page size, `capped` flag |
| 11 | Hidden HTTP method filter | CWE-650 | `spring.mvc.hiddenmethod.filter.enabled` | keep `false` unless a form truly needs `_method` |
| 12 | Container-wide 1 GB multipart limit | CWE-770 | `spring.servlet.multipart.max-file-size: 1GB` | per-endpoint check on top of the container limit |

## Reproduce

```bash
attacks/04-validation-binding.sh

# the mass-assignment one-liner
curl -s -X POST http://127.0.0.1:8084/vuln4/users \
     -d 'username=attacker&email=a@example.invalid&role=ADMIN&monthlyLimit=999999' \
     -H 'Content-Type: application/x-www-form-urlencoded'

# the same intent against the hardened endpoint
curl -s -X POST http://127.0.0.1:8084/safe4/users \
     -H 'Content-Type: application/json' \
     -d '{"username":"attacker","email":"a@example.invalid","role":"ADMIN"}'
```

The second call answers `400 malformed request body`: the unknown field `role` is not silently
dropped, it is an error — which is what makes the attempt visible in logs.

## Notes on specific items

* **Spring4Shell / binder exposure.** On a patched Spring the `class.classLoader` chain is dead, and
  the PoC shows nothing. Keep the probe in the range anyway: it documents the shape, and it reminds
  reviewers that the fix is the DTO boundary (a field that does not exist cannot be assigned), not the
  framework patch alone.
* **Path traversal.** Spring's default `HttpFirewall` rejects `%2f`, `%5c` and `%2e` sequences, so the
  encoded traversal attempt is refused before your code runs. That is one useful default — not an
  application control. `/safe4` normalises and checks containment so the property holds even if the
  firewall is relaxed for some other reason.
* **Upload.** Extension plus magic bytes is the minimum; add AV/CDR scan and store outside the web
  root under a generated name, served as a download with `Content-Disposition: attachment`.

## Fix, in the order that matters

1. **One request contract per endpoint.** A DTO narrower than the entity; no privileged field exists to
   be assigned.
2. **Validate at the trust boundary**, before any business logic: size, format, enum membership, numeric
   range. Reject unknown JSON properties.
3. **Identifiers are not inputs.** Sort column, direction, field lists, redirect targets: resolve from
   a server-side map and answer 400 for anything not in it.
4. **Files:** size cap, allow-list, magic bytes, generated name, containment check, no execution.
5. **Bound every growth path:** page size, export size, upload size, regex input length.

## Detection

* Semgrep rule `path-resolution-from-request-without-containment`, `unvalidated-redirect` (in
  `tools/semgrep/spring-security-rules.yml`).
* Grep for `@ModelAttribute` and `@RequestBody` parameters whose type is an entity.
* Contract tests: send an extra privileged field, expect 400.
