# 02 · Authorization and access control

Checklist section: **§2 Authorization** · Module: `m02-authorization` · Port: **8082**
PoC: [`attacks/02-authorization.sh`](../attacks/02-authorization.sh) · Run: `scripts/run-module.sh m02-authorization`

Users: `alice:alice-pass`, `bob:bob-pass`, `mallory:mallory-pass` (has `ROLE_ADMIN`, obtained through
the vulnerable registration path), `svc-report:svc-pass` (has `SCOPE_report:read`).

## What this module demonstrates

| # | Vulnerability | CWE | Insecure | Hardened |
|---|---------------|-----|----------|----------|
| 1 | IDOR / BOLA: any authenticated user reads any subscription | CWE-639 | `GET /vuln2/subscriptions/{id}` | `GET /safe2/subscriptions/{id}` (`@PreAuthorize` + owner predicate) |
| 2 | Sequential ids make enumeration trivial | CWE-200 | same | non-sequential ids **and** ownership |
| 3 | State change behind a "public read" matcher | CWE-352, CWE-650 | `GET /vuln2/subscriptions/{id}/cancel` | `POST /safe2/subscriptions/{id}/cancel` |
| 4 | `permitAll()` leftovers exposing data with PII | CWE-285 | `GET /vuln2/admin/subscriptions`, `GET /vuln2/internal/metrics` | `/safe2/admin/**` → `hasRole('ADMIN')` |
| 5 | `WebSecurityCustomizer.ignoring()` bypasses the whole chain | CWE-1188 | `GET /vuln2/bypass/whoami` | removed; public paths use `permitAll()` so they stay reviewable |
| 6 | Tenant boundary taken from a request parameter | CWE-863 | `GET /vuln2/tenant/subscriptions?tenantId=` | `GET /safe2/tenant/subscriptions` (tenant from principal) |
| 7 | Vacuous method security (`isAuthenticated()` only) | CWE-863 | `GET /vuln2/profile/{username}` | object-level policy bean `subscriptionAccess` |
| 8 | Privilege escalation via client-supplied authorities | CWE-269, CWE-915 | `POST /vuln2/register?authorities=ROLE_ADMIN` | `POST /safe2/register` (fixed `USER`) |
| 9 | No default-deny tail | CWE-1188 | implicit `permitAll` on `/vuln2/admin/**` | `.anyRequest().denyAll()` |

## Reproduce

```bash
attacks/02-authorization.sh

# the one-line version of the most common real-world bug
curl -s -u bob:bob-pass http://127.0.0.1:8082/vuln2/subscriptions/SUB-1001   # 200, alice's data
curl -s -u bob:bob-pass http://127.0.0.1:8082/safe2/subscriptions/SUB-1001   # 404
```

Watch the status codes at the end of the script: `/safe2` answers 401 without credentials,
404 for a foreign row, 200 for the owner, and the unknown path is denied by the default tail.

## Fix, in the order that matters

1. **Default deny, then enumerate.** Put `.anyRequest().denyAll()` (or `.authenticated()`) at the end
   of the chain. Every `permitAll()` becomes a line a reviewer can see and argue about.
2. **Object-level checks where the row is read.** `findByIdAndOwner(id, principal.getName())`, a
   tenant-scoped `@Query`, or Hibernate multi-tenancy. URL patterns cannot see data ownership.
3. **State changes are POST/PUT/PATCH/DELETE.** A GET that mutates will eventually sit behind a
   "reads are public" rule.
4. **Identity from the token, never from the request.** Tenant, user, role: from the principal.
5. **Answer 404 for foreign rows**, so authorization does not become an enumeration oracle.
6. **Write the matrix test.** See `m16-verification`: `(endpoint, caller, ownership, expected status)`
   for every protected endpoint. This is the only control that keeps working after the reviewer moves on.
7. **Never call `.ignoring()`.** If a path must be public, say it with `permitAll()`.

## Detection and review heuristics

* Ratio of `@*Mapping` to `@PreAuthorize`: if it is 40:3, three endpoints are the reviewed ones.
* Diff-based check: `git diff -U0 | grep 'permitAll\|ignoring()'` on every MR (in `scripts/run_sast.sh`).
* Log `authz_denied` with actor, resource and outcome — the denial spikes are your earliest IDOR probe.
