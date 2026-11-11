# 03 · Secrets and configuration

Checklist section: **§3 Secrets and configuration** · Module: `m03-secrets-config` · Port: **8083**
PoC: [`attacks/03-secrets-config.sh`](../attacks/03-secrets-config.sh) · Run: `scripts/run-module.sh m03-secrets-config`

> Every credential in this module is a **synthetic placeholder** taken from public documentation
> (`AKIAIOSFODNN7EXAMPLE`, `postgres`, `0123456789abcdef`). They exist so that scanners, log scrubbing
> and review practices can be exercised for real. None of them opens anything.

## What this module demonstrates

| # | Vulnerability | CWE | Insecure | Hardened |
|---|---------------|-----|----------|----------|
| 1 | Secret returned by an ordinary API call | CWE-200, CWE-540 | `GET /vuln3/config` | `GET /safe3/config-summary` (presence only) |
| 2 | Service hands out its own credential | CWE-522 | `GET /vuln3/integration/token` | `POST /safe3/integration/call` (signs, returns fingerprint) |
| 3 | Environment dump with credential-shaped values | CWE-526 | `GET /vuln3/env-dump` | removed; `credentialValuesReturned: 0` in `/safe3/config-summary` |
| 4 | Credential written to the application log | CWE-532 | `POST /vuln3/integration/check` | `POST /safe3/echo` (masked) |
| 5 | Dev tooling in a production-shaped config (H2 console) | CWE-489 | `POST /diagnostics`, `spring.h2.console.enabled: true` | `application-prod.yml` (`false`) |
| 6 | One credential for dev/ift/prod | CWE-522 | `GET /vuln3/per-env-credentials` | per-environment values from Vault, no repository default |
| 7 | Compiled-in default used as a silent fallback | CWE-1188 | `LegacyIntegrationProperties` (`:${...:fallback}`) | `VaultFileSecretProvider.resolve()` throws if missing |
| 8 | Secret material printed by `toString()` | CWE-532 | `LegacyIntegrationProperties` fields in dumps | `SecretHandle` (never reveals material, zeroes on close) |

## Reproduce

```bash
attacks/03-secrets-config.sh

curl -s http://127.0.0.1:8083/vuln3/config | python3 -m json.tool
curl -s http://127.0.0.1:8083/vuln3/integration/token
curl -s -X POST -H 'Content-Type: application/json' \
     -d '{"dbUser":"espd_app","dbPassword":"MY-MARKER"}' \
     http://127.0.0.1:8083/vuln3/integration/check
grep -n MY-MARKER logs/m03-secrets-config.log      # the "secret" is now in the log pipeline
```

Also try the reference path: start the module with a real injected secret and watch the sensitive
endpoint still refuse to print it.

```bash
RANGE_M03_SECRETS_DIR=/some/empty/dir scripts/run-module.sh m03-secrets-config
curl -s -X POST -H 'Content-Type: application/json' -d '{"requestId":"r1"}' \
     http://127.0.0.1:8083/safe3/integration/call      # 503: fail closed, no fallback credential
```

## Fix, in the order that matters

1. **Resolution order:** mounted secret file (Vault Agent / Kubernetes secret volume) → injected env
   variable → **fail startup**. Never a repository default: a fallback turns "missing secret" into
   "shared dev credential in production".
2. **Never return a credential.** A service *uses* secrets; the only thing an API may report is
   whether one is present and what its fingerprint is.
3. **Mask before logging.** `SecretHandle.toString()` shows length + 2 characters; the masking classes
   in `m09` do the same for whole log lines.
4. **One credential per environment and per service, least privilege.** The runtime DB user gets no
   DDL; integration tokens get one scope; nothing is reused across stands.
5. **Config hygiene:** `spring.h2.console.enabled=false` outside a local profile, `devtools` not in
   the runtime image, `management.endpoint.env.show-values: never`, active profiles asserted at startup.
6. **History is part of the secret.** Rotating a leaked key is mandatory; rewriting git history is
   optional. Assume every committed value has been read.

## Detection

* `gitleaks detect --source . --redact` on every MR **and** nightly over full history.
* Grep for the shape, not the value: `(password|secret|token|api[_-]?key)\s*[:=]\s*['"]?[A-Za-z0-9/+]{12,}`.
* Alert on `GET` responses that contain a field named like a credential (contract test, not a rule in
  someone's head).
* Check that `/actuator/env` is not exposed (`m12`).

## Where this appears in real reviews

`@Value("${db.password:postgres}")`, support endpoints that dump `System.getenv()`, `log.info`
with a credential "to debug the connection", `h2.console.enabled=true` in a shared deploy, and the
same secret across `dev`/`ift`/`prod` because "it is easier". Every one of them is a two-line diff.
