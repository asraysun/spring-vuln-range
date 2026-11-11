# 09 · Error handling, logging and security events

Checklist section: **§9 Error handling, logging, monitoring** · Module: `m09-logging-errors` · Port: **8089**
PoC: [`attacks/09-logging-errors.sh`](../attacks/09-logging-errors.sh) · Run: `scripts/run-module.sh m09-logging-errors`

## What this module demonstrates

| # | Vulnerability | CWE | Insecure | Hardened |
|---|---------------|-----|----------|----------|
| 1 | Stack trace in the HTTP response | CWE-209 | `GET /vuln9/boom` (`include-stacktrace: always`) | `SafeApiExceptionHandler` |
| 2 | SQL text and internals in the error body | CWE-209, CWE-200 | `GET /vuln9/report?id=` | generic problem detail + `incidentId` |
| 3 | User enumeration by message and by timing | CWE-204, CWE-208 | `POST /vuln9/login` | `POST /safe9/login` (same body, same work) |
| 4 | Validation errors that echo stored state | CWE-209 | `POST /vuln9/register` | rule-based violations only |
| 5 | PII and the caller's token in the log | CWE-532 | `POST /vuln9/audit/checkout` | `POST /safe9/audit/checkout` (masked) |
| 6 | CRLF log forging | CWE-117 | `POST /vuln9/audit/message?message=` | `POST /safe9/audit/message` |
| 7 | No security events at all | CWE-778 | `GET /vuln9/audit/trail` → "nothing is recorded" | `GET /safe9/audit/trail` (event stream) |
| 8 | Runtime/topology disclosure | CWE-200 | `GET /vuln9/debug/info` | — (removed; see `m12`) |
| 9 | No correlation id | CWE-778 | — | `CorrelationIdFilter` + `X-Correlation-Id` |

## Reproduce

```bash
attacks/09-logging-errors.sh

# stack trace + framework internals
curl -s http://127.0.0.1:8089/vuln9/boom

# enumeration
curl -s -X POST -H 'Content-Type: application/json' -d '{"username":"alice","password":"x"}'  http://127.0.0.1:8089/vuln9/login
curl -s -X POST -H 'Content-Type: application/json' -d '{"username":"nobody","password":"x"}' http://127.0.0.1:8089/vuln9/login

# card number and token into the log, then grep for it
curl -s -X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer demo-token' \
     -d '{"cardNumber":"4111111111111111","email":"alice@example.invalid","amount":"990.00"}' \
     http://127.0.0.1:8089/vuln9/audit/checkout
grep -rn 4111111111111111 logs/m09-logging-errors.log
```

The hardened failure shape, with a reference the caller can quote to support and the responder can
look up in the log store:

```bash
curl -s -i http://127.0.0.1:8089/safe9/error | head -12
```

## Fix, in the order that matters

1. **One generic client-facing error.** `server.error.include-stacktrace=never`,
   `include-message=never`, `include-binding-errors=never`, `include-exception=false`; a
   `@RestControllerAdvice` that maps exceptions to stable problem details.
2. **Correlation id everywhere.** Generated if the client does not send a sane one, put in the MDC,
   returned in a header, and carried into the incident id of a 500.
3. **Mask before writing.** `maskSecrets`, `maskIdentity`, `sanitiseForLog`: no card numbers, tokens,
   full e-mails, or CR/LF. Structured JSON logging makes scrubbing a pipeline rule, not a hope.
4. **Log the security events, not the noise:** `login_ok`, `login_failed`, `login_throttled`,
   `authz_denied`, `token_rejected`, `password_changed`, `config_changed` — actor (masked), resource,
   outcome, correlation id.
5. **Alert on the right things:** failure spikes, denial spikes, unusual export volumes, authenticaton
   from new regions. Detection latency is the difference between an incident and a breach.
6. **Retention and access:** logs are a secondary data store. Short retention for high-detail logs,
   strict read access, encryption at rest.

## Detection

* Semgrep rule `verbose-error-responses-enabled` (YAML) on every module's configuration.
* `scripts/run_sast.sh` includes it; CI fails on `include-stacktrace: always`.
* A log-hygiene test: send a known synthetic PAN to every endpoint and grep the log output for it.

## Where this appears in real reviews

`server.error.include-stacktrace=always` copied from a debugging session, an `@ExceptionHandler` that
returns `e.getMessage()`, `log.info("login failed for " + email + " password=" + password)`, and the
absence of any audit event for a password change. All four are review comments, and all four are
written down here so the comment has a reference.
