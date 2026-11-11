# 08 · Cryptography and TLS

Checklist section: **§8 Cryptography and TLS** · Module: `m08-crypto-tls` · Port: **8088** (HTTP), **8443** (HTTPS)
PoC: [`attacks/08-crypto-tls.sh`](../attacks/08-crypto-tls.sh) · Run: `scripts/run-module.sh m08-crypto-tls`

The HTTPS listener uses a **throw-away self-signed certificate generated at startup** (random password,
1-day validity, OS temp directory, deleted on exit). Nothing is committed: a keystore in a repository is
a credential, and "it is only the demo certificate" is how private keys reach git history.

## What this module demonstrates

| # | Vulnerability | CWE | Insecure | Hardened |
|---|---------------|-----|----------|----------|
| 1 | MD5 / SHA-1 as password hashes | CWE-916, CWE-327 | `POST /vuln8/hash` | `POST /safe8/hash-password` (Argon2id) |
| 2 | AES/ECB leaks plaintext structure | CWE-327 | `POST /vuln8/encrypt` | `POST /safe8/encrypt` (AES-GCM) |
| 3 | Static IV in CBC makes equal prefixes identical | CWE-329 | `POST /vuln8/encrypt-cbc` | random 96-bit IV per record |
| 4 | Padding oracle via distinct error messages | CWE-209, CWE-347 | `POST /vuln8/decrypt` | one generic 400 |
| 5 | Tokens from `java.util.Random` (time-seeded) | CWE-330, CWE-338 | `GET /vuln8/token/random`, `/token/predict?seed=` | `GET /safe8/token` (`SecureRandom`, 256 bit) |
| 6 | Hardcoded key material in the artifact | CWE-321, CWE-798 | `GET /vuln8/key-info` | `DataKeyProvider` (env / ephemeral, never a repo default) |
| 7 | Trust-all `TrustManager` + hostname verifier bypass | CWE-295 | `POST /vuln8/fetch-https` | `POST /safe8/fetch-https` (default trust store) |
| 8 | Non-constant-time secret comparison | CWE-208 | `InsecureTokenService` (m01) | `POST /safe8/token/verify` (`MessageDigest.isEqual`) |
| 9 | TLS protocol floor | CWE-326 | — | listener restricted to TLS 1.2/1.3 |

## Reproduce

```bash
attacks/08-crypto-tls.sh

# ECB: identical blocks in, identical blocks out
curl -s -X POST -H 'Content-Type: application/json' -d '{"plain":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}' \
     http://127.0.0.1:8088/vuln8/encrypt

# predictable token
SEED=$(curl -s http://127.0.0.1:8088/vuln8/token/random | sed -n 's/.*"seedUsed":\([0-9]*\).*/\1/p')
curl -s "http://127.0.0.1:8088/vuln8/token/predict?seed=$SEED"

# trust-all TLS, against a certificate that is not in any trust store
curl -s https://127.0.0.1:8443/vuln8/hash-info            # refused: correct behaviour
curl -sk https://127.0.0.1:8443/vuln8/hash-info           # accepted: what the vulnerable client does
curl -s -X POST -H 'Content-Type: application/json' \
     -d '{"url":"https://127.0.0.1:8443/vuln8/hash-info"}' http://127.0.0.1:8088/vuln8/fetch-https
```

The last call returns `certificateVerified: false` and the body: the application accepted a certificate
nobody trusts. `/safe8/fetch-https` reports the rejection instead, which is the control working.

## Fix, in the order that matters

1. **Passwords:** Argon2id (or BCrypt/scrypt with a tuned cost). Nothing else.
2. **Encryption:** authenticated modes only — AES-GCM or ChaCha20-Poly1305. Random IV per record, stored
   with the ciphertext, never derived from data that the attacker can influence.
3. **Randomness:** `SecureRandom`. Every token, code, id and salt. `Random` is a reproducible sequence.
4. **Keys:** from Vault/KMS, with a key id in the envelope so rotation can be gradual. No repository
   default, no `toString()` that prints material.
5. **TLS:** default trust store, hostname verification on, TLS 1.2+. Never a custom `X509TrustManager`
   that accepts everything — if an internal CA is needed, import the CA, do not disable verification.
6. **Errors:** one generic failure. Any distinction between "bad padding" and "bad tag" is an oracle.

## Detection

* FindSecBugs `WEAK_MESSAGE_DIGEST_MD5`, `WEAK_MESSAGE_DIGEST_SHA1`, `SSL_CONTEXT`, `WEAK_TRUST_MANAGER`.
* Semgrep rules `weak-message-digest-for-security`, `unauthenticated-cipher-mode`,
  `trust-all-x509-trust-manager`, `hostname-verification-disabled`.
* Grep: `TrustManager`, `setHostnameVerifier`, `SSLContext.getInstance`, `Cipher.getInstance("AES/ECB`,
  `new Random(` next to `token|code|secret`.

## Where this appears in real reviews

`Cipher.getInstance("AES/ECB/PKCS5Padding")` copied from a tutorial, CBC "because GCM was not in the
snippet", `new Random()` for reset codes, a static `KEY = "0verview-key-2020"`, and a trust-all
`RestTemplate` added to make an internal integration "work" with a self-signed certificate. Each is a
one-line change that silently removes a control someone else is relying on.
