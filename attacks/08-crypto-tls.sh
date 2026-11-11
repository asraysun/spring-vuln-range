#!/usr/bin/env bash
# Checklist section 8 — cryptography and TLS.  Target: m08-crypto-tls (8088, HTTPS 8443)
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
PORT=8088
HTTPS_PORT=8443
banner "08 · weak crypto, predictable tokens, trust-all TLS (port ${PORT} / ${HTTPS_PORT})"
up "${PORT}" m08-crypto-tls

# -----------------------------------------------------------------------------------------------
title "1. MD5 / SHA-1 as a password hash"
req POST "${PORT}" "/vuln8/hash" '{"value":"Corre7-Horse!"}'
note "Nobody needs to 'crack' anything: the same string always yields the same digest, so a"
note "precomputed table answers it, and a GPU tries billions of candidates per second."
note "Reference implementation: Argon2id, salted, memory-hard:"
req POST "${PORT}" "/safe8/hash-password" '{"password":"Corre7-Horse!"}'

# -----------------------------------------------------------------------------------------------
title "2. AES/ECB leaks the plaintext structure"
req POST "${PORT}" "/vuln8/encrypt" '{"plain":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}'
note "identicalBlocksPresent=true: 16 identical plaintext bytes became 16 identical ciphertext bytes."
note "Change one block and the rest of the ciphertext is unchanged: the data structure is public."
req POST "${PORT}" "/vuln8/encrypt" '{"plain":"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"}'

# -----------------------------------------------------------------------------------------------
title "3. Static IV in CBC makes equal prefixes encrypt identically"
req POST "${PORT}" "/vuln8/encrypt-cbc" '{"plain":"subscription=ESPD-BASIC;pad="}'
req POST "${PORT}" "/vuln8/encrypt-cbc" '{"plain":"subscription=ESPD-BASIC;pad="}'
note "Same input, same output, across calls and across users. A random IV per record stops that."
note "Reference implementation: AES-GCM, fresh 96-bit IV per call, integrity tag:"
req POST "${PORT}" "/safe8/encrypt" '{"plain":"subscription=ESPD-BASIC;pad="}'
req POST "${PORT}" "/safe8/encrypt" '{"plain":"subscription=ESPD-BASIC;pad="}'

# -----------------------------------------------------------------------------------------------
title "4. Padding oracle: distinct errors tell the attacker whether a block was well-formed"
req POST "${PORT}" "/vuln8/decrypt" '{"base64":"YWJjZGVmZ2hpamtsbW5vcA=="}'
req POST "${PORT}" "/vuln8/decrypt" '{"base64":"AAAAAAAAAAAAAAAAAAAAAA=="}'
note "Different messages = an oracle. Reference implementation answers one generic 400 for every"
note "failure, because AES-GCM authenticity gives nothing useful to report:"
req POST "${PORT}" "/safe8/decrypt" '{"envelopeBase64":"AAAAAAAAAAAAAAAAAAAAAA=="}'

# -----------------------------------------------------------------------------------------------
title "5. Predictable tokens from java.util.Random"
WEAK=$(curl -sS -m 5 "$(BASE_FOR_PORT ${PORT})/vuln8/token/random" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
SEED=$(curl -sS -m 5 "$(BASE_FOR_PORT ${PORT})/vuln8/token/random" | sed -n 's/.*"seedUsed":\([0-9]*\).*/\1/p')
echo "  token issued    : ${WEAK}"
echo "  seed the service used: ${SEED}"
req GET "${PORT}" "/vuln8/token/predict?seed=${SEED}"
note "Same generator, same seed, same token: the whole space is computable from the clock."
note "Reference implementation uses SecureRandom with 256 bits of entropy:"
req GET "${PORT}" "/safe8/token"
req POST "${PORT}" "/safe8/token/verify" '{"expected":"abc","provided":"abc"}'

# -----------------------------------------------------------------------------------------------
title "6. Hardcoded key material compiled into the artifact"
req GET "${PORT}" "/vuln8/key-info"
note "grep -r 's3cr3t\|key' on the jar finds it; so does anyone holding the artifact or the fork."

# -----------------------------------------------------------------------------------------------
title "7. Trust-all TrustManager and hostname-verifier bypass (real HTTPS handshake)"
note "The module serves a throw-away self-signed certificate on 127.0.0.1:${HTTPS_PORT}."
printf '  1) a verifying client rejects it (correct behaviour):\n'
curl -sS -m 6 --max-time 6 "https://127.0.0.1:${HTTPS_PORT}/vuln8/hash-info" 2>&1 | head -3 | sed 's/^/     /'
printf '  2) curl -k accepts it, just like a trust-all TrustManager does:\n'
curl -sSk -m 6 "https://127.0.0.1:${HTTPS_PORT}/vuln8/hash-info" 2>/dev/null | head -3 | sed 's/^/     /'
note "Inside the application, /vuln8/fetch-https uses exactly that trust-all client:"
req POST "${PORT}" "/vuln8/fetch-https" "{\"url\":\"https://127.0.0.1:${HTTPS_PORT}/vuln8/hash-info\"}"
note "Reference implementation uses the default JVM trust store and reports the rejection:"
req POST "${PORT}" "/safe8/fetch-https" "{\"url\":\"https://127.0.0.1:${HTTPS_PORT}/vuln8/hash-info\"}"

# -----------------------------------------------------------------------------------------------
title "8. TLS protocol floor on the listener"
printf '  TLS 1.0 handshake attempt (should fail): '
if command -v openssl >/dev/null 2>&1; then
  openssl s_client -connect "127.0.0.1:${HTTPS_PORT}" -tls1 </dev/null 2>&1 | grep -qi "handshake failure\|no protocols available\|unsupported" \
    && echo "refused (good)" || echo "check manually with: openssl s_client -connect 127.0.0.1:${HTTPS_PORT} -tls1"
else
  echo "openssl not available"
fi
echo
banner "done · details and fixes: docs/08-crypto-tls.md"
