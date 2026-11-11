#!/usr/bin/env bash
# Checklist section 13 — dependencies and supply chain.  Target: m13-supply-chain (8093)
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
PORT=8093
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
banner "13 · dependency risk and build integrity (port ${PORT})"
up "${PORT}" m13-supply-chain

# -----------------------------------------------------------------------------------------------
title "1. What this module actually ships"
req GET "${PORT}" "/vuln13/dependency-inventory"
note "These two versions are pinned on purpose. Your SCA gate must report them."

# -----------------------------------------------------------------------------------------------
title "2. Why the version matters: the gadget is on the classpath"
note "InvokerTransformer round-trips through ObjectOutputStream/ObjectInputStream. Whichever class"
note "the stream names gets instantiated and its methods invoked - the entry primitive of the"
note "classic commons-collections chains. The range stops at proving the primitive."
req POST "${PORT}" "/vuln13/gadget/round-trip" '{"method":"toUpperCase","target":"deserialization-primitive"}'
req POST "${PORT}" "/vuln13/gadget/round-trip" '{"method":"hashCode"}'

# -----------------------------------------------------------------------------------------------
title "3. fastjson with autoType enabled: JSON names the class"
req POST "${PORT}" "/vuln13/parse-json" \
  '{"@type":"com.example.vulnrange.m13.vuln.VulnerableSupplyChainController$AutotypeProbe","note":"chosen-by-payload"}'
note "Application code ran because the payload said so; 'sideEffects' is the proof."

# -----------------------------------------------------------------------------------------------
title "4. The compensating control, and the real fix"
note "ObjectInputFilter with an allow-list rejects anything outside the permitted classes:"
req POST "${PORT}" "/vuln13/gadget/with-filter" '{"base64":"rO0ABXNyABdqYXZhLnV0aWwuSGFzaE1hcAAAAAAAAAABAwAAeHB3CAAAAA=="}'
note "The fix is not a filter: it is an upgraded dependency and a parser with a concrete target type."
req POST "${PORT}" "/safe13/parse-json" \
  '{"@type":"com.example.vulnrange.m13.vuln.VulnerableSupplyChainController$AutotypeProbe","note":"x"}'
req POST "${PORT}" "/safe13/parse-json" '{"subscriptionId":"SUB-1001"}'
req GET "${PORT}" "/safe13/policy"

# -----------------------------------------------------------------------------------------------
title "5. Run the gate, not just the demo"
note "The gate must FAIL here; a green run means the scanner is not looking."
if [ -x "${ROOT}/scripts/run_sca.sh" ]; then
  echo "  ${ROOT}/scripts/run_sca.sh"
else
  echo "  ./mvnw -pl m13-supply-chain org.owasp:dependency-check-maven:check -DfailBuildOnCVSS=7"
fi
note "Then read tools/owasp/suppressions.xml: dated, named, owned exceptions only."
echo
banner "done · details and fixes: docs/13-supply-chain.md"
