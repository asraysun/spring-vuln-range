# 06 · Deserialization, XML and polymorphic JSON

Checklist section: **§6 Serialization, XML, remoting** · Module: `m06-deserialization` · Port: **8086**
PoC: [`attacks/06-deserialization.sh`](../attacks/06-deserialization.sh) · Run: `scripts/run-module.sh m06-deserialization`

> Scope note: the payloads here prove that **attacker-controlled bytes cause application code to run**
> (constructor, setter, `hashCode`), which is the primitive every gadget chain starts from. Turning that
> primitive into an exploit — an `ObjectFactory` over LDAP/RMI, a `TemplatesImpl` chain — is deliberately
> not provided, and the range never contacts anything but loopback.

## What this module demonstrates

| # | Vulnerability | CWE | Insecure | Hardened |
|---|---------------|-----|----------|----------|
| 1 | `ObjectInputStream.readObject` on untrusted bytes | CWE-502 | `POST /vuln6/session/import` | `POST /safe6/session/import` (`ObjectInputFilter` allow-list) |
| 2 | No depth/array/size limits on the stream | CWE-502, CWE-400 | same | filter rejects by depth, array length, bytes, references |
| 3 | XStream without type permissions | CWE-502 | `POST /vuln6/xml/xstream` | `POST /safe6/xml/xstream` (`NoTypePermission.NONE` + `allowTypes`) |
| 4 | XXE: external entity reads a local file | CWE-611 | `POST /vuln6/xml/xxe` | `POST /safe6/xml/parse` (`disallow-doctype-decl`) |
| 5 | XXE as an SSRF origin (`http://` entity) | CWE-611, CWE-918 | same parser | same fix: no DTD, no external entities |
| 6 | Jackson `activateDefaultTyping` with a lax validator | CWE-502 | `POST /vuln6/json/polymorphic` | `POST /safe6/json/data` (concrete target type) |
| 7 | Side effects made visible | — | `GET /vuln6/side-effects` | — |

## Reproduce

```bash
attacks/06-deserialization.sh

# what a legitimate stream looks like (produced by the server itself)
curl -s http://127.0.0.1:8086/vuln6/session/example

# attacker-crafted bytes: same shape, class and field values chosen by the attacker
# (the script generates this with python3 — no Java tooling required)
curl -s -X POST -H 'Content-Type: application/json' \
     --data-binary @/tmp/vulnrange-m06-payload.json \
     http://127.0.0.1:8086/vuln6/session/import
curl -s http://127.0.0.1:8086/vuln6/side-effects      # Probe.<init> / setNote / hashCode ran
```

XXE is self-contained: the module writes a marker file on startup and reports its path, the PoC builds
a `DOCTYPE` with a `SYSTEM "file://..."` entity pointing at it, and the vulnerable parser returns the
file's text. The hardened parser refuses the document outright.

## Fix, in the order that matters

1. **Do not deserialize object graphs from the network.** Exchange a schema-validated representation
   (JSON with a concrete DTO, Protobuf, Avro) and map it into your own types.
2. **If a binary format is unavoidable today:** `ObjectInputFilter` allow-list **plus** depth/array/byte
   limits, and treat every rejection as an attack signal. This is a compensating control, not the fix.
3. **Remove the gadget surface as well:** upgrade `commons-collections`, XStream, fastjson; drop
   `enableDefaultTyping`/`activateDefaultTyping`; never enable fastjson `autoType`.
4. **XML:** `disallow-doctype-decl=true` first, then external-general/parameter entities off,
   `secure-processing=true`, `XIncludeAware(false)`, `expandEntityReferences(false)`.
5. **Message brokers count too.** Kafka/Rabbit payloads are untrusted input; validate schema and origin.

## Detection

* FindSecBugs `OBJECT_DESERIALIZATION`, `XXE_*`; Semgrep rules
  `java-deserialization-of-untrusted-bytes`, `jackson-polymorphic-typing-enabled`,
  `fastjson-autotype-enabled`, `xxe-parser-without-hardening`.
* Grep: `readObject(`, `XStream(`, `newInstance()`, `activateDefaultTyping`, `fromXML`.
* Runtime: `-Djdk.serialFilter=...` as a JVM-wide backstop for anything the code review missed.

## Where this appears in real reviews

An endpoint that accepts a serialized object "for backwards compatibility", a session store that
portably serializes objects, an XML integration with a default parser, and `XStream` used because it
was in a blog post. All of them compile, all of them "work", and all of them are one payload away
from remote code execution.
