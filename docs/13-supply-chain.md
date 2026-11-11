# 13 · Dependencies and supply chain

Checklist section: **§13 Dependencies and build integrity** · Module: `m13-supply-chain` · Port: **8093**
PoC: [`attacks/13-supply-chain.sh`](../attacks/13-supply-chain.sh) · Run: `scripts/run-module.sh m13-supply-chain`

The vulnerability in this module is the dependency set, not the code. The parent POM pins
`commons-collections` **3.2.1** (`vulnerable.commons-collections.version`) and `fastjson` **1.2.24**
(`vulnerable.fastjson.version`); the module consumes both without declaring a version. Everything the
endpoints below show follows from those two lines. A scanner that reports this module as clean is not
looking, and no other finding from the same tool should be trusted.

## What this module demonstrates

| # | Vulnerability | CWE | Insecure | Hardened |
|---|---------------|-----|----------|----------|
| 1 | A vulnerable library shipped on the classpath and never flagged | CWE-1104, CWE-1395 | `commons-collections` 3.2.1, `fastjson` 1.2.24 (parent `pom.xml`); inventory at `GET /vuln13/dependency-inventory` | `baseline-upgrades` profile (`commons-collections4` 4.4); versions pinned and gated, not merely declared |
| 2 | Deserialization gadget reachable through `ObjectInputStream` with no filter | CWE-502, CWE-1395 | `POST /vuln13/gadget/round-trip` (`InvokerTransformer`, `$method`, `$target`) | `POST /safe13/deserialize-with-filter` (`ObjectInputFilter` allow-list, 64 KB cap) |
| 3 | JSON parser that instantiates the class named in the payload | CWE-502 | `POST /vuln13/parse-json` (`setAutoTypeSupport(true)`, `@type`) | `POST /safe13/parse-json` (concrete `OrderDocument`, unknown properties rejected) |
| 4 | No size limit before parsing attacker bytes | CWE-770, CWE-502 | `POST /vuln13/gadget/round-trip` (whole body decoded and read) | `MAX_PAYLOAD_BYTES` (64 KB) → 413 |
| 5 | No build gate on dependency risk | CWE-1104 | the module builds with the findings present | `dependency-check-maven` 10.0.4, `failBuildOnCVSS` 7, bound to the `sca` profile; `scripts/run_sca.sh` |
| 6 | Suppression used as a mute button | CWE-1104 | — (see `tools/owasp/suppressions.xml`) | dated, owned, expiring suppression entries; the m13 findings are deliberately not suppressed |
| 7 | Unreviewed upgrade "fix" | CWE-1395 | — | upgrade the library and drop the polymorphic parser; the filter buys time, the upgrade is the fix |

## Reproduce

```bash
attacks/13-supply-chain.sh

# what the module actually ships
curl -s http://127.0.0.1:8093/vuln13/dependency-inventory

# the gadget primitive: the stream names the class and the method
curl -s -X POST -H 'Content-Type: application/json' \
     -d '{"method":"toUpperCase","target":"deserialization-primitive"}' \
     http://127.0.0.1:8093/vuln13/gadget/round-trip

curl -s -X POST -H 'Content-Type: application/json' \
     -d '{"method":"hashCode"}' \
     http://127.0.0.1:8093/vuln13/gadget/round-trip

# fastjson autoType: the payload chooses the class, its setter runs
curl -s -X POST -H 'Content-Type: application/json' \
     -d '{"@type":"com.example.vulnrange.m13.vuln.VulnerableSupplyChainController$AutotypeProbe","note":"chosen-by-payload"}' \
     http://127.0.0.1:8093/vuln13/parse-json

# the compensating control, and the fix: upgraded class path and a concrete target type
curl -s -X POST -H 'Content-Type: application/json' \
     -d '{"base64":"rO0ABXNyABdqYXZhLnV0aWwuSGFzaE1hcAAAAAAAAAABAwAAeHB3CAAAAA=="}' \
     http://127.0.0.1:8093/vuln13/gadget/with-filter

curl -s -X POST -H 'Content-Type: application/json' \
     -d '{"@type":"com.example.vulnrange.m13.vuln.VulnerableSupplyChainController$AutotypeProbe","note":"x"}' \
     http://127.0.0.1:8093/safe13/parse-json
curl -s -X POST -H 'Content-Type: application/json' -d '{"subscriptionId":"SUB-1001"}' \
     http://127.0.0.1:8093/safe13/parse-json
curl -s http://127.0.0.1:8093/safe13/policy
```

The gate is the second half of the demonstration. It must **fail** here:

```bash
scripts/run_sca.sh
# or, without the wrapper:
./mvnw -B -pl m13-supply-chain org.owasp:dependency-check-maven:check \
       -DfailBuildOnCVSS=7 -DsuppressionFile=tools/owasp/suppressions.xml
# report: sast-results/dependency-check/ (HTML + JSON, per m13-supply-chain/pom.xml)
```

A green run is the finding: check that the NVD feed was downloaded, that transitive dependencies are
included, and that the threshold is actually wired to the exit code.

## Fix, in the order that matters

1. **Remove the parser that names classes.** fastjson `autoType` and Jackson default typing turn a
   parser into an object factory. Bind to a concrete type (`OrderDocument` in the `m13` safe package),
   reject unknown properties, and keep a size cap in front of the parser (`MAX_PAYLOAD_BYTES`).
2. **Upgrade the library, do not filter around it.** The `baseline-upgrades` profile points at
   `commons-collections4` 4.4; fastjson 1.2.x is replaced rather than configured. A filter on
   `ObjectInputStream` is a compensating control for formats you cannot remove today.
3. **If a binary format must stay today:** `ObjectInputFilter` allow-list built from the types you
   actually deserialize (`SafeSupplyChainController$OrderDocument`, `java.lang.String`, a narrow
   `java.base/java.util.*` slice) with `!*` as the default, plus depth/array/byte limits, plus a log
   line and an alert on every rejection.
4. **Pin and gate.** Every dependency pinned through the BOM, no range versions, resolved from an
   internal proxy with checksums. `dependency-check-maven` with `failBuildOnCVSS` 7, Trivy or Snyk on
   the image and the registry, and a nightly rescan so a new CVE in an old dependency resurfaces.
5. **Scan what you did not write.** Transitive dependencies, build plugins (`dependency-check` in
   `m13-supply-chain/pom.xml` is itself version-pinned for the same reason) and container images.
   A transitive CVE is your CVE.
6. **Suppress deliberately.** `tools/owasp/suppressions.xml` carries one template entry with why, who
   and an expiry date; the only real entry in a service should look like it, and an expired entry
   should fail the build.

## Detection

* `scripts/run_sca.sh` — step 1 `dependency:tree` into `sast-results/`, step 2 OWASP dependency-check
  on `m13-supply-chain` (expected FAIL), step 3 `trivy fs --severity CRITICAL,HIGH --exit-code 1`.
  The script exits `1` when the gate passes and `0` when it fails, which is the calibration test.
* The check is bound to the `sca` profile only (`./mvnw -Psca -pl m13-supply-chain verify`), so
  `scripts/run-module.sh` and a plain `./mvnw package` build the module normally — the gate is an
  explicit decision in CI, not a side effect of every local build, and it does not change `server.address`.
* What the scanner will actually report: `fastjson` 1.2.24 is inside the autoType CVE range
  (`CVE-2022-25845` and the 1.2.x family). `commons-collections` 3.2.1 is flagged as the
  ysoserial gadget carrier; note that its own invariants-bypass `CVE-2015-6420` was fixed in **3.2.2**,
  so a scanner that only claims 3.2.1 is "unpatched for CVE-2015-6420" is imprecise — the finding to
  keep is "deserialization gadget reachable", which is row 2 of the table and the reason the fix is
  `commons-collections4` plus an `ObjectInputFilter`, not a version bump alone.
* CI wiring: the `sca` job in `.github/workflows/security.yml` (dependency-check plus
  `aquasecurity/trivy-action`) and `sca-dependency-check` / `sca-trivy` in `.gitlab-ci.yml`, both with
  `failBuildOnCVSS=7` and no `allow_failure`.
* Semgrep rule `fastjson-autotype-enabled` (`$CONFIG.setAutoTypeSupport(true)`) still reports on
  `VulnerableSupplyChainController`; `scripts/run_sast.sh` also lists `setAutoTypeSupport\(true\)` as a
  grep fallback and prints the review shortcut that flags every new `<artifactId>` in a diff:
  `git diff -U0 -- 'pom.xml' | grep -n '^+.*<artifactId>'`.
* `scripts/run_secret_scan.sh` with `tools/gitleaks/.gitleaks.toml` (`useDefault = true`, local rules
  `spring-property-credential`, `jwt-secret-in-config`, `private-key-block`, `basic-auth-in-url`) covers
  the other build-integrity failure: a credential committed next to the dependency it belongs to.
* Grep for `<version>` inside a module POM (a version belongs in `dependencyManagement`), and review
  `git diff` on every lockfile/BOM update as security-relevant change, not housekeeping.

## Where this appears in real reviews

A `pom.xml` with a handful of versions pinned to whatever resolved the first time, and no scan of the
transitive graph; a `commons-collections` or `fastjson` that arrived three dependencies deep and nobody
declared; an "upgrade" that moves one artifact and leaves the gadget family on the classpath; a
scanner whose report is green because the database was stale or the suppression file grew an
`exclude all of org.apache.*` entry; and a `latest` tagged base image that pulls new CVEs on every
deploy. None of these is visible in review, which is why the gate — and a gate that fails on this
module specifically — is the control.
