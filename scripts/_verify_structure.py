"""Consistency check for the range: ports, reactor wiring, loopback binding, endpoint references.

No compiler needed. It catches the boring mistakes that make a demo fail in front of an audience:
a PoC pointing at a path that does not exist, a module missing from the reactor, a module bound to
something other than loopback, a port collision, or a missing writeup.
"""
import re
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODULES = [
    "m01-authentication", "m02-authorization", "m03-secrets-config", "m04-validation-binding",
    "m05-injection", "m06-deserialization", "m07-web-layer", "m08-crypto-tls",
    "m09-logging-errors", "m10-ssrf-webhooks", "m11-data-exposure", "m12-actuator",
    "m13-supply-chain", "m14-runtime-hardening", "m15-business-logic", "m16-verification",
]

problems: list[str] = []
notes: list[str] = []


def fail(message: str) -> None:
    problems.append(message)


# ---------------------------------------------------------------- reactor wiring
try:
    reactor = ET.parse(ROOT / "pom.xml").getroot()
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    declared = [m.text for m in reactor.findall("m:modules/m:module", ns)]
except Exception as exc:  # noqa: BLE001
    fail(f"root pom.xml is not parseable: {exc}")
    declared = []

for module in MODULES:
    if module not in declared:
        fail(f"{module}: not listed in the root pom.xml <modules>")
for extra in declared:
    if extra not in MODULES:
        fail(f"root pom.xml declares {extra}, which is not a known module")

# ---------------------------------------------------------------- ports and binding
seen: dict[int, str] = {}
for module in MODULES:
    pom = ROOT / module / "pom.xml"
    if not pom.is_file():
        fail(f"{module}: pom.xml missing")
        continue
    try:
        ET.parse(pom)
    except Exception as exc:  # noqa: BLE001
        fail(f"{module}/pom.xml is not parseable: {exc}")
    app = ROOT / module / "src/main/resources/application.yml"
    if not app.is_file():
        fail(f"{module}: application.yml missing")
        continue
    text = app.read_text(encoding="utf-8")
    port_match = re.search(r"^\s+port:\s*(\d+)", text, re.MULTILINE)
    if not port_match:
        fail(f"{module}: server.port not set")
    else:
        port = int(port_match.group(1))
        if port in seen:
            fail(f"{module}: port {port} already used by {seen[port]}")
        seen[port] = module
    if "address: 127.0.0.1" not in text:
        fail(f"{module}: server.address is not 127.0.0.1")

# ---------------------------------------------------------------- endpoint references in PoCs
def declared_endpoints(source_text: str) -> set[str]:
    """Full endpoint paths assembled from class-level @RequestMapping + method-level mappings."""
    bases = re.findall(r'@RequestMapping\("([^"]*)"\)\s*(?:@\w+(?:\([^)]*\))?\s*)*public class', source_text)
    base = bases[0] if bases else ""
    paths: set[str] = set()
    for kind, raw in re.findall(r'@(Get|Post|Put|Delete|Patch|Request)Mapping\(\s*(?:value\s*=\s*)?"([^"]*)"', source_text):
        paths.add((base + raw).rstrip("/") or "/")
    for raw in re.findall(r'@RequestMapping\("([^"]*)"\)', source_text):
        if raw.startswith("/"):
            paths.add(raw.rstrip("/") + "/**")
    return paths


for script in sorted((ROOT / "attacks").glob("*.sh")):
    if script.name == "lib.sh":
        continue
    index = script.name[:2]
    module = next((m for m in MODULES if m.startswith(f"m{index}-")), None)
    if module is None:
        fail(f"{script.name}: cannot map to a module")
        continue
    endpoints: set[str] = set()
    for java in (ROOT / module / "src/main/java").rglob("*.java"):
        endpoints |= declared_endpoints(java.read_text(encoding="utf-8", errors="ignore"))
    for path in sorted(set(re.findall(rf"/(?:vuln|safe){index}/[A-Za-z0-9_/.{{}}-]*",
                                      script.read_text(encoding="utf-8")))):
        candidate = path.split("{")[0].rstrip("/")
        if not candidate:
            continue
        matched = any(
            candidate == endpoint
            or endpoint.endswith("/**") and candidate.startswith(endpoint[:-3])
            or candidate.startswith(endpoint + "/")
            for endpoint in endpoints
        )
        if not matched:
            fail(f"{script.name}: {path} is not a declared endpoint in {module}")

# ---------------------------------------------------------------- documentation
for module in MODULES:
    index = module[1:3]
    if not list((ROOT / "docs").glob(f"{index}-*.md")) if (ROOT / "docs").is_dir() else []:
        notes.append(f"{module}: docs/{index}-*.md not written yet")

# ---------------------------------------------------------------- dangerous remnants
for module in MODULES:
    for java in (ROOT / module / "src/main/java").rglob("*.java") if (ROOT / module / "src/main/java").is_dir() else []:
        text = java.read_text(encoding="utf-8", errors="ignore")
        if "\t" in text:
            fail(f"{java.relative_to(ROOT)}: contains tab indentation")
        if re.search(r"\bSystem\.out\.println\(", text) and "Application" not in java.name:
            notes.append(f"{java.relative_to(ROOT)}: uses System.out.println (use a logger)")

print(f"modules checked: {len(MODULES)}")
print(f"ports in use   : {sorted(seen)}")
for note in notes:
    print(f"  NOTE  {note}")
if problems:
    print()
    for problem in problems:
        print(f"  FAIL  {problem}")
    print(f"\nRESULT: {len(problems)} problem(s)")
    raise SystemExit(1)
print("\nRESULT: range is self-consistent")
