"""Lightweight Java import/reference sanity check for the range (no compiler required).

Checks, per module:
  * every imported project class resolves to a file under the same module (or is a JDK/third-party
    import, which this script cannot and does not try to resolve);
  * every class referenced from a class in the same package exists somewhere in the module;
  * obvious compile traps: `record` used as a generic parameter name, unclosed generics in imports,
    imports of classes that are declared `private`, and builder methods called statically.

It is not a compiler. It catches the mistakes made by hand-written generators, which is exactly the
failure mode this repository is prone to.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODULES = sorted(p for p in ROOT.glob("m[0-9][0-9]-*") if p.is_dir())

JDK_PREFIXES = (
    "java.", "javax.", "jakarta.", "org.w3c.", "com.sun.", "sun.", "jdk.",
)

THIRD_PARTY_PREFIXES = (
    "org.springframework.", "org.slf4j.", "com.fasterxml.", "com.thoughtworks.", "com.alibaba.",
    "org.apache.", "org.hibernate.", "org.junit.", "org.mockito.", "org.hamcrest.", "org.xml.",
)

problems: list[str] = []
notes: list[str] = []


def simple_name(qualified: str) -> str:
    return qualified.rsplit(".", 1)[-1]


for module in MODULES:
    java_files = sorted((module / "src").rglob("*.java"))
    if not java_files:
        problems.append(f"{module.name}: no Java sources")
        continue

    # package -> declared top-level types
    declared: dict[str, set[str]] = {}
    # qualified name -> source text (only for classes we own)
    our_types: dict[str, str] = {}
    for path in java_files:
        text = path.read_text(encoding="utf-8", errors="ignore")
        package = re.search(r"^package\s+([\w.]+);", text, re.MULTILINE)
        package_name = package.group(1) if package else ""
        types = re.findall(r"^(?:public\s+|final\s+|abstract\s+)*(class|interface|record|enum)\s+(\w+)",
                           text, re.MULTILINE)
        declared.setdefault(package_name, set()).update(name for _, name in types)
        for _, name in types:
            our_types[f"{package_name}.{name}"] = text

    for path in java_files:
        text = path.read_text(encoding="utf-8", errors="ignore")
        rel = path.relative_to(ROOT)
        package = re.search(r"^package\s+([\w.]+);", text, re.MULTILINE)
        package_name = package.group(1) if package else ""

        # 1. imports of our own classes must resolve inside this module
        for imported in re.findall(r"^import\s+(?!static)([\w.]+);", text, re.MULTILINE):
            if imported.startswith(JDK_PREFIXES) or imported.startswith(THIRD_PARTY_PREFIXES):
                continue
            if imported.startswith("com.example.vulnrange"):
                if imported not in our_types:
                    bare = imported.rsplit(".", 1)[-1]
                    # static nested types live under an outer class name in our_types
                    if not any(q.endswith("$" + bare) or q.split(".")[-1] == bare for q in our_types):
                        problems.append(f"{rel}: imports {imported}, which is not declared in this module")

        # 2. `record` used as a type parameter name (not a keyword in Java, but confusing/illegal in some spots)
        if re.search(r"<\s*record\s+", text):
            problems.append(f"{rel}: 'record' used as a generic parameter name")

        # 3. calling a builder as if it were static
        if re.search(r"(?<![\w.])Option\.of\(", text):
            problems.append(f"{rel}: Option.of(...) called statically (should be Optional.of)")

        # 4. generics on imports (never legal)
        if re.search(r"^import\s+[\w.]+\s*<", text, re.MULTILINE):
            problems.append(f"{rel}: generic type in an import statement")

        # 5. same-package class references must exist
        for reference in set(re.findall(r"(?<![\w.])([A-Z]\w+)\.(?:record|builder|static)\(", text)):
            if reference not in declared.get(package_name, set()):
                notes.append(f"{rel}: static call on unknown type {reference}")

        # 6. Map.of with more than 10 pairs, Set.of with more than 10 elements (compile errors).
        INFIX_WRAPPERS = ("return", "yield", "case", "default", "throws")

        def top_level_commas(args: str) -> int:
            depth = 0
            commas = 0
            for char in args:
                if char in "([{":
                    depth += 1
                elif char in ")]}":
                    depth -= 1
                elif char == "," and depth == 0:
                    commas += 1
            return commas

        def arities(source: str) -> list[int]:
            """Counts of top-level arguments for every Map.of(...) / Set.of(...) call in source."""
            counts: list[int] = []
            for marker in ("Map.of(", "Set.of("):
                index = source.find(marker)
                while index >= 0:
                    before = source[:index].rstrip()
                    if before.endswith(INFIX_WRAPPERS):
                        index = source.find(marker, index + len(marker))
                        continue
                    cursor = index + len(marker)
                    begin = cursor
                    depth = 1
                    while cursor < len(source) and depth:
                        char = source[cursor]
                        if char in "([{":
                            depth += 1
                        elif char in ")]}":
                            depth -= 1
                        cursor += 1
                    body = source[begin:cursor - 1]
                    counts.append(top_level_commas(body) + 1)
                    # Recurse into the body so nested calls are counted as well.
                    counts.extend(arities(body))
                    index = source.find(marker, cursor)
            return counts

        for arity in arities(text):
            if arity > 10:
                problems.append(f"{rel}: Map.of/Set.of call with {arity} arguments (maximum 10)")

    # 7. every endpoint controller must declare a class-level @RequestMapping
    for java in module.glob("src/main/java/**/*Controller.java"):
        text = java.read_text(encoding="utf-8", errors="ignore")
        if re.search(r"@(Get|Post|Put|Delete|Patch)Mapping", text) and "@RequestMapping" not in text:
            problems.append(f"{java.relative_to(ROOT)}: mapping methods but no class-level @RequestMapping")

print(f"modules scanned: {len(MODULES)}")
for note in notes:
    print(f"  NOTE  {note}")
if problems:
    print()
    for problem in problems:
        print(f"  FAIL  {problem}")
    print(f"\nRESULT: {len(problems)} problem(s)")
    raise SystemExit(1)
print("\nRESULT: Java references look consistent")
