import sys

try:
    import yaml  # type: ignore
except ImportError:
    print("pyyaml not installed; skipping YAML validation")
    sys.exit(0)

files = sys.argv[1:]
bad = 0
for path in files:
    try:
        with open(path, encoding="utf-8") as handle:
            list(yaml.safe_load_all(handle))
        print(f"ok   {path}")
    except Exception as exc:  # noqa: BLE001 - report and continue
        bad += 1
        print(f"FAIL {path}: {exc}")
sys.exit(1 if bad else 0)
