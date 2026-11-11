import sys
import tomllib

bad = 0
for path in sys.argv[1:]:
    try:
        with open(path, "rb") as handle:
            tomllib.load(handle)
        print(f"ok   {path}")
    except Exception as exc:  # noqa: BLE001
        bad += 1
        print(f"FAIL {path}: {exc}")
sys.exit(1 if bad else 0)
