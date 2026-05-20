#!/usr/bin/env python3
"""Fix wallet payload format for btcrecover.

BTCRecover expects Blockchain.com wallet in this exact JSON format:
{"payload":"<base64>","pbkdf2_iterations":<number>,"version":<number>}

This script reads our extracted payload and converts it to the correct format.
"""

import os
import json
import re
import sys


def fix_payload(input_file, output_file):
    """Convert extracted payload to btcrecover-compatible format."""
    with open(input_file, "r", encoding="utf-8") as f:
        data = f.read().strip()

    # Extract the payload value
    payload = None

    # Case 1: Already has "payload":"..." format
    match = re.search(r'"payload"\s*:\s*"([A-Za-z0-9+/=]+)"', data)
    if match:
        payload = match.group(1)

    if not payload:
        # Case 2: Raw base64 data
        match = re.search(r'([A-Za-z0-9+/]{100,}={0,2})', data)
        if match:
            payload = match.group(1)

    if not payload:
        print("ERROR: Cannot extract payload from file")
        return False

    # Try to find pbkdf2_iterations
    iterations = 5000  # Default for older blockchain.com wallets
    iter_match = re.search(r'"pbkdf2_iterations"\s*:\s*(\d+)', data)
    if iter_match:
        iterations = int(iter_match.group(1))

    # Try to find version
    version = 3  # Default version
    ver_match = re.search(r'"version"\s*:\s*(\d+)', data)
    if ver_match:
        version = int(ver_match.group(1))

    # Build correct format for btcrecover
    wallet_json = json.dumps({
        "payload": payload,
        "pbkdf2_iterations": iterations,
        "version": version,
    })

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(wallet_json)

    print(f"  Payload length: {len(payload)} chars")
    print(f"  PBKDF2 iterations: {iterations}")
    print(f"  Version: {version}")
    print(f"  Saved to: {output_file}")
    print(f"  File size: {len(wallet_json)} bytes")

    return True


def main():
    print()
    print("=" * 55)
    print("  FIX WALLET PAYLOAD FOR BTCRECOVER")
    print("=" * 55)
    print()

    input_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wallet_payloads")
    output_dir = input_dir

    if not os.path.exists(input_dir):
        print("  ERROR: wallet_payloads folder not found!")
        return

    # Process all payload files
    for fname in os.listdir(input_dir):
        if fname.startswith("wallet_payload") and fname.endswith(".json"):
            input_file = os.path.join(input_dir, fname)
            output_file = os.path.join(output_dir, f"fixed_{fname}")
            print(f"  Processing: {fname}")
            success = fix_payload(input_file, output_file)
            if success:
                print(f"  OK!")
            print()

    print("  DONE!")
    print()
    print("  Now run btcrecover:")
    print('  cd "C:\\Users\\ERWIN SYAH ST\\Desktop\\btcrecover"')
    print('  python btcrecover.py --wallet "C:\\Users\\ERWIN SYAH ST\\Desktop\\cek\\wallet_payloads\\fixed_wallet_payload_0.json" --passwordlist "C:\\Users\\ERWIN SYAH ST\\Desktop\\cek\\passwords.txt"')
    print()


if __name__ == "__main__":
    main()
