#!/usr/bin/env python3
"""Extract Blockchain.com encrypted wallet payload from Chrome Local Storage.

Blockchain.com stores the encrypted wallet in browser Local Storage (LevelDB).
If you ever logged in successfully, the payload should still be there.

This script extracts it so we can use btcrecover to brute-force the password.
"""

import os
import sys
import json
import re
import struct

HOME = os.path.expanduser("~")

# All Chrome-based browser Local Storage paths
BROWSER_PATHS = {
    "Chrome Default": os.path.join(HOME, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Local Storage", "leveldb"),
    "Chrome Backup": os.path.join(HOME, "Desktop", "Chrome_Backup", "Default", "Local Storage", "leveldb"),
    "Brave": os.path.join(HOME, "AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data", "Default", "Local Storage", "leveldb"),
    "Edge": os.path.join(HOME, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Local Storage", "leveldb"),
    "AVG": os.path.join(HOME, "AppData", "Local", "AVG", "Browser", "User Data", "Default", "Local Storage", "leveldb"),
}

# Also check numbered Chrome profiles
for i in range(1, 50):
    profile_path = os.path.join(HOME, "AppData", "Local", "Google", "Chrome", "User Data", f"Profile {i}", "Local Storage", "leveldb")
    BROWSER_PATHS[f"Chrome Profile {i}"] = profile_path

# Patterns to find blockchain.com wallet payload
PAYLOAD_PATTERNS = [
    b'"payload"',
    b'"pbkdf2_iterations"',
    b'"version"',
    b'"guid"',
    b'blockchain',
]

# Wallet ID patterns
WALLET_IDS = [
    "1f330204-c407-45d2-8ccf-5d0a87a23cf6",
    "1af403a8-eb94-4534-b1f4-5c838c871a7b",
]


def scan_leveldb_file(filepath):
    """Read a LevelDB file and search for blockchain wallet data."""
    results = []
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except (OSError, PermissionError):
        return results

    text = data.decode("utf-8", errors="ignore")

    # Look for wallet payload JSON
    # Blockchain.com stores wallet as: {"guid":"...","payload":"...","pbkdf2_iterations":...}
    # Or just the encrypted payload string

    for wid in WALLET_IDS:
        if wid in text:
            results.append(("wallet_id", wid, filepath))

    # Search for payload pattern
    # The payload is a long base64-like string
    if '"payload"' in text or "'payload'" in text:
        # Try to extract JSON containing payload
        # Look for patterns like {"payload":"<base64data>","pbkdf2_iterations":5000,...}
        payload_regex = r'\{[^{}]*"payload"\s*:\s*"([A-Za-z0-9+/=]+)"[^{}]*\}'
        matches = re.finditer(payload_regex, text)
        for m in matches:
            payload = m.group(1)
            full_match = m.group(0)
            if len(payload) > 100:  # Real payloads are large
                results.append(("payload_json", full_match[:200] + "...", filepath))

    # Also search for raw encrypted wallet data
    # Blockchain.com v2/v3 format starts with specific patterns
    # Look for long base64 strings near blockchain keywords
    if "blockchain" in text.lower():
        # Find long base64 sequences (wallet payloads are typically 1000+ chars)
        b64_regex = r'[A-Za-z0-9+/]{500,}={0,2}'
        for m in re.finditer(b64_regex, text):
            b64_data = m.group(0)
            # Check if this is near a blockchain.com context
            start = max(0, m.start() - 200)
            context = text[start:m.start()].lower()
            if "blockchain" in context or "wallet" in context or "payload" in context:
                results.append(("base64_payload", f"len={len(b64_data)}", filepath))

    # Search for pbkdf2_iterations (strong indicator of wallet data)
    if "pbkdf2_iterations" in text:
        iter_regex = r'"pbkdf2_iterations"\s*:\s*(\d+)'
        for m in re.finditer(iter_regex, text):
            results.append(("pbkdf2_config", f"iterations={m.group(1)}", filepath))

    return results


def extract_full_payload(filepath, output_dir):
    """Try to extract the complete wallet payload from a file."""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except (OSError, PermissionError):
        return None

    text = data.decode("utf-8", errors="ignore")

    # Pattern 1: Full JSON wallet object
    payload_regex = r'\{[^{}]*"payload"\s*:\s*"([A-Za-z0-9+/=]+)"[^{}]*"pbkdf2_iterations"\s*:\s*(\d+)[^{}]*\}'
    matches = list(re.finditer(payload_regex, text))

    if not matches:
        # Try reverse order (iterations before payload)
        payload_regex2 = r'\{[^{}]*"pbkdf2_iterations"\s*:\s*(\d+)[^{}]*"payload"\s*:\s*"([A-Za-z0-9+/=]+)"[^{}]*\}'
        matches = list(re.finditer(payload_regex2, text))

    if not matches:
        # Try to find payload alone
        payload_regex3 = r'"payload"\s*:\s*"([A-Za-z0-9+/=]{100,})"'
        matches = list(re.finditer(payload_regex3, text))

    for i, m in enumerate(matches):
        try:
            full_json = m.group(0)
            out_file = os.path.join(output_dir, f"wallet_payload_{i}.json")
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(full_json)
            print(f"    SAVED: {out_file} ({len(full_json)} bytes)")
            return out_file
        except Exception as e:
            print(f"    Error saving: {e}")

    return None


def main():
    print()
    print("=" * 65)
    print("  EXTRACT BLOCKCHAIN.COM WALLET PAYLOAD")
    print("  From Chrome/Brave Local Storage (LevelDB)")
    print("=" * 65)
    print()

    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wallet_payloads")
    os.makedirs(output_dir, exist_ok=True)

    all_results = []

    for browser_name, ls_path in BROWSER_PATHS.items():
        if not os.path.exists(ls_path):
            continue

        print(f"  Scanning: {browser_name}")
        print(f"    Path: {ls_path}")

        file_count = 0
        for fname in os.listdir(ls_path):
            if not (fname.endswith(".log") or fname.endswith(".ldb") or fname == "CURRENT" or fname.endswith(".sst")):
                continue

            fpath = os.path.join(ls_path, fname)
            file_count += 1
            results = scan_leveldb_file(fpath)

            if results:
                for rtype, rvalue, rfile in results:
                    print(f"    FOUND [{rtype}]: {rvalue}")
                    all_results.append((rtype, rvalue, rfile))

                # Try to extract full payload
                if any(r[0] in ("payload_json", "base64_payload", "pbkdf2_config") for r in results):
                    extract_full_payload(fpath, output_dir)

        if file_count > 0:
            print(f"    ({file_count} files scanned)")
        print()

    print("=" * 65)
    print(f"  TOTAL FINDINGS: {len(all_results)}")
    print("=" * 65)
    print()

    if all_results:
        wallet_id_found = [r for r in all_results if r[0] == "wallet_id"]
        payload_found = [r for r in all_results if r[0] in ("payload_json", "base64_payload")]
        config_found = [r for r in all_results if r[0] == "pbkdf2_config"]

        if payload_found:
            print("  !!! WALLET PAYLOAD DITEMUKAN !!!")
            print(f"  Saved to: {output_dir}")
            print()
            print("  NEXT: Gunakan btcrecover untuk brute-force password:")
            print("    pip install btcrecover")
            print("    python -m btcrecover --wallet wallet_payloads/wallet_payload_0.json --passwordlist passwords.txt")
        elif wallet_id_found:
            print("  Wallet ID ditemukan di Local Storage tapi payload belum ter-extract.")
            print("  Coba buka Blockchain.com di browser, login sampai muncul halaman password,")
            print("  lalu jalankan script ini lagi.")
        else:
            print("  Tidak ditemukan wallet payload di Local Storage.")
    else:
        print("  Tidak ada data Blockchain.com di Local Storage browser.")
        print()
        print("  Kemungkinan:")
        print("  - Browser cache sudah dibersihkan")
        print("  - Login terakhir sudah lama dan data expired")
        print("  - Pakai mode Incognito saat login")

    print()


if __name__ == "__main__":
    main()
