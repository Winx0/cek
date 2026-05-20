#!/usr/bin/env python3
"""Extract Blockchain.com encrypted wallet payload from ALL Chrome profiles.

Focuses on finding payload from wallet 1af403a8 (2014).
Scans all Chrome profiles, Chrome Backup, and other browsers.
Also checks older LevelDB files that might contain 2014-era wallet data.
"""

import os
import sys
import json
import re

HOME = os.path.expanduser("~")

# All possible Local Storage paths
BROWSER_PATHS = {}

# Chrome profiles
chrome_base = os.path.join(HOME, "AppData", "Local", "Google", "Chrome", "User Data")
BROWSER_PATHS["Chrome Default"] = os.path.join(chrome_base, "Default", "Local Storage", "leveldb")
for i in range(1, 50):
    BROWSER_PATHS[f"Chrome Profile {i}"] = os.path.join(chrome_base, f"Profile {i}", "Local Storage", "leveldb")

# Chrome Backup
BROWSER_PATHS["Chrome Backup"] = os.path.join(HOME, "Desktop", "Chrome_Backup", "Default", "Local Storage", "leveldb")

# Other browsers
BROWSER_PATHS["Brave"] = os.path.join(HOME, "AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data", "Default", "Local Storage", "leveldb")
BROWSER_PATHS["Edge"] = os.path.join(HOME, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Local Storage", "leveldb")
BROWSER_PATHS["AVG"] = os.path.join(HOME, "AppData", "Local", "AVG", "Browser", "User Data", "Default", "Local Storage", "leveldb")

# Target wallet IDs
WALLET_IDS = [
    "1af403a8-eb94-4534-b1f4-5c838c871a7b",
    "1f330204-c407-45d2-8ccf-5d0a87a23cf6",
]

TARGET_ADDRESS = "1B8hgFxNK7ac2k5EtrAanxQPFcnfHLMcko"


def scan_file(filepath):
    """Scan a single LevelDB file for blockchain.com wallet data."""
    results = []
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except (OSError, PermissionError):
        return results

    text = data.decode("utf-8", errors="ignore")

    # Check for wallet IDs
    for wid in WALLET_IDS:
        if wid in text:
            results.append(("wallet_id", wid, filepath))

    # Check for target address
    if TARGET_ADDRESS in text:
        results.append(("target_address", TARGET_ADDRESS, filepath))

    # Look for payload JSON
    payload_regex = r'"payload"\s*:\s*"([A-Za-z0-9+/=]{100,})"'
    for m in re.finditer(payload_regex, text):
        payload = m.group(1)
        results.append(("payload", f"len={len(payload)}", filepath))

    # Look for pbkdf2_iterations
    if "pbkdf2_iterations" in text:
        iter_regex = r'"pbkdf2_iterations"\s*:\s*(\d+)'
        for m in re.finditer(iter_regex, text):
            results.append(("pbkdf2", f"iterations={m.group(1)}", filepath))

    # Look for guid field
    guid_regex = r'"guid"\s*:\s*"([0-9a-f-]{36})"'
    for m in re.finditer(guid_regex, text):
        results.append(("guid_field", m.group(1), filepath))

    return results


def extract_payload_with_context(filepath, output_dir):
    """Extract payload and surrounding context from file."""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except (OSError, PermissionError):
        return None

    text = data.decode("utf-8", errors="ignore")
    saved = []

    # Try to find full wallet JSON objects
    # Pattern: anything with payload + pbkdf2_iterations
    patterns = [
        r'\{[^{}]*"payload"\s*:\s*"([A-Za-z0-9+/=]{100,})"[^{}]*"pbkdf2_iterations"\s*:\s*(\d+)[^{}]*\}',
        r'\{[^{}]*"pbkdf2_iterations"\s*:\s*(\d+)[^{}]*"payload"\s*:\s*"([A-Za-z0-9+/=]{100,})"[^{}]*\}',
        r'"payload"\s*:\s*"([A-Za-z0-9+/=]{100,})"',
    ]

    for i, pattern in enumerate(patterns):
        for m in re.finditer(pattern, text):
            full = m.group(0)
            out_file = os.path.join(output_dir, f"payload_{os.path.basename(filepath)}_{i}_{m.start()}.json")
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(full)
            saved.append(out_file)
            print(f"    SAVED: {out_file} ({len(full)} bytes)")

    return saved


def main():
    print()
    print("=" * 65)
    print("  EXTRACT ALL BLOCKCHAIN.COM WALLET PAYLOADS")
    print("  Looking for wallet 1af403a8 (2014) data")
    print(f"  Target address: {TARGET_ADDRESS}")
    print("=" * 65)
    print()

    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wallet_payloads")
    os.makedirs(output_dir, exist_ok=True)

    all_results = []
    files_with_payload = []

    for browser_name, ls_path in BROWSER_PATHS.items():
        if not os.path.exists(ls_path):
            continue

        print(f"  [{browser_name}] {ls_path}")

        file_count = 0
        for fname in os.listdir(ls_path):
            if not (fname.endswith(".log") or fname.endswith(".ldb") or fname.endswith(".sst")):
                continue

            fpath = os.path.join(ls_path, fname)
            file_count += 1
            results = scan_file(fpath)

            if results:
                for rtype, rvalue, rfile in results:
                    print(f"    FOUND [{rtype}]: {rvalue}")
                    all_results.append((rtype, rvalue, rfile))

                    if rtype == "payload":
                        files_with_payload.append(rfile)

        if file_count > 0:
            print(f"    ({file_count} files)")
        print()

    # Extract all payloads found
    if files_with_payload:
        print("=" * 65)
        print("  EXTRACTING PAYLOADS...")
        print("=" * 65)
        print()
        unique_files = list(set(files_with_payload))
        for fpath in unique_files:
            print(f"  From: {fpath}")
            extract_payload_with_context(fpath, output_dir)
            print()

    # Summary
    print("=" * 65)
    print(f"  SUMMARY")
    print("=" * 65)
    print()
    print(f"  Total findings: {len(all_results)}")

    wallet_ids_found = [r for r in all_results if r[0] == "wallet_id"]
    payloads_found = [r for r in all_results if r[0] == "payload"]
    guids_found = [r for r in all_results if r[0] == "guid_field"]
    target_found = [r for r in all_results if r[0] == "target_address"]

    if wallet_ids_found:
        print(f"  Wallet IDs found: {len(wallet_ids_found)}")
        for r in wallet_ids_found:
            print(f"    - {r[1]} in {os.path.basename(r[2])}")

    if guids_found:
        print(f"  GUID fields found: {len(guids_found)}")
        for r in guids_found:
            print(f"    - {r[1]} in {os.path.basename(r[2])}")

    if payloads_found:
        print(f"  Payloads found: {len(payloads_found)}")

    if target_found:
        print()
        print("  " + "!" * 55)
        print(f"  !!! TARGET ADDRESS FOUND IN LOCAL STORAGE !!!")
        print(f"  !!! {TARGET_ADDRESS} !!!")
        print("  " + "!" * 55)
        for r in target_found:
            print(f"    File: {r[2]}")

    print()
    print(f"  All payloads saved to: {output_dir}")
    print()


if __name__ == "__main__":
    main()
