#!/usr/bin/env python3
"""Scan WhatsApp chat backup TXT for crypto data."""

import re
import os
import glob

SEARCH_DIR = r"D:\Downloads\Downloads"
TARGET = "1B8hgFxNK7ac2k5EtrAanxQPFcnfHLMcko"

# Find all WhatsApp chat files
files = glob.glob(os.path.join(SEARCH_DIR, "Chat WhatsApp*"))
if not files:
    files = glob.glob(os.path.join(SEARCH_DIR, "*WhatsApp*"))
if not files:
    files = glob.glob(os.path.join(SEARCH_DIR, "*.txt"))

print(f"Found {len(files)} file(s)")
print()

for fpath in files:
    print(f"Scanning: {os.path.basename(fpath)}")
    try:
        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except Exception as e:
        print(f"  Error: {e}")
        continue

    print(f"  Size: {len(text)} chars")

    # Check target address
    if TARGET in text:
        print()
        print("  " + "!" * 50)
        print(f"  !!! TARGET ADDRESS FOUND !!!")
        print("  " + "!" * 50)
        idx = text.find(TARGET)
        start = max(0, idx - 300)
        end = min(len(text), idx + 300)
        print(f"  Context:")
        print(text[start:end])
        print()

    # Find all BTC addresses
    btc_addrs = set(re.findall(r"[13][1-9A-HJ-NP-Za-km-z]{25,34}", text))
    bech32 = set(re.findall(r"bc1[02-9ac-hj-np-z]{6,87}", text))
    all_addrs = btc_addrs | bech32

    if all_addrs:
        print(f"  BTC addresses found: {len(all_addrs)}")
        for a in all_addrs:
            print(f"    {a}")
        print()

    # Keywords
    keywords = ["wallet", "bitcoin", "seed", "mnemonic", "blockchain",
                "trust", "private key", "recovery", "electrum", "coinbase",
                "freebitco", "indodax"]
    found_kw = [kw for kw in keywords if kw.lower() in text.lower()]
    if found_kw:
        print(f"  Keywords found: {found_kw}")
        print()

    # Show lines containing crypto keywords
    lines = text.split("\n")
    crypto_lines = []
    for line in lines:
        line_lower = line.lower()
        if any(kw in line_lower for kw in ["wallet", "bitcoin", "btc", "seed",
                "blockchain", "trust", "address", "withdraw", "freebitco"]):
            crypto_lines.append(line.strip())

    if crypto_lines:
        print(f"  Crypto-related lines ({len(crypto_lines)}):")
        for line in crypto_lines[:30]:
            print(f"    {line[:150]}")
        if len(crypto_lines) > 30:
            print(f"    ... and {len(crypto_lines) - 30} more")

    print()

print("Done.")
