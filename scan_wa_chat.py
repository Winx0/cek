#!/usr/bin/env python3
"""Scan WhatsApp chat backup TXT — extract ONLY important crypto data.

Focuses on finding:
- Blockchain.com Wallet IDs (UUID format)
- BTC addresses (legacy, segwit, bech32)
- Private keys (WIF format: starts with 5, K, or L)
- Seed/mnemonic phrases (12/24 English words)
- Email + password combinations
- Login credentials patterns
"""

import re
import os
import glob

SEARCH_DIR = r"D:\Downloads\Downloads"
TARGET = "1B8hgFxNK7ac2k5EtrAanxQPFcnfHLMcko"

# Patterns
RE_WALLET_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)
RE_BTC_ADDR = re.compile(r"\b[13][1-9A-HJ-NP-Za-km-z]{25,34}\b")
RE_BECH32 = re.compile(r"\bbc1[02-9ac-hj-np-z]{6,87}\b")
RE_WIF_KEY = re.compile(r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b")
RE_XKEY = re.compile(r"\b(?:xprv|xpub|yprv|ypub|zprv|zpub)[1-9A-HJ-NP-Za-km-z]{107,108}\b")
RE_EMAIL = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
RE_PASSWORD_PATTERN = re.compile(r"(?:password|pass|pwd|sandi|kata sandi|pw)\s*[:=]\s*(.+)", re.IGNORECASE)
RE_LOGIN_PATTERN = re.compile(r"(?:login|email|user|username|akun)\s*[:=]\s*(.+)", re.IGNORECASE)
RE_HEX_PRIVKEY = re.compile(r"\b[0-9a-fA-F]{64}\b")

# Find WhatsApp chat files
files = glob.glob(os.path.join(SEARCH_DIR, "Chat WhatsApp*"))
if not files:
    files = glob.glob(os.path.join(SEARCH_DIR, "*WhatsApp*.txt"))
if not files:
    files = [os.path.join(SEARCH_DIR, f) for f in os.listdir(SEARCH_DIR) if f.endswith(".txt")]

print()
print("=" * 60)
print("  WHATSAPP CHAT SCANNER — CRYPTO DATA EXTRACTOR")
print("=" * 60)
print()
print(f"  Files to scan: {len(files)}")
print()

for fpath in files:
    fname = os.path.basename(fpath)
    try:
        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except Exception as e:
        continue

    if len(text) < 10:
        continue

    results = []

    # 1. Target address
    if TARGET in text:
        idx = text.find(TARGET)
        start = max(0, idx - 200)
        end = min(len(text), idx + 200)
        results.append(("TARGET ADDRESS", TARGET, text[start:end].strip()))

    # 2. Wallet IDs (UUID)
    for m in RE_WALLET_ID.finditer(text):
        pos = m.start()
        line_start = text.rfind("\n", max(0, pos - 100), pos) + 1
        line_end = text.find("\n", pos, min(len(text), pos + 200))
        if line_end == -1:
            line_end = min(len(text), pos + 200)
        context = text[line_start:line_end].strip()
        results.append(("WALLET ID", m.group(0), context))

    # 3. BTC addresses
    for m in RE_BTC_ADDR.finditer(text):
        pos = m.start()
        line_start = text.rfind("\n", max(0, pos - 100), pos) + 1
        line_end = text.find("\n", pos, min(len(text), pos + 200))
        if line_end == -1:
            line_end = min(len(text), pos + 200)
        context = text[line_start:line_end].strip()
        results.append(("BTC ADDRESS", m.group(0), context))

    # 4. Bech32 addresses
    for m in RE_BECH32.finditer(text):
        results.append(("BTC BECH32", m.group(0), ""))

    # 5. WIF Private keys
    for m in RE_WIF_KEY.finditer(text):
        results.append(("PRIVATE KEY (WIF)", m.group(0), ""))

    # 6. Extended keys (xprv/xpub)
    for m in RE_XKEY.finditer(text):
        results.append(("EXTENDED KEY", m.group(0)[:20] + "...", ""))

    # 7. Password patterns
    for m in RE_PASSWORD_PATTERN.finditer(text):
        pos = m.start()
        line_start = text.rfind("\n", max(0, pos - 50), pos) + 1
        line_end = text.find("\n", pos, min(len(text), pos + 200))
        if line_end == -1:
            line_end = min(len(text), pos + 200)
        context = text[line_start:line_end].strip()
        results.append(("PASSWORD", m.group(1).strip()[:50], context))

    # 8. Login patterns
    for m in RE_LOGIN_PATTERN.finditer(text):
        pos = m.start()
        line_start = text.rfind("\n", max(0, pos - 50), pos) + 1
        line_end = text.find("\n", pos, min(len(text), pos + 200))
        if line_end == -1:
            line_end = min(len(text), pos + 200)
        context = text[line_start:line_end].strip()
        results.append(("LOGIN/EMAIL", m.group(1).strip()[:50], context))

    # 9. Seed phrase detection (12+ BIP39-like words in sequence)
    words = re.findall(r"\b[a-z]{3,8}\b", text.lower())
    # Simple check: look for lines with 12+ short words (potential seed)
    lines = text.split("\n")
    for line in lines:
        word_count = len(re.findall(r"\b[a-z]{3,8}\b", line.lower()))
        if word_count >= 12 and word_count <= 24 and len(line) < 300:
            if not any(skip in line.lower() for skip in ["http", "www", ".com", "pesan"]):
                results.append(("POSSIBLE SEED", f"{word_count} words", line.strip()[:200]))

    # Print results for this file
    if results:
        print(f"  FILE: {fname}")
        print("  " + "-" * 55)
        seen = set()
        for rtype, value, context in results:
            key = f"{rtype}:{value}"
            if key in seen:
                continue
            seen.add(key)
            print(f"    [{rtype}] {value}")
            if context and context != value:
                print(f"      >> {context[:150]}")
        print()

print("=" * 60)
print("  SCAN COMPLETE")
print("=" * 60)
print()
