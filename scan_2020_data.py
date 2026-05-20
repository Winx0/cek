#!/usr/bin/env python3
"""Scan HDD partitions (D, E, F) for files from 2020 related to crypto/wallet.

Focuses on:
- Files modified in 2020
- Contains crypto keywords (blockchain, wallet, bitcoin, seed, recovery, etc.)
- File types: txt, json, dat, bak, csv, key, aes, pdf, doc, docx, screenshot
- Also checks for wallet.aes.json backup files from Blockchain.com
"""

import os
import sys
import time
from datetime import datetime

# Config
SEARCH_DRIVES = ["D:\\", "E:\\", "F:\\"]
TARGET_YEAR = 2020

# File extensions to check content
TEXT_EXTENSIONS = {
    ".txt", ".json", ".csv", ".log", ".bak", ".backup",
    ".key", ".dat", ".aes", ".cfg", ".conf", ".ini",
    ".md", ".note", ".notes", ".rtf",
}

# File extensions of interest (by name/date only)
ALL_EXTENSIONS = {
    ".txt", ".json", ".csv", ".log", ".bak", ".backup",
    ".key", ".dat", ".aes", ".cfg", ".conf", ".ini",
    ".md", ".note", ".notes", ".rtf", ".pdf", ".doc",
    ".docx", ".xls", ".xlsx", ".png", ".jpg", ".jpeg",
    ".wallet", ".kdbx",
}

# Keywords to search in filenames
FILENAME_KEYWORDS = [
    "wallet", "bitcoin", "btc", "blockchain", "seed",
    "recovery", "backup", "crypto", "mnemonic", "private",
    "key", "passphrase", "freebitco", "coinbase", "indodax",
    "electrum", "address",
]

# Keywords to search inside text files
CONTENT_KEYWORDS = [
    "wallet", "bitcoin", "btc", "blockchain", "seed",
    "recovery phrase", "mnemonic", "private key",
    "1B8hgFxNK7ac2k5EtrAanxQPFcnfHLMcko",
    "ernisyach", "freebitco",
    "xprv", "xpub",
    "abandon",  # first BIP39 word (common in seed backups)
]

# Skip these folders
SKIP_DIRS = {
    "Windows", "Program Files", "Program Files (x86)",
    "$Recycle.Bin", "System Volume Information",
    "node_modules", ".git", "__pycache__",
    "AppData",
}

# Max file size for content scan (2MB)
MAX_CONTENT_SIZE = 2 * 1024 * 1024


def is_year_2020(timestamp):
    """Check if a timestamp is from year 2020 (or late 2019 / early 2021)."""
    try:
        dt = datetime.fromtimestamp(timestamp)
        return dt.year in [2019, 2020, 2021]
    except (OSError, ValueError):
        return False


def check_file_content(filepath, size):
    """Check if file contains crypto-related keywords."""
    if size > MAX_CONTENT_SIZE:
        return []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read().lower()
        matches = []
        for kw in CONTENT_KEYWORDS:
            if kw.lower() in content:
                matches.append(kw)
        return matches
    except Exception:
        return []


def main():
    print()
    print("=" * 65)
    print("  SCAN HDD 2020 — Cari file crypto/wallet dari tahun 2020")
    print("  Drives: D:\\, E:\\, F\\")
    print("  Target: 2019-2020-2021")
    print("=" * 65)
    print()

    results_filename = []
    results_content = []
    files_scanned = 0
    errors = 0

    for drive in SEARCH_DRIVES:
        if not os.path.exists(drive):
            print(f"  Drive {drive} tidak ditemukan, skip.")
            continue

        print(f"  Scanning {drive} ...")

        try:
            for root, dirs, files in os.walk(drive):
                # Skip system/irrelevant dirs
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

                for f in files:
                    filepath = os.path.join(root, f)
                    files_scanned += 1

                    if files_scanned % 50000 == 0:
                        print(f"    ... {files_scanned:,} files scanned, "
                              f"{len(results_filename) + len(results_content)} findings ...")

                    try:
                        stat = os.stat(filepath)
                    except (OSError, PermissionError):
                        errors += 1
                        continue

                    mtime = stat.st_mtime
                    size = stat.st_size

                    # Only files from 2020 era
                    if not is_year_2020(mtime):
                        continue

                    f_lower = f.lower()
                    _, ext = os.path.splitext(f_lower)

                    # Check 1: Filename contains crypto keywords
                    name_match = [kw for kw in FILENAME_KEYWORDS if kw in f_lower]
                    if name_match:
                        dt = datetime.fromtimestamp(mtime)
                        results_filename.append({
                            "path": filepath,
                            "size": size,
                            "modified": dt.strftime("%Y-%m-%d"),
                            "keywords": name_match,
                        })

                    # Check 2: Content scan for text files from 2020
                    if ext in TEXT_EXTENSIONS and size > 10 and size < MAX_CONTENT_SIZE:
                        content_matches = check_file_content(filepath, size)
                        if content_matches:
                            dt = datetime.fromtimestamp(mtime)
                            results_content.append({
                                "path": filepath,
                                "size": size,
                                "modified": dt.strftime("%Y-%m-%d"),
                                "keywords": content_matches,
                            })

        except (PermissionError, OSError) as e:
            errors += 1

    # Print results
    print()
    print("=" * 65)
    print(f"  SCAN COMPLETE")
    print(f"  Files scanned: {files_scanned:,}")
    print(f"  Errors: {errors}")
    print("=" * 65)
    print()

    # Filename matches
    if results_filename:
        print(f"  [FILENAME MATCH] {len(results_filename)} files with crypto-related names (2020):")
        print("  " + "-" * 55)
        for r in sorted(results_filename, key=lambda x: x["modified"]):
            print(f"    [{r['modified']}] {r['path']}")
            print(f"              Size: {r['size']} bytes | Keywords: {r['keywords']}")
        print()

    # Content matches
    if results_content:
        print(f"  [CONTENT MATCH] {len(results_content)} files containing crypto data (2020):")
        print("  " + "-" * 55)
        for r in sorted(results_content, key=lambda x: x["modified"]):
            print(f"    [{r['modified']}] {r['path']}")
            print(f"              Size: {r['size']} bytes | Found: {r['keywords']}")
        print()

    # Special: check if target address found anywhere
    target_found = [r for r in results_content if "1B8hgFxNK7ac2k5EtrAanxQPFcnfHLMcko" in r["keywords"]]
    if target_found:
        print("  " + "!" * 55)
        print("  !!! YOUR BTC ADDRESS FOUND IN FILES !!!")
        print("  " + "!" * 55)
        for r in target_found:
            print(f"    FILE: {r['path']}")
            print(f"    Date: {r['modified']}")
        print("  " + "!" * 55)
        print()

    if not results_filename and not results_content:
        print("  Tidak ditemukan file crypto dari tahun 2020 di drive D, E, F.")
        print()
        print("  Kemungkinan:")
        print("  - File wallet backup sudah terhapus")
        print("  - Data crypto disimpan di folder lain")
        print("  - Wallet hanya diakses via browser (tidak ada file lokal)")

    print()


if __name__ == "__main__":
    main()
