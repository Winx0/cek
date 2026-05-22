#!/usr/bin/env python3
"""Scan HDD (D, E, F) for WhatsApp backup data from 2020.

Searches for:
- WhatsApp database backups (msgstore-*.db.crypt12/crypt14)
- WhatsApp media folders
- WhatsApp exported chats (.txt)
- Google Drive WhatsApp backup references
- Any file related to WhatsApp from 2019-2021
"""

import os
import sys
from datetime import datetime

# Config
SEARCH_DRIVES = ["D:\\", "E:\\", "F:\\", "C:\\Users\\ERWIN SYAH ST"]

# WhatsApp-related keywords in filenames
WA_FILENAME_KEYWORDS = [
    "whatsapp",
    "msgstore",
    "wa_",
    "wabusiness",
    "chat_",
    "whatsapp chat",
    "exported chat",
]

# WhatsApp-related extensions
WA_EXTENSIONS = {
    ".crypt12", ".crypt14", ".crypt15", ".crypt",
    ".db", ".db.crypt12", ".db.crypt14",
}

# WhatsApp folder names
WA_FOLDER_NAMES = {
    "whatsapp",
    "whatsapp images",
    "whatsapp documents",
    "whatsapp databases",
    "whatsapp media",
    "whatsapp backup",
}

# Skip these folders
SKIP_DIRS = {
    "Windows", "Program Files", "Program Files (x86)",
    "$Recycle.Bin", "System Volume Information",
    "node_modules", ".git", "__pycache__",
}


def is_2020_era(timestamp):
    """Check if timestamp is from 2019-2021."""
    try:
        dt = datetime.fromtimestamp(timestamp)
        return dt.year in [2019, 2020, 2021]
    except (OSError, ValueError):
        return False


def main():
    print()
    print("=" * 65)
    print("  SCAN HDD — WhatsApp Backup Data 2020")
    print("  Drives: C (User), D, E, F")
    print("  Target: 2019-2020-2021")
    print("=" * 65)
    print()

    results = []
    wa_folders = []
    files_scanned = 0

    for drive in SEARCH_DRIVES:
        if not os.path.exists(drive):
            print(f"  {drive} tidak ditemukan, skip.")
            continue

        print(f"  Scanning {drive} ...")

        try:
            for root, dirs, files in os.walk(drive):
                # Skip system dirs
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

                # Check if current folder is WhatsApp-related
                folder_name = os.path.basename(root).lower()
                if folder_name in WA_FOLDER_NAMES:
                    wa_folders.append(root)

                for f in files:
                    filepath = os.path.join(root, f)
                    files_scanned += 1

                    if files_scanned % 100000 == 0:
                        print(f"    ... {files_scanned:,} files scanned ...")

                    f_lower = f.lower()

                    # Check if filename is WhatsApp-related
                    is_wa = any(kw in f_lower for kw in WA_FILENAME_KEYWORDS)

                    # Check extension
                    if not is_wa:
                        for ext in WA_EXTENSIONS:
                            if f_lower.endswith(ext):
                                is_wa = True
                                break

                    # Check if in WhatsApp folder
                    if not is_wa:
                        if "whatsapp" in root.lower():
                            is_wa = True

                    if not is_wa:
                        continue

                    # Get file info
                    try:
                        stat = os.stat(filepath)
                        size = stat.st_size
                        mtime = stat.st_mtime
                        dt = datetime.fromtimestamp(mtime)
                    except (OSError, PermissionError):
                        continue

                    # Filter: only 2020 era OR WhatsApp database files (any year)
                    is_database = "msgstore" in f_lower or f_lower.endswith((".crypt12", ".crypt14", ".crypt15"))
                    is_2020 = is_2020_era(mtime)

                    if is_2020 or is_database:
                        results.append({
                            "path": filepath,
                            "size": size,
                            "modified": dt.strftime("%Y-%m-%d %H:%M"),
                            "type": "database" if is_database else "other",
                        })

        except (PermissionError, OSError):
            pass

    # Print results
    print()
    print("=" * 65)
    print(f"  SCAN COMPLETE — {files_scanned:,} files scanned")
    print("=" * 65)
    print()

    # WhatsApp folders found
    if wa_folders:
        print(f"  [WHATSAPP FOLDERS] {len(wa_folders)} found:")
        print("  " + "-" * 55)
        for folder in wa_folders:
            print(f"    {folder}")
        print()

    # Database files (highest priority)
    databases = [r for r in results if r["type"] == "database"]
    others = [r for r in results if r["type"] == "other"]

    if databases:
        print(f"  [DATABASE FILES] {len(databases)} WhatsApp DB backups:")
        print("  " + "-" * 55)
        for r in sorted(databases, key=lambda x: x["modified"]):
            print(f"    [{r['modified']}] {r['path']}")
            print(f"              Size: {r['size']:,} bytes")
        print()

    if others:
        print(f"  [OTHER WA FILES] {len(others)} files (2020 era):")
        print("  " + "-" * 55)
        for r in sorted(others, key=lambda x: x["modified"])[:50]:
            print(f"    [{r['modified']}] {r['path']}")
            print(f"              Size: {r['size']:,} bytes")
        if len(others) > 50:
            print(f"    ... dan {len(others) - 50} file lainnya")
        print()

    if not results and not wa_folders:
        print("  Tidak ditemukan data WhatsApp di drive D, E, F.")
        print()
        print("  Kemungkinan:")
        print("  - WhatsApp backup ada di Google Drive (bukan lokal)")
        print("  - Data WhatsApp ada di HP langsung")
        print("  - Folder WhatsApp sudah dihapus")

    print()


if __name__ == "__main__":
    main()
