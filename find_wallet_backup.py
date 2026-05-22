#!/usr/bin/env python3
"""Find wallet backup files on all drives."""

import os

search_paths = ["C:\\Users\\ERWIN SYAH ST", "D:\\", "E:\\", "F:\\"]
keywords = ["wallet.aes", "wallet.json", "blockchain", "backup"]
found = []

for drive in search_paths:
    try:
        for root, dirs, files in os.walk(drive):
            skip = ["Windows", "Program Files", "node_modules", ".git",
                    "$Recycle.Bin", "System Volume Information"]
            dirs[:] = [d for d in dirs if d not in skip]
            for f in files:
                f_lower = f.lower()
                if any(k in f_lower for k in keywords):
                    if f_lower.endswith((".json", ".aes", ".bak", ".backup", ".dat", ".txt")):
                        full = os.path.join(root, f)
                        try:
                            size = os.path.getsize(full)
                            if size > 10:
                                found.append((full, size))
                                print(f"  {full} ({size} bytes)")
                        except Exception:
                            pass
            if root.count(os.sep) > 6:
                dirs.clear()
    except Exception:
        pass

if not found:
    print("Tidak ditemukan file backup wallet.")
else:
    print(f"\nTotal: {len(found)} file ditemukan")
