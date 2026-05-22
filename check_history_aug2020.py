#!/usr/bin/env python3
"""Check browser history for August 10, 2020 - the day BTC was received."""

import sqlite3
import shutil
import tempfile
import os
from datetime import datetime

HOME = os.path.expanduser("~")
CHROME_EPOCH = 11644473600

# Date range: Aug 5 - Aug 15, 2020
START_UNIX = 1596585600
END_UNIX = 1597449600

START_CHROME = (START_UNIX + CHROME_EPOCH) * 1000000
END_CHROME = (END_UNIX + CHROME_EPOCH) * 1000000

HISTORY_PATHS = []
chrome_base = os.path.join(HOME, "AppData", "Local", "Google", "Chrome", "User Data")
default_hist = os.path.join(chrome_base, "Default", "History")
if os.path.exists(default_hist):
    HISTORY_PATHS.append(("Chrome Default", default_hist))

for i in range(1, 50):
    p = os.path.join(chrome_base, f"Profile {i}", "History")
    if os.path.exists(p):
        HISTORY_PATHS.append((f"Chrome Profile {i}", p))

backup_hist = os.path.join(HOME, "Desktop", "Chrome_Backup", "Default", "History")
if os.path.exists(backup_hist):
    HISTORY_PATHS.append(("Chrome Backup", backup_hist))

brave_hist = os.path.join(HOME, "AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data", "Default", "History")
if os.path.exists(brave_hist):
    HISTORY_PATHS.append(("Brave", brave_hist))

avg_hist = os.path.join(HOME, "AppData", "Local", "AVG", "Browser", "User Data", "Default", "History")
if os.path.exists(avg_hist):
    HISTORY_PATHS.append(("AVG", avg_hist))


def query_history(name, db_path):
    results = []
    try:
        tmp_dir = tempfile.mkdtemp()
        tmp_path = os.path.join(tmp_dir, "History")
        shutil.copy2(db_path, tmp_path)
        conn = sqlite3.connect(tmp_path)
        c = conn.cursor()
        c.execute("""
            SELECT v.visit_time, u.url, u.title
            FROM visits v JOIN urls u ON v.url = u.id
            WHERE v.visit_time > ? AND v.visit_time < ?
            ORDER BY v.visit_time
        """, (START_CHROME, END_CHROME))
        for row in c.fetchall():
            visit_time, url, title = row
            unix_ts = (visit_time / 1000000) - CHROME_EPOCH
            dt = datetime.fromtimestamp(unix_ts)
            results.append((dt, url, title))
        conn.close()
        shutil.rmtree(tmp_dir, ignore_errors=True)
    except Exception as e:
        print(f"    Error: {e}")
    return results


def main():
    print()
    print("=" * 70)
    print("  BROWSER HISTORY: Aug 5-15, 2020")
    print("  (Around the date BTC was received: Aug 10, 2020)")
    print("=" * 70)
    print()

    all_results = []
    for name, db_path in HISTORY_PATHS:
        print(f"  Checking: {name}")
        results = query_history(name, db_path)
        if results:
            print(f"    Found {len(results)} visits")
            all_results.extend([(name, r) for r in results])
        else:
            print(f"    No visits found")

    print()
    print("=" * 70)
    print(f"  RESULTS: {len(all_results)} visits (Aug 5-15, 2020)")
    print("=" * 70)
    print()

    if not all_results:
        print("  No browser history found for this date range.")
        return

    crypto_keywords = ["blockchain", "wallet", "bitcoin", "btc", "freebitco",
                       "crypto", "login", "1af403a8", "1f330204", "1B8hg"]

    crypto_visits = []
    for name, (dt, url, title) in all_results:
        url_lower = url.lower()
        if any(kw.lower() in url_lower for kw in crypto_keywords):
            crypto_visits.append((name, dt, url, title))

    if crypto_visits:
        print("  [CRYPTO/WALLET VISITS]:")
        print("  " + "-" * 60)
        for name, dt, url, title in crypto_visits:
            print(f"    [{dt.strftime('%Y-%m-%d %H:%M')}] {url[:120]}")
            if title:
                print(f"      Title: {title}")
        print()
    else:
        print("  No crypto-related visits found in this date range.")
        print()
        print("  ALL visits:")
        print("  " + "-" * 60)
        for name, (dt, url, title) in sorted(all_results, key=lambda x: x[1][0])[:50]:
            print(f"    [{dt.strftime('%Y-%m-%d %H:%M')}] {url[:120]}")

    print()


if __name__ == "__main__":
    main()
