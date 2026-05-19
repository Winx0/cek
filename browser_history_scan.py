#!/usr/bin/env python3
"""Browser History Scanner for Blockchain.com / BTC Wallet Access (2020).

Scans Chrome and Brave browser databases (History, Login Data, Local Storage,
Bookmarks) for any access to blockchain.com or crypto wallet sites during 2020.

This helps recover:
- Blockchain.com Wallet ID (from URLs or Local Storage)
- Login credentials hints (saved usernames/emails)
- Bookmark entries to wallet pages
- Exact dates you accessed your wallet

Usage:
    python browser_history_scan.py
    python browser_history_scan.py --year 2020
    python browser_history_scan.py --year 2019 2020 2021

Requirements:
    Python 3.8+ with sqlite3 (built-in)
    Close Chrome/Brave before running (or it copies DB first)

READ-ONLY: This tool does not modify any browser data.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import sqlite3
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Target years to filter
DEFAULT_YEARS = [2019, 2020, 2021]

# Crypto-related URL patterns to search for
CRYPTO_URL_PATTERNS = [
    "blockchain.com",
    "blockchain.info",
    "login.blockchain.com",
    "blockchain.com/wallet",
    "electrum",
    "bitcoin",
    "btc",
    "wallet",
    "mycelium",
    "coinbase.com",
    "binance.com",
    "localbitcoins",
    "paxful",
    "bitfinex",
    "kraken.com",
    "bitstamp",
    "blockchain-wallet",
    "exodus",
    "atomic wallet",
    "wasabi",
    "sparrow",
]

# High-priority patterns (strongest indicators of wallet access)
HIGH_PRIORITY_PATTERNS = [
    "blockchain.com/wallet",
    "login.blockchain.com",
    "blockchain.info/wallet",
    "blockchain.com/#/login",
    "blockchain.com/#/recover",
    "blockchain.com/#/settings",
    "blockchain.com/wallet/#/home",
]

# Blockchain.com Wallet ID regex (UUID format in URL or storage)
RE_WALLET_ID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)

# BTC address pattern
RE_BTC_ADDR = re.compile(r"\b[13][1-9A-HJ-NP-Za-km-z]{25,34}\b")
RE_BECH32_ADDR = re.compile(r"\bbc1[02-9ac-hj-np-z]{6,87}\b")


# ---------------------------------------------------------------------------
# Chrome/Brave timestamp conversion
# ---------------------------------------------------------------------------

# Chrome stores timestamps as microseconds since 1601-01-01
CHROME_EPOCH_OFFSET = 11644473600  # seconds between 1601-01-01 and 1970-01-01


def chrome_time_to_datetime(chrome_timestamp: int) -> Optional[datetime]:
    """Convert Chrome's timestamp (microseconds since 1601-01-01) to datetime."""
    if not chrome_timestamp or chrome_timestamp <= 0:
        return None
    try:
        # Convert to Unix timestamp
        unix_ts = (chrome_timestamp / 1_000_000) - CHROME_EPOCH_OFFSET
        if unix_ts < 0 or unix_ts > 2000000000:  # Sanity check
            return None
        return datetime.fromtimestamp(unix_ts)
    except (OSError, ValueError, OverflowError):
        return None


def is_in_target_years(dt: Optional[datetime], years: List[int]) -> bool:
    """Check if datetime falls within target years."""
    if dt is None:
        return False
    return dt.year in years


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class BrowserResult:
    """A single finding from browser data."""
    source: str         # "history", "login", "localstorage", "bookmark"
    browser: str        # "Chrome", "Brave", etc.
    url: str
    title: str = ""
    visit_time: Optional[datetime] = None
    visit_count: int = 0
    extra_data: str = ""  # Additional context (username, wallet_id, etc.)
    priority: str = "medium"  # "high", "medium", "low"

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "browser": self.browser,
            "url": self.url,
            "title": self.title,
            "visit_time": self.visit_time.isoformat() if self.visit_time else None,
            "visit_count": self.visit_count,
            "extra_data": self.extra_data,
            "priority": self.priority,
        }


# ---------------------------------------------------------------------------
# Browser profile paths
# ---------------------------------------------------------------------------

def get_browser_profiles() -> List[Dict[str, str]]:
    """Find all Chrome/Brave/Edge browser profile paths."""
    profiles = []
    home = os.path.expanduser("~")
    system = platform.system()

    if system == "Windows":
        base_paths = {
            "Chrome": os.path.join(home, "AppData", "Local", "Google", "Chrome", "User Data"),
            "Brave": os.path.join(home, "AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data"),
            "Edge": os.path.join(home, "AppData", "Local", "Microsoft", "Edge", "User Data"),
            "AVG Browser": os.path.join(home, "AppData", "Local", "AVG", "Browser", "User Data"),
            "Opera": os.path.join(home, "AppData", "Roaming", "Opera Software", "Opera Stable"),
        }
    elif system == "Darwin":
        base_paths = {
            "Chrome": os.path.join(home, "Library", "Application Support", "Google", "Chrome"),
            "Brave": os.path.join(home, "Library", "Application Support", "BraveSoftware", "Brave-Browser"),
            "Edge": os.path.join(home, "Library", "Application Support", "Microsoft Edge"),
        }
    else:  # Linux
        base_paths = {
            "Chrome": os.path.join(home, ".config", "google-chrome"),
            "Brave": os.path.join(home, ".config", "BraveSoftware", "Brave-Browser"),
            "Edge": os.path.join(home, ".config", "microsoft-edge"),
        }

    for browser_name, base_path in base_paths.items():
        if not os.path.exists(base_path):
            continue

        # Check Default profile
        default_profile = os.path.join(base_path, "Default")
        if os.path.exists(default_profile):
            profiles.append({"browser": browser_name, "path": default_profile, "profile": "Default"})

        # Check numbered profiles (Profile 1, Profile 2, etc.)
        for item in os.listdir(base_path):
            if item.startswith("Profile "):
                profile_path = os.path.join(base_path, item)
                if os.path.isdir(profile_path):
                    profiles.append({"browser": browser_name, "path": profile_path, "profile": item})

    return profiles


# ---------------------------------------------------------------------------
# Database access helpers
# ---------------------------------------------------------------------------

def safe_open_db(db_path: str) -> Optional[str]:
    """Copy database to temp location (avoids lock issues) and return temp path."""
    if not os.path.exists(db_path):
        return None
    try:
        temp_dir = tempfile.mkdtemp(prefix="btc_browser_scan_")
        temp_path = os.path.join(temp_dir, os.path.basename(db_path))
        shutil.copy2(db_path, temp_path)
        # Also copy WAL and SHM files if they exist
        for ext in ["-wal", "-shm", "-journal"]:
            wal_path = db_path + ext
            if os.path.exists(wal_path):
                shutil.copy2(wal_path, temp_path + ext)
        return temp_path
    except (OSError, PermissionError) as e:
        print(f"    Warning: Cannot copy {db_path}: {e}")
        return None


def cleanup_temp(temp_path: str):
    """Remove temporary database copy."""
    try:
        temp_dir = os.path.dirname(temp_path)
        shutil.rmtree(temp_dir, ignore_errors=True)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Scanners
# ---------------------------------------------------------------------------

def scan_history(profile: Dict[str, str], years: List[int]) -> List[BrowserResult]:
    """Scan browser History database for crypto-related URLs in target years."""
    results = []
    db_path = os.path.join(profile["path"], "History")
    temp_path = safe_open_db(db_path)
    if not temp_path:
        return results

    try:
        conn = sqlite3.connect(temp_path)
        cursor = conn.cursor()

        # Query visits joined with urls
        cursor.execute("""
            SELECT u.url, u.title, v.visit_time, u.visit_count
            FROM urls u
            JOIN visits v ON u.id = v.url
            ORDER BY v.visit_time DESC
        """)

        for row in cursor.fetchall():
            url, title, visit_time_raw, visit_count = row
            url_lower = (url or "").lower()
            title_lower = (title or "").lower()

            # Check if URL matches crypto patterns
            is_crypto = any(pattern in url_lower for pattern in CRYPTO_URL_PATTERNS)
            if not is_crypto:
                is_crypto = any(pattern in title_lower for pattern in CRYPTO_URL_PATTERNS)

            if not is_crypto:
                continue

            # Convert timestamp and check year
            visit_dt = chrome_time_to_datetime(visit_time_raw)
            if not is_in_target_years(visit_dt, years):
                continue

            # Determine priority
            is_high = any(hp in url_lower for hp in HIGH_PRIORITY_PATTERNS)
            priority = "high" if is_high else "medium"

            # Check for Wallet ID in URL
            extra = ""
            wallet_ids = RE_WALLET_ID.findall(url)
            if wallet_ids:
                extra = f"WALLET ID: {wallet_ids[0]}"
                priority = "high"

            results.append(BrowserResult(
                source="history",
                browser=profile["browser"],
                url=url,
                title=title or "",
                visit_time=visit_dt,
                visit_count=visit_count or 0,
                extra_data=extra,
                priority=priority,
            ))

        conn.close()
    except sqlite3.Error as e:
        print(f"    DB error ({profile['browser']} History): {e}")
    finally:
        cleanup_temp(temp_path)

    return results


def scan_login_data(profile: Dict[str, str], years: List[int]) -> List[BrowserResult]:
    """Scan Login Data for saved credentials on crypto sites."""
    results = []
    db_path = os.path.join(profile["path"], "Login Data")
    temp_path = safe_open_db(db_path)
    if not temp_path:
        return results

    try:
        conn = sqlite3.connect(temp_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT origin_url, username_value, date_created, date_last_used
            FROM logins
        """)

        for row in cursor.fetchall():
            origin_url, username, date_created, date_last_used = row
            url_lower = (origin_url or "").lower()

            is_crypto = any(pattern in url_lower for pattern in CRYPTO_URL_PATTERNS)
            if not is_crypto:
                continue

            # Check dates
            created_dt = chrome_time_to_datetime(date_created)
            used_dt = chrome_time_to_datetime(date_last_used)

            # Accept if created or last used in target years
            in_years = is_in_target_years(created_dt, years) or is_in_target_years(used_dt, years)
            if not in_years:
                # Also include if no date filter and it's blockchain-related
                if "blockchain" not in url_lower:
                    continue

            visit_dt = used_dt or created_dt
            extra = f"Username/Email: {username}" if username else ""

            results.append(BrowserResult(
                source="login",
                browser=profile["browser"],
                url=origin_url,
                title="Saved Login",
                visit_time=visit_dt,
                extra_data=extra,
                priority="high",
            ))

        conn.close()
    except sqlite3.Error as e:
        print(f"    DB error ({profile['browser']} Login Data): {e}")
    finally:
        cleanup_temp(temp_path)

    return results


def scan_local_storage(profile: Dict[str, str], years: List[int]) -> List[BrowserResult]:
    """Scan Local Storage / LevelDB for Blockchain.com wallet IDs."""
    results = []

    # Chrome/Brave store Local Storage in a LevelDB folder
    ls_path = os.path.join(profile["path"], "Local Storage", "leveldb")
    if not os.path.exists(ls_path):
        return results

    # Scan .log and .ldb files for blockchain wallet data
    for fname in os.listdir(ls_path):
        if not (fname.endswith(".log") or fname.endswith(".ldb")):
            continue

        fpath = os.path.join(ls_path, fname)
        try:
            with open(fpath, "rb") as f:
                data = f.read()

            # Look for blockchain.com related data
            text = data.decode("utf-8", errors="ignore")

            # Search for wallet IDs
            if "blockchain" in text.lower() or "wallet" in text.lower():
                wallet_ids = RE_WALLET_ID.findall(text)
                btc_addrs = RE_BTC_ADDR.findall(text)

                for wid in set(wallet_ids):
                    results.append(BrowserResult(
                        source="localstorage",
                        browser=profile["browser"],
                        url="Local Storage (blockchain.com)",
                        title="Wallet ID from Local Storage",
                        extra_data=f"WALLET ID: {wid}",
                        priority="high",
                    ))

                for addr in set(btc_addrs):
                    results.append(BrowserResult(
                        source="localstorage",
                        browser=profile["browser"],
                        url="Local Storage",
                        title="BTC Address from Local Storage",
                        extra_data=f"BTC Address: {addr}",
                        priority="medium",
                    ))

        except (OSError, PermissionError):
            continue

    return results


def scan_bookmarks(profile: Dict[str, str]) -> List[BrowserResult]:
    """Scan Bookmarks file for crypto-related bookmarks."""
    results = []
    bm_path = os.path.join(profile["path"], "Bookmarks")
    if not os.path.exists(bm_path):
        return results

    try:
        with open(bm_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        def walk_bookmarks(node, depth=0):
            if isinstance(node, dict):
                if node.get("type") == "url":
                    url = node.get("url", "")
                    name = node.get("name", "")
                    url_lower = url.lower()

                    is_crypto = any(p in url_lower for p in CRYPTO_URL_PATTERNS)
                    if is_crypto:
                        # Check for wallet ID in URL
                        extra = ""
                        wallet_ids = RE_WALLET_ID.findall(url)
                        if wallet_ids:
                            extra = f"WALLET ID: {wallet_ids[0]}"

                        # Parse date_added (Chrome bookmark timestamp)
                        date_added = node.get("date_added")
                        dt = None
                        if date_added:
                            try:
                                dt = chrome_time_to_datetime(int(date_added))
                            except (ValueError, TypeError):
                                pass

                        results.append(BrowserResult(
                            source="bookmark",
                            browser=profile["browser"],
                            url=url,
                            title=name,
                            visit_time=dt,
                            extra_data=extra,
                            priority="high" if "blockchain" in url_lower else "medium",
                        ))

                for key, value in node.items():
                    if isinstance(value, (dict, list)):
                        walk_bookmarks(value, depth + 1)
            elif isinstance(node, list):
                for item in node:
                    walk_bookmarks(item, depth + 1)

        walk_bookmarks(data)
    except (json.JSONDecodeError, OSError) as e:
        print(f"    Bookmarks error ({profile['browser']}): {e}")

    return results


def scan_web_data(profile: Dict[str, str], years: List[int]) -> List[BrowserResult]:
    """Scan Web Data for autofill entries related to crypto."""
    results = []
    db_path = os.path.join(profile["path"], "Web Data")
    temp_path = safe_open_db(db_path)
    if not temp_path:
        return results

    try:
        conn = sqlite3.connect(temp_path)
        cursor = conn.cursor()

        # Search autofill for wallet-related entries
        cursor.execute("""
            SELECT name, value, date_created, date_last_used, count
            FROM autofill
            WHERE lower(name) LIKE '%wallet%'
               OR lower(name) LIKE '%address%'
               OR lower(name) LIKE '%seed%'
               OR lower(name) LIKE '%mnemonic%'
               OR lower(name) LIKE '%bitcoin%'
               OR lower(name) LIKE '%crypto%'
               OR lower(value) LIKE '%blockchain%'
        """)

        for row in cursor.fetchall():
            name, value, date_created, date_last_used, count = row

            created_dt = chrome_time_to_datetime(date_created)
            used_dt = chrome_time_to_datetime(date_last_used)

            in_years = is_in_target_years(created_dt, years) or is_in_target_years(used_dt, years)
            if not in_years and years != []:
                continue

            # Check if value contains wallet ID or BTC address
            extra = f"Field: {name} = {value}"
            priority = "medium"

            wallet_ids = RE_WALLET_ID.findall(str(value))
            if wallet_ids:
                extra = f"WALLET ID: {wallet_ids[0]} (from autofill field '{name}')"
                priority = "high"

            btc_addrs = RE_BTC_ADDR.findall(str(value))
            if btc_addrs:
                extra = f"BTC Address: {btc_addrs[0]} (from autofill field '{name}')"
                priority = "high"

            results.append(BrowserResult(
                source="autofill",
                browser=profile["browser"],
                url="Autofill Data",
                title=f"Autofill: {name}",
                visit_time=used_dt or created_dt,
                extra_data=extra,
                priority=priority,
            ))

        conn.close()
    except sqlite3.Error as e:
        print(f"    DB error ({profile['browser']} Web Data): {e}")
    finally:
        cleanup_temp(temp_path)

    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def generate_browser_report(results: List[BrowserResult], output_dir: str, years: List[int]) -> Dict[str, str]:
    """Generate reports from browser scan results."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    json_path = os.path.join(output_dir, f"browser_scan_{timestamp}.json")
    txt_path = os.path.join(output_dir, f"browser_scan_{timestamp}.txt")

    # JSON
    json_data = {
        "generated_at": datetime.now().isoformat(),
        "target_years": years,
        "total_findings": len(results),
        "results": [r.to_dict() for r in results],
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=2, default=str)

    # Text report
    lines = []
    lines.append("=" * 65)
    lines.append("  BROWSER HISTORY SCAN — BLOCKCHAIN.COM / CRYPTO WALLET")
    lines.append(f"  Target Years: {years}")
    lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 65)
    lines.append("")
    lines.append(f"  Total Findings: {len(results)}")
    lines.append("")

    # Group by priority
    high = [r for r in results if r.priority == "high"]
    medium = [r for r in results if r.priority == "medium"]

    if high:
        lines.append("-" * 65)
        lines.append(f"  [HIGH PRIORITY] {len(high)} findings")
        lines.append("-" * 65)
        for r in high:
            lines.append("")
            lines.append(f"  Browser: {r.browser}")
            lines.append(f"  Source:  {r.source}")
            lines.append(f"  URL:     {r.url}")
            if r.title:
                lines.append(f"  Title:   {r.title}")
            if r.visit_time:
                lines.append(f"  Date:    {r.visit_time.strftime('%Y-%m-%d %H:%M:%S')}")
            if r.visit_count:
                lines.append(f"  Visits:  {r.visit_count}")
            if r.extra_data:
                lines.append(f"  *** {r.extra_data} ***")

    if medium:
        lines.append("")
        lines.append("-" * 65)
        lines.append(f"  [MEDIUM] {len(medium)} findings")
        lines.append("-" * 65)
        for r in medium[:50]:
            time_str = r.visit_time.strftime('%Y-%m-%d %H:%M') if r.visit_time else "unknown"
            lines.append(f"  [{time_str}] {r.browser} | {r.url[:70]}")
            if r.extra_data:
                lines.append(f"           → {r.extra_data}")

    lines.append("")
    lines.append("-" * 65)
    lines.append("")
    lines.append("  NEXT STEPS:")
    lines.append("  1. If WALLET ID found → go to https://login.blockchain.com")
    lines.append("     Enter the Wallet ID + your password to access wallet")
    lines.append("  2. If email/username found → use for password recovery")
    lines.append("  3. If BTC address found → verify it matches yours")
    lines.append("  4. Check your email for 'blockchain' messages from 2020")
    lines.append("")
    lines.append("=" * 65)

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return {"text_report": txt_path, "json_report": json_path}


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Scan Chrome/Brave browser history for Blockchain.com wallet access in 2020",
    )
    parser.add_argument("--year", "-y", nargs="+", type=int, default=[2020],
                        help="Year(s) to filter (default: 2020)")
    parser.add_argument("--output", "-o", default="./browser_scan_reports",
                        help="Output directory")
    parser.add_argument("--all-years", action="store_true",
                        help="Show all crypto-related history regardless of year")

    args = parser.parse_args()
    years = [] if args.all_years else args.year

    print()
    print("=" * 60)
    print("  BROWSER HISTORY SCANNER — Blockchain.com / Crypto")
    print(f"  Filter: {'ALL YEARS' if not years else f'Year {years}'}")
    print("=" * 60)
    print()

    # Find browser profiles
    profiles = get_browser_profiles()
    if not profiles:
        print("  No Chrome/Brave/Edge browser profiles found!")
        sys.exit(1)

    print(f"  Found {len(profiles)} browser profile(s):")
    for p in profiles:
        print(f"    - {p['browser']} ({p['profile']})")
    print()

    all_results: List[BrowserResult] = []

    for profile in profiles:
        print(f"  Scanning {profile['browser']} ({profile['profile']})...")

        # History
        hist = scan_history(profile, years)
        if hist:
            print(f"    History: {len(hist)} crypto visits found")
        all_results.extend(hist)

        # Login Data
        logins = scan_login_data(profile, years)
        if logins:
            print(f"    Logins: {len(logins)} saved credentials found")
        all_results.extend(logins)

        # Local Storage
        ls = scan_local_storage(profile, years)
        if ls:
            print(f"    Local Storage: {len(ls)} wallet data entries found")
        all_results.extend(ls)

        # Bookmarks (no year filter — bookmarks persist)
        bm = scan_bookmarks(profile)
        if bm:
            print(f"    Bookmarks: {len(bm)} crypto bookmarks found")
        all_results.extend(bm)

        # Web Data / Autofill
        wd = scan_web_data(profile, years)
        if wd:
            print(f"    Autofill: {len(wd)} crypto-related entries found")
        all_results.extend(wd)

    print()
    print(f"  TOTAL: {len(all_results)} findings")
    print()

    if all_results:
        # Sort by priority then date
        all_results.sort(key=lambda r: (0 if r.priority == "high" else 1, r.visit_time or datetime.min), reverse=True)

        # Print key findings immediately
        wallet_ids = set()
        emails = set()
        for r in all_results:
            if "WALLET ID:" in r.extra_data:
                wid = r.extra_data.split("WALLET ID:")[1].strip().split()[0]
                wallet_ids.add(wid)
            if "Username/Email:" in r.extra_data:
                email = r.extra_data.split("Username/Email:")[1].strip()
                if email:
                    emails.add(email)

        if wallet_ids:
            print("  " + "!" * 60)
            print("  !!! BLOCKCHAIN.COM WALLET ID DITEMUKAN !!!")
            print("  " + "!" * 60)
            for wid in wallet_ids:
                print(f"  Wallet ID: {wid}")
            print()
            print("  LOGIN: https://login.blockchain.com")
            print("  Masukkan Wallet ID di atas + password Anda")
            print("  " + "!" * 60)
            print()

        if emails:
            print(f"  Email/Username terkait crypto:")
            for e in emails:
                print(f"    → {e}")
            print()

        # Generate report
        report = generate_browser_report(all_results, args.output, years)
        print(f"  Reports saved:")
        print(f"    Text: {report['text_report']}")
        print(f"    JSON: {report['json_report']}")
    else:
        print("  Tidak ada akses crypto ditemukan untuk tahun tersebut.")
        print()
        print("  Saran:")
        print("  - Coba --all-years untuk lihat semua tahun")
        print("  - Coba --year 2019 2020 2021 untuk range lebih luas")
        print("  - Cek apakah browser history sudah dihapus")
        print("  - Cek browser lain yang mungkin Anda pakai dulu")

    print()


if __name__ == "__main__":
    main()
