#!/usr/bin/env python3
"""Password Hunter — Extract saved passwords from Chrome/Brave browsers.

Scans browser Login Data databases for saved credentials related to:
- blockchain.com / blockchain.info
- crypto exchanges (coinbase, binance, etc.)
- Any login using the target email

On Windows, Chrome encrypts passwords using DPAPI (Data Protection API).
This script decrypts them using the current Windows user session.

REQUIREMENTS:
- Windows (DPAPI decryption)
- Python 3.8+
- Must run as the SAME Windows user who saved the passwords
- Close Chrome/Brave before running (or passwords may be locked)

Usage:
    python password_hunter.py
    python password_hunter.py --email etngrupid@gmail.com
    python password_hunter.py --all

READ-ONLY: This does NOT modify any browser data.
"""

from __future__ import annotations

import base64
import json
import os
import platform
import shutil
import sqlite3
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional

# Windows-specific imports for decryption
if platform.system() == "Windows":
    try:
        import ctypes
        import ctypes.wintypes

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [
                ("cbData", ctypes.wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char)),
            ]

    except ImportError:
        pass

    try:
        from Crypto.Cipher import AES
        HAS_PYCRYPTO = True
    except ImportError:
        try:
            from Cryptodome.Cipher import AES
            HAS_PYCRYPTO = True
        except ImportError:
            HAS_PYCRYPTO = False


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TARGET_EMAIL = "ernisyach@yahoo.com"

# URLs to prioritize
PRIORITY_URLS = [
    "blockchain.com",
    "blockchain.info",
    "login.blockchain.com",
    "coinbase.com",
    "binance.com",
    "localbitcoins",
    "paxful.com",
    "kraken.com",
    "bitstamp.net",
    "bitfinex.com",
    "indodax.com",
    "tokocrypto.com",
    "pintu.co.id",
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "mail.google.com",
]

# Also search for these emails across all saved logins
TARGET_EMAILS = [
    "ernisyach@yahoo.com",
    "etngrupid@gmail.com",
    "lahanbasa@gmail.com",
    "ir.pangkubaranisyah@gmail.com",
    "adaqua91@gmail.com",
    "antek_syah@yahoo.com",
    "indoantek@gmail.com",
    "Suddahshop@gmail.com",
]


@dataclass
class SavedPassword:
    browser: str
    profile: str
    url: str
    username: str
    password: str  # Decrypted password (or "[ENCRYPTED - needs key]")
    date_created: Optional[datetime] = None
    date_last_used: Optional[datetime] = None
    priority: str = "medium"  # "high", "medium", "low"

    def to_dict(self) -> dict:
        return {
            "browser": self.browser,
            "profile": self.profile,
            "url": self.url,
            "username": self.username,
            "password": self.password,
            "date_created": self.date_created.isoformat() if self.date_created else None,
            "date_last_used": self.date_last_used.isoformat() if self.date_last_used else None,
            "priority": self.priority,
        }


# ---------------------------------------------------------------------------
# Chrome timestamp conversion
# ---------------------------------------------------------------------------

CHROME_EPOCH_OFFSET = 11644473600


def chrome_time_to_datetime(chrome_timestamp: int) -> Optional[datetime]:
    if not chrome_timestamp or chrome_timestamp <= 0:
        return None
    try:
        unix_ts = (chrome_timestamp / 1_000_000) - CHROME_EPOCH_OFFSET
        if unix_ts < 0 or unix_ts > 2000000000:
            return None
        return datetime.fromtimestamp(unix_ts)
    except (OSError, ValueError, OverflowError):
        return None


# ---------------------------------------------------------------------------
# DPAPI Decryption (Windows)
# ---------------------------------------------------------------------------

def dpapi_decrypt(encrypted: bytes) -> Optional[bytes]:
    """Decrypt data using Windows DPAPI (CryptUnprotectData)."""
    if platform.system() != "Windows":
        return None

    try:
        blob_in = DATA_BLOB()
        blob_in.cbData = len(encrypted)
        blob_in.pbData = ctypes.cast(
            ctypes.create_string_buffer(encrypted, len(encrypted)),
            ctypes.POINTER(ctypes.c_char),
        )

        blob_out = DATA_BLOB()

        result = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in),
            None,  # description
            None,  # optional entropy
            None,  # reserved
            None,  # prompt struct
            0,     # flags
            ctypes.byref(blob_out),
        )

        if result:
            decrypted = ctypes.string_at(blob_out.pbData, blob_out.cbData)
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)
            return decrypted
        return None
    except Exception:
        return None


def get_chrome_encryption_key(local_state_path: str) -> Optional[bytes]:
    """Get the AES encryption key from Chrome's Local State file (v80+)."""
    try:
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)

        encrypted_key_b64 = local_state["os_crypt"]["encrypted_key"]
        encrypted_key = base64.b64decode(encrypted_key_b64)

        # Remove "DPAPI" prefix (first 5 bytes)
        if encrypted_key[:5] == b"DPAPI":
            encrypted_key = encrypted_key[5:]

        # Decrypt with DPAPI
        decrypted_key = dpapi_decrypt(encrypted_key)
        return decrypted_key

    except (KeyError, json.JSONDecodeError, OSError, Exception):
        return None


def decrypt_chrome_password(encrypted_password: bytes, key: Optional[bytes]) -> str:
    """Decrypt a Chrome password.

    Chrome v80+ uses AES-256-GCM with a key from Local State.
    Older versions use DPAPI directly.
    """
    if not encrypted_password:
        return ""

    # Chrome v80+ format: starts with "v10" or "v11"
    if encrypted_password[:3] in (b"v10", b"v11"):
        if not key or not HAS_PYCRYPTO:
            # Try without pycryptodome — manual AES-GCM
            return decrypt_aes_gcm_manual(encrypted_password, key)

        try:
            # Nonce: bytes 3-15 (12 bytes)
            nonce = encrypted_password[3:15]
            # Ciphertext + tag: bytes 15 onwards
            ciphertext_tag = encrypted_password[15:]
            # Last 16 bytes are the GCM tag
            ciphertext = ciphertext_tag[:-16]
            tag = ciphertext_tag[-16:]

            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted.decode("utf-8", errors="replace")
        except Exception:
            return "[DECRYPTION FAILED - v80+ AES]"

    # Older Chrome: DPAPI encrypted directly
    decrypted = dpapi_decrypt(encrypted_password)
    if decrypted:
        return decrypted.decode("utf-8", errors="replace")

    return "[ENCRYPTED - cannot decrypt]"


def decrypt_aes_gcm_manual(encrypted_password: bytes, key: Optional[bytes]) -> str:
    """Fallback AES-GCM decryption without pycryptodome."""
    if not key:
        return "[NEEDS DECRYPTION KEY]"

    # Try using ctypes to call Windows BCrypt API for AES-GCM
    if platform.system() == "Windows":
        try:
            nonce = encrypted_password[3:15]
            ciphertext_tag = encrypted_password[15:]
            ciphertext = ciphertext_tag[:-16]
            tag = ciphertext_tag[-16:]

            # Use Windows BCrypt for AES-GCM
            return _bcrypt_aes_gcm_decrypt(key, nonce, ciphertext, tag)
        except Exception:
            pass

    return "[ENCRYPTED - install pycryptodome: pip install pycryptodome]"


def _bcrypt_aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> str:
    """Decrypt using Windows BCrypt AES-GCM."""
    try:
        import ctypes
        from ctypes import wintypes

        bcrypt = ctypes.windll.bcrypt

        # Constants
        BCRYPT_AES_ALGORITHM = "AES"
        BCRYPT_CHAINING_MODE = "ChainingMode"
        BCRYPT_CHAIN_MODE_GCM = "ChainingModeGCM"

        # Open algorithm provider
        hAlg = ctypes.c_void_p()
        status = bcrypt.BCryptOpenAlgorithmProvider(
            ctypes.byref(hAlg),
            BCRYPT_AES_ALGORITHM,
            None,
            0,
        )
        if status != 0:
            return "[BCRYPT OPEN FAILED]"

        # Set chaining mode to GCM
        mode = BCRYPT_CHAIN_MODE_GCM.encode("utf-16-le")
        bcrypt.BCryptSetProperty(
            hAlg,
            BCRYPT_CHAINING_MODE.encode("utf-16-le"),
            mode,
            len(mode),
            0,
        )

        # Generate symmetric key
        hKey = ctypes.c_void_p()
        status = bcrypt.BCryptGenerateSymmetricKey(
            hAlg,
            ctypes.byref(hKey),
            None,
            0,
            key,
            len(key),
            0,
        )
        if status != 0:
            bcrypt.BCryptCloseAlgorithmProvider(hAlg, 0)
            return "[BCRYPT KEY FAILED]"

        # Prepare auth info structure for GCM
        class BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(ctypes.Structure):
            _fields_ = [
                ("cbSize", ctypes.c_ulong),
                ("dwInfoVersion", ctypes.c_ulong),
                ("pbNonce", ctypes.c_void_p),
                ("cbNonce", ctypes.c_ulong),
                ("pbAuthData", ctypes.c_void_p),
                ("cbAuthData", ctypes.c_ulong),
                ("pbTag", ctypes.c_void_p),
                ("cbTag", ctypes.c_ulong),
                ("pbMacContext", ctypes.c_void_p),
                ("cbMacContext", ctypes.c_ulong),
                ("cbAAD", ctypes.c_ulong),
                ("cbData", ctypes.c_ulonglong),
                ("dwFlags", ctypes.c_ulong),
            ]

        auth_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO()
        auth_info.cbSize = ctypes.sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO)
        auth_info.dwInfoVersion = 1  # BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION

        nonce_buf = ctypes.create_string_buffer(nonce)
        auth_info.pbNonce = ctypes.cast(nonce_buf, ctypes.c_void_p)
        auth_info.cbNonce = len(nonce)

        tag_buf = ctypes.create_string_buffer(tag)
        auth_info.pbTag = ctypes.cast(tag_buf, ctypes.c_void_p)
        auth_info.cbTag = len(tag)

        # Decrypt
        output = ctypes.create_string_buffer(len(ciphertext))
        output_len = ctypes.c_ulong(0)

        ct_buf = ctypes.create_string_buffer(ciphertext)

        status = bcrypt.BCryptDecrypt(
            hKey,
            ct_buf,
            len(ciphertext),
            ctypes.byref(auth_info),
            None,
            0,
            output,
            len(ciphertext),
            ctypes.byref(output_len),
            0,
        )

        # Cleanup
        bcrypt.BCryptDestroyKey(hKey)
        bcrypt.BCryptCloseAlgorithmProvider(hAlg, 0)

        if status == 0:
            return output.raw[:output_len.value].decode("utf-8", errors="replace")
        else:
            return f"[BCRYPT DECRYPT FAILED: 0x{status:08X}]"

    except Exception as e:
        return f"[DECRYPT ERROR: {e}]"


# ---------------------------------------------------------------------------
# Browser profile discovery
# ---------------------------------------------------------------------------

def get_browser_profiles() -> List[dict]:
    """Find all Chrome/Brave/Edge browser profiles with Login Data."""
    profiles = []
    home = os.path.expanduser("~")

    if platform.system() != "Windows":
        print("  ⚠️  Password decryption only works on Windows (DPAPI).")
        return profiles

    base_paths = {
        "Chrome": os.path.join(home, "AppData", "Local", "Google", "Chrome", "User Data"),
        "Brave": os.path.join(home, "AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data"),
        "Edge": os.path.join(home, "AppData", "Local", "Microsoft", "Edge", "User Data"),
        "AVG Browser": os.path.join(home, "AppData", "Local", "AVG", "Browser", "User Data"),
        "Opera": os.path.join(home, "AppData", "Roaming", "Opera Software", "Opera Stable"),
    }

    for browser_name, base_path in base_paths.items():
        if not os.path.exists(base_path):
            continue

        # Get encryption key from Local State
        local_state_path = os.path.join(base_path, "Local State")
        encryption_key = get_chrome_encryption_key(local_state_path)

        # Default profile
        default_profile = os.path.join(base_path, "Default")
        if os.path.exists(os.path.join(default_profile, "Login Data")):
            profiles.append({
                "browser": browser_name,
                "path": default_profile,
                "profile": "Default",
                "key": encryption_key,
            })

        # Numbered profiles
        try:
            for item in os.listdir(base_path):
                if item.startswith("Profile "):
                    profile_path = os.path.join(base_path, item)
                    if os.path.exists(os.path.join(profile_path, "Login Data")):
                        profiles.append({
                            "browser": browser_name,
                            "path": profile_path,
                            "profile": item,
                            "key": encryption_key,
                        })
        except OSError:
            pass

    return profiles


# ---------------------------------------------------------------------------
# Password extraction
# ---------------------------------------------------------------------------

def extract_passwords(profile: dict, target_email: str, scan_all: bool = False) -> List[SavedPassword]:
    """Extract saved passwords from a browser profile's Login Data."""
    results = []
    db_path = os.path.join(profile["path"], "Login Data")

    if not os.path.exists(db_path):
        return results

    # Copy to temp (avoid lock)
    try:
        temp_dir = tempfile.mkdtemp(prefix="pw_hunt_")
        temp_path = os.path.join(temp_dir, "Login Data")
        shutil.copy2(db_path, temp_path)
        # Copy WAL/SHM
        for ext in ["-wal", "-shm", "-journal"]:
            src = db_path + ext
            if os.path.exists(src):
                shutil.copy2(src, temp_path + ext)
    except (OSError, PermissionError) as e:
        print(f"    ⚠️  Cannot copy {db_path}: {e}")
        print(f"       Close {profile['browser']} and try again!")
        return results

    try:
        conn = sqlite3.connect(temp_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT origin_url, username_value, password_value, 
                   date_created, date_last_used
            FROM logins
            ORDER BY date_last_used DESC
        """)

        key = profile.get("key")

        for row in cursor.fetchall():
            url, username, password_blob, date_created, date_last_used = row

            if not url:
                continue

            url_lower = url.lower()
            username_lower = (username or "").lower()

            # Determine if this entry is relevant
            is_priority_url = any(p in url_lower for p in PRIORITY_URLS)
            is_target_email = any(
                email.lower() in username_lower
                for email in TARGET_EMAILS
            )
            is_specific_target = target_email.lower() in username_lower

            if not scan_all and not is_priority_url and not is_target_email:
                continue

            # Determine priority
            if is_specific_target and ("blockchain" in url_lower):
                priority = "critical"
            elif is_specific_target:
                priority = "high"
            elif is_priority_url and is_target_email:
                priority = "high"
            elif is_priority_url or is_target_email:
                priority = "medium"
            else:
                priority = "low"

            # Decrypt password
            password_str = ""
            if password_blob:
                password_str = decrypt_chrome_password(password_blob, key)

            created_dt = chrome_time_to_datetime(date_created)
            used_dt = chrome_time_to_datetime(date_last_used)

            results.append(SavedPassword(
                browser=profile["browser"],
                profile=profile["profile"],
                url=url,
                username=username or "",
                password=password_str,
                date_created=created_dt,
                date_last_used=used_dt,
                priority=priority,
            ))

        conn.close()
    except sqlite3.Error as e:
        print(f"    DB error: {e}")
    finally:
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except OSError:
            pass

    return results


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def generate_password_report(results: List[SavedPassword], output_dir: str) -> dict:
    """Generate report files."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    txt_path = os.path.join(output_dir, f"passwords_{timestamp}.txt")
    json_path = os.path.join(output_dir, f"passwords_{timestamp}.json")

    # JSON (full detail)
    json_data = {
        "generated_at": datetime.now().isoformat(),
        "target_email": TARGET_EMAIL,
        "total_found": len(results),
        "results": [r.to_dict() for r in results],
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=2, default=str)

    # Text report
    lines = []
    lines.append("=" * 65)
    lines.append("  PASSWORD HUNTER — Saved Browser Credentials")
    lines.append(f"  Target: {TARGET_EMAIL}")
    lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 65)
    lines.append("")
    lines.append(f"  Total entries found: {len(results)}")
    lines.append("")

    # Sort by priority
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    results.sort(key=lambda r: priority_order.get(r.priority, 99))

    critical = [r for r in results if r.priority == "critical"]
    high = [r for r in results if r.priority == "high"]
    medium = [r for r in results if r.priority == "medium"]

    if critical:
        lines.append("!" * 65)
        lines.append("  !!!! BLOCKCHAIN.COM CREDENTIALS FOUND !!!!")
        lines.append("!" * 65)
        for r in critical:
            lines.append(f"  URL:      {r.url}")
            lines.append(f"  Email:    {r.username}")
            lines.append(f"  Password: {r.password}")
            if r.date_last_used:
                lines.append(f"  Last used: {r.date_last_used.strftime('%Y-%m-%d')}")
            lines.append("")
        lines.append("!" * 65)
        lines.append("")

    if high:
        lines.append("-" * 65)
        lines.append(f"  [HIGH PRIORITY] {len(high)} entries")
        lines.append("-" * 65)
        for r in high:
            lines.append(f"  [{r.browser}] {r.url}")
            lines.append(f"    User: {r.username}")
            lines.append(f"    Pass: {r.password}")
            if r.date_last_used:
                lines.append(f"    Last: {r.date_last_used.strftime('%Y-%m-%d')}")
            lines.append("")

    if medium:
        lines.append("-" * 65)
        lines.append(f"  [MEDIUM] {len(medium)} entries")
        lines.append("-" * 65)
        for r in medium[:30]:
            lines.append(f"  [{r.browser}] {r.url}")
            lines.append(f"    User: {r.username}")
            lines.append(f"    Pass: {r.password}")
            lines.append("")

    lines.append("")
    lines.append("=" * 65)
    lines.append("  ⚠️  SECURITY:")
    lines.append("  - DELETE this file after you recover your wallet!")
    lines.append("  - NEVER share this file with anyone.")
    lines.append("  - Change passwords on important accounts afterward.")
    lines.append("=" * 65)

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return {"text_report": txt_path, "json_report": json_path}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Extract saved browser passwords for crypto wallet recovery",
    )
    parser.add_argument("--email", "-e", default=TARGET_EMAIL,
                        help=f"Target email (default: {TARGET_EMAIL})")
    parser.add_argument("--all", action="store_true",
                        help="Show ALL saved passwords (not just crypto-related)")
    parser.add_argument("--output", "-o", default="./password_reports",
                        help="Output directory for reports")

    args = parser.parse_args()

    print()
    print("=" * 60)
    print("  PASSWORD HUNTER — Browser Saved Credentials")
    print(f"  Target email: {args.email}")
    print("=" * 60)
    print()

    if platform.system() != "Windows":
        print("  ❌ This tool only works on Windows (uses DPAPI for decryption)")
        sys.exit(1)

    # Check if pycryptodome is available
    if not HAS_PYCRYPTO:
        print("  ⚠️  pycryptodome not installed. Trying Windows BCrypt fallback.")
        print("     For best results: pip install pycryptodome")
        print()

    # Find browser profiles
    profiles = get_browser_profiles()
    if not profiles:
        print("  ❌ No browser profiles with Login Data found!")
        print("     Make sure Chrome/Brave is installed for this user.")
        sys.exit(1)

    print(f"  Found {len(profiles)} browser profile(s)")
    print()

    all_results: List[SavedPassword] = []

    for profile in profiles:
        print(f"  Scanning {profile['browser']} ({profile['profile']})...")

        results = extract_passwords(profile, args.email, scan_all=args.all)
        if results:
            # Count by priority
            crit = sum(1 for r in results if r.priority == "critical")
            high = sum(1 for r in results if r.priority == "high")
            med = sum(1 for r in results if r.priority == "medium")

            parts = []
            if crit:
                parts.append(f"{crit} CRITICAL")
            if high:
                parts.append(f"{high} high")
            if med:
                parts.append(f"{med} medium")

            print(f"    Found: {', '.join(parts) if parts else f'{len(results)} entries'}")
        all_results.extend(results)

    print()
    print(f"  TOTAL: {len(all_results)} saved credentials found")
    print()

    if all_results:
        # Print critical/high immediately
        critical = [r for r in all_results if r.priority == "critical"]
        high = [r for r in all_results if r.priority == "high"]

        if critical:
            print("  " + "!" * 55)
            print("  !!! BLOCKCHAIN.COM PASSWORD FOUND !!!")
            print("  " + "!" * 55)
            for r in critical:
                print(f"  URL:      {r.url}")
                print(f"  Email:    {r.username}")
                print(f"  Password: {r.password}")
                if r.date_last_used:
                    print(f"  Last used: {r.date_last_used.strftime('%Y-%m-%d')}")
                print()
            print("  " + "!" * 55)
            print()
            print("  TRY THIS NOW:")
            print("  1. Go to https://login.blockchain.com")
            print("  2. Click 'Log In with Wallet ID' or use email")
            print("  3. Enter password above")
            print()

        if high:
            print(f"  Other crypto-related passwords ({len(high)}):")
            for r in high:
                print(f"    [{r.browser}] {r.url}")
                print(f"      User: {r.username}")
                print(f"      Pass: {r.password}")
                print()

        # Also show common password patterns (user might reuse)
        passwords_found = set()
        for r in all_results:
            if r.password and not r.password.startswith("["):
                passwords_found.add(r.password)

        if passwords_found:
            print()
            print(f"  📋 UNIQUE PASSWORDS FOUND: {len(passwords_found)}")
            print("  (You may have reused one of these for blockchain.com)")
            print("  " + "-" * 50)
            for i, pw in enumerate(sorted(passwords_found), 1):
                # Show password with slight masking for display
                if len(pw) > 3:
                    display = pw[:2] + "*" * (len(pw) - 3) + pw[-1]
                else:
                    display = pw
                print(f"    {i:3d}. {display}")
            print()

        # Generate report
        report = generate_password_report(all_results, args.output)
        print(f"  Full reports saved to:")
        print(f"    Text: {report['text_report']}")
        print(f"    JSON: {report['json_report']}")
        print()
        print("  ⚠️  Reports contain FULL passwords — keep them SAFE!")
        print("  ⚠️  DELETE reports after wallet recovery!")

    else:
        print("  No relevant saved passwords found.")
        print()
        print("  Possible reasons:")
        print("  - Passwords were never saved in browser")
        print("  - Browser data was cleared")
        print("  - Different browser/profile was used")
        print()
        print("  Try: python password_hunter.py --all")
        print("  (shows ALL saved passwords — you might recognize one)")

    print()


if __name__ == "__main__":
    main()
