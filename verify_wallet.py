#!/usr/bin/env python3
"""Verify if target BTC address exists inside encrypted Blockchain.com wallet payload.

Tries each password from passwords.txt to decrypt the wallet,
then checks if address 1B8hgFxNK7ac2k5EtrAanxQPFcnfHLMcko is inside.
"""

import json
import hashlib
import base64
import os
import sys

try:
    from Crypto.Cipher import AES
except ImportError:
    from Cryptodome.Cipher import AES

TARGET_ADDRESS = "1B8hgFxNK7ac2k5EtrAanxQPFcnfHLMcko"

def try_decrypt(payload_bytes, password, iterations):
    """Try to decrypt Blockchain.com wallet payload with given password."""
    try:
        iv = payload_bytes[:16]
        enc_data = payload_bytes[16:]

        # Derive key using PBKDF2-SHA1
        key = hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), iv, iterations, dkLen=32)

        # Decrypt with AES-256-CBC
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(enc_data)

        # Remove PKCS7 padding
        pad_len = decrypted[-1]
        if 0 < pad_len <= 16:
            # Verify padding
            if all(b == pad_len for b in decrypted[-pad_len:]):
                decrypted = decrypted[:-pad_len]

        # Try to decode as UTF-8
        text = decrypted.decode("utf-8", errors="ignore")

        # Check if it looks like valid JSON wallet data
        if "{" in text and ("guid" in text or "keys" in text or "addr" in text):
            return text
        return None
    except Exception:
        return None


def main():
    print()
    print("=" * 60)
    print("  VERIFY: Does wallet contain target BTC address?")
    print(f"  Target: {TARGET_ADDRESS}")
    print("=" * 60)
    print()

    # Load wallet payload
    payload_file = os.path.join("wallet_payloads", "fixed_wallet_payload_0.json")
    if not os.path.exists(payload_file):
        print("  ERROR: fixed_wallet_payload_0.json not found!")
        print("  Run fix_wallet_payload.py first.")
        return

    with open(payload_file, "r") as f:
        wallet = json.loads(f.read())

    payload_b64 = wallet["payload"]
    iterations = wallet.get("pbkdf2_iterations", 5000)

    # Fix base64 padding if needed
    missing_padding = len(payload_b64) % 4
    if missing_padding:
        payload_b64 += "=" * (4 - missing_padding)

    payload_bytes = base64.b64decode(payload_b64)

    print(f"  Payload size: {len(payload_bytes)} bytes")
    print(f"  PBKDF2 iterations: {iterations}")
    print()

    # Load passwords
    pwd_file = "passwords.txt"
    if not os.path.exists(pwd_file):
        print("  ERROR: passwords.txt not found!")
        print("  Create it with your passwords (one per line).")
        return

    with open(pwd_file, "r", encoding="utf-8") as f:
        passwords = [line.strip() for line in f if line.strip()]

    print(f"  Passwords to try: {len(passwords)}")
    print()
    print("  Trying passwords...")
    print()

    for i, pwd in enumerate(passwords):
        result = try_decrypt(payload_bytes, pwd, iterations)

        if result:
            print(f"  PASSWORD FOUND: \"{pwd}\"")
            print()

            # Check for target address
            if TARGET_ADDRESS in result:
                print("  " + "!" * 55)
                print(f"  !!! ADDRESS CONFIRMED IN THIS WALLET !!!")
                print(f"  !!! {TARGET_ADDRESS} !!!")
                print("  " + "!" * 55)
            else:
                print("  Address NOT in this wallet payload.")
                print("  (Could be in a different wallet or generated via HD)")

            # Check for GUID
            if "1af403a8" in result:
                print(f"  GUID: 1af403a8-eb94-4534-b1f4-5c838c871a7b (2014)")
            elif "1f330204" in result:
                print(f"  GUID: 1f330204-c407-45d2-8ccf-5d0a87a23cf6 (2021)")

            # Save decrypted wallet
            out_file = os.path.join("wallet_payloads", "decrypted_wallet.json")
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(result)
            print(f"  Decrypted wallet saved: {out_file}")
            print()

            # Show first 300 chars
            print("  First 300 chars of decrypted data:")
            print("  " + "-" * 50)
            print(f"  {result[:300]}")
            print()
            return

        # Progress
        if (i + 1) % 1 == 0:
            print(f"    [{i+1}/{len(passwords)}] Tried: {pwd} -> No match")

    print()
    print("  No password matched.")
    print("  Add more passwords to passwords.txt and try again.")
    print()


if __name__ == "__main__":
    main()
