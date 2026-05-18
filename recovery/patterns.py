"""Regex patterns + validators for Bitcoin artifacts.

Validation goes beyond regex to cut down false positives:
  - Base58Check addresses (P2PKH "1...", P2SH "3...") are checksum-verified.
  - Bech32 addresses ("bc1...") are checksum-verified per BIP173/BIP350.
  - WIF private keys are Base58Check-verified.
  - Extended keys (xprv/xpub/yprv/ypub/zprv/zpub) are Base58Check-verified.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import List, Optional


# ---------------------------------------------------------------------------
# Regex (broad first-pass filters; validators below confirm matches)
# ---------------------------------------------------------------------------

# Legacy P2PKH ("1...") and P2SH ("3..."). 26-35 chars, base58 alphabet.
RE_BTC_BASE58_ADDR = re.compile(
    r"\b[13][1-9A-HJ-NP-Za-km-z]{25,34}\b"
)

# bech32 / bech32m mainnet ("bc1...") - BIP173/BIP350. 14-74 chars after "bc1".
RE_BTC_BECH32_ADDR = re.compile(
    r"\bbc1[02-9ac-hj-np-z]{6,87}\b"
)

# WIF private keys: starts with 5 (uncompressed, 51 chars) or K/L (compressed, 52 chars).
RE_WIF = re.compile(
    r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b"
)

# BIP32 extended keys (mainnet & common variants). 111 chars, base58.
RE_XKEY = re.compile(
    r"\b(?:xprv|xpub|yprv|ypub|zprv|zpub|Yprv|Ypub|Zprv|Zpub)[1-9A-HJ-NP-Za-km-z]{107,108}\b"
)

# Hex-encoded raw private keys (32 bytes = 64 hex chars). Use word boundary check
# in caller because plain 64-hex is very ambiguous on its own.
RE_RAW_PRIVKEY_HEX = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")

# Indicator words that strongly suggest wallet material is nearby.
RE_KEYWORDS = re.compile(
    r"\b(?:seed|mnemonic|passphrase|recovery\s+phrase|private\s+key|"
    r"wallet|electrum|bitcoin|trezor|ledger|xprv|xpub|wif|bip39|bip32|bip44)\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Base58 / Base58Check
# ---------------------------------------------------------------------------

_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}


def b58decode(s: str) -> Optional[bytes]:
    """Decode a base58 string. Returns None if any char is invalid."""
    if not s:
        return None
    n = 0
    for ch in s.encode("ascii", errors="ignore"):
        if ch not in _B58_INDEX:
            return None
        n = n * 58 + _B58_INDEX[ch]
    # Convert integer to big-endian bytes.
    full = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    # Leading '1's in base58 represent leading zero bytes.
    pad = 0
    for ch in s:
        if ch == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + full


def b58check_valid(s: str) -> bool:
    """Verify Base58Check encoding (last 4 bytes are double-SHA256 checksum)."""
    raw = b58decode(s)
    if raw is None or len(raw) < 5:
        return False
    payload, checksum = raw[:-4], raw[-4:]
    expect = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return checksum == expect


# ---------------------------------------------------------------------------
# Bech32 / Bech32m (BIP173 + BIP350)
# ---------------------------------------------------------------------------

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

_BECH32_CONST = 1
_BECH32M_CONST = 0x2BC830A3


def _bech32_polymod(values: List[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= gen[i]
    return chk


def _bech32_hrp_expand(hrp: str) -> List[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def bech32_valid(addr: str) -> bool:
    """Validate a bech32 / bech32m mainnet BTC address.

    Accepts both BIP173 (segwit v0) and BIP350 (segwit v1+, e.g. taproot).
    """
    addr = addr.lower()
    if any(ord(c) < 33 or ord(c) > 126 for c in addr):
        return False
    if "1" not in addr:
        return False
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr) or len(addr) > 90:
        return False
    hrp, data_part = addr[:pos], addr[pos + 1 :]
    if hrp != "bc":
        return False
    try:
        data = [_BECH32_CHARSET.index(c) for c in data_part]
    except ValueError:
        return False
    polymod = _bech32_polymod(_bech32_hrp_expand(hrp) + data)
    if polymod == _BECH32_CONST:
        spec = "bech32"
    elif polymod == _BECH32M_CONST:
        spec = "bech32m"
    else:
        return False
    # Witness version is the first data symbol.
    witver = data[0]
    if witver == 0 and spec != "bech32":
        return False
    if witver != 0 and spec != "bech32m":
        return False
    return True


# ---------------------------------------------------------------------------
# Match data class
# ---------------------------------------------------------------------------

@dataclass
class Match:
    kind: str          # "btc_address", "wif", "xkey", "hex_privkey", "keyword"
    value: str
    line_no: int
    snippet: str       # surrounding text, redacted

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "value": self.value,
            "line_no": self.line_no,
            "snippet": self.snippet,
        }


def _redact(value: str) -> str:
    """Redact sensitive material so the report is safe-ish to share for help.

    Keeps first 6 and last 4 characters, masks the middle. The full value is
    only kept in the encrypted/local JSON, not the human-readable report.
    """
    if len(value) <= 12:
        return value[:2] + "*" * (len(value) - 2)
    return f"{value[:6]}...{value[-4:]}"


def _make_snippet(line: str, value: str, redact: bool = True, width: int = 80) -> str:
    line = line.rstrip("\n")
    if redact:
        shown = _redact(value)
        line = line.replace(value, shown)
    if len(line) <= width:
        return line
    idx = line.find(_redact(value)) if redact else line.find(value)
    if idx < 0:
        return line[:width] + "..."
    half = width // 2
    start = max(0, idx - half)
    end = min(len(line), idx + half)
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(line) else ""
    return f"{prefix}{line[start:end]}{suffix}"


# ---------------------------------------------------------------------------
# Per-line scan
# ---------------------------------------------------------------------------

def scan_line(line: str, line_no: int, redact_snippets: bool = True) -> List[Match]:
    """Run all regex+validator checks on a single line of text."""
    matches: List[Match] = []

    for m in RE_BTC_BASE58_ADDR.finditer(line):
        v = m.group(0)
        if b58check_valid(v):
            matches.append(Match("btc_address", v, line_no, _make_snippet(line, v, redact_snippets)))

    for m in RE_BTC_BECH32_ADDR.finditer(line):
        v = m.group(0)
        if bech32_valid(v):
            matches.append(Match("btc_address", v, line_no, _make_snippet(line, v, redact_snippets)))

    for m in RE_WIF.finditer(line):
        v = m.group(0)
        if b58check_valid(v):
            matches.append(Match("wif", v, line_no, _make_snippet(line, v, redact_snippets)))

    for m in RE_XKEY.finditer(line):
        v = m.group(0)
        if b58check_valid(v):
            matches.append(Match("xkey", v, line_no, _make_snippet(line, v, redact_snippets)))

    # hex privkey is too noisy to report on its own; only flag when a wallet
    # keyword appears nearby on the same line.
    if RE_KEYWORDS.search(line):
        for m in RE_RAW_PRIVKEY_HEX.finditer(line):
            v = m.group(0)
            # secp256k1 group order; valid privkeys must be 1 <= k < n.
            n = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
            try:
                k = int(v, 16)
            except ValueError:
                continue
            if 0 < k < n:
                matches.append(Match("hex_privkey", v, line_no, _make_snippet(line, v, redact_snippets)))

    return matches
