"""File carver for Bitcoin wallet artifacts in raw disk data.

Scans raw byte chunks (from raw_disk.py) looking for:
1. wallet.dat file signatures (Berkeley DB magic bytes)
2. BTC addresses (legacy, segwit) in raw bytes
3. WIF private keys in raw bytes
4. BIP32 extended keys (xprv/xpub)
5. BIP39 seed phrases (sequences of English words)
6. Electrum wallet JSON signatures
7. Bitcoin Core key patterns

All operations are READ-ONLY analysis of byte data.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .patterns import (
    RE_BTC_BASE58_ADDR,
    RE_BTC_BECH32_ADDR,
    RE_WIF,
    RE_XKEY,
    RE_RAW_PRIVKEY_HEX,
    b58check_valid,
    bech32_valid,
)
from .wordlist import BIP39_WORDS, VALID_SEED_LENGTHS

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Magic bytes / signatures for file carving
# ---------------------------------------------------------------------------

# Berkeley DB 4.x magic (wallet.dat uses BDB btree)
# At offset 12 in the file: 0x00053162 (BDB btree magic, little-endian)
BDB_MAGIC_OFFSET = 12
BDB_BTREE_MAGIC = b"\x62\x31\x05\x00"  # 0x00053162 LE

# Alternative: Berkeley DB header starts with these at offset 0
# Page size (4 bytes LE) at offset 12, then magic at offset 12
# Actually the reliable signature: bytes 12-15 = 0x00053162
BDB_HEADER_PATTERNS = [
    BDB_BTREE_MAGIC,
    b"\x61\x15\x06\x00",  # BDB hash magic
]

# Bitcoin Core wallet.dat contains these strings
WALLET_DAT_STRINGS = [
    b"name\x00",               # Key name marker
    b"bestblock\x00",          # Best block hash
    b"defaultkey",             # Default key
    b"key\x00",                # Key entry
    b"ckey\x00",               # Encrypted key
    b"mkey\x00",               # Master key
    b"wkey\x00",               # Wallet key (older format)
    b"pool\x00",               # Key pool
    b"version\x00",            # Wallet version
    b"setting\x00",            # Setting entry
    b"tx\x00",                 # Transaction
    b"acc\x00",                # Account
    b"acentry\x00",            # Account entry
    b"minversion\x00",         # Minimum version
    b"orderposnext\x00",       # Order position
]

# Electrum wallet signatures (JSON-based)
ELECTRUM_SIGNATURES = [
    b'"keystore"',
    b'"seed_type"',
    b'"wallet_type"',
    b'"x_pubkeys"',
    b'"seed":',
    b'"addresses"',
    b'"electrum',
]

# BIP39 seed-related contextual markers in raw bytes
SEED_CONTEXT_MARKERS = [
    b"seed",
    b"mnemonic",
    b"recovery",
    b"backup",
    b"12 words",
    b"24 words",
    b"write down",
    b"phrase",
]

# Private key export markers
PRIVKEY_MARKERS = [
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN PRIVATE KEY-----",
    b"5Hw",  # Common WIF prefix uncompressed
    b"5Jb",
    b"5J4",
    b"5HueCGU",  # Wiki example prefix
    b"Kw",   # Common WIF compressed prefix
    b"Kx",
    b"L1",
    b"L2",
    b"L5",
    b"xprv",
    b"yprv",
    b"zprv",
]


# ---------------------------------------------------------------------------
# Carving result types
# ---------------------------------------------------------------------------

@dataclass
class CarveResult:
    """A single finding from raw disk carving."""
    kind: str              # "wallet_dat", "btc_address", "wif", "xkey", "seed_phrase",
                           # "electrum_wallet", "privkey_region"
    disk_offset: int       # Byte offset on disk where found
    value: str             # The extracted value (address, key, etc.)
    context: bytes         # Surrounding raw bytes for context (max 256 bytes)
    confidence: str        # "high", "medium", "low"
    details: str           # Human-readable description

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "disk_offset": self.disk_offset,
            "disk_offset_hex": f"0x{self.disk_offset:X}",
            "disk_offset_mb": f"{self.disk_offset / (1024*1024):.1f} MB",
            "value": self.value,
            "confidence": self.confidence,
            "details": self.details,
        }


@dataclass
class CarveStats:
    """Statistics from a carving session."""
    bytes_scanned: int = 0
    chunks_processed: int = 0
    wallet_dat_found: int = 0
    addresses_found: int = 0
    wif_keys_found: int = 0
    xkeys_found: int = 0
    seed_phrases_found: int = 0
    electrum_wallets_found: int = 0
    privkey_regions_found: int = 0
    start_time: float = 0.0
    end_time: float = 0.0

    @property
    def duration(self) -> float:
        return self.end_time - self.start_time

    @property
    def speed_mbps(self) -> float:
        if self.duration <= 0:
            return 0
        return (self.bytes_scanned / (1024 * 1024)) / self.duration


# ---------------------------------------------------------------------------
# Main Carver
# ---------------------------------------------------------------------------

class DiskCarver:
    """Scans raw disk byte chunks for Bitcoin wallet artifacts.

    Usage:
        carver = DiskCarver(target_address="1B8hgFxNK7ac2k5EtrAanxQPFcnfHLMcko")
        for offset, chunk in raw_disk_reader.read_chunks():
            carver.process_chunk(offset, chunk)
        results = carver.results
    """

    def __init__(
        self,
        target_address: Optional[str] = None,
        scan_wallet_dat: bool = True,
        scan_addresses: bool = True,
        scan_keys: bool = True,
        scan_seeds: bool = True,
        max_results: int = 10000,
    ):
        """
        Args:
            target_address: If set, specifically look for this address in raw bytes.
            scan_wallet_dat: Look for wallet.dat file headers.
            scan_addresses: Look for BTC addresses in text.
            scan_keys: Look for WIF/xprv/hex private keys.
            scan_seeds: Look for BIP39 seed phrases.
            max_results: Stop after this many findings.
        """
        self.target_address = target_address
        self.scan_wallet_dat = scan_wallet_dat
        self.scan_addresses = scan_addresses
        self.scan_keys = scan_keys
        self.scan_seeds = scan_seeds
        self.max_results = max_results

        self.results: List[CarveResult] = []
        self.stats = CarveStats()

        # Deduplication: avoid reporting the same value hundreds of times
        self._seen_values: Set[str] = set()
        # Track wallet.dat regions to avoid duplicate reports
        self._wallet_offsets: Set[int] = set()

        # Pre-encode target address for fast byte search
        self._target_bytes = target_address.encode("ascii") if target_address else None

        # BIP39 word pattern for raw bytes (match printable ASCII word sequences)
        self._bip39_sorted = sorted(BIP39_WORDS, key=len, reverse=True) if BIP39_WORDS else []

    @property
    def is_full(self) -> bool:
        return len(self.results) >= self.max_results

    def process_chunk(self, offset: int, chunk: bytes):
        """Process a raw byte chunk from disk.

        Args:
            offset: The disk byte offset where this chunk starts.
            chunk: Raw bytes read from disk.
        """
        if self.is_full:
            return

        self.stats.chunks_processed += 1
        self.stats.bytes_scanned += len(chunk)

        # --- Priority 1: Target address search ---
        if self._target_bytes:
            self._find_target_address(offset, chunk)

        # --- Priority 2: wallet.dat detection ---
        if self.scan_wallet_dat:
            self._find_wallet_dat(offset, chunk)

        # --- Priority 3: Key material ---
        if self.scan_keys:
            self._find_keys(offset, chunk)

        # --- Priority 4: Addresses ---
        if self.scan_addresses:
            self._find_addresses(offset, chunk)

        # --- Priority 5: Seed phrases ---
        if self.scan_seeds:
            self._find_seeds(offset, chunk)

    def _add_result(self, result: CarveResult) -> bool:
        """Add a result if not duplicate. Returns True if added."""
        if self.is_full:
            return False
        # Deduplicate by value (skip exact duplicates)
        dedup_key = f"{result.kind}:{result.value[:64]}"
        if dedup_key in self._seen_values:
            return False
        self._seen_values.add(dedup_key)
        self.results.append(result)
        return True

    def _get_context(self, chunk: bytes, pos: int, context_size: int = 128) -> bytes:
        """Extract surrounding bytes for context."""
        start = max(0, pos - context_size)
        end = min(len(chunk), pos + context_size)
        return chunk[start:end]

    # --- Target address ---
    def _find_target_address(self, offset: int, chunk: bytes):
        """Search for the specific target BTC address in raw bytes."""
        if not self._target_bytes:
            return

        pos = 0
        while True:
            idx = chunk.find(self._target_bytes, pos)
            if idx == -1:
                break

            absolute_offset = offset + idx
            context = self._get_context(chunk, idx, 256)

            result = CarveResult(
                kind="target_address",
                disk_offset=absolute_offset,
                value=self.target_address,
                context=context,
                confidence="high",
                details=f"Your target address found at disk offset {absolute_offset:,} bytes "
                        f"({absolute_offset/(1024*1024):.1f} MB). Surrounding data may contain keys.",
            )
            self._add_result(result)
            pos = idx + len(self._target_bytes)

    # --- wallet.dat detection ---
    def _find_wallet_dat(self, offset: int, chunk: bytes):
        """Look for Berkeley DB (wallet.dat) file headers and content markers."""
        # Check for BDB btree magic
        for magic in BDB_HEADER_PATTERNS:
            pos = 0
            while True:
                idx = chunk.find(magic, pos)
                if idx == -1:
                    break

                absolute_offset = offset + idx
                # Avoid reporting same wallet region multiple times
                region_key = absolute_offset // (64 * 1024)  # Group by 64KB region
                if region_key in self._wallet_offsets:
                    pos = idx + len(magic)
                    continue
                self._wallet_offsets.add(region_key)

                # Verify: check for wallet.dat-specific strings nearby
                nearby = chunk[max(0, idx-512):min(len(chunk), idx+4096)]
                wallet_score = sum(1 for s in WALLET_DAT_STRINGS if s in nearby)

                if wallet_score >= 2:
                    confidence = "high"
                    details = (f"wallet.dat header found! Score: {wallet_score}/14 markers. "
                              f"This is very likely a Bitcoin Core wallet file.")
                elif wallet_score >= 1:
                    confidence = "medium"
                    details = (f"Possible wallet.dat fragment. Score: {wallet_score}/14 markers.")
                else:
                    # Just BDB magic without wallet strings — could be any BDB file
                    pos = idx + len(magic)
                    continue

                context = self._get_context(chunk, idx, 256)
                result = CarveResult(
                    kind="wallet_dat",
                    disk_offset=absolute_offset - (idx - max(0, idx-12)),  # Adjust to file start
                    value=f"wallet.dat (BDB header, {wallet_score} markers)",
                    context=context,
                    confidence=confidence,
                    details=details,
                )
                if self._add_result(result):
                    self.stats.wallet_dat_found += 1

                pos = idx + 4096  # Skip past this region

    # --- Key material ---
    def _find_keys(self, offset: int, chunk: bytes):
        """Find WIF private keys, xprv/xpub, and hex private keys."""
        # Try to decode chunk as text (ignore errors)
        try:
            text = chunk.decode("ascii", errors="ignore")
        except Exception:
            return

        # WIF keys
        for m in RE_WIF.finditer(text):
            v = m.group(0)
            if v in self._seen_values:
                continue
            if b58check_valid(v):
                absolute_offset = offset + m.start()
                context = self._get_context(chunk, m.start(), 128)
                result = CarveResult(
                    kind="wif",
                    disk_offset=absolute_offset,
                    value=v,
                    context=context,
                    confidence="high",
                    details=f"WIF private key found! This can directly access a BTC wallet.",
                )
                if self._add_result(result):
                    self.stats.wif_keys_found += 1

        # Extended keys (xprv/xpub/yprv/ypub/zprv/zpub)
        for m in RE_XKEY.finditer(text):
            v = m.group(0)
            if v in self._seen_values:
                continue
            if b58check_valid(v):
                absolute_offset = offset + m.start()
                context = self._get_context(chunk, m.start(), 128)
                is_private = v.startswith(("xprv", "yprv", "zprv"))
                result = CarveResult(
                    kind="xkey",
                    disk_offset=absolute_offset,
                    value=v,
                    context=context,
                    confidence="high",
                    details=f"{'PRIVATE' if is_private else 'Public'} extended key (BIP32). "
                            f"{'Can derive all child keys!' if is_private else 'Can track addresses.'}",
                )
                if self._add_result(result):
                    self.stats.xkeys_found += 1

        # Hex private keys (only near wallet-related context)
        for marker in PRIVKEY_MARKERS:
            marker_pos = chunk.find(marker)
            if marker_pos != -1:
                # Search nearby region for hex keys
                region_start = max(0, marker_pos - 256)
                region_end = min(len(chunk), marker_pos + 512)
                region_text = text[region_start:region_end]

                for m in RE_RAW_PRIVKEY_HEX.finditer(region_text):
                    v = m.group(0)
                    if v in self._seen_values:
                        continue
                    # Validate range
                    n = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
                    try:
                        k = int(v, 16)
                    except ValueError:
                        continue
                    if 0 < k < n:
                        absolute_offset = offset + region_start + m.start()
                        context = self._get_context(chunk, marker_pos, 128)
                        result = CarveResult(
                            kind="hex_privkey",
                            disk_offset=absolute_offset,
                            value=v,
                            context=context,
                            confidence="medium",
                            details="Raw hex private key found near crypto context markers.",
                        )
                        if self._add_result(result):
                            self.stats.privkey_regions_found += 1
                break  # Only process first marker hit per chunk

    # --- Addresses ---
    def _find_addresses(self, offset: int, chunk: bytes):
        """Find BTC addresses in raw bytes."""
        try:
            text = chunk.decode("ascii", errors="ignore")
        except Exception:
            return

        # Base58 addresses
        for m in RE_BTC_BASE58_ADDR.finditer(text):
            v = m.group(0)
            if v in self._seen_values:
                continue
            if b58check_valid(v):
                absolute_offset = offset + m.start()
                # Only report if near wallet context (otherwise too noisy)
                nearby = chunk[max(0, m.start()-256):min(len(chunk), m.start()+256)]
                has_context = any(marker in nearby for marker in WALLET_DAT_STRINGS + PRIVKEY_MARKERS)

                # Always report target address, otherwise need context
                if v == self.target_address:
                    confidence = "high"
                elif has_context:
                    confidence = "medium"
                else:
                    continue  # Skip isolated addresses (too many false positives)

                context = self._get_context(chunk, m.start(), 128)
                result = CarveResult(
                    kind="btc_address",
                    disk_offset=absolute_offset,
                    value=v,
                    context=context,
                    confidence=confidence,
                    details=f"BTC address found in deleted/raw data region.",
                )
                if self._add_result(result):
                    self.stats.addresses_found += 1

        # Bech32 addresses (less common in 2020 wallets but check anyway)
        for m in RE_BTC_BECH32_ADDR.finditer(text):
            v = m.group(0)
            if v in self._seen_values:
                continue
            if bech32_valid(v):
                absolute_offset = offset + m.start()
                context = self._get_context(chunk, m.start(), 128)
                result = CarveResult(
                    kind="btc_address",
                    disk_offset=absolute_offset,
                    value=v,
                    context=context,
                    confidence="medium",
                    details="Bech32 BTC address found in raw data.",
                )
                if self._add_result(result):
                    self.stats.addresses_found += 1

    # --- Seed phrases ---
    def _find_seeds(self, offset: int, chunk: bytes):
        """Find BIP39 seed phrases in raw bytes."""
        if not BIP39_WORDS:
            return

        try:
            text = chunk.decode("utf-8", errors="ignore")
        except Exception:
            return

        # Look for regions that have seed context markers
        has_seed_context = any(marker in chunk for marker in SEED_CONTEXT_MARKERS)

        # Quick check: does this chunk contain multiple BIP39 words?
        # Only do expensive word-by-word analysis if at least some BIP39 words present
        word_pattern = re.compile(r"[a-z]{3,8}")
        words_in_chunk = word_pattern.findall(text.lower())

        bip39_count = sum(1 for w in words_in_chunk if w in BIP39_WORDS)

        # Need at least 12 BIP39 words to potentially contain a seed
        if bip39_count < 12:
            return

        # Now do a proper sliding window search for consecutive BIP39 words
        tokens = list(re.finditer(r"[a-zA-Z]{3,8}", text))

        i = 0
        while i < len(tokens):
            word = tokens[i].group(0).lower()
            if word not in BIP39_WORDS:
                i += 1
                continue

            # Found a BIP39 word, try to extend the sequence
            seq_start_pos = tokens[i].start()
            seq_words = [word]
            j = i + 1

            while j < len(tokens) and len(seq_words) < 24:
                next_word = tokens[j].group(0).lower()
                if next_word not in BIP39_WORDS:
                    break
                # Check gap isn't too large (max ~20 chars for separators)
                gap = tokens[j].start() - tokens[j-1].end()
                if gap > 20:
                    break
                seq_words.append(next_word)
                j += 1

            if len(seq_words) in VALID_SEED_LENGTHS:
                absolute_offset = offset + seq_start_pos
                phrase = " ".join(seq_words)

                # Check for adjacent duplicates (common in false positives like wordlists)
                dup_count = sum(1 for a, b in zip(seq_words, seq_words[1:]) if a == b)
                if dup_count > 2:
                    i = j
                    continue

                # Higher confidence if near seed context markers
                confidence = "high" if has_seed_context else "medium"

                context = self._get_context(chunk, seq_start_pos, 64)
                result = CarveResult(
                    kind="seed_phrase",
                    disk_offset=absolute_offset,
                    value=phrase,
                    context=context,
                    confidence=confidence,
                    details=f"{len(seq_words)}-word BIP39 seed phrase found in raw disk data!",
                )
                if self._add_result(result):
                    self.stats.seed_phrases_found += 1

                i = j  # Skip past this sequence
            else:
                i += 1

    # --- Electrum wallet ---
    def find_electrum_wallets(self, offset: int, chunk: bytes):
        """Find Electrum wallet JSON fragments."""
        score = sum(1 for sig in ELECTRUM_SIGNATURES if sig in chunk)
        if score >= 2:
            # Find the first signature position
            positions = []
            for sig in ELECTRUM_SIGNATURES:
                idx = chunk.find(sig)
                if idx != -1:
                    positions.append(idx)

            if positions:
                first_pos = min(positions)
                absolute_offset = offset + first_pos
                context = self._get_context(chunk, first_pos, 256)

                result = CarveResult(
                    kind="electrum_wallet",
                    disk_offset=absolute_offset,
                    value=f"Electrum wallet data ({score}/{len(ELECTRUM_SIGNATURES)} signatures)",
                    context=context,
                    confidence="high" if score >= 3 else "medium",
                    details=f"Electrum wallet JSON fragment found. May contain encrypted seed or keys.",
                )
                if self._add_result(result):
                    self.stats.electrum_wallets_found += 1


# ---------------------------------------------------------------------------
# Convenience: Extract a full wallet.dat from raw disk
# ---------------------------------------------------------------------------

def extract_wallet_region(
    disk_path: str,
    offset: int,
    output_path: str,
    size: int = 2 * 1024 * 1024,  # Default 2MB extraction
) -> bool:
    """Extract a raw region from disk to a file (potential wallet.dat recovery).

    Args:
        disk_path: Path to the raw disk device.
        offset: Byte offset where wallet.dat header was found.
        output_path: Path to save the extracted data.
        size: How many bytes to extract (default 2MB covers most wallet.dat files).

    Returns:
        True if extraction was successful.
    """
    from .raw_disk import RawDiskReader

    # Align offset to start of potential file (wallet.dat header is at offset 12)
    file_start = max(0, offset - 12)
    file_start = file_start - (file_start % 512)  # Align to sector

    reader = RawDiskReader(disk_path, chunk_size=size, start_offset=file_start)

    try:
        if not reader.open():
            return False

        for chunk_offset, data in reader.read_chunks():
            os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
            with open(output_path, "wb") as f:
                f.write(data)
            logger.info(f"Extracted {len(data):,} bytes to {output_path}")
            reader.close()
            return True

    except Exception as e:
        logger.error(f"Extraction failed: {e}")
    finally:
        reader.close()

    return False
