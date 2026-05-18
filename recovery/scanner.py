"""Filesystem scanner engine.

Walks the filesystem looking for:
1. Known wallet files by name/extension
2. Text-based files that may contain BTC addresses, keys, or seed phrases
3. Known wallet application data directories

All operations are READ-ONLY. Nothing is modified or uploaded.
"""

from __future__ import annotations

import os
import platform
import re
import sys
import time
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Generator, List, Optional, Set, Tuple

from .patterns import Match, scan_line, RE_KEYWORDS
from .wordlist import find_seed_candidates, is_likely_seed_phrase

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class ScanConfig:
    """Scanner configuration."""

    # Root paths to scan. Empty = auto-detect based on OS.
    roots: List[str] = field(default_factory=list)

    # Maximum file size to content-scan (bytes). Files larger are skipped for
    # content scanning but still checked by name/extension.
    max_file_size: int = 50 * 1024 * 1024  # 50 MB

    # Maximum text file size for line-by-line scan
    max_text_size: int = 10 * 1024 * 1024  # 10 MB

    # Whether to scan hidden directories (dotfiles)
    scan_hidden: bool = True

    # Whether to follow symbolic links
    follow_symlinks: bool = False

    # Skip these directory names
    skip_dirs: Set[str] = field(default_factory=lambda: {
        "node_modules", ".git", "__pycache__", ".cache",
        "System Volume Information", "$Recycle.Bin",
        "Windows", "Program Files", "Program Files (x86)",
    })

    # File extensions to content-scan for text
    text_extensions: Set[str] = field(default_factory=lambda: {
        ".txt", ".md", ".csv", ".json", ".xml", ".log", ".conf", ".cfg",
        ".ini", ".yaml", ".yml", ".toml", ".env", ".bak", ".backup",
        ".key", ".pem", ".asc", ".gpg", ".wallet", ".dat", ".db",
        ".sql", ".rtf", ".doc", ".html", ".htm", ".py", ".js", ".sh",
        ".bat", ".ps1", ".note", ".notes",
    })

    # Redact sensitive values in report snippets
    redact_snippets: bool = True

    # Progress callback: called with (files_scanned, matches_found, current_path)
    progress_callback: Optional[Callable[[int, int, str], None]] = None


# ---------------------------------------------------------------------------
# Known wallet file patterns (era ~2017-2021)
# ---------------------------------------------------------------------------

# Exact filenames
WALLET_FILENAMES: Set[str] = {
    "wallet.dat",           # Bitcoin Core, Litecoin Core, etc.
    "default_wallet",       # Electrum
    ".wallet",             # various
    "electrum.dat",
    "multibit.wallet",
    "multibit.key",
    "multibit-hd.wallet.aes",
    "btcprivkey.txt",
    "keys.db",
    "wallet.aes.json",     # MyEtherWallet-style but may contain BTC
    "keystore",
    "wallet.json",
    "wallet.csv",
    "seed.txt",
    "seed_backup.txt",
    "recovery.txt",
    "mnemonic.txt",
    "passphrase.txt",
}

# File extensions that are wallet-specific
WALLET_EXTENSIONS: Set[str] = {
    ".wallet",
    ".kdbx",    # KeePass (may contain seed/keys)
    ".aes",
    ".aes.json",
}

# Directory names that indicate wallet data
WALLET_DIR_NAMES: Set[str] = {
    "electrum",
    "bitcoin",
    "bitcoin-core",
    "multibit",
    "multibit-hd",
    "armory",
    "wasabi",
    "wasabi wallet",
    "sparrow",
    "exodus",
    "atomic",
    "atomic wallet",
    "jaxx",
    "jaxx liberty",
    "copay",
    "breadwallet",
    "mycelium",
    "blockchain",
    "greenaddress",
    "samourai",
    "bluewallet",
    "trust wallet",
    "coinomi",
    "ledger live",
    "trezor",
}


def get_default_scan_roots() -> List[str]:
    """Return default scan roots based on OS."""
    system = platform.system()

    if system == "Windows":
        roots = []
        # User home
        home = os.path.expanduser("~")
        roots.append(home)
        # Common locations
        for drive in "CDEFGH":
            d = f"{drive}:\\"
            if os.path.exists(d):
                roots.append(d)
        return roots

    elif system == "Darwin":  # macOS
        home = os.path.expanduser("~")
        return [
            home,
            "/Volumes",  # External drives
        ]

    else:  # Linux
        home = os.path.expanduser("~")
        roots = [home]
        # Check for additional mount points
        for mnt in ["/mnt", "/media", "/run/media"]:
            if os.path.exists(mnt):
                roots.append(mnt)
        return roots


def get_known_wallet_paths() -> List[str]:
    """Return OS-specific paths where wallet software typically stores data."""
    system = platform.system()
    home = os.path.expanduser("~")
    paths = []

    if system == "Windows":
        appdata = os.environ.get("APPDATA", os.path.join(home, "AppData", "Roaming"))
        localappdata = os.environ.get("LOCALAPPDATA", os.path.join(home, "AppData", "Local"))
        paths = [
            os.path.join(appdata, "Bitcoin"),
            os.path.join(appdata, "Electrum"),
            os.path.join(appdata, "Electrum", "wallets"),
            os.path.join(appdata, "MultiBit"),
            os.path.join(appdata, "MultiBitHD"),
            os.path.join(appdata, "Armory"),
            os.path.join(appdata, "WasabiWallet"),
            os.path.join(localappdata, "Sparrow"),
            os.path.join(appdata, "Exodus"),
            os.path.join(appdata, "atomic", "Local Storage"),
            os.path.join(appdata, "Jaxx"),
            os.path.join(appdata, "Jaxx Liberty"),
            os.path.join(appdata, "Copay"),
            os.path.join(appdata, "Coinomi"),
            os.path.join(localappdata, "Ledger Live"),
            os.path.join(home, "Documents"),
            os.path.join(home, "Desktop"),
            os.path.join(home, "Downloads"),
        ]

    elif system == "Darwin":
        lib = os.path.join(home, "Library")
        paths = [
            os.path.join(lib, "Application Support", "Bitcoin"),
            os.path.join(lib, "Application Support", "Electrum"),
            os.path.join(lib, "Application Support", "Electrum", "wallets"),
            os.path.join(lib, "Application Support", "MultiBit"),
            os.path.join(lib, "Application Support", "MultiBitHD"),
            os.path.join(lib, "Application Support", "Armory"),
            os.path.join(lib, "Application Support", "WasabiWallet"),
            os.path.join(lib, "Application Support", "Sparrow"),
            os.path.join(lib, "Application Support", "Exodus"),
            os.path.join(lib, "Application Support", "Atomic"),
            os.path.join(lib, "Application Support", "Jaxx Liberty"),
            os.path.join(lib, "Application Support", "Coinomi"),
            os.path.join(home, "Documents"),
            os.path.join(home, "Desktop"),
            os.path.join(home, "Downloads"),
        ]

    else:  # Linux
        paths = [
            os.path.join(home, ".bitcoin"),
            os.path.join(home, ".electrum"),
            os.path.join(home, ".electrum", "wallets"),
            os.path.join(home, ".multibit"),
            os.path.join(home, ".multibit-hd"),
            os.path.join(home, ".armory"),
            os.path.join(home, ".wasabiwallet"),
            os.path.join(home, ".config", "sparrow"),
            os.path.join(home, ".config", "Exodus"),
            os.path.join(home, ".config", "atomic"),
            os.path.join(home, ".local", "share", "jaxx-liberty"),
            os.path.join(home, ".config", "Coinomi"),
            os.path.join(home, "Documents"),
            os.path.join(home, "Desktop"),
            os.path.join(home, "Downloads"),
        ]

    return [p for p in paths if os.path.exists(p)]


# ---------------------------------------------------------------------------
# File result
# ---------------------------------------------------------------------------

@dataclass
class FileResult:
    """Result of scanning a single file."""
    path: str
    reason: str  # "wallet_file", "wallet_dir", "content_match"
    matches: List[Match] = field(default_factory=list)
    seed_phrases: List[List[str]] = field(default_factory=list)
    size: int = 0
    modified_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "reason": self.reason,
            "matches": [m.to_dict() for m in self.matches],
            "seed_phrases_count": len(self.seed_phrases),
            "size": self.size,
            "modified_time": self.modified_time,
        }


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class BTCRecoveryScanner:
    """Main scanner class. Read-only filesystem scan for BTC wallet artifacts."""

    def __init__(self, config: Optional[ScanConfig] = None):
        self.config = config or ScanConfig()
        self.results: List[FileResult] = []
        self.stats = {
            "files_scanned": 0,
            "dirs_scanned": 0,
            "files_skipped": 0,
            "errors": 0,
            "start_time": 0.0,
            "end_time": 0.0,
        }
        self._seen_paths: Set[str] = set()

    def scan(self) -> List[FileResult]:
        """Run the full scan. Returns list of FileResult."""
        self.stats["start_time"] = time.time()
        self.results = []
        self._seen_paths = set()

        # Phase 1: Check known wallet paths first (fast, high confidence)
        logger.info("Phase 1: Scanning known wallet directories...")
        for wpath in get_known_wallet_paths():
            self._scan_directory(wpath, is_wallet_dir=True)

        # Phase 2: Walk configured roots
        roots = self.config.roots or get_default_scan_roots()
        logger.info(f"Phase 2: Scanning {len(roots)} root(s): {roots}")
        for root in roots:
            if os.path.isdir(root):
                self._scan_directory(root, is_wallet_dir=False)

        self.stats["end_time"] = time.time()
        duration = self.stats["end_time"] - self.stats["start_time"]
        logger.info(
            f"Scan complete in {duration:.1f}s. "
            f"Files: {self.stats['files_scanned']}, "
            f"Results: {len(self.results)}, "
            f"Errors: {self.stats['errors']}"
        )
        return self.results

    def _scan_directory(self, root: str, is_wallet_dir: bool = False):
        """Walk a directory tree."""
        try:
            for dirpath, dirnames, filenames in os.walk(
                root, followlinks=self.config.follow_symlinks
            ):
                self.stats["dirs_scanned"] += 1

                # Check if current dir is a wallet-related dir
                dir_lower = os.path.basename(dirpath).lower()
                in_wallet_dir = is_wallet_dir or dir_lower in WALLET_DIR_NAMES

                # Filter directories to skip
                dirnames[:] = [
                    d for d in dirnames
                    if d not in self.config.skip_dirs
                    and (self.config.scan_hidden or not d.startswith("."))
                ]

                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)

                    # Avoid scanning same file twice (symlinks, etc.)
                    try:
                        real_path = os.path.realpath(filepath)
                    except OSError:
                        continue
                    if real_path in self._seen_paths:
                        continue
                    self._seen_paths.add(real_path)

                    self._scan_file(filepath, filename, in_wallet_dir)

        except PermissionError:
            self.stats["errors"] += 1
            logger.debug(f"Permission denied: {root}")
        except OSError as e:
            self.stats["errors"] += 1
            logger.debug(f"OS error scanning {root}: {e}")

    def _scan_file(self, filepath: str, filename: str, in_wallet_dir: bool):
        """Analyze a single file."""
        try:
            stat = os.stat(filepath)
        except OSError:
            self.stats["errors"] += 1
            return

        size = stat.st_size
        mtime = stat.st_mtime
        filename_lower = filename.lower()

        self.stats["files_scanned"] += 1

        # Progress callback
        if self.config.progress_callback and self.stats["files_scanned"] % 1000 == 0:
            self.config.progress_callback(
                self.stats["files_scanned"],
                len(self.results),
                filepath,
            )

        # --- Check 1: Known wallet filename ---
        if filename_lower in WALLET_FILENAMES:
            result = FileResult(
                path=filepath,
                reason="wallet_file",
                size=size,
                modified_time=mtime,
            )
            # Try to content-scan it too
            self._content_scan(filepath, size, result)
            self.results.append(result)
            logger.info(f"[WALLET FILE] {filepath}")
            return

        # --- Check 2: Wallet extension ---
        for ext in WALLET_EXTENSIONS:
            if filename_lower.endswith(ext):
                result = FileResult(
                    path=filepath,
                    reason="wallet_file",
                    size=size,
                    modified_time=mtime,
                )
                self._content_scan(filepath, size, result)
                self.results.append(result)
                logger.info(f"[WALLET EXT] {filepath}")
                return

        # --- Check 3: In wallet directory → scan content ---
        if in_wallet_dir and size <= self.config.max_file_size:
            result = FileResult(
                path=filepath,
                reason="wallet_dir",
                size=size,
                modified_time=mtime,
            )
            self._content_scan(filepath, size, result)
            if result.matches or result.seed_phrases:
                self.results.append(result)
                logger.info(f"[WALLET DIR MATCH] {filepath}")
            return

        # --- Check 4: Text file content scan ---
        _, ext = os.path.splitext(filename_lower)
        if ext in self.config.text_extensions and size <= self.config.max_text_size:
            result = FileResult(
                path=filepath,
                reason="content_match",
                size=size,
                modified_time=mtime,
            )
            self._content_scan(filepath, size, result)
            if result.matches or result.seed_phrases:
                self.results.append(result)
                logger.info(f"[CONTENT MATCH] {filepath}")

    def _content_scan(self, filepath: str, size: int, result: FileResult):
        """Scan file content line by line for BTC artifacts."""
        if size > self.config.max_text_size:
            return

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                full_text_lines: List[str] = []
                for line_no, line in enumerate(f, 1):
                    full_text_lines.append(line)
                    matches = scan_line(line, line_no, self.config.redact_snippets)
                    result.matches.extend(matches)

                    # Limit matches per file to avoid flooding
                    if len(result.matches) > 100:
                        break

                # Seed phrase detection on full text
                if len(full_text_lines) < 50000:  # Don't seed-scan huge files
                    full_text = "".join(full_text_lines)
                    candidates = find_seed_candidates(full_text)
                    for start, end, words in candidates:
                        if is_likely_seed_phrase(words):
                            result.seed_phrases.append(words)

        except (OSError, UnicodeDecodeError):
            self.stats["errors"] += 1
        except Exception as e:
            self.stats["errors"] += 1
            logger.debug(f"Error scanning {filepath}: {e}")
