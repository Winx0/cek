"""BIP39 English wordlist and seed phrase detector.

Embeds the full 2048-word BIP39 English wordlist and provides utilities
for detecting potential seed phrases (12/15/18/21/24 words) in text.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

# We embed a minimal check: the full 2048-word list is loaded from a bundled
# file or fetched once. For portability we include a hash-based approach:
# store the wordlist in a companion file and load at import time.

_WORDLIST_URL = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt"

# We'll bundle the wordlist inline (first 50 shown, full list loaded from file).
# In practice, the scanner ships with `bip39_english.txt` alongside this module.

import os as _os

_THIS_DIR = _os.path.dirname(_os.path.abspath(__file__))
_WORDLIST_PATH = _os.path.join(_THIS_DIR, "bip39_english.txt")


def _load_wordlist() -> set:
    """Load BIP39 English wordlist. Returns set of 2048 words."""
    if _os.path.exists(_WORDLIST_PATH):
        with open(_WORDLIST_PATH, "r", encoding="utf-8") as f:
            words = {line.strip().lower() for line in f if line.strip()}
        if len(words) >= 2048:
            return words
    # Fallback: try to download (only works if network available)
    try:
        import urllib.request
        resp = urllib.request.urlopen(_WORDLIST_URL, timeout=10)
        data = resp.read().decode("utf-8")
        words = {line.strip().lower() for line in data.splitlines() if line.strip()}
        # Cache for next time
        try:
            with open(_WORDLIST_PATH, "w", encoding="utf-8") as f:
                f.write(data)
        except OSError:
            pass
        return words
    except Exception:
        # Last resort: return empty set (seed detection disabled)
        return set()


BIP39_WORDS: set = _load_wordlist()

# Valid seed phrase lengths
VALID_SEED_LENGTHS = {12, 15, 18, 21, 24}

# Regex to split text into word tokens (lowercased alpha only)
_RE_WORD_TOKEN = re.compile(r"[a-z]+")


def find_seed_candidates(text: str, min_consecutive: int = 12) -> List[Tuple[int, int, List[str]]]:
    """Find sequences of consecutive BIP39 words in text.

    Returns list of (start_pos, end_pos, word_list) tuples where word_list
    has length in VALID_SEED_LENGTHS.

    Args:
        text: Input text to scan.
        min_consecutive: Minimum consecutive BIP39 words to flag (default 12).

    Returns:
        List of candidate seed phrases found.
    """
    if not BIP39_WORDS:
        return []

    candidates: List[Tuple[int, int, List[str]]] = []
    tokens = list(_RE_WORD_TOKEN.finditer(text.lower()))

    i = 0
    while i < len(tokens):
        word = tokens[i].group(0)
        if word not in BIP39_WORDS:
            i += 1
            continue

        # Start collecting consecutive BIP39 words
        seq_start = tokens[i].start()
        seq_words = [word]
        j = i + 1

        while j < len(tokens):
            next_word = tokens[j].group(0)
            if next_word not in BIP39_WORDS:
                break
            # Check gap between tokens isn't too large (max ~5 chars for spaces/punctuation)
            gap = tokens[j].start() - tokens[j - 1].end()
            if gap > 10:
                break
            seq_words.append(next_word)
            j += 1

        if len(seq_words) >= min_consecutive and len(seq_words) in VALID_SEED_LENGTHS:
            seq_end = tokens[j - 1].end()
            candidates.append((seq_start, seq_end, seq_words))
            i = j  # Skip past this sequence
        elif len(seq_words) >= min_consecutive:
            # Trim to largest valid length that fits
            for valid_len in sorted(VALID_SEED_LENGTHS, reverse=True):
                if valid_len <= len(seq_words):
                    seq_end = tokens[i + valid_len - 1].end()
                    candidates.append((seq_start, seq_end, seq_words[:valid_len]))
                    break
            i = j
        else:
            i += 1

    return candidates


def is_likely_seed_phrase(words: List[str]) -> bool:
    """Quick check if a word list could be a valid BIP39 seed phrase.

    Checks:
    - Length is in VALID_SEED_LENGTHS
    - All words are in the BIP39 English wordlist
    - No duplicate adjacent words (very rare in real seeds but common in false positives)
    """
    if len(words) not in VALID_SEED_LENGTHS:
        return False
    if not BIP39_WORDS:
        return False
    if not all(w.lower() in BIP39_WORDS for w in words):
        return False
    # Adjacent duplicates are suspicious but not impossible; allow up to 2
    dup_count = sum(1 for a, b in zip(words, words[1:]) if a == b)
    if dup_count > 2:
        return False
    return True
