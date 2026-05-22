"""Report generator for BTC recovery scan results.

Produces:
1. A human-readable text summary (safe to share for help — sensitive data redacted)
2. A JSON file with full details (keep private!)
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime
from typing import Dict, List

from .scanner import BTCRecoveryScanner, FileResult
from .patterns import _redact


def generate_report(
    scanner: BTCRecoveryScanner,
    output_dir: str = ".",
    prefix: str = "btc_recovery",
) -> Dict[str, str]:
    """Generate both text and JSON reports.

    Args:
        scanner: A scanner that has already run .scan().
        output_dir: Directory to write reports to.
        prefix: Filename prefix.

    Returns:
        Dict with keys "text_report" and "json_report" containing file paths.
    """
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    text_path = os.path.join(output_dir, f"{prefix}_{timestamp}.txt")
    json_path = os.path.join(output_dir, f"{prefix}_{timestamp}.json")

    # --- JSON Report (full detail, KEEP PRIVATE) ---
    json_data = {
        "generated_at": datetime.now().isoformat(),
        "scanner_version": "0.1.0",
        "stats": scanner.stats,
        "total_findings": len(scanner.results),
        "results": [r.to_dict() for r in scanner.results],
    }

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=2, default=str)

    # --- Text Report (redacted, safe-ish to share) ---
    lines: List[str] = []
    lines.append("=" * 70)
    lines.append("  BTC WALLET RECOVERY SCAN REPORT")
    lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 70)
    lines.append("")

    # Stats
    duration = scanner.stats.get("end_time", 0) - scanner.stats.get("start_time", 0)
    lines.append(f"  Scan Duration:   {duration:.1f} seconds")
    lines.append(f"  Files Scanned:   {scanner.stats.get('files_scanned', 0):,}")
    lines.append(f"  Dirs Scanned:    {scanner.stats.get('dirs_scanned', 0):,}")
    lines.append(f"  Errors:          {scanner.stats.get('errors', 0):,}")
    lines.append(f"  Total Findings:  {len(scanner.results)}")
    lines.append("")
    lines.append("-" * 70)

    if not scanner.results:
        lines.append("")
        lines.append("  No Bitcoin wallet artifacts found.")
        lines.append("")
        lines.append("  Suggestions:")
        lines.append("  - Try scanning external drives or backup locations")
        lines.append("  - Use data recovery tools (PhotoRec/TestDisk) if disk was formatted")
        lines.append("  - Check cloud backups (Google Drive, Dropbox, OneDrive)")
        lines.append("  - Check email for wallet backup attachments")
        lines.append("")
    else:
        # Group by reason
        wallet_files = [r for r in scanner.results if r.reason == "wallet_file"]
        wallet_dirs = [r for r in scanner.results if r.reason == "wallet_dir"]
        content_matches = [r for r in scanner.results if r.reason == "content_match"]

        if wallet_files:
            lines.append("")
            lines.append(f"  [HIGH PRIORITY] Wallet Files Found: {len(wallet_files)}")
            lines.append("  " + "-" * 50)
            for r in wallet_files:
                lines.append(f"    File: {r.path}")
                lines.append(f"    Size: {r.size:,} bytes")
                lines.append(f"    Modified: {datetime.fromtimestamp(r.modified_time).strftime('%Y-%m-%d %H:%M')}")
                if r.matches:
                    lines.append(f"    Contains {len(r.matches)} crypto pattern(s)")
                if r.seed_phrases:
                    lines.append(f"    ⚠️  SEED PHRASE DETECTED ({len(r.seed_phrases[0])} words)")
                lines.append("")

        if wallet_dirs:
            lines.append("")
            lines.append(f"  [MEDIUM] Matches in Wallet Directories: {len(wallet_dirs)}")
            lines.append("  " + "-" * 50)
            for r in wallet_dirs[:20]:  # Limit display
                lines.append(f"    File: {r.path}")
                if r.matches:
                    kinds = set(m.kind for m in r.matches)
                    lines.append(f"    Types: {', '.join(kinds)}")
                lines.append("")

        if content_matches:
            lines.append("")
            lines.append(f"  [CONTENT] Files with BTC Patterns: {len(content_matches)}")
            lines.append("  " + "-" * 50)
            for r in content_matches[:50]:  # Limit display
                lines.append(f"    File: {r.path}")
                if r.matches:
                    for m in r.matches[:5]:
                        lines.append(f"      [{m.kind}] line {m.line_no}: {m.snippet}")
                if r.seed_phrases:
                    lines.append(f"      ⚠️  POSSIBLE SEED PHRASE ({len(r.seed_phrases[0])} words)")
                lines.append("")

    lines.append("-" * 70)
    lines.append("")
    lines.append("  NEXT STEPS:")
    lines.append("  1. Check HIGH PRIORITY files first — these are likely wallet files.")
    lines.append("  2. wallet.dat files can be opened with Bitcoin Core (may need passphrase).")
    lines.append("  3. Electrum wallets can be restored with Electrum software.")
    lines.append("  4. Seed phrases (12/24 words) can restore wallets in any compatible app.")
    lines.append("  5. WIF private keys can be imported directly into most wallets.")
    lines.append("  6. Full details (unredacted) are in the JSON report — KEEP IT SAFE.")
    lines.append("")
    lines.append("  ⚠️  SECURITY WARNING:")
    lines.append("  - NEVER share the JSON report with anyone.")
    lines.append("  - NEVER paste private keys or seed phrases into websites.")
    lines.append("  - Use OFFLINE wallets to import/verify keys.")
    lines.append("")
    lines.append("=" * 70)

    with open(text_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return {
        "text_report": text_path,
        "json_report": json_path,
    }


def print_summary(scanner: BTCRecoveryScanner):
    """Print a quick summary to stdout."""
    duration = scanner.stats.get("end_time", 0) - scanner.stats.get("start_time", 0)
    print(f"\n{'='*50}")
    print(f"  SCAN COMPLETE")
    print(f"  Duration: {duration:.1f}s")
    print(f"  Files scanned: {scanner.stats.get('files_scanned', 0):,}")
    print(f"  Findings: {len(scanner.results)}")
    print(f"{'='*50}\n")

    if scanner.results:
        # Quick categorization
        wallet_files = [r for r in scanner.results if r.reason == "wallet_file"]
        seed_files = [r for r in scanner.results if r.seed_phrases]
        key_files = [r for r in scanner.results if any(m.kind in ("wif", "xkey", "hex_privkey") for m in r.matches)]

        if wallet_files:
            print(f"  🔑 Wallet files found: {len(wallet_files)}")
            for r in wallet_files[:5]:
                print(f"     → {r.path}")

        if seed_files:
            print(f"  🌱 Files with possible seed phrases: {len(seed_files)}")
            for r in seed_files[:5]:
                print(f"     → {r.path}")

        if key_files:
            print(f"  🔐 Files with private keys: {len(key_files)}")
            for r in key_files[:5]:
                print(f"     → {r.path}")

        print(f"\n  See full report for details.")
    else:
        print("  No BTC wallet artifacts found on this scan.")
        print("  Try: external drives, cloud backups, or data recovery tools.")
