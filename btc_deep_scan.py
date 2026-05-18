#!/usr/bin/env python3
"""BTC Deep Disk Scanner — Raw Sector Recovery Tool.

Reads raw disk sectors directly (bypassing filesystem) to find deleted
Bitcoin wallet files, private keys, seed phrases, and addresses.

This tool can recover data that was "deleted" but not yet overwritten
on the disk — perfect for finding wallet.dat from a reinstalled OS.

REQUIRES: Run as Administrator (Windows) or root (Linux).

Usage:
    python btc_deep_scan.py                             # Interactive drive selection
    python btc_deep_scan.py --drive D                   # Scan drive D:
    python btc_deep_scan.py --drive D --target 1B8hg... # Search for specific address
    python btc_deep_scan.py --drive D --extract         # Auto-extract found wallet.dat
    python btc_deep_scan.py --physical 1                # Scan PhysicalDrive1

Requirements:
    Python 3.8+ (no external dependencies)
    Administrator/root privileges (required for raw disk access)

WARNING:
    This tool is READ-ONLY. It does NOT modify your disk.
    But the output may contain sensitive private keys — keep reports secure!
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import sys
import time
from datetime import datetime
from typing import List, Optional

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from recovery.raw_disk import (
    RawDiskReader,
    DiskInfo,
    is_admin,
    list_available_drives,
    DEFAULT_CHUNK_SIZE,
    FAST_CHUNK_SIZE,
)
from recovery.carver import (
    DiskCarver,
    CarveResult,
    extract_wallet_region,
)


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )


def format_size(size_bytes: int) -> str:
    """Format bytes to human-readable string."""
    if size_bytes >= 1024**4:
        return f"{size_bytes / (1024**4):.1f} TB"
    elif size_bytes >= 1024**3:
        return f"{size_bytes / (1024**3):.1f} GB"
    elif size_bytes >= 1024**2:
        return f"{size_bytes / (1024**2):.1f} MB"
    elif size_bytes >= 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes} bytes"


def format_time(seconds: float) -> str:
    """Format seconds to human-readable time."""
    if seconds >= 3600:
        h = int(seconds // 3600)
        m = int((seconds % 3600) // 60)
        return f"{h}h {m}m"
    elif seconds >= 60:
        m = int(seconds // 60)
        s = int(seconds % 60)
        return f"{m}m {s}s"
    return f"{seconds:.1f}s"


def print_banner():
    print()
    print("=" * 65)
    print("  BTC DEEP DISK SCANNER v0.1.0")
    print("  Raw sector recovery — finds DELETED wallet data")
    print("  READ-ONLY: Your disk will NOT be modified")
    print("=" * 65)
    print()


def print_drives(drives: List[DiskInfo]):
    """Display available drives."""
    print("  Available drives:")
    print("  " + "-" * 55)
    print(f"  {'#':<4} {'Type':<10} {'Label':<20} {'Size':<12}")
    print("  " + "-" * 55)
    for i, d in enumerate(drives):
        print(f"  {i:<4} {d.disk_type:<10} {d.label:<20} {format_size(d.size_bytes):<12}")
    print("  " + "-" * 55)
    print()


def progress_callback(bytes_read: int, total_bytes: int):
    """Print scan progress."""
    if total_bytes > 0:
        pct = (bytes_read / total_bytes) * 100
        speed = bytes_read / (1024 * 1024)  # Just show MB scanned
        print(
            f"\r  Progress: {format_size(bytes_read)} / {format_size(total_bytes)} "
            f"({pct:.1f}%) ",
            end="", flush=True,
        )
    else:
        print(f"\r  Scanned: {format_size(bytes_read)} ", end="", flush=True)


def generate_deep_report(
    carver: DiskCarver,
    disk_info: DiskInfo,
    output_dir: str,
    target_address: Optional[str] = None,
) -> dict:
    """Generate reports from deep scan results."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # --- JSON report (full detail) ---
    json_path = os.path.join(output_dir, f"deep_scan_{timestamp}.json")
    json_data = {
        "generated_at": datetime.now().isoformat(),
        "tool": "btc_deep_scan v0.1.0",
        "disk": {
            "path": disk_info.path,
            "label": disk_info.label,
            "size": disk_info.size_bytes,
            "type": disk_info.disk_type,
        },
        "target_address": target_address,
        "stats": {
            "bytes_scanned": carver.stats.bytes_scanned,
            "chunks_processed": carver.stats.chunks_processed,
            "duration_seconds": carver.stats.duration,
            "speed_mbps": carver.stats.speed_mbps,
            "wallet_dat_found": carver.stats.wallet_dat_found,
            "addresses_found": carver.stats.addresses_found,
            "wif_keys_found": carver.stats.wif_keys_found,
            "xkeys_found": carver.stats.xkeys_found,
            "seed_phrases_found": carver.stats.seed_phrases_found,
        },
        "results": [r.to_dict() for r in carver.results],
    }

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=2, default=str)

    # --- Text report (summary) ---
    txt_path = os.path.join(output_dir, f"deep_scan_{timestamp}.txt")
    lines = []
    lines.append("=" * 65)
    lines.append("  BTC DEEP DISK SCAN REPORT")
    lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  Disk: {disk_info.label} ({format_size(disk_info.size_bytes)})")
    if target_address:
        lines.append(f"  Target: {target_address}")
    lines.append("=" * 65)
    lines.append("")
    lines.append(f"  Scan Duration:     {format_time(carver.stats.duration)}")
    lines.append(f"  Data Scanned:      {format_size(carver.stats.bytes_scanned)}")
    lines.append(f"  Speed:             {carver.stats.speed_mbps:.1f} MB/s")
    lines.append(f"  Total Findings:    {len(carver.results)}")
    lines.append("")
    lines.append("-" * 65)

    if not carver.results:
        lines.append("")
        lines.append("  No Bitcoin wallet artifacts found in raw disk data.")
        lines.append("")
        lines.append("  This could mean:")
        lines.append("  - The data has been overwritten by new files")
        lines.append("  - The wallet was on a different partition/drive")
        lines.append("  - The wallet used a format not detected by this tool")
        lines.append("")
    else:
        # Group by kind
        by_kind: dict = {}
        for r in carver.results:
            by_kind.setdefault(r.kind, []).append(r)

        # Target address hits
        if "target_address" in by_kind:
            lines.append("")
            lines.append(f"  🎯 TARGET ADDRESS FOUND: {len(by_kind['target_address'])} location(s)")
            lines.append("  " + "-" * 50)
            for r in by_kind["target_address"]:
                lines.append(f"    Disk offset: {r.disk_offset:,} bytes ({r.disk_offset/(1024*1024):.1f} MB)")
                lines.append(f"    Confidence: {r.confidence}")
                lines.append(f"    Details: {r.details}")
                lines.append("")

        # wallet.dat
        if "wallet_dat" in by_kind:
            lines.append("")
            lines.append(f"  🔑 WALLET.DAT FILES: {len(by_kind['wallet_dat'])} found")
            lines.append("  " + "-" * 50)
            for r in by_kind["wallet_dat"]:
                lines.append(f"    Offset: {r.disk_offset:,} bytes ({r.disk_offset/(1024*1024):.1f} MB)")
                lines.append(f"    Confidence: {r.confidence}")
                lines.append(f"    {r.details}")
                lines.append("")

        # WIF keys
        if "wif" in by_kind:
            lines.append("")
            lines.append(f"  🔐 WIF PRIVATE KEYS: {len(by_kind['wif'])} found")
            lines.append("  " + "-" * 50)
            for r in by_kind["wif"]:
                # Redact middle of key
                redacted = r.value[:6] + "..." + r.value[-4:]
                lines.append(f"    Key: {redacted}")
                lines.append(f"    Offset: {r.disk_offset:,} bytes")
                lines.append("")

        # Extended keys
        if "xkey" in by_kind:
            lines.append("")
            lines.append(f"  🗝️  EXTENDED KEYS (xprv/xpub): {len(by_kind['xkey'])} found")
            lines.append("  " + "-" * 50)
            for r in by_kind["xkey"]:
                redacted = r.value[:8] + "..." + r.value[-4:]
                lines.append(f"    Key: {redacted}")
                lines.append(f"    Offset: {r.disk_offset:,} bytes")
                lines.append("")

        # Seed phrases
        if "seed_phrase" in by_kind:
            lines.append("")
            lines.append(f"  🌱 SEED PHRASES: {len(by_kind['seed_phrase'])} found")
            lines.append("  " + "-" * 50)
            for r in by_kind["seed_phrase"]:
                word_count = len(r.value.split())
                # Redact: show first 2 words and last word only
                words = r.value.split()
                redacted = f"{words[0]} {words[1]} ... {words[-1]} ({word_count} words)"
                lines.append(f"    Phrase: {redacted}")
                lines.append(f"    Offset: {r.disk_offset:,} bytes")
                lines.append(f"    Confidence: {r.confidence}")
                lines.append("")

        # Electrum
        if "electrum_wallet" in by_kind:
            lines.append("")
            lines.append(f"  ⚡ ELECTRUM WALLET DATA: {len(by_kind['electrum_wallet'])} found")
            lines.append("  " + "-" * 50)
            for r in by_kind["electrum_wallet"]:
                lines.append(f"    Offset: {r.disk_offset:,} bytes")
                lines.append(f"    {r.details}")
                lines.append("")

        # Other addresses
        if "btc_address" in by_kind:
            lines.append("")
            lines.append(f"  📍 BTC ADDRESSES (near wallet data): {len(by_kind['btc_address'])} found")
            lines.append("  " + "-" * 50)
            for r in by_kind["btc_address"][:20]:  # Limit display
                lines.append(f"    {r.value}  (offset: {r.disk_offset:,})")
            if len(by_kind["btc_address"]) > 20:
                lines.append(f"    ... and {len(by_kind['btc_address'])-20} more (see JSON report)")
            lines.append("")

    lines.append("-" * 65)
    lines.append("")
    lines.append("  NEXT STEPS:")
    lines.append("  1. If wallet.dat found → use --extract to recover the file")
    lines.append("  2. If WIF key found → import into Electrum (offline!)")
    lines.append("  3. If seed phrase found → restore in any BIP39 wallet (offline!)")
    lines.append("  4. If target address found → wallet.dat is likely nearby on disk")
    lines.append("")
    lines.append("  ⚠️  SECURITY:")
    lines.append("  - JSON report has FULL unredacted keys — KEEP IT SAFE")
    lines.append("  - Do all key imports on an OFFLINE machine")
    lines.append("  - NEVER share these reports with anyone")
    lines.append("")
    lines.append("=" * 65)

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return {"text_report": txt_path, "json_report": json_path}


def main():
    parser = argparse.ArgumentParser(
        description="BTC Deep Disk Scanner — Raw sector recovery for deleted wallet data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                  Interactive mode (list drives, choose)
  %(prog)s --drive D                        Scan drive D: raw sectors
  %(prog)s --drive D E F                    Scan multiple drives
  %(prog)s --drive D --target 1B8hg...      Search for specific BTC address
  %(prog)s --physical 1                     Scan PhysicalDrive1 (entire disk)
  %(prog)s --drive D --extract              Auto-extract found wallet.dat files
  %(prog)s --drive D --fast                 Faster scan (larger chunks, less thorough)
  %(prog)s --drive D --offset 0 --length 10G  Scan first 10GB only

IMPORTANT:
  - Must run as Administrator (right-click PowerShell → Run as Administrator)
  - This is READ-ONLY — your disk is never modified
  - Scan speed: ~50-150 MB/s depending on HDD speed
  - A 500GB HDD takes approximately 1-3 hours
        """,
    )

    parser.add_argument(
        "--drive", "-d",
        nargs="+",
        default=[],
        help="Drive letter(s) to scan (e.g., D E F)",
    )
    parser.add_argument(
        "--physical", "-p",
        type=int,
        default=None,
        help="Physical drive number (e.g., 1 for PhysicalDrive1)",
    )
    parser.add_argument(
        "--target", "-t",
        default=None,
        help="Target BTC address to specifically search for",
    )
    parser.add_argument(
        "--output", "-o",
        default="./btc_deep_scan_reports",
        help="Output directory for reports (default: ./btc_deep_scan_reports)",
    )
    parser.add_argument(
        "--extract",
        action="store_true",
        help="Auto-extract found wallet.dat files to output directory",
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Faster scanning (4MB chunks, may miss some fragmented data)",
    )
    parser.add_argument(
        "--offset",
        type=str,
        default="0",
        help="Start offset (supports K, M, G suffixes, e.g., '100G')",
    )
    parser.add_argument(
        "--length",
        type=str,
        default=None,
        help="Length to scan (supports K, M, G suffixes, e.g., '50G')",
    )
    parser.add_argument(
        "--no-seeds",
        action="store_true",
        help="Skip seed phrase scanning (faster but may miss recovery phrases)",
    )
    parser.add_argument(
        "--no-addresses",
        action="store_true",
        help="Skip address scanning (faster, only look for keys and wallet files)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose logging",
    )

    args = parser.parse_args()
    setup_logging(args.verbose)

    print_banner()

    # --- Check admin ---
    if not is_admin():
        print("  ❌ ERROR: This tool requires Administrator privileges!")
        print()
        if platform.system() == "Windows":
            print("  How to fix:")
            print("  1. Close this window")
            print("  2. Right-click PowerShell → 'Run as Administrator'")
            print("  3. Navigate to this folder and run the script again")
            print()
            print("  Or from current PowerShell:")
            print("    Start-Process python -ArgumentList 'btc_deep_scan.py','--drive','D' -Verb RunAs")
        else:
            print("  Run with: sudo python3 btc_deep_scan.py")
        print()
        sys.exit(1)

    print("  ✅ Running with Administrator privileges")
    print()

    # --- Parse size arguments ---
    def parse_size(s: str) -> int:
        """Parse size string like '100G', '500M', '1T'."""
        s = s.strip().upper()
        multipliers = {"K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
        for suffix, mult in multipliers.items():
            if s.endswith(suffix):
                return int(float(s[:-1]) * mult)
        return int(s)

    start_offset = parse_size(args.offset)
    end_offset = None
    if args.length:
        end_offset = start_offset + parse_size(args.length)

    # --- Determine disk(s) to scan ---
    disk_targets: List[DiskInfo] = []

    if args.physical is not None:
        path = f"\\\\.\\PhysicalDrive{args.physical}"
        disk_targets.append(DiskInfo(
            path=path,
            size_bytes=0,  # Will be determined on open
            size_gb=0,
            label=f"PhysicalDrive{args.physical}",
            disk_type="physical",
        ))
    elif args.drive:
        for letter in args.drive:
            letter = letter.strip().upper().rstrip(":\\")
            if len(letter) == 1 and letter.isalpha():
                path = f"\\\\.\\{letter}:"
                # Try to get size
                from recovery.raw_disk import _get_drive_size_windows
                size = 0
                if platform.system() == "Windows":
                    size = _get_drive_size_windows(path) or 0
                disk_targets.append(DiskInfo(
                    path=path,
                    size_bytes=size,
                    size_gb=size / (1024**3) if size else 0,
                    label=f"{letter}:\\",
                    disk_type="logical",
                ))
            else:
                print(f"  ⚠️  Invalid drive letter: {letter}")
    else:
        # Interactive mode: list drives and let user choose
        print("  No drive specified. Listing available drives...")
        print()
        drives = list_available_drives()
        if not drives:
            print("  ❌ No accessible drives found!")
            print("  Make sure the HDD is connected and recognized by Windows.")
            sys.exit(1)

        print_drives(drives)

        try:
            choice = input("  Enter drive number(s) to scan (comma-separated, e.g., '0,1,2'): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n  Cancelled.")
            sys.exit(0)

        for idx_str in choice.split(","):
            try:
                idx = int(idx_str.strip())
                if 0 <= idx < len(drives):
                    disk_targets.append(drives[idx])
                else:
                    print(f"  ⚠️  Invalid index: {idx}")
            except ValueError:
                # Maybe it's a drive letter
                letter = idx_str.strip().upper()
                if len(letter) == 1 and letter.isalpha():
                    for d in drives:
                        if d.label.startswith(letter):
                            disk_targets.append(d)
                            break

    if not disk_targets:
        print("  ❌ No valid drives selected!")
        sys.exit(1)

    # --- Display scan plan ---
    print()
    print("  SCAN PLAN:")
    print("  " + "-" * 50)
    for d in disk_targets:
        size_str = format_size(d.size_bytes) if d.size_bytes else "unknown size"
        print(f"    {d.label} ({d.disk_type}) — {size_str}")
    if args.target:
        print(f"    Target address: {args.target}")
    if start_offset > 0:
        print(f"    Start offset: {format_size(start_offset)}")
    if end_offset:
        print(f"    Scan length: {format_size(end_offset - start_offset)}")
    chunk_size = FAST_CHUNK_SIZE if args.fast else DEFAULT_CHUNK_SIZE
    print(f"    Chunk size: {format_size(chunk_size)}")
    print(f"    Mode: {'FAST' if args.fast else 'THOROUGH'}")
    print()

    # Estimate time
    total_size = sum(d.size_bytes for d in disk_targets if d.size_bytes)
    if end_offset:
        total_size = min(total_size, end_offset - start_offset) if total_size else end_offset - start_offset
    if total_size > 0:
        est_time_slow = total_size / (50 * 1024 * 1024)   # 50 MB/s (slow HDD)
        est_time_fast = total_size / (150 * 1024 * 1024)  # 150 MB/s (fast)
        print(f"  Estimated time: {format_time(est_time_fast)} — {format_time(est_time_slow)}")
        print()

    # Confirm
    try:
        input("  Press ENTER to start deep scan (Ctrl+C to abort)... ")
    except (KeyboardInterrupt, EOFError):
        print("\n  Cancelled.")
        sys.exit(0)

    print()

    # --- Run scan ---
    all_results: List[CarveResult] = []

    for disk_info in disk_targets:
        print(f"  Scanning: {disk_info.label} ...")
        print()

        # Create carver
        carver = DiskCarver(
            target_address=args.target,
            scan_wallet_dat=True,
            scan_addresses=not args.no_addresses,
            scan_keys=True,
            scan_seeds=not args.no_seeds,
        )
        carver.stats.start_time = time.time()

        # Create reader
        reader = RawDiskReader(
            disk_path=disk_info.path,
            chunk_size=chunk_size,
            start_offset=start_offset,
            end_offset=end_offset or disk_info.size_bytes or None,
        )

        if not reader.open():
            print(f"  ❌ Failed to open {disk_info.label}!")
            print(f"     Make sure you're running as Administrator.")
            continue

        try:
            for offset, chunk in reader.read_chunks(progress_callback=progress_callback):
                carver.process_chunk(offset, chunk)

                # Also check for Electrum wallets
                carver.find_electrum_wallets(offset, chunk)

                # Real-time notification of high-priority findings
                if carver.results and carver.results[-1] not in all_results:
                    last = carver.results[-1]
                    if last.confidence == "high":
                        print(f"\n  🚨 FOUND: [{last.kind}] at offset {last.disk_offset:,} — {last.details[:60]}")

                if carver.is_full:
                    print(f"\n  ⚠️  Max results reached ({carver.max_results}). Stopping.")
                    break

        except KeyboardInterrupt:
            print(f"\n\n  Scan interrupted. Processing partial results...")
        finally:
            reader.close()

        carver.stats.end_time = time.time()

        # Clear progress line
        print("\r" + " " * 100 + "\r", end="")

        # Print quick stats for this drive
        print(f"  {disk_info.label} done:")
        print(f"    Scanned: {format_size(carver.stats.bytes_scanned)}")
        print(f"    Duration: {format_time(carver.stats.duration)}")
        print(f"    Speed: {carver.stats.speed_mbps:.1f} MB/s")
        print(f"    Findings: {len(carver.results)}")
        print()

        all_results.extend(carver.results)

        # Generate report per drive
        report_paths = generate_deep_report(
            carver, disk_info, args.output, args.target
        )
        print(f"    📄 Text: {report_paths['text_report']}")
        print(f"    📋 JSON: {report_paths['json_report']}")
        print()

        # --- Extract wallet.dat if requested ---
        if args.extract and carver.stats.wallet_dat_found > 0:
            print("  Extracting found wallet.dat files...")
            extract_dir = os.path.join(args.output, "extracted_wallets")
            os.makedirs(extract_dir, exist_ok=True)

            for i, r in enumerate(carver.results):
                if r.kind == "wallet_dat" and r.confidence == "high":
                    out_file = os.path.join(extract_dir, f"wallet_recovered_{i}.dat")
                    success = extract_wallet_region(
                        disk_info.path,
                        r.disk_offset,
                        out_file,
                        size=2 * 1024 * 1024,  # 2 MB
                    )
                    if success:
                        print(f"    ✅ Extracted: {out_file}")
                    else:
                        print(f"    ❌ Failed to extract at offset {r.disk_offset}")
            print()

    # --- Final summary ---
    print()
    print("=" * 65)
    print("  SCAN COMPLETE — SUMMARY")
    print("=" * 65)
    print()
    print(f"  Total findings across all drives: {len(all_results)}")
    print()

    if all_results:
        # Categorize
        kinds = {}
        for r in all_results:
            kinds[r.kind] = kinds.get(r.kind, 0) + 1

        for kind, count in sorted(kinds.items(), key=lambda x: -x[1]):
            emoji = {
                "target_address": "🎯",
                "wallet_dat": "🔑",
                "wif": "🔐",
                "xkey": "🗝️",
                "seed_phrase": "🌱",
                "electrum_wallet": "⚡",
                "btc_address": "📍",
                "hex_privkey": "🔢",
                "privkey_region": "🔢",
            }.get(kind, "•")
            print(f"    {emoji}  {kind}: {count}")

        print()
        print(f"  Reports saved to: {os.path.abspath(args.output)}")
        print()
        print("  ⚠️  IMPORTANT:")
        print("  - JSON reports contain FULL private keys — KEEP THEM SAFE!")
        print("  - Use an OFFLINE computer to import any recovered keys")
        print("  - If wallet.dat was found, try opening with Bitcoin Core")
    else:
        print("  No findings. The deleted data may have been overwritten.")
        print()
        print("  Suggestions:")
        print("  - Try scanning the physical drive instead of logical partition")
        print("  - Try scanning without --offset to cover the whole disk")
        print("  - The wallet data may be on a different drive")
        print("  - If disk was heavily used after deletion, data may be unrecoverable")

    print()
    print("=" * 65)


if __name__ == "__main__":
    main()
