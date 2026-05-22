#!/usr/bin/env python3
"""BTC Wallet Recovery Scanner — CLI Entry Point.

Scans your local filesystem for remnants of Bitcoin wallets, private keys,
seed phrases, and addresses. ALL OPERATIONS ARE READ-ONLY.

Usage:
    python btc_recovery_scan.py                     # Scan default locations
    python btc_recovery_scan.py --roots C:\\ D:\\    # Scan specific drives
    python btc_recovery_scan.py --roots /home/user  # Scan specific directory
    python btc_recovery_scan.py --fast              # Quick scan (known paths only)
    python btc_recovery_scan.py --output ./results  # Custom output directory

Requirements:
    Python 3.8+ (no external dependencies needed)
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time

# Add parent directory to path so recovery package is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from recovery.scanner import BTCRecoveryScanner, ScanConfig, get_known_wallet_paths
from recovery.report import generate_report, print_summary


def setup_logging(verbose: bool = False):
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )


def progress_callback(files_scanned: int, matches_found: int, current_path: str):
    """Print scan progress."""
    # Truncate path for display
    display_path = current_path
    if len(display_path) > 60:
        display_path = "..." + display_path[-57:]
    print(f"\r  Scanning: {files_scanned:>8,} files | {matches_found:>4} findings | {display_path:<60}", end="", flush=True)


def main():
    parser = argparse.ArgumentParser(
        description="BTC Wallet Recovery Scanner - Find lost Bitcoin wallet files on your PC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          Scan default locations (home directory + drives)
  %(prog)s --roots /home/user       Scan specific directory
  %(prog)s --roots C:\\ D:\\ E:\\      Scan multiple drives (Windows)
  %(prog)s --fast                   Quick scan (only known wallet paths)
  %(prog)s --deep                   Deep scan (include hidden dirs, larger files)
  %(prog)s --output ./my_results    Save reports to custom directory
  %(prog)s --no-redact              Don't redact values in text report (CAREFUL!)

SECURITY NOTES:
  - This tool is READ-ONLY. It does not modify any files.
  - Reports contain sensitive data. Keep them secure!
  - Never share the JSON report with anyone.
  - Use offline/air-gapped systems when handling private keys.
        """,
    )

    parser.add_argument(
        "--roots",
        nargs="+",
        default=[],
        help="Root directories/drives to scan (default: auto-detect)",
    )
    parser.add_argument(
        "--output", "-o",
        default="./btc_recovery_reports",
        help="Output directory for reports (default: ./btc_recovery_reports)",
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Quick scan: only check known wallet paths (faster but may miss files)",
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        help="Deep scan: larger file size limits, include more extensions",
    )
    parser.add_argument(
        "--no-redact",
        action="store_true",
        help="Don't redact sensitive values in text report (use with caution!)",
    )
    parser.add_argument(
        "--max-size",
        type=int,
        default=None,
        help="Max file size to content-scan in MB (default: 10MB, deep: 50MB)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output (show debug messages)",
    )
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable progress indicator",
    )

    args = parser.parse_args()
    setup_logging(args.verbose)

    print()
    print("=" * 60)
    print("  BTC WALLET RECOVERY SCANNER v0.1.0")
    print("  Read-only filesystem scan for Bitcoin wallet artifacts")
    print("=" * 60)
    print()

    # Build config
    config = ScanConfig()

    if args.roots:
        config.roots = args.roots

    if args.fast:
        # Only scan known wallet paths
        config.roots = get_known_wallet_paths()
        config.skip_dirs = set()  # Don't skip anything in targeted paths
        print("  Mode: FAST (known wallet paths only)")
    elif args.deep:
        config.max_file_size = 100 * 1024 * 1024  # 100 MB
        config.max_text_size = 50 * 1024 * 1024    # 50 MB
        config.scan_hidden = True
        # Add more extensions for deep scan
        config.text_extensions.update({
            ".doc", ".docx", ".pdf", ".odt", ".xls", ".xlsx",
            ".ppt", ".pptx", ".zip", ".7z", ".tar", ".gz",
        })
        print("  Mode: DEEP (extended file types, larger size limits)")
    else:
        print("  Mode: STANDARD")

    if args.max_size:
        config.max_text_size = args.max_size * 1024 * 1024

    if args.no_redact:
        config.redact_snippets = False
        print("  ⚠️  Redaction DISABLED — report will contain full keys/addresses!")

    if not args.no_progress:
        config.progress_callback = progress_callback

    # Show scan targets
    targets = config.roots or ["(auto-detect based on OS)"]
    print(f"  Scan targets: {', '.join(targets)}")
    print()

    # Confirm
    try:
        input("  Press ENTER to start scanning (Ctrl+C to abort)... ")
    except KeyboardInterrupt:
        print("\n\n  Scan cancelled.")
        sys.exit(0)

    print()
    print("  Scanning... (this may take several minutes)")
    print()

    # Run scanner
    scanner = BTCRecoveryScanner(config)

    try:
        results = scanner.scan()
    except KeyboardInterrupt:
        print("\n\n  Scan interrupted by user.")
        print(f"  Partial results: {len(scanner.results)} findings in {scanner.stats.get('files_scanned', 0):,} files")
        # Still generate report with partial results
        results = scanner.results

    # Clear progress line
    if not args.no_progress:
        print("\r" + " " * 120 + "\r", end="")

    # Print summary
    print_summary(scanner)

    # Generate reports
    if scanner.results:
        report_paths = generate_report(scanner, output_dir=args.output)
        print(f"  📄 Text report (redacted):  {report_paths['text_report']}")
        print(f"  📋 JSON report (FULL):      {report_paths['json_report']}")
        print()
        print("  ⚠️  The JSON report contains UNREDACTED private keys and seeds.")
        print("     Keep it SECURE. Do NOT share it. Do NOT upload it anywhere.")
    else:
        print("  No findings to report.")
        print()
        print("  💡 Tips to try:")
        print("     - Use --deep for a more thorough scan")
        print("     - Scan external drives: --roots /path/to/drive")
        print("     - Check cloud sync folders (Dropbox, Google Drive, OneDrive)")
        print("     - Try data recovery: PhotoRec (free) can find deleted files")
        print("     - Check old email attachments for wallet backups")

    print()


if __name__ == "__main__":
    main()
