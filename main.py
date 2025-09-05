#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PacketWhiz — Network Forensics & Analysis (NFA) Tool
CLI entrypoint (authors: Omar Tamer & Farida Ismail)

"""

from __future__ import annotations
import sys
import os
import json
import argparse
from typing import Any, Dict

# -------------------------
# Banner (always shown)
# -------------------------
VERSION = "0.1"

def banner() -> None:
    art = r"""
   ____            _        _   _       _     
  |  _ \ __ _  ___| | _____| |_| |_ ___| |__  
  | |_) / _` |/ __| |/ / _ \ __| __/ __| '_ \ 
  |  __/ (_| | (__|   <  __/ |_| || (__| | | |
  |_|   \__,_|\___|_|\_\___|\__|\__\___|_| |_|
                 PacketWhiz  (NFA)
    """
    print(art)
    print(f" Version: {VERSION}")
    print(" Authors: Omar Tamer & Farida Ismail  |  Mode: CLI\n")

# -------------------------
# EMPTY STUB FUNCTIONS
# -------------------------
# Parsers
def parse_pcap(file_path: str):
    """Parse PCAP/PCAPNG file → return packet data"""
    return {"packets": []}

def parse_logs(file_path: str):
    """Parse raw log file → return log lines"""
    return {"lines": []}

# Analyzers
def detect_and_group(data: Dict[str, Any]):
    """Detect protocols in data"""
    return {"counts": {}, "by_proto": {}}

def reconstruct_sessions(data: Dict[str, Any]):
    """Rebuild network sessions"""
    return []

def extract_credentials(data: Dict[str, Any]):
    """Extract usernames/passwords"""
    return []

def extract_files(data: Dict[str, Any], outdir: str = "pwz_output"):
    """Extract files/attachments"""
    return []

def detect_indicators(data: Dict[str, Any]):
    """Detect suspicious indicators"""
    return {
        "cleartext_creds": [],
        "failed_logins": [],
        "beaconing": [],
        "dns_tunneling": [],
    }

# Utils
def find_flags(data: Dict[str, Any]):
    """CTF mode → find FLAG{} patterns and decode"""
    return {"flags": [], "evidence": []}

def visualize(results: Dict[str, Any], outdir: str = "pwz_output", enable_geoip: bool = False):
    """Create charts/graphs"""
    return {}

def export_report(results: Dict[str, Any], outdir: str = "pwz_output", format: str = "html"):
    """Export HTML/PDF report"""
    return {}

# -------------------------
# CLI
# -------------------------
def build_argparser() -> argparse.ArgumentParser:
    # Disable default help so we can always show the banner first
    p = argparse.ArgumentParser(
        prog="packetwhiz",
        description="PacketWhiz — Lightweight, beginner-friendly, but powerful network forensics toolkit.",
        add_help=False,
    )

    # Our own help/version flags (so banner always shows)
    p.add_argument("-h", "--help", action="store_true", help="Show this help message and exit")
    p.add_argument("-v", "--version", action="store_true", help="Show version and exit")

    # Input
    src = p.add_argument_group("Input")
    src.add_argument("--pcap", help="Input .pcap / .pcapng file")
    src.add_argument("--log", help="Input raw .txt log file")

    # Features
    feat = p.add_argument_group("Features")
    feat.add_argument("--protocols", action="store_true", help="Detect protocols (HTTP, DNS, FTP, SMB, etc.)")
    feat.add_argument("--sessions", action="store_true", help="Reconstruct sessions / conversations")
    feat.add_argument("--extract-creds", action="store_true", help="Extract credentials")
    feat.add_argument("--extract-files", action="store_true", help="Extract files/attachments")
    feat.add_argument("--indicators", action="store_true", help="Detect suspicious indicators")
    feat.add_argument("--viz", action="store_true", help="Generate visualizations (charts/graphs)")
    feat.add_argument("--geoip", action="store_true", help="Enable GeoIP lookups in visualizations")
    feat.add_argument("--report", choices=["html", "pdf", "both"], help="Export report (HTML/PDF)")
    feat.add_argument("--ctf", action="store_true", help="CTF mode: regex + decoders for flags")

    # Output
    out = p.add_argument_group("Output")
    out.add_argument("-o", "--outdir", default="pwz_output", help="Output directory")
    out.add_argument("--json", action="store_true", help="Also save raw JSON results")
    out.add_argument("-q", "--quiet", action="store_true", help="Less console output")

    return p

# -------------------------
# Helpers
# -------------------------
def _log(msg: str, quiet: bool = False):
    if not quiet:
        print(msg)

def _ensure_outdir(path: str):
    os.makedirs(path, exist_ok=True)

def _load_input(args) -> Dict[str, Any]:
    if args.pcap:
        return {"source_type": "pcap", "data": parse_pcap(args.pcap)}
    if args.log:
        return {"source_type": "log", "data": parse_logs(args.log)}
    raise ValueError("Please provide --pcap or --log input.")

# -------------------------
# Run (workflow)
# -------------------------
def run(args) -> int:
    _ensure_outdir(args.outdir)

    try:
        loaded = _load_input(args)
    except Exception as e:
        print(f"[!] Input error: {e}")
        return 2

    src_type = loaded["source_type"]
    data = loaded["data"]
    results: Dict[str, Any] = {"source_type": src_type}

    if args.protocols:
        _log("[*] Detecting protocols...", args.quiet)
        results["protocols"] = detect_and_group(data)

    if args.sessions:
        _log("[*] Reconstructing sessions...", args.quiet)
        results["sessions"] = reconstruct_sessions(data)

    if args.extract_creds:
        _log("[*] Extracting credentials...", args.quiet)
        results["credentials"] = extract_credentials(data)

    if args.extract_files:
        _log("[*] Extracting files & attachments...", args.quiet)
        results["files"] = extract_files(data, outdir=args.outdir)

    if args.indicators:
        _log("[*] Detecting suspicious indicators...", args.quiet)
        results["indicators"] = detect_indicators(data)

    if args.ctf:
        _log("[*] Running CTF helpers...", args.quiet)
        results["ctf"] = find_flags(data)

    if args.viz:
        _log("[*] Building visualizations...", args.quiet)
        visualize(results, outdir=args.outdir, enable_geoip=args.geoip)

    if args.report:
        _log(f"[*] Exporting report ({args.report})...", args.quiet)
        export_report(results, outdir=args.outdir, format=args.report)

    if args.json:
        with open(os.path.join(args.outdir, "results.json"), "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        _log(f"[*] Wrote JSON: {os.path.join(args.outdir, 'results.json')}", args.quiet)

    _log("\n✅ Done.", args.quiet)
    return 0

# -------------------------
# Main
# -------------------------
def main():
    # Always show banner first
    banner()

    parser = build_argparser()
    # Parse known so we can control help/version behavior without argparse exiting early
    args, unknown = parser.parse_known_args()

    # Handle --version
    if args.version:
        return 0

    # Handle --help (our own)
    if args.help:
        print(parser.format_help())
        return 0

    # Require input files
    if not (args.pcap or args.log):
        print(parser.format_help())
        print("\n[!] Please provide --pcap or --log.\n")
        return 1

    # Normalize names
    args.extract_creds = getattr(args, "extract_creds", False)
    args.extract_files = getattr(args, "extract_files", False)

    try:
        return run(args)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        return 130

if __name__ == "__main__":
    sys.exit(main())
