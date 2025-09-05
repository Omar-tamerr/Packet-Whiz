#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import time
import argparse
import tempfile
import contextlib
import subprocess
import gzip
import shutil
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Callable, Optional, Iterable, Tuple, List

# ---- readline for history & tab-completion ----
try:
    import readline  # type: ignore
    import rlcompleter  # type: ignore
except Exception:
    readline = None  # type: ignore

VERSION = "0.1"
EXIT_OK = 0
EXIT_USAGE = 1
EXIT_INPUT_ERR = 2
EXIT_INTERRUPT = 130
HIST_PATH = str(Path.home() / ".packetwhiz_history")

BANNER = r"""
     ██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗██╗    ██╗██╗  ██╗██╗███████╗
     ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝██║    ██║██║  ██║██║╚══███╔╝
     ██████╔╝███████║██║     █████╔╝ █████╗     ██║   ██║ █╗ ██║███████║██║  ███╔╝ 
     ██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║   ██║███╗██║██╔══██║██║ ███╔╝  
     ██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║   ╚███╔███╔╝██║  ██║██║███████╗
     ╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝╚══════╝

    01010000 01100001 01100011 01101011 01100101 01110100 01010111 01101000 01101001 01111010
"""

def banner() -> None:
    print(BANNER)
    print(" PacketWhiz — Network Forensics & Analysis (NFA)")
    print(f" Version: {VERSION}")
    print(" Authors: Omar Tamer & Farida Ismail  |  Mode: CLI\n")

# --- package qualifier helper (makes relative imports robust) ---
PKG = (__package__ or "packetwhiz").split(".")[0]
def _q(mod: str) -> str:
    return mod if mod.startswith(PKG + ".") else f"{PKG}.{mod}"

# -------------------------------
# Sandboxed CWD helpers (no unintended writes)
# -------------------------------
@contextlib.contextmanager
def _temp_cwd():
    old = os.getcwd()
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        try:
            yield Path(tmp)
        finally:
            os.chdir(old)

def _analysis_sandbox_if_no_writes(args):
    wants_output = bool(args.report)
    if getattr(args, "no_writes", False):
        return _temp_cwd()
    if args.no_prompt and not wants_output and not args.shell:
        return _temp_cwd()
    return contextlib.nullcontext()

# -------------------------------
# Dynamic import helpers
# -------------------------------
def _import_with_fallback(module: str, names: List[str]) -> Optional[Callable]:
    try:
        mod = __import__(module, fromlist=["*"])
    except Exception:
        return None
    for n in names:
        fn = getattr(mod, n, None)
        if callable(fn):
            return fn
    return None

def _safe_import_with_fallback(module: str, names: List[str]) -> Optional[Callable]:
    with _temp_cwd():
        return _import_with_fallback(module, names)

# -------------------------------
# CLI
# -------------------------------
EPILOG = """examples:
  packetwhiz --pcap sample.pcap --protocols
  packetwhiz --pcap sample.pcap --all --no-prompt
  packetwhiz --pcap sample.pcap --extract-files
  packetwhiz --pcap sample.pcap --pcap-stats
  packetwhiz --pcap sample.pcap --talkers
  packetwhiz --pcap sample.pcap --protocols --report html -o PacketWhiz_output
  packetwhiz --pcap sample.pcap --shell
"""

def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="packetwhiz",
        description="PacketWhiz — Lightweight, beginner-friendly, powerful network forensics toolkit.",
        add_help=False,
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=EPILOG,
    )
    # meta
    p.add_argument("-h", "--help", action="store_true", help="Show this help message and exit")
    p.add_argument("-v", "--version", action="store_true", help="Show version and exit")
    p.add_argument("-V", "--verbose", action="store_true", help="Verbose mode (print extra details)")

    # input
    src = p.add_argument_group("Input")
    src.add_argument("--pcap", help="Input .pcap/.pcapng (accepts .gz)")
    src.add_argument("--log", help="Input raw .txt/.log file")

    # features
    feat = p.add_argument_group("Features")
    feat.add_argument("--protocols", action="store_true", help="Detect protocol distribution")
    feat.add_argument("--sessions", action="store_true", help="Reconstruct sessions/conversations")
    feat.add_argument("--extract-creds", action="store_true", help="Extract credentials")
    feat.add_argument("--extract-files", action="store_true", help="Extract/carve files (preview; confirm to save)")
    feat.add_argument("--indicators", action="store_true", help="Detect suspicious indicators")
    feat.add_argument("--pcap-stats", action="store_true", help="Show capinfos & tshark protocol hierarchy (read-only)")
    feat.add_argument("--talkers", action="store_true", help="Show top talkers (src→dst:port) (read-only)")
    feat.add_argument("--report", choices=["html", "txt", "both"], help="Export report (writes to -o)")
    feat.add_argument("--ctf", action="store_true", help="CTF helper: find FLAG{} with common decoders")

    # output & UX
    out = p.add_argument_group("Output & UX")
    out.add_argument("-o", "--outdir", default="PacketWhiz_output",
                     help="Output directory (used only when writing)")
    out.add_argument("-q", "--quiet", action="store_true", help="Less console output")
    out.add_argument("--no-prompt", dest="no_prompt", action="store_true",
                     help="Non-interactive: never ask to save; skip writes unless --report is set")
    out.add_argument("--no-propmt", dest="no_prompt", action="store_true", help=argparse.SUPPRESS)  # typo alias
    out.add_argument("--no-writes", action="store_true",
                     help="Force zero disk writes (also via PWZ_NO_WRITES=1)")
    out.add_argument("--shell", action="store_true", help="Interactive guided shell for non-experts")

    # convenience
    p.add_argument("--all", action="store_true", help="Run analysis modules at once (no report implied)")
    return p

# -------------------------------
# Logging & small utils
# -------------------------------
def _log(msg: str, quiet: bool = False) -> None:
    if not quiet:
        print(msg)

def _vlog(msg: str, args) -> None:
    if getattr(args, "verbose", False) and not getattr(args, "quiet", False):
        print(f"[v] {msg}")

@contextlib.contextmanager
def _timed(label: str, args):
    t0 = time.time()
    yield
    t1 = time.time()
    _vlog(f"{label} took {t1 - t0:.3f}s", args)

def _resolve_parser():
    # prefer log_parser; fall back to historical log_parcer
    parse_pcap_fn = _import_with_fallback(_q("parser.pcap_parser"), ["load_pcap", "parse_pcap", "read_pcap"])
    parse_logs_fn = (
        _import_with_fallback(_q("parser.log_parser"), ["load_logs", "parse_logs", "read_logs"]) or
        _import_with_fallback(_q("parser.log_parcer"), ["load_logs", "parse_logs", "read_logs"])
    )
    return parse_pcap_fn, parse_logs_fn

def _get(proto_map: dict, *keys):
    for k in keys:
        for cand in (k, k.upper(), k.lower()):
            if cand in proto_map:
                return proto_map[cand]
    return 0

def _has_cmd(cmd: str) -> bool:
    from shutil import which
    return which(cmd) is not None

def _run_cmd(cmd: Iterable[str]) -> Tuple[int, str, str]:
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out, err = p.communicate()
        return p.returncode, out, err
    except Exception as e:
        return 1, "", str(e)

# -------------------------------
# Smarter path resolution (typos + .gz)
# -------------------------------
def _candidate_paths(name: str) -> List[Path]:
    p = Path(name)
    cands = [p]
    if not p.is_absolute():
        cands += [Path.cwd() / name, Path.cwd().parent / name]
    if "witp" in name:
        fixed = name.replace("witp", "with")
        cands += [Path(fixed), Path.cwd() / fixed, Path.cwd().parent / fixed]
    if not name.endswith(".gz"):
        cands += [Path(str(name) + ".gz")]
        if not p.is_absolute():
            cands += [Path.cwd() / (str(name) + ".gz"), Path.cwd().parent / (str(name) + ".gz")]
    else:
        cands += [Path(name[:-3])]
        if not p.is_absolute():
            cands += [Path.cwd() / name[:-3], Path.cwd().parent / name[:-3]]
    seen, uniq = set(), []
    for cp in cands:
        key = str(cp.resolve()) if cp.is_absolute() else str(cp)
        if key not in seen:
            uniq.append(cp); seen.add(key)
    return uniq

def _resolve_input_path_maybe_gz(name: str) -> Tuple[Optional[str], Optional[str]]:
    for cand in _candidate_paths(name):
        if cand.exists():
            return str(cand), None
    hint = f"File not found: {name}. Tried: " + ", ".join(str(c) for c in _candidate_paths(name)[:5]) + " ..."
    return None, hint

# -------------------------------
# Load input
# -------------------------------
def _load_input(args) -> Dict[str, Any]:
    parse_pcap_fn, parse_logs_fn = _resolve_parser()

    if args.pcap:
        orig, hint = _resolve_input_path_maybe_gz(args.pcap)
        if not orig:
            raise FileNotFoundError(hint)
        path = Path(orig)
        if str(path).endswith(".gz"):
            with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmpf:
                tmp_path = Path(tmpf.name)
            try:
                with gzip.open(path, "rb") as gz, open(tmp_path, "wb") as out:
                    shutil.copyfileobj(gz, out)
                if not parse_pcap_fn:
                    raise RuntimeError("parser.pcap_parser function not found.")
                with _timed("parse_pcap", args):
                    data = parse_pcap_fn(str(tmp_path))
                return {"source_type": "pcap", "data": data, "input_path": str(path)}
            finally:
                try: tmp_path.unlink(missing_ok=True)
                except Exception: pass

        if not parse_pcap_fn:
            raise RuntimeError("parser.pcap_parser function not found.")
        with _timed("parse_pcap", args):
            data = parse_pcap_fn(str(path))
        return {"source_type": "pcap", "data": data, "input_path": str(path)}

    if args.log:
        orig, hint = _resolve_input_path_maybe_gz(args.log)
        if not orig:
            raise FileNotFoundError(hint)
        path = Path(orig)
        if not parse_logs_fn:
            raise RuntimeError("parser.log_parcer function not found.")
        with _timed("parse_logs", args):
            data = parse_logs_fn(str(path))
        return {"source_type": "log", "data": data, "input_path": str(path)}

    raise ValueError("Please provide --pcap or --log input.")

# -------------------------------
# Pretty printers
# -------------------------------
def _print_protocol_summary(obj: Any, quiet: bool = False):
    if quiet: return
    protos = obj or {}
    counts = protos.get("counts") if isinstance(protos, dict) else None
    to_show = counts if isinstance(counts, dict) else (protos if isinstance(protos, dict) else {})
    if not to_show:
        print("[!] No protocol stats returned.\n"); return

    print("\n[ Protocol Summary ]")
    for k, v in to_show.items():
        print(f" - {str(k).upper()}: {v}")

    tcp = _get(to_show, "tcp"); udp = _get(to_show, "udp")
    http = _get(to_show, "http"); https = _get(to_show, "https", "tls", "ssl")
    dns = _get(to_show, "dns")
    jpegs = _get(to_show, "image-jfif", "image/jpeg", "jpeg", "jpg")
    media = _get(to_show, "media", "http-media", "http.file_data")

    notes: List[str] = []
    if http > 0:
        if https == 0:
            notes.append("Clear-text HTTP observed (no TLS) → content/credentials are readable on the wire.")
        else:
            notes.append("Mixed HTTP/HTTPS traffic → some content encrypted, some clear-text.")
        if jpegs or media:
            notes.append("HTTP includes media/images → files can likely be reassembled.")
        if dns > 0:
            notes.append("DNS + HTTP present → consistent with normal web browsing.")
    elif https > 0:
        notes.append("HTTPS present without HTTP → application payloads are encrypted.")
    else:
        if tcp > 0 and udp > 0:
            notes.append("Transport-layer traffic present; no obvious application layer identified.")
        elif tcp > 0:
            notes.append("TCP traffic present; consider enabling deeper analyzers.")
        elif udp > 0:
            notes.append("UDP traffic present; check for DNS/QUIC/other UDP protocols.")

    if notes:
        print("\n[ Assessment ]")
        for n in notes: print(f" • {n}")
        if http > 0 and https == 0:
            print(" • Tip: Use --extract-files / --extract-creds to recover artifacts from clear-text HTTP.")
    print()

def _print_credentials(creds: Any, quiet: bool = False):
    if quiet: return
    if not creds:
        print("[!] No credentials found.\n"); return
    print("\n[ Credentials Found ]")
    for c in creds:
        if isinstance(c, dict):
            user = c.get("username") or c.get("user") or ""
            pwd  = c.get("password") or c.get("pass") or ""
            src  = c.get("source") or c.get("proto") or ""
            extra = f" ({src})" if src else ""
            print(f" - {user}:{pwd}{extra}")
        else:
            print(f" - {c}")
    print()

def _print_files(files: Any, quiet: bool = False, max_show: int = 5):
    if quiet: return
    if not files:
        print("[!] No files extracted.\n"); return
    print("\n[ Extracted Files ]")
    shown = 0
    for f in files:
        if isinstance(f, dict):
            name = f.get("filename") or f.get("name") or ""
            path = f.get("path") or f.get("filepath") or ""
            mtype = f.get("mime") or f.get("type") or ""
            size  = f.get("size")
            size_txt = f" | {size} bytes" if isinstance(size, int) else ""
            mt_txt = f" | {mtype}" if mtype else ""
            print(f" - {name} -> {path}{mt_txt}{size_txt}")
        else:
            print(f" - {f}")
        shown += 1
        if shown >= max_show: break
    if isinstance(files, (list, tuple)) and len(files) > max_show:
        print(f" ... and {len(files) - max_show} more\n")
    else:
        print()

def _print_indicators(ind: Any, quiet: bool = False):
    if quiet: return
    if not ind or not isinstance(ind, dict):
        print("[!] No indicators found.\n"); return
    print("\n[ Indicators ]")
    for k, v in ind.items():
        if not v: continue
        print(f" - {k}:")
        if isinstance(v, (list, tuple)):
            for item in v[:10]: print(f"    • {item}")
            if len(v) > 10: print(f"    • ... ({len(v)-10} more)")
        else:
            print(f"    • {v}")
    print()

def _print_flags(flags: Any, quiet: bool = False):
    if quiet: return
    if not flags:
        print("[!] No flags found.\n"); return
    print("\n[ CTF Flags ]")
    if isinstance(flags, dict):
        arr = flags.get("flags") or flags.get("matches") or flags
        if isinstance(arr, list):
            for f in arr: print(f" - {f}")
        else:
            print(f" - {arr}")
    elif isinstance(flags, list):
        for f in flags: print(f" - {f}")
    else:
        print(f" - {flags}")
    print()

# -------------------------------
# Files: preview & save
# -------------------------------
def _isatty() -> bool:
    try: return sys.stdin.isatty()
    except Exception: return False

def _preview_extract_files(data, args):
    extractor = _safe_import_with_fallback(_q("analyzers.files"), ["extract_files", "carve_files", "recover_files"])
    if not extractor:
        return None
    try:
        with _timed("extract_files (preview)", args):
            return extractor(data)
    except TypeError:
        pass
    with _temp_cwd() as tmp:
        with _timed("extract_files (preview to temp)", args):
            try:
                return extractor(data, outdir=str(tmp))
            except TypeError:
                return extractor(args.pcap, outdir=str(tmp))

def _save_extract_files(data, args, dest: Path):
    extractor = _import_with_fallback(_q("analyzers.files"), ["extract_files", "carve_files", "recover_files"])
    if not extractor:
        return [], False
    dest.mkdir(parents=True, exist_ok=True)
    wrote_any = False
    old = os.getcwd()
    os.chdir(dest)
    try:
        with _timed("extract_files (save)", args):
            try:
                files = extractor(data, outdir=".")
            except TypeError:
                files = extractor(args.pcap, outdir=".")
        if files:
            wrote_any = True
        return files or [], wrote_any
    finally:
        os.chdir(old)

# -------------------------------
# PCAP stats & talkers
# -------------------------------
def _pcap_stats(input_path: str, args) -> None:
    if _has_cmd("capinfos"):
        _log("\n[ capinfos ]", args.quiet)
        rc, out, err = _run_cmd(["capinfos", input_path])
        print(out if out else err or "(no output)")
    else:
        print("\n[ capinfos ] not found on PATH")

    if _has_cmd("tshark"):
        _log("\n[ tshark protocol hierarchy ]", args.quiet)
        rc, out, err = _run_cmd(["tshark", "-r", input_path, "-q", "-z", "io,phs"])
        print(out if out else err or "(no output)")
    else:
        print("\n[ tshark ] not found on PATH")
    print()

def _talkers(input_path: str, args, top_n: int = 10) -> None:
    if not _has_cmd("tshark"):
        print("[!] tshark not found on PATH; cannot compute talkers.\n")
        return
    _log("[*] Computing top talkers (src→dst:port)...", args.quiet)
    fields = ["-T","fields","-e","ip.src","-e","ip.dst","-e","tcp.dstport","-e","udp.dstport"]
    rc, out, err = _run_cmd(["tshark", "-r", input_path] + fields)
    if rc != 0:
        print(err or "[!] tshark failed.\n"); return
    counts: Counter[str] = Counter()
    for line in out.splitlines():
        if not line.strip(): continue
        parts = line.split("\t")
        src = parts[0] if len(parts)>0 else ""
        dst = parts[1] if len(parts)>1 else ""
        tcp_port = parts[2] if len(parts)>2 else ""
        udp_port = parts[3] if len(parts)>3 else ""
        if not src or not dst: continue
        port = tcp_port or udp_port or ""
        key = f"{src} → {dst}" + (f":{port}" if port else "")
        counts[key] += 1
    if not counts:
        print("[!] No talkers detected (no IP data?)\n"); return
    print("\n[ Top Talkers ]")
    for i, (k, v) in enumerate(counts.most_common(top_n), 1):
        print(f" {i:>2}. {k}  ({v} pkts)")
    print()

# -------------------------------
# Built-in report writers (HTML/TXT)
# -------------------------------
def _builtin_report(results: Dict[str, Any], outdir: str, fmt: str) -> List[str]:
    Path(outdir).mkdir(parents=True, exist_ok=True)
    written: List[str] = []

    protos = results.get("protocols")
    creds  = results.get("credentials")
    files  = results.get("files")
    inds   = results.get("indicators")
    flags  = results.get("ctf")
    meta   = results.get("meta", {})

    if fmt in ("txt", "both"):
        txt_path = Path(outdir) / "report.txt"
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(f"PacketWhiz Report (v{VERSION})\n")
            f.write(f"Input: {meta.get('input','')}\n\n")
            if protos:
                f.write("[Protocol Summary]\n")
                summary = protos.get("counts", protos) if isinstance(protos, dict) else protos
                if isinstance(summary, dict):
                    for k, v in summary.items():
                        f.write(f" - {str(k).upper()}: {v}\n")
                f.write("\n")
            if creds:
                f.write("[Credentials]\n")
                for c in creds:
                    if isinstance(c, dict):
                        u=c.get("username") or c.get("user",""); p=c.get("password") or c.get("pass","")
                        s=c.get("source") or c.get("proto","")
                        f.write(f" - {u}:{p} ({s})\n")
                    else:
                        f.write(f" - {c}\n")
                f.write("\n")
            if files:
                f.write("[Files]\n")
                for it in files:
                    if isinstance(it, dict):
                        nm=it.get("filename") or it.get("name",""); pt=it.get("path","")
                        mt=it.get("mime") or it.get("type",""); sz=it.get("size")
                        suffix = f" ({mt}, {sz} bytes)" if mt or sz else ""
                        f.write(f" - {nm} -> {pt}{suffix}\n")
                    else:
                        f.write(f" - {it}\n")
                f.write("\n")
            if inds:
                f.write("[Indicators]\n")
                for k,v in inds.items():
                    f.write(f" - {k}:\n")
                    if isinstance(v,(list,tuple)):
                        for item in v[:50]:
                            f.write(f"    • {item}\n")
                    else:
                        f.write(f"    • {v}\n")
                f.write("\n")
            if flags:
                f.write("[CTF Flags]\n")
                arr = flags.get("flags", flags) if isinstance(flags, dict) else flags
                if isinstance(arr, list):
                    for fl in arr:
                        f.write(f" - {fl}\n")
                else:
                    f.write(f" - {arr}\n")
                f.write("\n")
        written.append(str(txt_path))

    if fmt in ("html", "both"):
        html_path = Path(outdir) / "report.html"
        def esc(s:str)->str:
            return (s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;") if isinstance(s,str) else str(s))
        with open(html_path, "w", encoding="utf-8") as f:
            f.write("<!doctype html><meta charset='utf-8'>")
            f.write("<title>PacketWhiz Report</title>")
            f.write("<style>body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:24px}"
                    "h1{margin-top:0} h2{margin-top:28px} code,pre{background:#f6f6f6;padding:8px;border-radius:6px}"
                    "table{border-collapse:collapse} td,th{border:1px solid #ddd;padding:6px 10px}</style>")
            f.write(f"<h1>PacketWhiz Report <small style='font-size:60%;color:#666'>(v{VERSION})</small></h1>")
            f.write(f"<p><b>Input:</b> {esc(meta.get('input',''))}</p>")
            if protos:
                f.write("<h2>Protocol Summary</h2><table><tr><th>Protocol</th><th>Count</th></tr>")
                summary = protos.get("counts", protos) if isinstance(protos, dict) else protos
                if isinstance(summary, dict):
                    for k,v in summary.items():
                        f.write(f"<tr><td>{esc(str(k).upper())}</td><td>{esc(v)}</td></tr>")
                f.write("</table>")
            if creds:
                f.write("<h2>Credentials</h2><ul>")
                for c in creds:
                    if isinstance(c, dict):
                        u=c.get("username") or c.get("user",""); p=c.get("password") or c.get("pass","")
                        s=c.get("source") or c.get("proto","")
                        f.write(f"<li><code>{esc(u)}:{esc(p)}</code> {('('+esc(s)+')') if s else ''}</li>")
                    else:
                        f.write(f"<li>{esc(c)}</li>")
                f.write("</ul>")
            if files:
                f.write("<h2>Files</h2><ul>")
                for it in files:
                    if isinstance(it, dict):
                        nm=it.get("filename") or it.get("name",""); pt=it.get("path","")
                        mt=it.get("mime") or it.get("type",""); sz=it.get("size")
                        detail=""
                        if mt or sz: detail=f" <small>({esc(mt) if mt else ''}{', ' if mt and sz else ''}{esc(sz)} bytes)</small>"
                        f.write(f"<li><code>{esc(nm)}</code> <small>{esc(pt)}</small>{detail}</li>")
                    else:
                        f.write(f"<li>{esc(it)}</li>")
                f.write("</ul>")
            if inds:
                f.write("<h2>Indicators</h2>")
                for k,v in inds.items():
                    f.write(f"<h3>{esc(k)}</h3><ul>")
                    if isinstance(v,(list,tuple)):
                        for item in v[:200]:
                            f.write(f"<li><code>{esc(str(item))}</code></li>")
                    else:
                        f.write(f"<li><code>{esc(str(v))}</code></li>")
                    f.write("</ul>")
            if flags:
                f.write("<h2>CTF Flags</h2><ul>")
                arr = flags.get("flags", flags) if isinstance(flags, dict) else flags
                if isinstance(arr, list):
                    for fl in arr:
                        f.write(f"<li><code>{esc(fl)}</code></li>")
                else:
                    f.write(f"<li><code>{esc(arr)}</code></li>")
                f.write("</ul>")
        written.append(str(html_path))

    return written

# -------------------------------
# Core workflow
# -------------------------------
def run(args) -> int:
    try:
        loaded = _load_input(args)
    except Exception as e:
        print(f"[!] Input error: {e}")
        return EXIT_INPUT_ERR

    src_type = loaded["source_type"]
    data = loaded["data"]
    input_path = loaded.get("input_path", "")
    results: Dict[str, Any] = {"source_type": src_type, "meta": {"version": VERSION, "input": input_path}}

    try:
        pkt_count = (
            len(data)
            if hasattr(data, "__len__")
            else len(getattr(data, "packets", []))
            if hasattr(data, "packets")
            else len((data or {}).get("packets", []))
        )
        _log(f"[*] Loaded {pkt_count} packets.", args.quiet)
    except Exception:
        pass

    if args.pcap_stats and input_path:
        _pcap_stats(input_path, args)

    if args.talkers and input_path:
        _talkers(input_path, args)

    if args.protocols:
        detect_protocols_fn = _safe_import_with_fallback(
            _q("analyzers.protocol"), ["detect_protocols", "analyze_protocols", "detect_and_group"]
        )
        if detect_protocols_fn:
            _log("[*] Detecting protocols...", args.quiet)
            with _timed("detect_protocols", args):
                try:
                    results["protocols"] = detect_protocols_fn(data)
                except TypeError:
                    results["protocols"] = detect_protocols_fn(args.pcap)
            _print_protocol_summary(results.get("protocols"), args.quiet)
        else:
            _log("[!] Protocol analyzer not available.", args.quiet)

    if args.sessions:
        reconstruct_sessions_fn = _safe_import_with_fallback(
            _q("analyzers.protocol"), ["reconstruct_sessions", "sessions", "build_sessions"]
        )
        if reconstruct_sessions_fn:
            _log("[*] Reconstructing sessions...", args.quiet)
            with _timed("reconstruct_sessions", args):
                try:
                    results["sessions"] = reconstruct_sessions_fn(data)
                except TypeError:
                    results["sessions"] = reconstruct_sessions_fn(args.pcap)

    if args.extract_creds:
        extract_credentials_fn = _safe_import_with_fallback(
            _q("analyzers.creds"), ["extract_credentials", "find_credentials", "harvest_credentials"]
        )
        if extract_credentials_fn:
            _log("[*] Extracting credentials...", args.quiet)
            with _timed("extract_credentials", args):
                try:
                    creds = extract_credentials_fn(data)
                except TypeError:
                    creds = extract_credentials_fn(args.pcap)
            results["credentials"] = creds
            _print_credentials(creds, args.quiet)

    if args.extract_files:
        _log("[*] Extracting files (preview only; nothing is saved yet)...", args.quiet)
        files_preview = _preview_extract_files(data, args)
        results["files"] = files_preview
        _print_files(files_preview, args.quiet)

        save = False
        if not args.no_prompt and not args.quiet and _isatty():
            ans = input("Do you want to save extracted files to disk? [y/N]: ").strip().lower()
            save = ans in ("y", "yes")

        if save:
            folder_name = input("Enter output folder name (default: PacketWhiz_output): ").strip() or "PacketWhiz_output"
            outdir = Path(folder_name)
            files_written, wrote_any = _save_extract_files(data, args, outdir)
            if wrote_any:
                _log(f"[*] Files saved in: {outdir}", args.quiet)
            if files_preview and any(isinstance(f, dict) and "content" in f for f in (files_preview or [])):
                outdir.mkdir(parents=True, exist_ok=True)
                wrote_any2 = False
                for f in files_preview:
                    if isinstance(f, dict) and "content" in f:
                        name = f.get("filename") or f.get("name") or "file.bin"
                        path = outdir / name
                        try:
                            with open(path, "wb") as fp:
                                fp.write(f["content"])
                            wrote_any2 = True
                        except Exception:
                            pass
                if wrote_any2:
                    _log(f"[*] Additional in-memory artifacts saved in: {outdir}", args.quiet)

    if args.indicators:
        find_indicators_fn = _safe_import_with_fallback(
            _q("analyzers.indicators"), ["find_indicators", "detect_indicators", "analyze_indicators"]
        )
        if find_indicators_fn:
            _log("[*] Detecting suspicious indicators...", args.quiet)
            with _timed("find_indicators", args):
                try:
                    ind = find_indicators_fn(data)
                except TypeError:
                    ind = find_indicators_fn(args.pcap)
            results["indicators"] = ind
            _print_indicators(ind, args.quiet)

    if args.ctf:
        find_flags_fn = _safe_import_with_fallback(
            _q("utils.flag_finder"), ["find_flags", "search_flags", "ctf_helper"]
        )
        if find_flags_fn:
            _log("[*] Running CTF helpers...", args.quiet)
            with _timed("find_flags", args):
                try:
                    fl = find_flags_fn(data)
                except TypeError:
                    try:
                        fl = find_flags_fn(Path.cwd())
                    except TypeError:
                        fl = find_flags_fn(args.pcap)
            results["ctf"] = fl
            _print_flags(fl, args.quiet)

    if (args.report and not args.no_prompt):
        outdir = Path(args.outdir)
        generate_report_fn = _import_with_fallback(_q("utils.report"), ["generate_report", "export_report", "build_report"])
        fmt = args.report
        if not generate_report_fn:
            written = _builtin_report(results, str(outdir), fmt)
            if written:
                _log(f"[*] Report written: {', '.join(written)}", args.quiet)
        else:
            outdir.mkdir(parents=True, exist_ok=True)
            _log(f"[*] Exporting report ({fmt})...", args.quiet)
            with _timed("generate_report", args):
                try:
                    generate_report_fn(results, str(outdir), fmt=fmt)
                except TypeError:
                    generate_report_fn(results, str(outdir))

    return EXIT_OK

# -------------------------------
# Interactive Shell (with tab-completion)
# -------------------------------
SHELL_HELP = """
Shell actions:
  1) PCAP stats (capinfos + tshark hierarchy)  — no writes
  2) Protocol summary
  3) Top talkers (src→dst:port)                — no writes
  4) Extract files (preview)                   — shows found files; asks before saving
  5) Save files now                            — pick folder; writes artifacts
  6) Credentials                               — show extracted credentials
  7) Indicators                                — beaconing / dns tunneling / etc.
  8) CTF flags                                 — scan for FLAG{}
  r) Generate report (html/txt/both)           — choose format & folder
  h) Help     q) Quit
"""

_SHELL_CMDS = [
    "1","2","3","4","5","6","7","8",
    "stats","pcap-stats",
    "protocol","protocols",
    "talkers",
    "extract","files",
    "save",
    "creds","credentials",
    "ind","indicators",
    "ctf","flags",
    "r","report",
    "h","help","?","q","quit","exit"
]

def _shell_history_load():
    if readline is None:
        return
    try:
        readline.read_history_file(HIST_PATH)
    except FileNotFoundError:
        pass
    except Exception:
        pass

def _shell_history_save():
    if readline is None:
        return
    try:
        Path(HIST_PATH).parent.mkdir(parents=True, exist_ok=True)
        readline.write_history_file(HIST_PATH)
    except Exception:
        pass

def _shell_setup_completer():
    if readline is None:
        return
    def completer(text, state):
        options = [c for c in _SHELL_CMDS if c.startswith(text)]
        if state < len(options):
            return options[state]
        return None
    try:
        readline.set_completer(completer)  # type: ignore
        readline.parse_and_bind("tab: complete")
    except Exception:
        pass

def shell(args) -> int:
    args.no_prompt = False
    _shell_history_load()
    _shell_setup_completer()

    try:
        loaded = _load_input(args)
    except Exception as e:
        print(f"[!] Input error: {e}")
        _shell_history_save()
        return EXIT_INPUT_ERR

    data = loaded["data"]
    input_path = loaded.get("input_path", "")

    print(SHELL_HELP.strip(), "\n")
    extracted_preview = None

    while True:
        try:
            choice = input("packetwhiz> ").strip().lower()
            if readline is not None and choice:
                try:
                    readline.add_history(choice)
                except Exception:
                    pass
        except EOFError:
            print()
            _shell_history_save()
            return EXIT_OK
        except KeyboardInterrupt:
            print()
            _shell_history_save()
            return EXIT_INTERRUPT

        if choice in ("q", "quit", "exit"):
            _shell_history_save()
            return EXIT_OK
        if choice in ("h", "help", "?"):
            print(SHELL_HELP)
            continue

        if choice in ("1", "stats", "pcap-stats"):
            if not input_path:
                print("[!] PCAP path unknown.")
            else:
                _pcap_stats(input_path, args)

        elif choice in ("2", "protocol", "protocols"):
            detect_protocols_fn = _safe_import_with_fallback(
                _q("analyzers.protocol"), ["detect_protocols", "analyze_protocols", "detect_and_group"]
            )
            if not detect_protocols_fn:
                print("[!] Protocol analyzer not available."); continue
            print("[*] Detecting protocols...]")
            try:
                protos = detect_protocols_fn(data)
            except TypeError:
                protos = detect_protocols_fn(args.pcap)
            _print_protocol_summary(protos, args.quiet)

        elif choice in ("3", "talkers"):
            if not input_path:
                print("[!] PCAP path unknown.")
            else:
                _talkers(input_path, args)

        elif choice in ("4", "extract", "files"):
            print("[*] Extracting files (preview only; nothing is saved yet)...")
            if extracted_preview is None:
                extracted_preview = _preview_extract_files(data, args)
            _print_files(extracted_preview, args.quiet)

        elif choice in ("5", "save"):
            if extracted_preview is None:
                print("[i] Run '4' first to preview files."); continue
            folder = input("Output folder (default: PacketWhiz_output): ").strip() or "PacketWhiz_output"
            outdir = Path(folder)
            files_written, wrote_any = _save_extract_files(data, args, outdir)
            if wrote_any:
                print(f"[*] Files saved in: {outdir}")
            if extracted_preview and any(isinstance(f, dict) and "content" in f for f in (extracted_preview or [])):
                outdir.mkdir(parents=True, exist_ok=True)
                for f in extracted_preview:
                    if isinstance(f, dict) and "content" in f:
                        name = f.get("filename") or f.get("name") or "file.bin"
                        with open(outdir / name, "wb") as fp:
                            fp.write(f["content"])
                print(f"[*] Additional in-memory artifacts saved in: {outdir}")

        elif choice in ("6", "creds", "credentials"):
            extract_credentials_fn = _safe_import_with_fallback(
                _q("analyzers.creds"), ["extract_credentials", "find_credentials", "harvest_credentials"]
            )
            if not extract_credentials_fn:
                print("[!] Credentials analyzer not available."); continue
            print("[*] Extracting credentials...")
            try:
                creds = extract_credentials_fn(data)
            except TypeError:
                creds = extract_credentials_fn(args.pcap)
            _print_credentials(creds, args.quiet)

        elif choice in ("7", "ind", "indicators"):
            find_indicators_fn = _safe_import_with_fallback(
                _q("analyzers.indicators"), ["find_indicators", "detect_indicators", "analyze_indicators"]
            )
            if not find_indicators_fn:
                print("[!] Indicators analyzer not available."); continue
            print("[*] Detecting suspicious indicators...")
            try:
                ind = find_indicators_fn(data)
            except TypeError:
                ind = find_indicators_fn(args.pcap)
            _print_indicators(ind, args.quiet)

        elif choice in ("8", "ctf", "flags"):
            find_flags_fn = _safe_import_with_fallback(
                _q("utils.flag_finder"), ["find_flags", "search_flags", "ctf_helper"]
            )
            if not find_flags_fn:
                print("[!] CTF helper not available."); continue
            print("[*] Running CTF helpers...")
            try:
                fl = find_flags_fn(data)
            except TypeError:
                try:
                    fl = find_flags_fn(Path.cwd())
                except TypeError:
                    fl = find_flags_fn(args.pcap)
            _print_flags(fl, args.quiet)

        elif choice in ("r", "report"):
            fmt = input("Format [html/txt/both] (default: html): ").strip().lower() or "html"
            if fmt not in ("html","txt","both"):
                print("[i] Unsupported format; falling back to html.")
                fmt = "html"
            outdir = Path(input("Output folder (default: PacketWhiz_output): ").strip() or "PacketWhiz_output")
            generate_report_fn = _import_with_fallback(_q("utils.report"), ["generate_report", "export_report", "build_report"])
            minimal = {"protocols": None, "meta": {"input": input_path}}
            if not generate_report_fn:
                written = _builtin_report(minimal, str(outdir), fmt)
                if written:
                    print(f"[*] Report written: {', '.join(written)}")
            else:
                outdir.mkdir(parents=True, exist_ok=True)
                print(f"[*] Exporting report ({fmt}) to {outdir} ...")
                try:
                    generate_report_fn(minimal, str(outdir), fmt=fmt)
                except TypeError:
                    generate_report_fn(minimal, str(outdir))
                print("[*] Report done.")
        else:
            print("Unknown command. Type 'h' for help.")

# -------------------------------
# Main
# -------------------------------
def main() -> int:
    banner()
    parser = build_argparser()
    args, _ = parser.parse_known_args()

    # Env safety override
    if os.environ.get("PWZ_NO_WRITES", "").strip() == "1":
        args.no_writes = True
        args.no_prompt = True

    if args.version:
        return EXIT_OK
    if args.help:
        print(parser.format_help()); return EXIT_OK

    if args.all:
        args.protocols = True
        args.sessions = True
        args.extract_creds = True
        args.extract_files = True
        args.indicators = True
        args.ctf = True

    if not (args.pcap or args.log):
        if not args.shell:
            print(parser.format_help())
            print("\n[!] Please provide --pcap or --log, or use --shell.\n")
            return EXIT_USAGE

    if args.shell:
        try:
            return shell(args)
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user."); return EXIT_INTERRUPT

    with _analysis_sandbox_if_no_writes(args):
        try:
            return run(args)
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user."); return EXIT_INTERRUPT

if __name__ == "__main__":
    sys.exit(main())

