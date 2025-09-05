#!/usr/bin/env python3
# utils/report.py
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List

__all__ = ["generate_report", "export_report", "build_report"]

# ---- minimal HTML escaping ----
def _esc(s: Any) -> str:
    if s is None:
        return ""
    if not isinstance(s, str):
        try:
            s = str(s)
        except Exception:
            s = repr(s)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def _ensure_dir(p: str | Path) -> None:
    Path(p).mkdir(parents=True, exist_ok=True)

def _norm_counts(obj: Any) -> Dict[str, Any]:
    # Accept either {"counts": {...}} or just {"http": 10, ...} or a list of tuples
    if isinstance(obj, dict) and "counts" in obj and isinstance(obj["counts"], dict):
        return obj["counts"]
    if isinstance(obj, dict):
        return obj
    if isinstance(obj, list):
        try:
            return {str(k): v for k, v in obj}
        except Exception:
            return {}
    return {}

# ---------- TXT writer ----------
def _write_txt(results: Dict[str, Any], outdir: str) -> str:
    _ensure_dir(outdir)
    path = Path(outdir) / "report.txt"

    meta   = results.get("meta", {})
    protos = results.get("protocols")
    creds  = results.get("credentials")
    files  = results.get("files")
    inds   = results.get("indicators")
    flags  = results.get("ctf")

    with open(path, "w", encoding="utf-8") as f:
        f.write("PacketWhiz Report\n")
        if meta:
            f.write(f"Input: {meta.get('input','')}\n")
            f.write(f"Version: {meta.get('version','')}\n")
        f.write("\n")

        # Protocols
        if protos:
            f.write("[Protocol Summary]\n")
            counts = _norm_counts(protos)
            for k, v in counts.items():
                f.write(f" - {str(k).upper()}: {v}\n")
            f.write("\n")

        # Credentials
        if creds:
            f.write("[Credentials]\n")
            for c in creds:
                if isinstance(c, dict):
                    user = c.get("username") or c.get("user") or ""
                    pwd  = c.get("password") or c.get("pass") or ""
                    src  = c.get("source")   or c.get("proto") or ""
                    srcs = f" ({src})" if src else ""
                    f.write(f" - {user}:{pwd}{srcs}\n")
                else:
                    f.write(f" - {c}\n")
            f.write("\n")

        # Files
        if files:
            f.write("[Files]\n")
            for it in files:
                if isinstance(it, dict):
                    nm = it.get("filename") or it.get("name") or ""
                    pt = it.get("path") or it.get("filepath") or ""
                    mt = it.get("mime") or it.get("type") or ""
                    sz = it.get("size")
                    extra = []
                    if mt: extra.append(mt)
                    if isinstance(sz, int): extra.append(f"{sz} bytes")
                    tail = f" ({', '.join(extra)})" if extra else ""
                    f.write(f" - {nm} -> {pt}{tail}\n")
                else:
                    f.write(f" - {it}\n")
            f.write("\n")

        # Indicators
        if inds and isinstance(inds, dict):
            f.write("[Indicators]\n")
            for k, v in inds.items():
                f.write(f" - {k}:\n")
                if isinstance(v, (list, tuple)):
                    for item in v:
                        f.write(f"    • {item}\n")
                else:
                    f.write(f"    • {v}\n")
            f.write("\n")

        # Flags
        if flags:
            f.write("[CTF Flags]\n")
            arr = flags.get("flags", flags) if isinstance(flags, dict) else flags
            if isinstance(arr, list):
                for fl in arr:
                    f.write(f" - {fl}\n")
            else:
                f.write(f" - {arr}\n")
            f.write("\n")

    return str(path)

# ---------- HTML writer ----------
def _write_html(results: Dict[str, Any], outdir: str) -> str:
    _ensure_dir(outdir)
    path = Path(outdir) / "report.html"

    meta   = results.get("meta", {})
    protos = results.get("protocols")
    creds  = results.get("credentials")
    files  = results.get("files")
    inds   = results.get("indicators")
    flags  = results.get("ctf")

    with open(path, "w", encoding="utf-8") as f:
        f.write("<!doctype html><meta charset='utf-8'>")
        f.write("<title>PacketWhiz Report</title>")
        f.write(
            "<style>"
            "body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:24px}"
            "h1{margin-top:0} h2{margin-top:28px}"
            "code,pre{background:#f6f6f6;padding:6px 8px;border-radius:6px}"
            "table{border-collapse:collapse;margin-top:8px}"
            "td,th{border:1px solid #ddd;padding:6px 10px;text-align:left}"
            "ul{margin-top:6px}"
            "</style>"
        )

        f.write("<h1>PacketWhiz Report</h1>")
        if meta:
            f.write("<p>")
            if meta.get("input"):   f.write(f"<b>Input:</b> {_esc(meta['input'])}<br>")
            if meta.get("version"): f.write(f"<b>Version:</b> {_esc(meta['version'])}")
            f.write("</p>")

        # Protocols
        if protos:
            f.write("<h2>Protocol Summary</h2>")
            counts = _norm_counts(protos)
            f.write("<table><tr><th>Protocol</th><th>Count</th></tr>")
            for k, v in counts.items():
                f.write(f"<tr><td>{_esc(str(k).upper())}</td><td>{_esc(v)}</td></tr>")
            f.write("</table>")

        # Credentials
        if creds:
            f.write("<h2>Credentials</h2><ul>")
            for c in creds:
                if isinstance(c, dict):
                    u = c.get("username") or c.get("user") or ""
                    p = c.get("password") or c.get("pass") or ""
                    s = c.get("source")   or c.get("proto") or ""
                    sfx = f" <small>({_esc(s)})</small>" if s else ""
                    f.write(f"<li><code>{_esc(u)}:{_esc(p)}</code>{sfx}</li>")
                else:
                    f.write(f"<li>{_esc(c)}</li>")
            f.write("</ul>")

        # Files
        if files:
            f.write("<h2>Files</h2><ul>")
            for it in files:
                if isinstance(it, dict):
                    nm = it.get("filename") or it.get("name") or ""
                    pt = it.get("path") or it.get("filepath") or ""
                    mt = it.get("mime") or it.get("type") or ""
                    sz = it.get("size")
                    tail = []
                    if mt: tail.append(_esc(mt))
                    if isinstance(sz, int): tail.append(f"{sz} bytes")
                    tail_html = f" <small>({' ,'.join(tail)})</small>" if tail else ""
                    f.write(f"<li><code>{_esc(nm)}</code> <small>{_esc(pt)}</small>{tail_html}</li>")
                else:
                    f.write(f"<li>{_esc(it)}</li>")
            f.write("</ul>")

        # Indicators
        if inds and isinstance(inds, dict):
            f.write("<h2>Indicators</h2>")
            for k, v in inds.items():
                f.write(f"<h3>{_esc(k)}</h3><ul>")
                if isinstance(v, (list, tuple)):
                    for item in v:
                        f.write(f"<li><code>{_esc(item)}</code></li>")
                else:
                    f.write(f"<li><code>{_esc(v)}</code></li>")
                f.write("</ul>")

        # Flags
        if flags:
            f.write("<h2>CTF Flags</h2><ul>")
            arr = flags.get("flags", flags) if isinstance(flags, dict) else flags
            if isinstance(arr, list):
                for fl in arr:
                    f.write(f"<li><code>{_esc(fl)}</code></li>")
            else:
                f.write(f"<li><code>{_esc(arr)}</code></li>")
            f.write("</ul>")

    return str(path)

# ---------- public API ----------
def generate_report(results: Dict[str, Any], outdir: str, fmt: str = "html") -> List[str]:
    """
    Generate a report into `outdir`.
    fmt: "html", "txt", or "both"
    Returns a list of written file paths.
    """
    fmt = (fmt or "html").lower()
    written: List[str] = []
    if fmt in ("txt", "both"):
        written.append(_write_txt(results, outdir))
    if fmt in ("html", "both"):
        written.append(_write_html(results, outdir))
    if fmt not in ("html", "txt", "both"):
        # Fallback to html if someone passes "pdf" or anything else
        written.append(_write_html(results, outdir))
    return written

# Backwards-compatible aliases expected by main.py
def export_report(results: Dict[str, Any], outdir: str, fmt: str = "html") -> List[str]:
    return generate_report(results, outdir, fmt)

def build_report(results: Dict[str, Any], outdir: str, fmt: str = "html") -> List[str]:
    return generate_report(results, outdir, fmt)

