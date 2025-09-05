#!/usr/bin/env python3
from __future__ import annotations
import re, os, subprocess, codecs, base64, gzip, io, urllib.parse
from typing import Any, Dict, List, Tuple

# Public entrypoints (main.py looks for any of these)
__all__ = ["find_flags", "search_flags", "ctf_helper"]

# ---------- helpers ----------

def _has_cmd(cmd: str) -> bool:
    from shutil import which
    return which(cmd) is not None

def _run(cmd: List[str]) -> Tuple[int, str, str]:
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out, err = p.communicate()
        return p.returncode, out, err
    except Exception as e:
        return 1, "", str(e)

def _safe_b64(s: str) -> str | None:
    # strip non-b64 and pad
    t = re.sub(r"[^A-Za-z0-9+/=]", "", s)
    if len(t) < 8:  # too short
        return None
    try:
        missing = (-len(t)) % 4
        t = t + ("=" * missing)
        b = base64.b64decode(t, validate=False)
        if not b:
            return None
        # decode as utf-8 if printable
        txt = b.decode("utf-8", errors="ignore")
        # sanity: ensure at least some letters/spaces
        if re.search(r"[A-Za-z]{3,}", txt):
            return txt
    except Exception:
        return None
    return None

def _hex_to_text(s: str) -> str | None:
    h = re.sub(r"[^0-9A-Fa-f]", "", s)
    if len(h) % 2 != 0 or len(h) < 8:
        return None
    try:
        b = bytes.fromhex(h)
        return b.decode("utf-8", errors="ignore")
    except Exception:
        return None

def _maybe_gunzip(b: bytes) -> str | None:
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(b)) as gz:
            return gz.read().decode("utf-8", errors="ignore")
    except Exception:
        return None

def _rot13(s: str) -> str:
    return codecs.decode(s, "rot_13")

def _bytes_to_text(b: bytes) -> str:
    # try utf-8 first, fallback latin-1
    try:
        return b.decode("utf-8", errors="ignore")
    except Exception:
        return b.decode("latin-1", errors="ignore")

# pull payload bytes using tshark
def _payloads_from_pcap(path: str) -> List[bytes]:
    payloads: List[bytes] = []
    if _has_cmd("tshark"):
        # data.data gives hex byte stream of frame payload; data.text sometimes pretty text
        rc, out, err = _run(["tshark", "-r", path, "-T", "fields", "-e", "data.data"])
        if rc == 0 and out:
            for line in out.splitlines():
                line = line.strip().replace(":", "")
                if not line:
                    continue
                try:
                    payloads.append(bytes.fromhex(line))
                except Exception:
                    continue
    return payloads

def _payloads_from_parsed(data: Any) -> List[bytes]:
    """Best-effort extractor from a parsed object produced by parser.pcap_parser."""
    # Expect either {"packets":[{"payload": b"..."}]} or similar
    payloads: List[bytes] = []
    if isinstance(data, dict):
        pkts = data.get("packets") or []
        for p in pkts:
            if isinstance(p, dict):
                for key in ("payload", "data", "raw", "bytes"):
                    v = p.get(key)
                    if isinstance(v, (bytes, bytearray)):
                        payloads.append(bytes(v))
                    elif isinstance(v, str):
                        payloads.append(v.encode("utf-8", errors="ignore"))
    return payloads

# ---------- core search ----------

_FLAG_RE = re.compile(r"FLAG\{[^}]{3,256}\}", re.IGNORECASE)

def _scan_text_for_flags(text: str) -> List[str]:
    hits = []
    for m in _FLAG_RE.finditer(text):
        hits.append(m.group(0))
    return hits

def _unique_keep_order(seq: List[str]) -> List[str]:
    seen = set(); out = []
    for s in seq:
        if s not in seen:
            out.append(s); seen.add(s)
    return out

def _try_decoders(text: str) -> List[str]:
    """Apply common decoders and collect flags found."""
    found: List[str] = []

    # direct
    found += _scan_text_for_flags(text)

    # url-decoded
    try:
        ud = urllib.parse.unquote_plus(text)
        if ud != text:
            found += _scan_text_for_flags(ud)
    except Exception:
        pass

    # base64 substrings
    for cand in re.findall(r"[A-Za-z0-9+/=]{12,}", text):
        dec = _safe_b64(cand)
        if dec:
            found += _scan_text_for_flags(dec)

    # hex substrings
    for cand in re.findall(r"(?:[0-9A-Fa-f]{2} ?){8,}", text):
        dec = _hex_to_text(cand)
        if dec:
            found += _scan_text_for_flags(dec)

    # rot13
    r13 = _rot13(text)
    if r13 != text:
        found += _scan_text_for_flags(r13)

    return found

def _scan_bytes_for_flags(b: bytes) -> List[str]:
    found: List[str] = []

    # plain decode
    txt = _bytes_to_text(b)
    found += _try_decoders(txt)

    # gzip?
    gz = _maybe_gunzip(b)
    if gz:
        found += _try_decoders(gz)

    return found

# ---------- public API ----------

def find_flags(source: Any) -> Dict[str, Any]:
    """
    source can be:
      - dict returned by parse_pcap / parse_logs
      - pcap file path (str)
      - directory path (scan all files for FLAG{...})
    Returns: {"flags": [...], "evidence": [{"where": "...", "preview": "..."}]}
    """
    flags: List[str] = []
    evidence: List[Dict[str, str]] = []

    # gather payloads
    payloads: List[bytes] = []
    if isinstance(source, str) and os.path.exists(source):
        if os.path.isdir(source):
            # simple file scan
            for root, _, files in os.walk(source):
                for fn in files:
                    try:
                        p = os.path.join(root, fn)
                        with open(p, "rb") as f:
                            b = f.read()
                        hits = _scan_bytes_for_flags(b)
                        for h in hits:
                            flags.append(h)
                            evidence.append({"where": p, "preview": h})
                    except Exception:
                        continue
            return {"flags": _unique_keep_order(flags), "evidence": evidence}

        # assume PCAP
        payloads = _payloads_from_pcap(source)

    elif isinstance(source, dict):
        payloads = _payloads_from_parsed(source)

    # scan payloads
    for i, b in enumerate(payloads):
        hits = _scan_bytes_for_flags(b)
        if hits:
            prev = _bytes_to_text(b)[:120].replace("\n", " ")
            for h in hits:
                flags.append(h)
                evidence.append({"where": f"payload#{i}", "preview": prev})

    return {"flags": _unique_keep_order(flags), "evidence": evidence}

# provide alt names for main.py fallbacks
search_flags = find_flags
ctf_helper = find_flags

