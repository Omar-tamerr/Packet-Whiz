#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
from typing import List, Dict, Any

def parse_log(filename: str) -> List[Dict[str, Any]]:
    """
    Parse raw text logs into a list of packet-like dictionaries.

    Each entry looks like:
    {
        "timestamp": "12:01:23",
        "src_ip": "192.168.1.5",
        "dst_ip": "192.168.1.10",
        "protocol": "TCP",
        "payload": "Flags [P.], length 48"
    }
    """
    packets: List[Dict[str, Any]] = []


    line_re = re.compile(
        r"(?P<time>\d{2}:\d{2}:\d{2})\s+IP\s+(?P<src>[\d\.]+)\.\d+\s*>\s*(?P<dst>[\d\.]+)\.\d+:\s*(?P<rest>.*)"
    )

    with open(filename, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            match = line_re.match(line)
            if match:
                packets.append({
                    "timestamp": match.group("time"),
                    "src_ip": match.group("src"),
                    "dst_ip": match.group("dst"),
                    "protocol": "TCP" if "Flags" in match.group("rest") else "UNKNOWN",
                    "payload": match.group("rest")
                })
            else:
         
                packets.append({
                    "timestamp": None,
                    "src_ip": None,
                    "dst_ip": None,
                    "protocol": "UNKNOWN",
                    "payload": line
                })

    return packets