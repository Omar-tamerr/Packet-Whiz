from collections import Counter
from typing import List, Dict, Any

def detect_indicators(packets: List[Dict[str, Any]]) -> Dict[str, Any]:
    alerts = {
        "cleartext_creds": [],
        "failed_logins": [],
        "beaconing": [],
        "dns_tunneling": []
    }

    # 1. Cleartext passwords in payload
    for pkt in packets:
        if "password=" in pkt.get("payload", "").lower():
            alerts["cleartext_creds"].append(pkt)

    # 2. Failed logins
    for pkt in packets:
        if "530 Login incorrect" in pkt.get("payload", ""):
            alerts["failed_logins"].append(pkt)

    # 3. Beaconing (simple heuristic: same src/dst repeating often)
    pair_counter = Counter((pkt["src_ip"], pkt["dst_ip"]) for pkt in packets if pkt["src_ip"] and pkt["dst_ip"])
    for pair, count in pair_counter.items():
        if count > 10:  # threshold, tune later
            alerts["beaconing"].append({"pair": pair, "count": count})

    # 4. DNS tunneling (long suspicious queries)
    for pkt in packets:
        if pkt.get("protocol") == "DNS" and len(pkt.get("payload", "")) > 100:
            alerts["dns_tunneling"].append(pkt)

    return alerts