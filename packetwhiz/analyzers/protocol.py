from collections import defaultdict
from typing import List, Dict, Any

def detect_and_group(packets: List[Dict[str, Any]]) -> Dict[str, Any]:
    proto_summary = defaultdict(list)

    for pkt in packets:
        proto = pkt.get("protocol", "UNKNOWN")
        proto_summary[proto].append(pkt)

    return {
        "counts": {proto: len(pkts) for proto, pkts in proto_summary.items()},
        "by_proto": proto_summary
    }
