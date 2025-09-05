import pyshark

def parse_pcap(filename):
    cap = pyshark.FileCapture(filename, keep_packets=False)
    packets = []
    for pkt in cap:
        try:
            packets.append({
                "timestamp": pkt.sniff_time,
                "src_ip": pkt.ip.src if "IP" in pkt else None,
                "dst_ip": pkt.ip.dst if "IP" in pkt else None,
                "protocol": pkt.highest_layer,
                "payload": str(pkt)
            })
        except AttributeError:
            continue
    return packets
