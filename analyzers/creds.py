import base64
import re
from typing import List, Dict, Any

def extract_credentials(packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    creds = []

    for pkt in packets:
        payload = pkt.get("payload", "")
        # HTTP Basic Auth
        if "Authorization: Basic" in payload:
            try:
                encoded = payload.split("Authorization: Basic ")[1].split()[0]
                decoded = base64.b64decode(encoded).decode(errors="ignore")
                creds.append({"protocol": "HTTP", "credential": decoded})
            except Exception:
                continue

        # FTP USER/PASS
        if payload.startswith("USER ") or payload.startswith("PASS "):
            creds.append({"protocol": "FTP", "credential": payload.strip()})

        # SMTP AUTH
        if "AUTH LOGIN" in payload:
            creds.append({"protocol": "SMTP", "credential": payload.strip()})

    return creds

