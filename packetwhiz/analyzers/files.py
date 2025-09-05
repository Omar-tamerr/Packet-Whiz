import os
import re
from typing import List, Dict, Any

def extract_files(packets: List[Dict[str, Any]], outdir: str = "pwz_output") -> List[str]:
    """
    Extract files from traffic (basic HTTP/SMTP/FTP).
    Saves to outdir and returns list of file paths.
    """
    os.makedirs(outdir, exist_ok=True)
    extracted_files = []

    for i, pkt in enumerate(packets):
        payload = pkt.get("payload", "")

        if "Content-Disposition:" in payload and "filename=" in payload:
            match = re.search(r'filename="?([^"]+)"?', payload)
            if match:
                filename = match.group(1)
                filepath = os.path.join(outdir, filename)

                with open(filepath, "wb") as f:
                    f.write(payload.encode())  

                extracted_files.append(filepath)

    return extracted_files