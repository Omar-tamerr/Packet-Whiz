

# PacketWhiz — Network Forensics & Analysis (NFA)

PacketWhiz is a lightweight, beginner-friendly toolkit for practical network forensics. It helps you analyze PCAPs/logs, summarize protocols, extract credentials and files, detect indicators, run CTF flag scans, and generate reports — with **no accidental writes** unless you explicitly choose to save.

**Authors:** Omar Tamer & Farida Ismail
**Version:** 0.1
**Repository:** [https://github.com/Omar-tamerr/Packet-Whiz](https://github.com/Omar-tamerr/Packet-Whiz)

---

## Features

* **No-surprise I/O**: Nothing is written to disk unless you confirm (saving files or exporting a report).
* **Protocol summary**: Clear detection with friendly assessment (e.g., clear-text HTTP vs HTTPS).
* **Credentials & files**: Extract credentials; carve files with a preview-first flow.
* **Indicators**: Beaconing, DNS tunneling, and other suspicious patterns (extensible analyzers).
* **CTF helper**: Finds `FLAG{...}` in raw payloads and common encodings (URL/Base64/hex/rot13/gzip).
* **PCAP utilities**: `--pcap-stats` (capinfos + protocol hierarchy) and `--talkers` (top src→dst\:port).
* **Interactive shell**: Guided menu with **tab completion** and **persistent history**.
* **Quality of life**: Auto-handle `.gz` PCAPs, fix common path typos, verbose timing logs.

---

## Requirements

* **Python** 3.9+
* **Optional (recommended)**:

  * `tshark` and `capinfos` (Wireshark CLI) for richer payload extraction and stats

PacketWhiz works without Wireshark CLIs but with reduced capabilities.

---

## Installation

```bash
git clone https://github.com/Omar-tamerr/Packet-Whiz.git
cd Packet-Whiz
python3 -m venv .venv
source .venv/bin/activate
# No extra Python deps required for core features
```

---

## Quick Start

Protocol summary:

```bash
python3 main.py --pcap sample.pcap --protocols
```

Broad analysis without writing:

```bash
python3 main.py --pcap sample.pcap --all --no-prompt
```

Interactive shell (tab completion, ↑/↓ history):

```bash
python3 main.py --pcap sample.pcap --shell
```

Export a report (writes only because you asked to):

```bash
python3 main.py --pcap sample.pcap --protocols --report html -o PacketWhiz_output
```

---

## Command-Line Usage

```
packetwhiz [OPTIONS]

Input:
  --pcap PATH                Input .pcap/.pcapng (also accepts .gz)
  --log PATH                 Input raw text log

Features:
  --protocols                Detect protocol distribution
  --sessions                 Reconstruct sessions/conversations
  --extract-creds            Extract credentials
  --extract-files            Extract/carve files (preview first)
  --indicators               Detect suspicious indicators
  --pcap-stats               Show capinfos & tshark protocol hierarchy (read-only)
  --talkers                  Show top talkers (src→dst:port) (read-only)
  --ctf                      Find CTF flags (FLAG{...}) with common decoders
  --report {html,txt,both}   Export report (writes to -o)

Output & UX:
  -o, --outdir DIR           Output folder when writing (default: PacketWhiz_output)
  -q, --quiet                Less console output
  -V, --verbose              Verbose mode + timing for key steps
  --no-prompt                Never ask to save; skip writes unless --report is set
  --no-writes                Force zero disk writes (or set PWZ_NO_WRITES=1)
  --shell                    Interactive guided shell for non-experts

Convenience:
  --all                      Enable: protocols, sessions, extract-creds, extract-files, indicators, ctf

Meta:
  -h, --help                 Show help and exit
  -v, --version              Show version and exit
```

### Useful examples

```bash
# Protocol summary with assessment
python3 main.py --pcap web.pcap --protocols

# Top talkers
python3 main.py --pcap traffic.pcap --talkers

# Creds + files (preview first; then optional save)
python3 main.py --pcap http.cap --extract-creds --extract-files

# CTF flags
python3 main.py --pcap challenge.pcap --ctf

# Text + HTML report
python3 main.py --pcap case.pcap --protocols --indicators --report both -o Incident_2025-09-05
```

> Tip: Passing a `.gz` PCAP (e.g., `capture.pcap.gz`) is supported — PacketWhiz auto-decompresses to a temporary file for analysis.

---

## Interactive Shell

Start the guided shell:

```bash
python3 main.py --pcap sample.pcap --shell
```

Commands:

* `1` — PCAP stats (capinfos + tshark hierarchy)
* `2` — Protocol summary
* `3` — Top talkers (src→dst\:port)
* `4` — Extract files (preview only)
* `5` — Save files (choose folder)
* `6` — Credentials
* `7` — Indicators
* `8` — CTF flags
* `r` — Generate report (html/txt/both)
* `h` — Help
* `q` — Quit

**Tab completion** suggests commands; **history** is saved to `~/.packetwhiz_history`.

---

## Reports

* Built-in **HTML** and **TXT** report generators (`utils/report.py`).
* Sections: Protocols, Credentials, Files, Indicators, CTF Flags.
* Only created if you explicitly run with `--report` (CLI) or `r` (shell).

---

## Safety: Explicit Writes Only

* Analysis doesn’t create any folders or files by default.
* Disk writes happen only when you:

  * save carved files (prompt or shell `5`)
  * export a report (`--report` / shell `r`)
* `--no-prompt` ensures non-interactive, read-only behavior.
* `--no-writes` or `PWZ_NO_WRITES=1` enforces zero writes.

---

## Project Structure

```
Packet-Whiz/
├── main.py
├── analyzers/
│   ├── protocol.py         # detect_protocols(), reconstruct_sessions()
│   ├── creds.py            # extract_credentials()
│   ├── files.py            # extract_files()
│   └── indicators.py       # find_indicators()
├── parser/
│   ├── pcap_parser.py      # load/parse pcap
│   └── log_parcer.py       # load/parse logs
└── utils/
    ├── flag_finder.py      # find_flags() / CTF helper
    └── report.py           # generate_report() (HTML/TXT)
```

`main.py` dynamically imports these functions. If a module is missing, it prints a clear message and continues when possible.

---

## Troubleshooting

* **PCAP not found**
  We try `./`, `../`, typo fix `witp→with`, and `.gz`. Verify the path and extension.
* **`capinfos` / `tshark` missing**
  Install Wireshark CLI tools (e.g., `sudo apt install wireshark-common` on Debian/Ubuntu).
* **No files/creds detected**
  Some captures won’t contain extractable artifacts. Start with `--protocols` and `--pcap-stats`.
* **CTF flags not found**
  The helper checks multiple encodings. If still nothing, investigate with `--talkers` and targeted protocol tools.

---

## Contributing

Contributions are welcome! Please:

1. Keep disk-write behavior explicit and user-driven.
2. Keep analyzers modular with simple function signatures.
3. Add concise docstrings and example usage in PRs.
4. Prefer zero external Python dependencies; rely on system tools when reasonable.

---

## License

See [LICENSE](./LICENSE).

---

## Credits

Thanks to the Wireshark community for `tshark` and `capinfos`, which make practical network forensics accessible.

