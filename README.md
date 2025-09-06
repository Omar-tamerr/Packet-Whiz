# PacketWhiz — Network Forensics & Analysis (NFA)

[![PyPI version](https://img.shields.io/pypi/v/packetwhiz-nfa.svg)](https://pypi.org/project/packetwhiz-nfa/)  
[![Python versions](https://img.shields.io/pypi/pyversions/packetwhiz-nfa.svg)](https://pypi.org/project/packetwhiz-nfa/)

<p align="center">
  <img alt="PacketWhiz main screen" src="https://raw.githubusercontent.com/Omar-tamerr/packetwhiz/main/packetwhiz/Img/main-page.png" width="900">
</p>

PacketWhiz is a lightweight, beginner-friendly, but powerful network forensics toolkit.
It parses PCAP/PCAPNG (optionally `.gz`) or simple logs, summarizes protocols, finds indicators,
previews file carving, extracts credentials when possible, generates quick reports, and includes
a guided interactive shell for non-experts.

---

## Highlights

* **Safe-by-default I/O** — nothing is written to disk unless you explicitly say so
* **Protocol summary** — quick view of HTTP/HTTPS/DNS/… counts + assessment notes
* **Indicators** — surface beaconing patterns, suspicious pairs, etc.
* **File extraction (preview-first)** — see what can be carved before saving
* **Credentials** — attempts clear-text credential recovery where applicable
* **CTF helper** — finds `FLAG{}` patterns with common encodings/containers
* **PCAP stats** — `capinfos` and `tshark` protocol hierarchy (read-only)
* **Top talkers** — most chatty `src → dst[:port]` pairs (read-only)
* **Reports** — `html` or `txt` reports you can hand to a teammate
* **Interactive shell** — tab completion + history (`~/.packetwhiz_history`)

---

## Installation

### Requirements

* Python **3.9+**
* Optional CLI tools (only needed for some features):

  * `tshark` (for protocol hierarchy & talkers)
  * `capinfos` (Wireshark suite)

### Quick Start

```bash
# Install from PyPI
pip install packetwhiz-nfa

# Run the tool (both forms are equivalent):
packetwhiz --help
# or
python -m packetwhiz --help
```

> Prefer a venv (`python3 -m venv .venv && source .venv/bin/activate`) to keep dependencies clean.

---

## Usage

### Common options

```bash
packetwhiz --pcap sample.pcap --protocols
packetwhiz --pcap sample.pcap --extract-files           # preview first; choose whether to save
packetwhiz --pcap sample.pcap --indicators
packetwhiz --pcap sample.pcap --pcap-stats              # capinfos + tshark protocol hierarchy
packetwhiz --pcap sample.pcap --talkers                 # top src→dst[:port]
packetwhiz --pcap sample.pcap --report html -o PacketWhiz_output
packetwhiz --pcap sample.pcap --ctf
packetwhiz --shell --pcap sample.pcap                   # guided shell for non-experts
```

### “Do a lot for me” run

```bash
packetwhiz --pcap sample.pcap --all --no-prompt
```

What `--all` does: runs `--protocols --sessions --extract-creds --extract-files --indicators --ctf`.
It still **does not write to disk** unless you later choose to save or specify `--report`.

### Zero-write safety

No writes occur unless you explicitly confirm saving, pass `--report`, or run “save now” in the shell.
You can hard-enforce no writes with `--no-writes` or `PWZ_NO_WRITES=1`.

---

## Interactive Shell

```bash
packetwhiz --shell --pcap sample.pcap
```

<p align="center">
  <img alt="Shell feature" src="packetwhiz/Img/shell-feature.png" width="900">
</p>

You’ll see options like:

```
1) PCAP stats (capinfos + tshark hierarchy)  — no writes
2) Protocol summary
3) Top talkers (src→dst:port)                — no writes
4) Extract files (preview)
5) Save files now
6) Credentials
7) Indicators
8) CTF flags
r) Generate report (html/txt/both)
h) Help     q) Quit
```

* **Tab completion** for commands (e.g., `pro…` → `protocols`)
* **Command history** is saved to `~/.packetwhiz_history`
* File extraction is **preview-first**; saving asks for a destination folder.

---

## Visuals

### Protocols

<p align="center">
  <img alt="Protocols feature" src="packetwhiz/Img/protocols-feature.png" width="900">
</p>

### Indicators (beaconing, suspicious pairs, etc.)

<p align="center">
  <img alt="Indicators" src="packetwhiz/Img/indicators.png" width="900">
</p>

### Top Talkers

<p align="center">
  <img alt="Top talkers" src="packetwhiz/Img/talkers.png" width="900">
</p>

### Shell Example (command 1)

<p align="center">
  <img alt="Shell command example" src="packetwhiz/Img/shell-command-one.png" width="900">
</p>

---

## Reports

Generate HTML or text reports containing whatever you ran in the session:

```bash
packetwhiz --pcap sample.pcap --protocols --indicators --report both -o PacketWhiz_output
```

Or from the shell: `r` → choose `html`, `txt`, or `both`, then choose the output folder.

---

## Useful Examples

```bash
# 1) Quick protocol picture + talkers (read-only)
packetwhiz --pcap corp_traffic.pcap --protocols --talkers

# 2) Preview then save carved files
packetwhiz --pcap web_no_tls.pcap --extract-files
# ... if you see interesting hits, choose to save and pick an output folder

# 3) Indicators + simple text report
packetwhiz --pcap beaconing_slice.pcap --indicators --report txt -o PacketWhiz_output

# 4) CTF mode
packetwhiz --pcap ctf.pcap --ctf

# 5) All analyses (no writes), then decide
packetwhiz --pcap case1.pcap --all --no-prompt
```

---

## Troubleshooting

**“parser.pcap\_parser function not found.”**
Make sure you installed the package from PyPI and not just a stray script.

**“File not found” with slight typos or `.gz`**
PacketWhiz tries common path fixes (parent folder, `.gz` partner, and some typo healing like `witp→with`).
If you pass `x.pcap.gz`, it will transparently decompress to a temp file.

**Need Wireshark CLI tools**
Install `tshark` and `capinfos` if you want protocol hierarchy and stats:

* Debian/Ubuntu: `sudo apt install tshark`
* macOS (Homebrew): `brew install wireshark`

---

## Authors & Collaboration

**PacketWhiz** is a collaborative project by:

* **Omar Tamer** ([@Omar-tamerr](https://github.com/Omar-tamerr)) — co-founder, project lead, CLI & shell UX, analyzers integration, and reporting.
* **Farida Ismail** ([@faridaaismaill12](https://github.com/faridaaismaill12)) — co-founder, **network forensics expert**, design collaborator, and analyzer workflows.

If you use PacketWhiz in a write-up, class, or video, please credit both authors.

---

## Contributing

PRs are welcome!
Before submitting, please run your changes locally and keep the CLI safe-by-default (no unintended writes).

---

## License

MIT — see `LICENSE`.

