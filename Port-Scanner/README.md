# Python Port Scanner

A multithreaded TCP connect port scanner written in Python, similar in concept to Nmap's `-sT` scan. It performs a full three-way handshake against each port, grabs service banners on open ports, and writes a formatted report to file.

## Features

- **Multithreaded scanning** — configurable thread count for fast scans across large port ranges
- **TCP connect scan** — full three-way handshake (no raw sockets/root required)
- **Banner grabbing** — passive read first (catches SSH/FTP/SMTP greeting banners), with an HTTP HEAD fallback on common web ports
- **Service identification** — maps well-known ports to service names
- **Graceful interrupt handling** — Ctrl+C stops all threads cleanly and still writes a partial report
- **Colored terminal output** for open ports
- **Argument validation** and sane defaults
- **Report file output** with target, timing, and results

## Requirements

- Python 3.7+
- `colorama`

## Installation

```bash
git clone https://github.com/ShaziaSadique/Python-Port-Scanner.git
cd Python-Port-Scanner
pip install -r requirements.txt
```

## Usage

```bash
python port_scanner.py -t <target> [options]
```

If `-t` is omitted, the script will prompt for a target interactively.

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-t`, `--target` | Target IP or hostname | prompted if omitted |
| `-s`, `--start` | Start port | 1 |
| `-e`, `--end` | End port | 1024 |
| `-th`, `--threads` | Number of threads | 100 |
| `-o`, `--output` | Output report filename | auto-generated |
| `--timeout` | Per-connection timeout (seconds) | 1.0 |
| `--no-banner` | Skip banner grabbing (faster scan) | off |

### Examples

Scan the default range (ports 1–1024) on a target:
```bash
python port_scanner.py -t scanme.nmap.org
```

Scan a custom port range with more threads:
```bash
python port_scanner.py -t 192.168.1.10 -s 1 -e 65535 -th 300
```

Fast scan without banner grabbing, custom output file:
```bash
python port_scanner.py -t example.com --no-banner -o example_scan.txt
```

## Sample Output

```
=======================================================
Professional TCP Connect Port Scanner
=======================================================
Target  : scanme.nmap.org
IP      : 45.33.32.156
Ports   : 1-1024
Threads : 100

[OPEN] 22     SSH             SSH-2.0-OpenSSH_6.6.1p1
[OPEN] 80     HTTP            HTTP/1.1 200 OK

Scan Completed
Open Ports : 2
Time Taken : 3.42 seconds
Results saved to scanme_nmap_org_scan.txt
```

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Only scan systems you own or have explicit permission to test. Unauthorized port scanning may violate computer misuse laws in your jurisdiction.

## Author

**Shazia Sadique**
GitHub: [ShaziaSadique](https://github.com/ShaziaSadique)

## License

MIT License — free to use, modify, and distribute.
