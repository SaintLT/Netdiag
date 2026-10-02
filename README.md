# Network Diagnostic Toolkit (netdiag) v1.0

A Python toolkit for diagnosing network problems and learning the concepts behind each result.
Standard library only. Python 3.8+. No installation needed.

## Quick start

```bash
python -m netdiag diag example.com --html report.html   # run everything, get findings + HTML report
```

Optional: `pip install .` gives you a plain `netdiag` command (`netdiag diag example.com`).

## Commands

| Command | Purpose |
|---------|---------|
| `diag <host>` | Machine info, DNS, latency, HTTPS and port checks, then a plain-language findings list. `--html FILE` / `--json-file FILE` save reports. |
| `info` | This machine's IP, default gateway and DNS servers |
| `ping <host>` | TCP latency, loss, jitter (no admin rights). `--icmp` uses the system ping |
| `monitor <host>` | Live running loss/latency until Ctrl+C. `-c N` stops after N probes |
| `dns <name>` | `-t A AAAA MX TXT NS SOA CNAME PTR`; repeat `-s <resolver>` to compare resolvers |
| `rdns <ip>` | Reverse lookup (IP to hostname) |
| `scan <host>` | TCP port scan: `-p 22,80,8000-8100`, `--banner` |
| `http <url>` | DNS / TCP / TLS / first-byte timings, status, certificate days left |
| `trace <host>` | Route via system traceroute / tracert / tracepath |

`ping`, `dns`, `rdns`, `scan`, `http` and `info` accept `--json`. Exit codes: 0 = ok, 1 = problem found, 2 = bad input.

## How it is organised

```
netdiag/
  cli.py          argument parsing, output formatting, the diag workflow
  tcp_ping.py     TCP handshake timing, loss, jitter
  dns_tools.py    hand-built DNS client (UDP, TCP fallback, name compression)
  portscan.py     threaded connect scanner, banner grabbing
  http_check.py   per-phase HTTP(S) timing, TLS version, cert expiry
  info.py         local IP, gateway, DNS servers
  system_tools.py wrappers for system ping / traceroute
  report.py       self-contained HTML report
tests/            16 tests (local servers and a fake DNS server; no internet needed)
```

Each module returns plain dictionaries and never prints, so a GUI or web front end can reuse them.

## What each tool teaches

| Tool | Concept |
|------|---------|
| ping / monitor | TCP handshake time as RTT; loss and jitter |
| dns / rdns | DNS wire format, record types, resolver differences, NXDOMAIN vs timeout |
| scan | open / closed (RST) / filtered (silence) port states |
| http | where time goes: DNS, TCP, TLS, server response |
| trace | TTL expiry and hop-by-hop path |
| diag | reading symptoms to find the layer that is failing |

## Tests

```bash
python -m unittest discover -s tests -v
```

## Limits and notes
- Only scan systems you own or have permission to test.
- `trace` and `--icmp` need the system tools installed; the toolkit does not send raw ICMP itself.
- Port scans are TCP connect scans; "filtered" means no reply, usually a firewall.
- On Windows, `info` reads the gateway from `ipconfig` and DNS servers fall back to public defaults.
- Ideas for later: UDP scan, DNSSEC checks, web or terminal UI.
