# netdiag: Network Diagnostic Toolkit

A Python command-line toolkit that finds out *what is wrong* with a network connection and explains the
networking concept behind each result. Standard library only, so there is nothing to install but Python 3.8+.

`netdiag diag <host>` runs every check in one go and finishes with a plain-language list of problems.

![diag terminal output](docs/diag-terminal.png)

## Features

- **One-command diagnosis** of DNS, latency, HTTPS and open ports, with an HTML or JSON report
- **Hand-built DNS client** (UDP with TCP fallback, name compression) that can query specific resolvers and compare them
- **TCP latency, packet loss and jitter** with no admin rights, plus a live `monitor` mode
- **HTTPS timing breakdown**: DNS, TCP connect, TLS handshake and first byte, plus certificate expiry
- **Threaded port scanner** that tells open, closed and filtered ports apart
- **Local network info**: IP, default gateway and DNS servers (Windows, macOS, Linux)

![HTML report](docs/report.png)

## Install

```bash
git clone https://github.com/<your-username>/netdiag.git
cd netdiag
pip install -e .          # gives you the `netdiag` command
```

No install is needed to try it: `python -m netdiag diag example.com` works from the project folder.

On Windows, if `netdiag` is not recognized after installing, pip's Scripts folder is not on your PATH
(pip prints a warning with its location). Add that folder to PATH and reopen your terminal, or keep using
`python -m netdiag`.

## Usage

```bash
netdiag diag example.com --html report.html     # everything, with a shareable report
netdiag info                                    # this machine: IP, gateway, DNS servers
netdiag ping example.com -c 5                   # TCP latency, loss, jitter
netdiag monitor 1.1.1.1                         # live loss/latency until Ctrl+C
netdiag dns example.com -t A MX TXT             # DNS records
netdiag dns example.com -s 8.8.8.8 -s 1.1.1.1   # compare resolvers
netdiag rdns 8.8.8.8                            # reverse lookup
netdiag scan 192.168.1.1 -p 1-1024 --banner     # port scan
netdiag http https://example.com                # timing breakdown + certificate expiry
netdiag trace example.com                       # route (system traceroute/tracert)
```

`ping`, `dns`, `rdns`, `scan`, `http` and `info` accept `--json`.
Exit codes: `0` ok, `1` a problem was found, `2` bad input.

## Which command when

| Situation | Run |
|-----------|-----|
| Something is wrong, cause unknown | `netdiag diag <site>` |
| Is it the site or just me? | `netdiag http <site>` and `netdiag ping <site>` |
| Pages load slowly | `netdiag dns <site> -s <isp-dns> -s 8.8.8.8`, then `netdiag trace <site>` |
| Connection drops on and off | `netdiag monitor 1.1.1.1` |
| Checking what a device exposes | `netdiag scan <your own device>` |

## What each tool teaches

| Tool | Concept |
|------|---------|
| ping / monitor | TCP handshake time as RTT; loss and jitter |
| dns / rdns | DNS wire format, record types, resolver differences, NXDOMAIN vs timeout |
| scan | open / closed (RST) / filtered (silence) port states |
| http | where time goes: DNS, TCP, TLS, server response |
| trace | TTL expiry and hop-by-hop path |
| diag | reading symptoms to find the layer that is failing |

## Project layout

```
netdiag/
  cli.py          argument parsing, output formatting, the diag workflow
  tcp_ping.py     TCP handshake timing, loss, jitter
  dns_tools.py    hand-built DNS client
  portscan.py     threaded connect scanner, banner grabbing
  http_check.py   per-phase HTTP(S) timing, TLS version, certificate expiry
  info.py         local IP, gateway, DNS servers
  system_tools.py wrappers for system ping / traceroute
  report.py       self-contained HTML report
tests/            17 tests using local servers and a fake DNS server (no internet needed)
```

Each module returns plain dictionaries and never prints, so a GUI or web front end can reuse them.

## Tests

```bash
python -m unittest discover -s tests -v
```

## Notes and limits

- **Only scan systems you own or have permission to test.**
- `trace` and `ping --icmp` use the system tools; the toolkit does not send raw ICMP itself.
- Port scans are TCP connect scans. "Filtered" means no reply, usually a firewall.
- On Windows the scanner waits at least 2.5 s per port, because Windows is slow to report closed ports.
- Latency is measured with TCP handshakes, so it reflects what applications experience, not ICMP echo time.

## Roadmap

UDP scanning, DNSSEC checks, and a web or terminal interface.

## License

MIT. See [LICENSE](LICENSE).