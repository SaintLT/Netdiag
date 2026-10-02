"""Command-line interface: python -m netdiag <command> [options]"""
import argparse
import datetime
import ipaddress
import json
import socket
import sys
import time
from urllib.parse import urlparse

from . import __version__
from .dns_tools import RECORD_TYPES, lookup, reverse_name, system_nameservers
from .http_check import http_check
from .info import gather_info
from .portscan import COMMON_PORTS, parse_ports, scan
from .report import render_html
from .system_tools import icmp_ping, traceroute
from .tcp_ping import summarize, tcp_ping


def emit(args, data, render):
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        render(data)


def clean_host(value):
    """Accept 'example.com', 'https://example.com/path' or 'example.com:8080'."""
    if "://" in value:
        return urlparse(value).hostname or value
    return value.split("/")[0].split(":")[0] if value.count(":") == 1 else value


# ---------- renderers ----------

def render_info(r):
    print(f"Hostname:        {r['hostname']}  ({r['os']})")
    print(f"Local IP:        {r['local_ip'] or 'unknown (no route to the internet?)'}")
    print(f"Default gateway: {r['default_gateway'] or 'unknown'}")
    note = "" if r.get("dns_source", "system") == "system" else "  (public defaults - system DNS not detected)"
    print(f"DNS servers:     {', '.join(r['dns_servers'])}{note}")


def render_ping(r):
    if "error" in r:
        print(f"Error: {r['error']}")
        return
    print(f"--- {r['host']} ({r['ip']}:{r['port']}) TCP ping statistics ---")
    print(f"{r['sent']} sent, {r['received']} received, {r['loss_pct']}% loss")
    if r["received"]:
        print(f"rtt min/avg/max/jitter = {r['min_ms']}/{r['avg_ms']}/{r['max_ms']}/{r['jitter_ms']} ms")


def render_dns(results):
    for r in results:
        head = f"; {r['name']} {r['qtype']} @ {r['server']}"
        if "error" in r:
            print(f"{head}\n  error: {r['error']}")
            continue
        print(f"{head}  [{r['rcode']}, {r['elapsed_ms']} ms]")
        if not r["answers"]:
            print("  (no records)")
        for a in r["answers"]:
            print(f"  {a['name']:<30} {a['ttl']:>6}  {a['type']:<6} {a['data']}")


def render_scan(r):
    if "error" in r:
        print(f"Error: {r['error']}")
        return
    c = r["counts"]
    print(f"Scan of {r['host']} ({r['ip']}): {r['scanned']} ports - "
          f"{c['open']} open, {c['closed']} closed, {c['filtered']} filtered")
    for p in r["results"]:
        if p["state"] == "open":
            banner = f"  {p['banner']}" if p["banner"] else ""
            print(f"  {p['port']:>5}/tcp  open  {p['service']}{banner}")


def render_http(r):
    if "status" in r:
        print(f"{r['url']} -> {r['status']} {r['reason']}")
    else:
        print(f"{r['url']} -> FAILED: {r.get('error', 'unknown error')}")
    if r.get("ip"):
        print(f"  IP: {r['ip']}" + (f"   TLS: {r['tls_version']}" if r.get("tls_version") else ""))
    for phase, ms in r["timings_ms"].items():
        print(f"  {phase:<14}{ms:>9.1f} ms")
    if "cert_days_left" in r:
        print(f"  certificate expires in {r['cert_days_left']} days")
    if r.get("headers", {}).get("location"):
        print(f"  redirects to: {r['headers']['location']}")


# ---------- commands ----------

def cmd_ping(args):
    if args.icmp:
        return icmp_ping(args.host, args.count)

    def live(seq, ip, port, rtt, status):
        shown = f"time={rtt:.1f} ms" if rtt is not None else status
        print(f"[{seq}] {ip}:{port}  {shown}", file=sys.stderr if args.json else sys.stdout)

    result = tcp_ping(args.host, args.port, args.count, args.timeout, on_result=live)
    emit(args, result, render_ping)
    return 0 if result.get("received") else 1


def cmd_dns(args):
    servers = args.server or [system_nameservers()[0]]
    results = [lookup(args.name, t.upper(), s, timeout=args.timeout)
               for s in servers for t in args.type]
    emit(args, results, render_dns)
    return 0 if all("error" not in r for r in results) else 1


def cmd_scan(args):
    try:
        ports = parse_ports(args.ports) if args.ports else COMMON_PORTS
    except ValueError as exc:
        print(f"Invalid --ports: {exc}")
        return 2
    result = scan(args.host, ports, args.timeout, args.workers, args.banner)
    emit(args, result, render_scan)
    return 1 if "error" in result else 0


def cmd_http(args):
    result = http_check(args.url, args.timeout, verify=not args.insecure)
    emit(args, result, render_http)
    return 0 if "status" in result else 1


def cmd_trace(args):
    return traceroute(args.host, args.max_hops)


def cmd_rdns(args):
    try:
        name = reverse_name(args.ip)
    except ValueError:
        print(f"Invalid IP address: {args.ip}")
        return 2
    servers = args.server or [system_nameservers()[0]]
    results = [lookup(name, "PTR", s, timeout=args.timeout) for s in servers]
    emit(args, results, render_dns)
    return 0 if all("error" not in r for r in results) else 1


def cmd_info(args):
    emit(args, gather_info(), render_info)
    return 0


def cmd_monitor(args):
    """Probe repeatedly and show running loss/latency until Ctrl+C (or --count)."""
    rtts, sent, ip = [], 0, None
    print(f"Monitoring {args.host}:{args.port} every {args.interval}s - Ctrl+C to stop")
    try:
        while args.count == 0 or sent < args.count:
            r = tcp_ping(args.host, args.port, count=1, timeout=args.timeout, interval=0)
            if "error" in r:
                print(f"Error: {r['error']}")
                return 1
            sent += 1
            ip = r["ip"]
            if r["received"]:
                rtts.append(r["avg_ms"])
                shown = f"{r['avg_ms']:.1f} ms"
            else:
                shown = "FAILED"
            loss = (sent - len(rtts)) / sent * 100
            avg = sum(rtts) / len(rtts) if rtts else 0
            print(f"[{sent}] {shown:>10} | loss {loss:5.1f}% | avg {avg:.1f} ms")
            if args.count == 0 or sent < args.count:
                time.sleep(args.interval)
    except KeyboardInterrupt:
        print()
    if sent:
        print()
        render_ping(summarize(args.host, ip, args.port, sent, rtts))
    return 0 if rtts else 1


def cmd_diag(args):
    """Run the main checks and print plain-language findings."""
    host = clean_host(args.target)
    findings = []
    report = {"target": host, "generated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

    print("== This machine ==")
    report["info"] = gather_info()
    render_info(report["info"])

    print("\n== DNS ==")
    try:
        ipaddress.ip_address(host)
        print("  (target is an IP address - skipping DNS)")
        dns, resolved = [], True
    except ValueError:
        dns = [lookup(host, t) for t in ("A", "AAAA")]
        render_dns(dns)
        resolved = any(r.get("answers") for r in dns)
        if not resolved:
            # The resolver says no, but the OS may still know the name (hosts file, local DNS).
            try:
                os_ip = socket.getaddrinfo(host, None)[0][4][0]
                print(f"  note: the resolver returned nothing, but the OS resolves it to {os_ip} "
                      "(hosts file or local DNS)")
                resolved = True
            except socket.gaierror:
                pass
    report["dns"] = dns
    if not resolved:
        findings.append("DNS: the name did not resolve - check the hostname and your resolver.")

    print("\n== TCP latency (port 443) ==")
    ping = tcp_ping(host, 443, count=5, timeout=2.0, interval=0.3)
    render_ping(ping)
    report["ping"] = ping
    if "error" not in ping:
        if ping["received"] == 0:
            findings.append("Connectivity: port 443 unreachable - host down, firewall, or no HTTPS.")
        elif ping["loss_pct"] > 0:
            findings.append(f"Packet loss: {ping['loss_pct']}% of connection attempts failed.")
        if ping.get("jitter_ms", 0) > 50:
            findings.append(f"Jitter is high ({ping['jitter_ms']} ms) - unstable link.")

    print("\n== HTTPS ==")
    web = http_check(host)
    render_http(web)
    report["http"] = web
    if "error" in web:
        findings.append(f"HTTPS: {web['error']}")
    else:
        if web["status"] >= 500:
            findings.append(f"HTTPS: server error {web['status']}.")
        elif web["status"] >= 400:
            findings.append(f"HTTPS: server answered {web['status']} {web['reason']} "
                            "(blocked, login required, or page not found).")
        if web.get("cert_days_left", 999) < 14:
            findings.append(f"TLS: certificate expires in {web['cert_days_left']} days.")
        for phase, ms in web["timings_ms"].items():
            if phase != "total" and ms > 1000:
                findings.append(f"Slow {phase}: {ms} ms.")

    print("\n== Common ports ==")
    ports = scan(host, COMMON_PORTS, timeout=1.0)
    render_scan(ports)
    report["ports"] = ports

    print("\n== Findings ==")
    if findings:
        for f in findings:
            print(f"  ! {f}")
    else:
        print("  No problems detected.")
    report["findings"] = findings
    if args.json_file:
        with open(args.json_file, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"\nJSON report saved to {args.json_file}")
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(render_html(report))
        print(f"\nHTML report saved to {args.html}")
    return 1 if findings else 0


# ---------- parser ----------

def build_parser():
    parser = argparse.ArgumentParser(prog="netdiag", description="Network Diagnostic Toolkit")
    parser.add_argument("--version", action="version", version=f"netdiag {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add(name, func, help_):
        p = sub.add_parser(name, help=help_)
        p.set_defaults(func=func)
        return p

    p = add("ping", cmd_ping, "Latency/loss test (TCP by default, --icmp for system ping)")
    p.add_argument("host")
    p.add_argument("-p", "--port", type=int, default=443)
    p.add_argument("-c", "--count", type=int, default=4)
    p.add_argument("-t", "--timeout", type=float, default=2.0)
    p.add_argument("--icmp", action="store_true", help="use the system ICMP ping instead")
    p.add_argument("--json", action="store_true")

    p = add("dns", cmd_dns, "Query DNS records, optionally against specific resolvers")
    p.add_argument("name")
    p.add_argument("-t", "--type", nargs="+", default=["A"], choices=list(RECORD_TYPES), type=str.upper)
    p.add_argument("-s", "--server", action="append", help="resolver IP (repeat to compare)")
    p.add_argument("--timeout", type=float, default=3.0)
    p.add_argument("--json", action="store_true")

    p = add("scan", cmd_scan, "TCP port scan (only scan hosts you have permission to test)")
    p.add_argument("host")
    p.add_argument("-p", "--ports", help="e.g. 22,80,8000-8100 (default: common ports)")
    p.add_argument("--timeout", type=float, default=1.0)
    p.add_argument("--workers", type=int, default=100)
    p.add_argument("--banner", action="store_true", help="grab service banners from open ports")
    p.add_argument("--json", action="store_true")

    p = add("http", cmd_http, "HTTP(S) check with DNS/TCP/TLS/first-byte timings")
    p.add_argument("url")
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--insecure", action="store_true", help="skip certificate verification")
    p.add_argument("--json", action="store_true")

    p = add("trace", cmd_trace, "Trace the route (uses system traceroute/tracert)")
    p.add_argument("host")
    p.add_argument("--max-hops", type=int, default=30)

    p = add("rdns", cmd_rdns, "Reverse DNS: find the hostname for an IP (PTR lookup)")
    p.add_argument("ip")
    p.add_argument("-s", "--server", action="append", help="resolver IP (repeat to compare)")
    p.add_argument("--timeout", type=float, default=3.0)
    p.add_argument("--json", action="store_true")

    p = add("info", cmd_info, "Show this machine's IP, gateway and DNS servers")
    p.add_argument("--json", action="store_true")

    p = add("monitor", cmd_monitor, "Continuously probe a host and show live loss/latency")
    p.add_argument("host")
    p.add_argument("-p", "--port", type=int, default=443)
    p.add_argument("-i", "--interval", type=float, default=1.0)
    p.add_argument("-c", "--count", type=int, default=0, help="stop after N probes (0 = until Ctrl+C)")
    p.add_argument("-t", "--timeout", type=float, default=2.0)

    p = add("diag", cmd_diag, "Run DNS, latency, HTTPS and port checks with a findings summary")
    p.add_argument("target", help="hostname or URL")
    p.add_argument("--json-file", help="also save the full report as JSON")
    p.add_argument("--html", help="also save a shareable HTML report")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except BrokenPipeError:  # e.g. `netdiag scan ... --json | head`
        return 0
