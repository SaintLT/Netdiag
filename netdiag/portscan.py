"""Threaded TCP connect scanner with optional banner grabbing.

Only scan systems you own or have explicit permission to test.
"""
import platform
import socket
from concurrent.futures import ThreadPoolExecutor

# Windows retries a refused connection for ~2 seconds before reporting it, so a
# shorter timeout would mislabel closed ports as "filtered".
MIN_TIMEOUT = 2.5 if platform.system() == "Windows" else 0.0

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
                1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]
HTTP_PORTS = {80, 8000, 8080, 8888}


def parse_ports(spec):
    """'22,80,8000-8010' -> sorted list of unique ports."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            if lo > hi:
                raise ValueError(f"invalid range: {part}")
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad or not ports:
        raise ValueError("ports must be between 1 and 65535")
    return sorted(ports)


def service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def _grab_banner(sock, port):
    sock.settimeout(0.7)
    try:
        if port in HTTP_PORTS:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        data = sock.recv(256)
    except OSError:
        return ""
    return data.decode("utf-8", "replace").strip().splitlines()[0][:100] if data.strip() else ""


def scan_port(family, addr_base, port, timeout, banner):
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((addr_base[0], port))
    except ConnectionRefusedError:
        state, info = "closed", ""
    except (socket.timeout, OSError):
        state, info = "filtered", ""  # no answer: likely a firewall dropping packets
    else:
        state, info = "open", _grab_banner(sock, port) if banner else ""
    finally:
        sock.close()
    return {"port": port, "state": state, "service": service_name(port), "banner": info}


def scan(host, ports, timeout=1.0, workers=100, banner=False):
    try:
        family, _, _, _, addr = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)[0]
    except socket.gaierror as exc:
        return {"host": host, "error": f"DNS resolution failed: {exc}"}
    base = (addr[0],)
    timeout = max(timeout, MIN_TIMEOUT)
    with ThreadPoolExecutor(max_workers=min(workers, len(ports))) as pool:
        results = list(pool.map(lambda p: scan_port(family, base, p, timeout, banner), ports))
    results.sort(key=lambda r: r["port"])
    counts = {s: sum(r["state"] == s for r in results) for s in ("open", "closed", "filtered")}
    return {"host": host, "ip": addr[0], "scanned": len(ports), "counts": counts, "results": results}
