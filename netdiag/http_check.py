"""HTTP(S) check with a timing breakdown: DNS -> TCP -> TLS -> first byte.

Knowing *which phase* is slow is the core of web troubleshooting.
"""
import socket
import ssl
import time
from urllib.parse import urlparse


def _ms(start):
    return round((time.perf_counter() - start) * 1000, 1)


def http_check(url, timeout=5.0, verify=True):
    if "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    host, https = parsed.hostname, parsed.scheme == "https"
    port = parsed.port or (443 if https else 80)
    path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
    result = {"url": url, "timings_ms": {}}
    timings = result["timings_ms"]
    sock = None

    try:
        t = time.perf_counter()
        family, stype, proto, _, addr = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)[0]
        timings["dns"] = _ms(t)
        result["ip"] = addr[0]

        t = time.perf_counter()
        sock = socket.socket(family, stype, proto)
        sock.settimeout(timeout)
        sock.connect(addr)
        timings["tcp_connect"] = _ms(t)

        if https:
            ctx = ssl.create_default_context()
            if not verify:
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            t = time.perf_counter()
            sock = ctx.wrap_socket(sock, server_hostname=host)
            timings["tls_handshake"] = _ms(t)
            result["tls_version"] = sock.version()
            cert = sock.getpeercert()
            if cert:
                expires = ssl.cert_time_to_seconds(cert["notAfter"])
                result["cert_days_left"] = int((expires - time.time()) // 86400)

        request = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: netdiag/1.0\r\n"
                   "Accept: */*\r\nConnection: close\r\n\r\n")
        t = time.perf_counter()
        sock.sendall(request.encode())
        first = sock.recv(1)
        timings["first_byte"] = _ms(t)
        raw = first
        while b"\r\n\r\n" not in raw and len(raw) < 65536:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
        head = raw.split(b"\r\n\r\n")[0].decode("iso-8859-1").split("\r\n")
        parts = head[0].split(" ", 2)
        result["status"] = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
        result["reason"] = parts[2] if len(parts) > 2 else ""
        result["headers"] = {k.strip().lower(): v.strip()
                             for k, _, v in (h.partition(":") for h in head[1:])}
        timings["total"] = round(sum(timings.values()), 1)
    except ssl.SSLCertVerificationError as exc:
        result["error"] = f"TLS certificate verification failed: {exc.verify_message}"
    except ssl.SSLError as exc:
        result["error"] = f"TLS error: {exc}"
    except socket.gaierror as exc:
        result["error"] = f"DNS resolution failed: {exc}"
    except socket.timeout:
        result["error"] = "timed out"
    except OSError as exc:
        result["error"] = exc.strerror or str(exc)
    finally:
        if sock:
            sock.close()
    return result
