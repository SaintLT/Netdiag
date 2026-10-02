"""A small DNS client built directly on the wire format (RFC 1035).

Writing it by hand lets you query a *specific* resolver, see the response code
and timing, and compare resolvers - things the OS resolver hides from you.
"""
import ipaddress
import platform
import random
import socket
import struct
import subprocess
import time

RECORD_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28}
TYPE_NAMES = {v: k for k, v in RECORD_TYPES.items()}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


class DNSError(Exception):
    pass


DEFAULT_NAMESERVERS = ["8.8.8.8", "1.1.1.1"]


def _is_usable_ip(text):
    try:
        ip = ipaddress.ip_address(text.split("%")[0])
    except ValueError:
        return False
    # fe80:: / fec0:: addresses need a scope id to be reachable, so skip them
    return not (ip.is_link_local or getattr(ip, "is_site_local", False))


def parse_ipconfig_dns(text):
    """Pull DNS server addresses out of Windows `ipconfig /all` output."""
    servers, collecting = [], False
    for line in text.splitlines():
        stripped = line.strip()
        if "DNS Servers" in line and ":" in line:
            collecting = True
            stripped = line.split(":", 1)[1].strip()
        elif not (collecting and stripped and ". :" not in line and _is_usable_ip(stripped)):
            collecting = False
            continue
        if _is_usable_ip(stripped) and stripped not in servers:
            servers.append(stripped)
    return servers


def detect_nameservers():
    """The resolvers this machine is configured to use, or [] if undetectable."""
    if platform.system() == "Windows":
        try:
            out = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True,
                                 errors="replace", timeout=5).stdout
        except (OSError, subprocess.SubprocessError):
            return []
        return parse_ipconfig_dns(out)
    servers = []
    try:
        with open("/etc/resolv.conf") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    servers.append(parts[1])
    except OSError:
        pass
    return servers


def system_nameservers():
    """Configured resolvers, falling back to public ones if none can be found."""
    return detect_nameservers() or list(DEFAULT_NAMESERVERS)


def reverse_name(ip):
    """'8.8.8.8' -> '8.8.8.8.in-addr.arpa' (works for IPv6 too). Raises ValueError."""
    return ipaddress.ip_address(ip).reverse_pointer


def build_query(name, qtype):
    tid = random.randint(0, 0xFFFF)
    header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)  # RD (recursion desired) set
    qname = b"".join(
        bytes([len(label)]) + label
        for label in (p.encode("idna") for p in name.rstrip(".").split("."))
    ) + b"\x00"
    return tid, header + qname + struct.pack("!HH", qtype, 1)


def read_name(data, offset):
    """Decode a (possibly compressed) domain name. Returns (name, next_offset)."""
    labels, jumped, end, hops = [], False, offset, 0
    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            if not jumped:
                end = offset + 2
            jumped = True
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            hops += 1
            if hops > 20:
                raise DNSError("compression pointer loop")
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels), (end if jumped else offset)


def parse_response(data, expected_id):
    if len(data) < 12:
        raise DNSError("response too short")
    tid, flags, qd, an, _, _ = struct.unpack("!HHHHHH", data[:12])
    if tid != expected_id:
        raise DNSError("transaction ID mismatch")
    offset = 12
    for _ in range(qd):
        _, offset = read_name(data, offset)
        offset += 4
    answers = []
    for _ in range(an):
        name, offset = read_name(data, offset)
        rtype, _, ttl, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        answers.append({
            "name": name,
            "type": TYPE_NAMES.get(rtype, str(rtype)),
            "ttl": ttl,
            "data": _decode_rdata(rtype, data, offset, rdlen),
        })
        offset += rdlen
    return {"rcode": RCODES.get(flags & 0xF, str(flags & 0xF)),
            "truncated": bool(flags & 0x0200), "answers": answers}


def _decode_rdata(rtype, data, offset, rdlen):
    rdata = data[offset:offset + rdlen]
    if rtype == 1:
        return socket.inet_ntop(socket.AF_INET, rdata)
    if rtype == 28:
        return socket.inet_ntop(socket.AF_INET6, rdata)
    if rtype in (2, 5, 12):
        return read_name(data, offset)[0]
    if rtype == 15:
        pref = struct.unpack("!H", rdata[:2])[0]
        return f"{pref} {read_name(data, offset + 2)[0] or '.'}"
    if rtype == 16:
        parts, i = [], 0
        while i < len(rdata):
            n = rdata[i]
            parts.append(rdata[i + 1:i + 1 + n].decode("utf-8", "replace"))
            i += 1 + n
        return "".join(parts)
    if rtype == 6:
        mname, off = read_name(data, offset)
        rname, off = read_name(data, off)
        serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", data[off:off + 20])
        return f"{mname} {rname} serial={serial} refresh={refresh} retry={retry} expire={expire} min={minimum}"
    return rdata.hex()


def _udp_exchange(server, port, packet, timeout):
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (server, port))
        return sock.recvfrom(4096)[0]


def _tcp_exchange(server, port, packet, timeout):
    with socket.create_connection((server, port), timeout=timeout) as sock:
        sock.sendall(struct.pack("!H", len(packet)) + packet)
        length = struct.unpack("!H", _recv_exact(sock, 2))[0]
        return _recv_exact(sock, length)


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise DNSError("connection closed early")
        buf += chunk
    return buf


def lookup(name, qtype="A", server=None, port=53, timeout=3.0):
    """Query one nameserver. Always returns a dict; check the 'error' key."""
    server = server or system_nameservers()[0]
    result = {"name": name, "qtype": qtype.upper(), "server": server}
    if qtype.upper() not in RECORD_TYPES:
        result["error"] = f"unsupported record type (use one of {', '.join(RECORD_TYPES)})"
        return result
    tid, packet = build_query(name, RECORD_TYPES[qtype.upper()])
    start = time.perf_counter()
    try:
        data = _udp_exchange(server, port, packet, timeout)
        parsed = parse_response(data, tid)
        if parsed["truncated"]:  # response too big for UDP: retry over TCP
            data = _tcp_exchange(server, port, packet, timeout)
            parsed = parse_response(data, tid)
            result["via"] = "tcp"
    except socket.timeout:
        result["error"] = "timeout (no response from server)"
        return result
    except (OSError, DNSError, UnicodeError) as exc:
        result["error"] = str(exc)
        return result
    result["elapsed_ms"] = round((time.perf_counter() - start) * 1000, 1)
    result.update(rcode=parsed["rcode"], answers=parsed["answers"])
    return result
