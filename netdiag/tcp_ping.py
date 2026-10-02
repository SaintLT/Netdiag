"""TCP "ping": measure reachability and latency without needing root/ICMP.

Why TCP? Raw ICMP sockets need administrator rights on most systems, and many
networks drop ICMP. Timing a TCP handshake to an open port (e.g. 443) works
for everyone and measures something closer to what applications experience.
"""
import socket
import time


def tcp_ping(host, port=443, count=4, timeout=2.0, interval=1.0, on_result=None):
    """Connect to host:port `count` times and return latency statistics.

    on_result(seq, ip, port, rtt_ms_or_None, status) is called after each
    attempt so a CLI can print live output.
    """
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return {"host": host, "port": port, "error": f"DNS resolution failed: {exc}"}

    family, stype, proto, _, addr = infos[0]
    rtts = []
    for seq in range(1, count + 1):
        sock = socket.socket(family, stype, proto)
        sock.settimeout(timeout)
        rtt = None
        start = time.perf_counter()
        try:
            sock.connect(addr)
            rtt = (time.perf_counter() - start) * 1000
            rtts.append(rtt)
            status = "ok"
        except socket.timeout:
            status = "timeout"
        except ConnectionRefusedError:
            status = "refused"
        except OSError as exc:
            status = exc.strerror or str(exc)
        finally:
            sock.close()
        if on_result:
            on_result(seq, addr[0], port, rtt, status)
        if seq < count:
            time.sleep(interval)

    return summarize(host, addr[0], port, count, rtts)


def summarize(host, ip, port, sent, rtts):
    received = len(rtts)
    result = {
        "host": host,
        "ip": ip,
        "port": port,
        "sent": sent,
        "received": received,
        "loss_pct": round((sent - received) / sent * 100, 1) if sent else 0.0,
    }
    if rtts:
        # Jitter = mean absolute difference between consecutive samples (RFC 3550 style).
        diffs = [abs(a - b) for a, b in zip(rtts, rtts[1:])]
        result.update(
            min_ms=round(min(rtts), 2),
            avg_ms=round(sum(rtts) / received, 2),
            max_ms=round(max(rtts), 2),
            jitter_ms=round(sum(diffs) / len(diffs), 2) if diffs else 0.0,
        )
    return result
