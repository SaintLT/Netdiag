"""Local network facts: hostname, local IP, default gateway, DNS servers.

First step of any troubleshooting: is *this* machine configured sanely?
"""
import platform
import re
import socket
import struct
import subprocess

from .dns_tools import DEFAULT_NAMESERVERS, detect_nameservers


def local_ip():
    """The IP used for outbound traffic. A UDP 'connect' sends no packets."""
    for target, family in (("8.8.8.8", socket.AF_INET), ("2001:4860:4860::8888", socket.AF_INET6)):
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.connect((target, 80))
                return sock.getsockname()[0]
        except OSError:
            continue
    return None


def _run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def default_gateway():
    system = platform.system()
    if system == "Linux":
        try:
            with open("/proc/net/route") as fh:
                next(fh)
                for line in fh:
                    f = line.split()
                    if f[1] == "00000000":
                        return socket.inet_ntoa(struct.pack("<L", int(f[2], 16)))
        except (OSError, StopIteration, IndexError, ValueError):
            pass
        m = re.search(r"default via (\S+)", _run(["ip", "route", "show", "default"]))
        return m.group(1) if m else None
    if system == "Darwin":
        m = re.search(r"gateway:\s*(\S+)", _run(["route", "-n", "get", "default"]))
        return m.group(1) if m else None
    if system == "Windows":
        m = re.search(r"Default Gateway[ .]*:\s*(\d+\.\d+\.\d+\.\d+)", _run(["ipconfig"]))
        return m.group(1) if m else None
    return None


def gather_info():
    detected = detect_nameservers()
    return {
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()}",
        "local_ip": local_ip(),
        "default_gateway": default_gateway(),
        "dns_servers": detected or list(DEFAULT_NAMESERVERS),
        "dns_source": "system" if detected else "defaults (system DNS not detected)",
    }