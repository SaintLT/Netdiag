"""Thin wrappers around the OS ping and traceroute programs.

ICMP and TTL-based tracing need raw sockets (admin rights), so rather than
reimplement them we run the system tools and stream their output.
"""
import platform
import shutil
import subprocess

IS_WINDOWS = platform.system() == "Windows"


def _run(cmd):
    """Stream a command's output line by line; return its exit code."""
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    except OSError as exc:
        print(f"Could not run {cmd[0]}: {exc}")
        return 127
    try:
        for line in proc.stdout:
            print(line.rstrip())
        return proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        return 130


def icmp_ping(host, count=4):
    if not shutil.which("ping"):
        print("`ping` was not found on this system. Try the TCP ping instead (without --icmp).")
        return 127
    return _run(["ping", "-n" if IS_WINDOWS else "-c", str(count), host])


def traceroute(host, max_hops=30):
    if IS_WINDOWS and shutil.which("tracert"):
        return _run(["tracert", "-h", str(max_hops), host])
    if shutil.which("traceroute"):
        return _run(["traceroute", "-m", str(max_hops), host])
    if shutil.which("tracepath"):
        return _run(["tracepath", "-m", str(max_hops), host])
    print("No traceroute tool found (looked for tracert, traceroute, tracepath). "
          "Install one, e.g. `sudo apt install traceroute`.")
    return 127
