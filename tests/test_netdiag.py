import socket
import struct
import threading
import io
import json
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, HTTPServer

from netdiag import cli, dns_tools
from netdiag.info import gather_info
from netdiag.report import render_html
from netdiag.http_check import http_check
from netdiag.portscan import parse_ports, scan
from netdiag.tcp_ping import tcp_ping, summarize


class QuietHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def start_http():
    server = HTTPServer(("127.0.0.1", 0), QuietHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def stop(server):
    server.shutdown()
    server.server_close()


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class FakeDNS(threading.Thread):
    """UDP server that answers every query with A=192.0.2.7 using name compression."""
    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]

    def run(self):
        data, addr = self.sock.recvfrom(512)
        header = struct.pack("!HHHHHH", struct.unpack("!H", data[:2])[0], 0x8180, 1, 1, 0, 0)
        question = data[12:]
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + bytes([192, 0, 2, 7])
        self.sock.sendto(header + question + answer, addr)
        self.sock.close()


class Tests(unittest.TestCase):
    def test_parse_ports(self):
        self.assertEqual(parse_ports("80, 22,8000-8002"), [22, 80, 8000, 8001, 8002])
        with self.assertRaises(ValueError):
            parse_ports("70000")
        with self.assertRaises(ValueError):
            parse_ports("10-5")

    def test_scan_open_and_closed(self):
        server = start_http()
        open_port = server.server_address[1]
        closed_port = free_port()
        r = scan("127.0.0.1", [open_port, closed_port], timeout=1)
        states = {p["port"]: p["state"] for p in r["results"]}
        self.assertEqual(states[open_port], "open")
        self.assertEqual(states[closed_port], "closed")
        stop(server)

    def test_tcp_ping(self):
        server = start_http()
        r = tcp_ping("127.0.0.1", server.server_address[1], count=3, interval=0.01)
        self.assertEqual(r["received"], 3)
        self.assertEqual(r["loss_pct"], 0.0)
        stop(server)
        r = tcp_ping("127.0.0.1", free_port(), count=2, interval=0.01)
        self.assertEqual(r["loss_pct"], 100.0)

    def test_summarize_jitter(self):
        r = summarize("h", "1.1.1.1", 443, 4, [10.0, 20.0, 10.0])
        self.assertEqual(r["jitter_ms"], 10.0)
        self.assertEqual(r["loss_pct"], 25.0)

    def test_http_check(self):
        server = start_http()
        r = http_check(f"http://127.0.0.1:{server.server_address[1]}/")
        self.assertEqual(r["status"], 200)
        self.assertIn("first_byte", r["timings_ms"])
        stop(server)

    def test_http_check_failure(self):
        r = http_check(f"http://127.0.0.1:{free_port()}/")
        self.assertIn("error", r)

    def test_dns_lookup_against_fake_server(self):
        fake = FakeDNS()
        fake.start()
        r = dns_tools.lookup("example.test", "A", "127.0.0.1", port=fake.port, timeout=2)
        self.assertEqual(r["rcode"], "NOERROR")
        self.assertEqual(r["answers"][0]["data"], "192.0.2.7")
        self.assertEqual(r["answers"][0]["name"], "example.test")

    def test_dns_timeout(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))  # listens, never replies
        r = dns_tools.lookup("example.test", "A", "127.0.0.1", port=s.getsockname()[1], timeout=0.3)
        self.assertIn("timeout", r["error"])
        s.close()

    def test_read_name_loop_protection(self):
        with self.assertRaises(dns_tools.DNSError):
            dns_tools.read_name(b"\xc0\x00", 0)


class NewFeatureTests(unittest.TestCase):
    def test_reverse_name(self):
        self.assertEqual(dns_tools.reverse_name("8.8.4.4"), "4.4.8.8.in-addr.arpa")
        self.assertTrue(dns_tools.reverse_name("2001:db8::1").endswith("ip6.arpa"))
        with self.assertRaises(ValueError):
            dns_tools.reverse_name("not-an-ip")

    def test_ptr_record_decoding(self):
        name = b"\x03www\x07example\x03com\x00"
        self.assertEqual(dns_tools._decode_rdata(12, name, 0, len(name)), "www.example.com")

    def test_gather_info_shape(self):
        info = gather_info()
        for key in ("hostname", "os", "local_ip", "default_gateway", "dns_servers"):
            self.assertIn(key, info)
        self.assertIsInstance(info["dns_servers"], list)

    def test_html_report_escapes_and_renders(self):
        report = {"target": "<script>x</script>", "generated": "now",
                  "findings": ["DNS: broken <b>"], "dns": [], "ping": {"error": "boom"},
                  "http": {"url": "https://a", "status": 200, "reason": "OK",
                           "timings_ms": {"dns": 5.0, "tcp_connect": 10.0, "total": 15.0}},
                  "ports": {"scanned": 1, "counts": {"open": 1, "closed": 0, "filtered": 0},
                            "results": [{"port": 80, "state": "open", "service": "http", "banner": ""}]}}
        out = render_html(report)
        self.assertNotIn("<script>x", out)
        self.assertIn("&lt;script&gt;", out)
        self.assertIn("80/tcp", out)

    def run_cli(self, argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main(argv)
        return code, buf.getvalue()

    def test_cli_monitor_and_scan_json(self):
        server = start_http()
        port = str(server.server_address[1])
        code, out = self.run_cli(["monitor", "127.0.0.1", "-p", port, "-c", "3", "-i", "0.01"])
        self.assertEqual(code, 0)
        self.assertIn("3 sent, 3 received", out)
        code, out = self.run_cli(["scan", "127.0.0.1", "-p", port, "--json"])
        self.assertEqual(json.loads(out)["counts"]["open"], 1)
        stop(server)

    def test_cli_bad_inputs(self):
        self.assertEqual(self.run_cli(["rdns", "nope"])[0], 2)
        self.assertEqual(self.run_cli(["scan", "127.0.0.1", "-p", "99999"])[0], 2)
        self.assertEqual(self.run_cli(["monitor", "127.0.0.1", "-p", str(free_port()), "-c", "1"])[0], 1)

    def test_clean_host(self):
        self.assertEqual(cli.clean_host("https://example.com/path?q=1"), "example.com")
        self.assertEqual(cli.clean_host("example.com:8080"), "example.com")
        self.assertEqual(cli.clean_host("example.com"), "example.com")


if __name__ == "__main__":
    unittest.main()
