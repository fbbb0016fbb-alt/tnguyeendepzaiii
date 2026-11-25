"""Personal DNS-over-HTTPS gateway; Python 3.11+, no third-party packages."""
from __future__ import annotations

import argparse
import base64
import binascii
import hmac
import ipaddress
import json
import os
from pathlib import Path
import secrets
import struct
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parent
MAX_MESSAGE = 65535
TYPES = {"A": 1, "AAAA": 28, "HTTPS": 65}


def read_name(packet, start):
    labels, offset, end, seen = [], start, None, set()
    while True:
        if offset >= len(packet) or offset in seen:
            raise ValueError("Truncated or cyclic DNS name")
        seen.add(offset)
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("Truncated DNS pointer")
            end = end if end is not None else offset + 2
            offset = ((length & 0x3F) << 8) | packet[offset + 1]
            continue
        if length & 0xC0:
            raise ValueError("Invalid DNS label")
        offset += 1
        if not length:
            break
        if offset + length > len(packet):
            raise ValueError("Truncated DNS label")
        labels.append(packet[offset:offset + length].decode("ascii").lower())
        offset += length
        if sum(len(s) + 1 for s in labels) > 254:
            raise ValueError("DNS name too long")
    return ".".join(labels), end if end is not None else offset


def parse_question(packet):
    if not 12 <= len(packet) <= MAX_MESSAGE:
        raise ValueError("Invalid DNS message size")
    ident, flags, qd, an, ns, ar = struct.unpack("!6H", packet[:12])
    if flags & 0xF800 or qd != 1 or an or ns:
        raise ValueError("Only single-question standard DNS queries are supported")
    name, end = read_name(packet, 12)
    if end + 4 > len(packet):
        raise ValueError("Missing DNS question fields")
    qtype, qclass = struct.unpack("!HH", packet[end:end + 4])
    return ident, flags, name, qtype, qclass, end + 4


def question_bytes(name, qtype, qclass=1):
    labels = name.rstrip(".").encode("idna").split(b".") if name.rstrip(".") else []
    if any(not label or len(label) > 63 for label in labels):
        raise ValueError("Invalid DNS labels")
    result = b"".join(bytes([len(label)]) + label for label in labels) + b"\0"
    if len(result) > 255:
        raise ValueError("DNS name too long")
    return result + struct.pack("!HH", qtype, qclass)


def make_query(name, qtype=1):
    return struct.pack("!6H", secrets.randbelow(65536), 0x0100, 1, 0, 0, 0) + question_bytes(name, qtype)


def local_answer(query, ip=None, ttl=60, rcode=0):
    ident, flags, name, qtype, qclass, _ = parse_question(query)
    question = question_bytes(name, qtype, qclass)
    data = ipaddress.ip_address(ip).packed if ip else None
    count = int(data is not None)
    # A rewritten answer is not DNSSEC authenticated; preserve only RD and CD.
    header = struct.pack("!6H", ident, 0x8080 | (flags & 0x0110) | rcode, 1, count, 0, 0)
    rr = b""
    if data is not None:
        rr = b"\xc0\x0c" + struct.pack("!HHIH", qtype, qclass, ttl, len(data)) + data
    return header + question + rr


def read_config(path):
    config = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    config["redirect_ipv4"] = str(ipaddress.IPv4Address(config["redirect_ipv4"]))
    if not 0 <= config.get("ttl", 60) <= 86400:
        raise ValueError("TTL must be between 0 and 86400")
    for upstream in config["upstreams"]:
        if urllib.parse.urlsplit(upstream).scheme != "https":
            raise ValueError("Upstream DNS must use HTTPS")
    if not config["upstreams"]:
        raise ValueError("At least one upstream is required")
    return config


class Resolver:
    def __init__(self, config):
        self.config = config
        self.blocked = set(config["block_domains"])
        self.redirected = set(config["redirect_domains"])

    def resolve(self, query):
        _, _, name, qtype, qclass, _ = parse_question(query)
        ttl = self.config.get("ttl", 60)
        # Exact names only: the reference snapshot does not prove wildcard rules.
        if qclass == 1 and name in self.blocked:
            ip = "0.0.0.0" if qtype == 1 else None
            return local_answer(query, ip, ttl)
        if qclass == 1 and name in self.redirected:
            if qtype == 1:
                return local_answer(query, self.config["redirect_ipv4"], ttl)
            # Avoid leaking a competing address through AAAA or HTTPS/SVCB hints.
            if qtype in (28, 64, 65):
                return local_answer(query, ttl=ttl)
        for upstream in self.config["upstreams"]:
            try:
                req = urllib.request.Request(upstream, data=query, headers={
                    "Content-Type": "application/dns-message", "Accept": "application/dns-message",
                    "User-Agent": "PersonalDNS/1.0",
                })
                with urllib.request.urlopen(req, timeout=6) as response:
                    body = response.read(MAX_MESSAGE + 1)
                    content_type = response.headers.get_content_type()
                if content_type != "application/dns-message" or not 12 <= len(body) <= MAX_MESSAGE:
                    raise ValueError("Invalid upstream content")
                flags = struct.unpack("!H", body[2:4])[0]
                if not flags & 0x8000 or body[:2] != query[:2]:
                    raise ValueError("Invalid upstream DNS response")
                if struct.unpack("!H", body[4:6])[0] != 1:
                    raise ValueError("Invalid upstream question count")
                reply_name, end = read_name(body, 12)
                if reply_name != name or body[end:end + 4] != struct.pack("!HH", qtype, qclass):
                    raise ValueError("Upstream DNS question mismatch")
                return body
            except (OSError, ValueError, UnicodeError):
                continue
        return local_answer(query, rcode=2)  # SERVFAIL, not a false NXDOMAIN.


class Gateway(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, resolver, token):
        self.resolver, self.token = resolver, token
        self.slots = threading.BoundedSemaphore(24)
        super().__init__(address, Handler)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            try:
                request.sendall(b"HTTP/1.0 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    server_version = "PersonalDNS/1.0"

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, fmt, *args):
        # Request paths contain access tokens. Never put them in access logs.
        pass

    def reply(self, status, body=b"", content_type="text/plain; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def permitted(self):
        path = urllib.parse.urlsplit(self.path).path
        candidates = ["/dns-query/" + self.server.token, "/doh.php/" + self.server.token]
        return any(hmac.compare_digest(path.encode(), item.encode()) for item in candidates)

    def do_GET(self):
        if self.path == "/health":
            self.reply(200, b'{"status":"ok"}', "application/json")
            return
        if not self.permitted():
            self.reply(404)
            return
        values = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get("dns", [])
        if len(values) != 1 or len(values[0]) > 87380:
            self.reply(400)
            return
        try:
            value = values[0].encode("ascii")
            body = base64.b64decode(value + b"=" * (-len(value) % 4), altchars=b"-_", validate=True)
        except (ValueError, UnicodeError, binascii.Error):
            self.reply(400)
            return
        self.answer(body)

    def do_POST(self):
        if not self.permitted():
            self.reply(404)
            return
        if self.headers.get_content_type() != "application/dns-message":
            self.reply(415)
            return
        if self.headers.get("Transfer-Encoding"):
            self.reply(400)
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if not 12 <= length <= MAX_MESSAGE:
            self.reply(400)
            return
        self.answer(self.rfile.read(length))

    def answer(self, query):
        try:
            answer = self.server.resolver.resolve(query)
        except (ValueError, UnicodeError, struct.error):
            self.reply(400)
            return
        self.reply(200, answer, "application/dns-message")


def query_server(url, name, qtype):
    req = urllib.request.Request(url, data=make_query(name, qtype), headers={
        "Content-Type": "application/dns-message", "Accept": "application/dns-message",
    })
    with urllib.request.urlopen(req, timeout=20) as response:
        packet = response.read(MAX_MESSAGE)
    header = struct.unpack("!6H", packet[:12])
    _, offset = read_name(packet, 12)
    offset += 4
    answers = []
    for _ in range(header[3]):
        _, offset = read_name(packet, offset)
        kind, cls, ttl, length = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10
        raw = packet[offset:offset + length]
        offset += length
        if kind in (1, 28):
            answers.append({"type": kind, "address": str(ipaddress.ip_address(raw)), "ttl": ttl})
    return {"name": name, "rcode": header[1] & 15, "answers": answers}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve")
    serve.add_argument("--config", type=Path, default=ROOT / "config.json")
    serve.add_argument("--token-file", type=Path, default=ROOT / ".doh-token")
    serve.add_argument("--listen")
    serve.add_argument("--port", type=int)
    check = commands.add_parser("query")
    check.add_argument("--url", required=True)
    check.add_argument("--name", required=True)
    check.add_argument("--type", choices=TYPES, default="A")
    args = parser.parse_args()
    if args.command == "query":
        print(json.dumps(query_server(args.url, args.name, TYPES[args.type]), indent=2))
        return
    config = read_config(args.config)
    token = os.environ.get("DOH_TOKEN", "").strip()
    if not token:
        if args.token_file.exists():
            token = args.token_file.read_text(encoding="ascii").strip()
        else:
            token = secrets.token_urlsafe(32)
            args.token_file.write_text(token + "\n", encoding="ascii")
            args.token_file.chmod(0o600)
    if len(token) < 32 or not all(c.isalnum() or c in "-_" for c in token):
        parser.error("DOH_TOKEN must contain at least 32 URL-safe characters")
    try:
        port = args.port if args.port is not None else int(os.environ.get("PORT", config.get("port", 8053)))
    except ValueError:
        parser.error("PORT must be an integer")
    if not 0 <= port <= 65535:
        parser.error("PORT must be between 0 and 65535")
    address = (args.listen or config.get("listen", "127.0.0.1"), port)
    server = Gateway(address, Resolver(config), token)
    bound_host, bound_port = server.server_address[:2]
    print(f"DNS gateway: http://{bound_host}:{bound_port}/dns-query/<token>", flush=True)
    print(f"Token file: {args.token_file} (or DOH_TOKEN environment variable)", flush=True)
    print(f"Redirect destination: {config['redirect_ipv4']}; HTTPS/API backend is separate.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
