"""Protocol and HTTP integration tests. Never install an OS profile or root CA."""
import base64
import copy
import json
import os
from pathlib import Path
import plistlib
import struct
import socket
import subprocess
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

from configure import generate
from dns_server import (Gateway, Resolver, build_download_profile, local_answer, make_query,
                        parse_question, profile_download_path, read_config, read_name)

ROOT = Path(__file__).resolve().parent
TOKEN = "integration-test-token-0123456789abcdef"


class ProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = read_config(ROOT / "config.json")
        cls.resolver = Resolver(cls.config)
        cls.snapshot = json.loads((ROOT / "reference" / "snapshot.json").read_text(encoding="utf-8"))

    def test_all_observed_redirects_and_blocks(self):
        tested = 0
        for name, observation in self.snapshot["observations"].items():
            if observation["action"] not in ("redirect", "block"):
                continue
            with self.subTest(name=name):
                response = self.resolver.resolve(make_query(name))
                expected = self.config["redirect_ipv4"] if observation["action"] == "redirect" else "0.0.0.0"
                self.assertEqual(response[-4:], bytes(map(int, expected.split("."))))
                self.assertEqual(struct.unpack("!H", response[6:8])[0], 1)
                self.assertEqual(response[3] & 15, 0)
                tested += 1
        self.assertEqual(tested, 51)

    def test_aaaa_and_https_do_not_bypass_redirects(self):
        for name in self.config["redirect_domains"] + self.config["block_domains"]:
            for qtype in (28, 64, 65):
                with self.subTest(name=name, qtype=qtype):
                    response = self.resolver.resolve(make_query(name, qtype))
                    self.assertEqual(struct.unpack("!H", response[6:8])[0], 0)
                    self.assertEqual(response[3] & 15, 0)

    def test_nonlisted_subdomain_uses_upstream_not_assumed_wildcard(self):
        class UpstreamResponse:
            headers = __import__("email.message", fromlist=["Message"]).Message()
            headers["Content-Type"] = "application/dns-message"
            def __init__(self, packet): self.packet = packet
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, limit): return self.packet
        query = make_query("unobserved.revenuecat.com")
        expected = local_answer(query, "192.0.2.42")
        with patch("dns_server.urllib.request.urlopen", return_value=UpstreamResponse(expected)) as call:
            self.assertEqual(self.resolver.resolve(query), expected)
            self.assertEqual(call.call_count, 1)

    def test_upstream_failure_is_servfail(self):
        with patch("dns_server.urllib.request.urlopen", side_effect=OSError("offline")):
            response = self.resolver.resolve(make_query("example.org"))
            self.assertEqual(response[3] & 15, 2)

    def test_upstream_wrong_question_is_rejected(self):
        class WrongResponse:
            headers = __import__("email.message", fromlist=["Message"]).Message()
            headers["Content-Type"] = "application/dns-message"
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, limit): return wrong
        query = make_query("example.org")
        wrong = local_answer(make_query("other.example"), "192.0.2.9")
        wrong = query[:2] + wrong[2:]
        with patch("dns_server.urllib.request.urlopen", return_value=WrongResponse()):
            response = self.resolver.resolve(query)
            self.assertEqual(response[3] & 15, 2)

    def test_invalid_dns_packets(self):
        packets = [b"", b"\0" * 12, struct.pack("!6H", 1, 256, 1, 0, 0, 0) + b"\xc0\x0c\0\1\0\1"]
        for packet in packets:
            with self.subTest(packet=packet), self.assertRaises(ValueError):
                parse_question(packet)

    def test_modified_answers_clear_dnssec_ad(self):
        query = make_query("api.revenuecat.com")
        flags = struct.unpack("!H", query[2:4])[0] | 0x0020
        query = query[:2] + struct.pack("!H", flags) + query[4:]
        response = self.resolver.resolve(query)
        self.assertFalse(struct.unpack("!H", response[2:4])[0] & 0x0020)

    def test_local_backend_address_is_configurable(self):
        config = copy.deepcopy(self.config)
        config["redirect_ipv4"] = "192.0.2.123"
        response = Resolver(config).resolve(make_query("api.revenuecat.com"))
        self.assertEqual(response[-4:], b"\xc0\x00\x02\x7b")


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        config = read_config(ROOT / "config.json")
        cls.server = Gateway(("127.0.0.1", 0), Resolver(config), TOKEN, profile_host="dns.example.com")
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        cls.endpoint = cls.base + "/dns-query/" + TOKEN

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def test_get_post_and_php_alias(self):
        packet = make_query("api.revenuecat.com")
        encoded = base64.urlsafe_b64encode(packet).rstrip(b"=").decode()
        get = urllib.request.urlopen(self.endpoint + "?dns=" + encoded, timeout=3)
        req = urllib.request.Request(self.endpoint, data=packet, headers={"Content-Type": "application/dns-message"})
        post = urllib.request.urlopen(req, timeout=3)
        alias = self.base + "/doh.php/" + TOKEN + "?dns=" + encoded
        with get, post, urllib.request.urlopen(alias, timeout=3) as third:
            first = get.read()
            self.assertEqual(first, post.read())
            self.assertEqual(first, third.read())
            self.assertEqual(get.headers.get_content_type(), "application/dns-message")

    def test_bad_token_and_payload_are_rejected(self):
        cases = [(self.base + "/dns-query/wrong?dns=AAAA", 404),
                 (self.endpoint + "?dns=!!!", 400),
                 (self.endpoint + "?dns=AAAA", 400)]
        for url, code in cases:
            with self.subTest(url=url), self.assertRaises(urllib.error.HTTPError) as result:
                urllib.request.urlopen(url, timeout=3)
            self.assertEqual(result.exception.code, code)

    def test_wrong_post_media_type(self):
        req = urllib.request.Request(self.endpoint, data=make_query("example.org"),
                                     headers={"Content-Type": "text/plain"})
        with self.assertRaises(urllib.error.HTTPError) as result:
            urllib.request.urlopen(req, timeout=3)
        self.assertEqual(result.exception.code, 415)

    def test_safari_profile_has_correct_headers_and_contents(self):
        url = self.base + profile_download_path(TOKEN)
        with urllib.request.urlopen(url, timeout=3) as response:
            raw = response.read()
            self.assertEqual(response.headers.get_content_type(), "application/x-apple-aspen-config")
            self.assertIn('attachment; filename="dns-by-tnguyeendepzaii.mobileconfig"',
                          response.headers["Content-Disposition"])
            self.assertEqual(int(response.headers["Content-Length"]), len(raw))
            self.assertEqual(response.headers["Cache-Control"], "no-store")
        profile = plistlib.loads(raw)
        self.assertEqual(profile["PayloadDisplayName"], "DNS by tnguyeendepzaii")
        self.assertEqual(profile["PayloadOrganization"], "TikTok: tnguyen2601_")
        dns = next(x["DNSSettings"] for x in profile["PayloadContent"] if "DNSSettings" in x)
        self.assertEqual(dns["ServerURL"], "https://dns.example.com/dns-query/" + TOKEN)
        self.assertEqual(dns["SupplementalMatchDomains"], self.server.resolver.config["match_domains"])
        original = plistlib.loads((ROOT / "reference/original-profile.xml").read_bytes())
        ca = lambda p: next(x["PayloadContent"] for x in p["PayloadContent"]
                            if x["PayloadType"] == "com.apple.security.root")
        self.assertEqual(ca(profile), ca(original))

    def test_profile_head_and_repeated_downloads(self):
        url = self.base + profile_download_path(TOKEN)
        with urllib.request.urlopen(url, timeout=3) as response:
            first = response.read()
        with urllib.request.urlopen(url, timeout=3) as response:
            self.assertEqual(response.read(), first)
        request = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(request, timeout=3) as response:
            self.assertEqual(response.read(), b"")
            self.assertEqual(int(response.headers["Content-Length"]), len(first))
            self.assertEqual(response.headers.get_content_type(), "application/x-apple-aspen-config")

    def test_profile_requires_download_link(self):
        for path in ("/dns", "/dns/wrong.mobileconfig", "/dns/" + TOKEN + ".mobileconfig"):
            with self.subTest(path=path), self.assertRaises(urllib.error.HTTPError) as result:
                urllib.request.urlopen(self.base + path, timeout=3)
            self.assertEqual(result.exception.code, 404)

    def test_request_host_cannot_change_dns_profile(self):
        request = urllib.request.Request(self.base + profile_download_path(TOKEN),
                                         headers={"Host": "attacker.example"})
        with urllib.request.urlopen(request, timeout=3) as response:
            profile = plistlib.loads(response.read())
        dns = next(x["DNSSettings"] for x in profile["PayloadContent"] if "DNSSettings" in x)
        self.assertTrue(dns["ServerURL"].startswith("https://dns.example.com/"))

    def test_profile_without_hostname_is_unavailable(self):
        server = Gateway(("127.0.0.1", 0), self.server.resolver, TOKEN, profile_host="")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}" + profile_download_path(TOKEN)
            with self.assertRaises(urllib.error.HTTPError) as result:
                urllib.request.urlopen(url, timeout=3)
            self.assertEqual(result.exception.code, 503)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


class ProfileTests(unittest.TestCase):
    def test_download_hostname_cannot_inject_profile_url(self):
        for host in ("https://evil.example", "dns.example.com/path", "a.example:443", "-bad.example"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                build_download_profile(host, TOKEN, [], ROOT / "profile-template.plist")

    def test_default_profile_is_dns_only_and_preserves_scope(self):
        config = read_config(ROOT / "config.json")
        host, raw = generate("dns.example.com", TOKEN, config["match_domains"])
        profile = plistlib.loads(raw)
        self.assertEqual(len(profile["PayloadContent"]), 1)
        dns = profile["PayloadContent"][0]["DNSSettings"]
        self.assertEqual(dns["SupplementalMatchDomains"], config["match_domains"])
        self.assertEqual(dns["ServerURL"], f"https://dns.example.com/dns-query/{TOKEN}")
        self.assertNotIn("ServerAddresses", dns)

    def test_original_ca_only_in_explicit_mirror_profile(self):
        original = plistlib.loads((ROOT / "reference" / "original-profile.xml").read_bytes())
        ca = next(p["PayloadContent"] for p in original["PayloadContent"]
                  if p["PayloadType"] == "com.apple.security.root")
        _, raw = generate("dns.example.com", TOKEN, ["example.com"], ca)
        profile = plistlib.loads(raw)
        self.assertEqual(profile["PayloadContent"][0]["PayloadContent"], ca)
        self.assertIn("CA ben goc", profile["PayloadDisplayName"])

    def test_bad_hostname_is_rejected(self):
        for domain in ("https://dns.example.com", "dns.example.com/abc", "localhost", "-bad.example"):
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                generate(domain, TOKEN, [])


class DeploymentTests(unittest.TestCase):
    def check_start(self, override=False):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        env = os.environ.copy()
        env.update(DOH_TOKEN=TOKEN, PORT="invalid-but-overridden" if override else str(port))
        command = [sys.executable, str(ROOT / "dns_server.py"), "serve", "--listen", "127.0.0.1"]
        if override:
            command += ["--port", str(port)]
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            for _ in range(50):
                if process.poll() is not None:
                    self.fail("Server exited before healthcheck")
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=0.3) as r:
                        self.assertEqual(json.load(r), {"status": "ok"})
                    break
                except OSError:
                    time.sleep(0.1)
            else:
                self.fail("Healthcheck did not become ready")
        finally:
            process.terminate()
            output, errors = process.communicate(timeout=5)
        self.assertIn(f":{port}/dns-query/<token>".encode(), output)
        self.assertEqual(errors, b"")

    def test_hosting_port_environment(self):
        self.check_start()

    def test_cli_port_overrides_environment(self):
        self.check_start(override=True)

    def test_invalid_hosting_port_fails_with_clear_error(self):
        for port in ("wrong", "70000"):
            with self.subTest(port=port):
                env = os.environ.copy()
                env.update(DOH_TOKEN=TOKEN, PORT=port)
                result = subprocess.run([sys.executable, str(ROOT / "dns_server.py"), "serve"],
                                        env=env, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 2)
                self.assertIn(b"PORT must be", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
