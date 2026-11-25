"""Generate a deployment environment and an unsigned iPhone DNS profile."""
import argparse
import ipaddress
import json
from pathlib import Path
import plistlib
import re
import secrets
import uuid

ROOT = Path(__file__).resolve().parent


def generate(domain, token, match_domains, original_ca=None):
    host = domain.rstrip(".").lower().encode("idna").decode("ascii")
    if "." not in host or len(host) > 253 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in host.split(".")
    ):
        raise ValueError("Use a hostname, e.g. dns.example.com; no scheme or path")
    if len(token) < 32 or not re.fullmatch(r"[A-Za-z0-9_-]+", token):
        raise ValueError("Invalid access token")
    profile_id, dns_id = str(uuid.uuid4()).upper(), str(uuid.uuid4()).upper()
    settings = {"DNSProtocol": "HTTPS", "ServerURL": f"https://{host}/dns-query/{token}",
                "SupplementalMatchDomains": match_domains}
    dns = {"PayloadType": "com.apple.dnsSettings.managed", "PayloadVersion": 1,
           "PayloadIdentifier": f"personal.dns.{dns_id.lower()}", "PayloadUUID": dns_id,
           "PayloadDisplayName": "DNS ca nhan", "DNSSettings": settings}
    profile = {"PayloadContent": [dns], "PayloadType": "Configuration", "PayloadVersion": 1,
               "PayloadDisplayName": "DNS ca nhan", "PayloadOrganization": "Personal DNS",
               "PayloadIdentifier": f"personal.profile.{profile_id.lower()}", "PayloadUUID": profile_id,
               "PayloadRemovalDisallowed": False,
               "PayloadDescription": "DNS ca nhan. Khong cai chung chi goc, khong kem backend VIP."}
    if original_ca:
        ca_id = str(uuid.uuid4()).upper()
        profile["PayloadContent"].insert(0, {
            "PayloadType": "com.apple.security.root", "PayloadVersion": 1,
            "PayloadIdentifier": f"personal.reference.ca.{ca_id.lower()}", "PayloadUUID": ca_id,
            "PayloadDisplayName": "Locket Lab Test CA (ben van hanh goc)",
            "PayloadDescription": "CA cua ben goc, khong phai CA rieng cua ban.",
            "PayloadCertificateFileName": "original-operator-ca.der", "PayloadContent": original_ca,
        })
        profile["PayloadDisplayName"] = "DNS ca nhan - CA ben goc"
        profile["PayloadDescription"] = "Dung backend va CA cua ben goc. Khong phai he thong VIP doc lap."
    return host, plistlib.dumps(profile, fmt=plistlib.FMT_XML, sort_keys=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--domain", required=True, help="Your real DNS hostname")
    parser.add_argument("--redirect-ip", help="IP of your already-working API backend; not just the DNS VPS")
    parser.add_argument("--with-original-ca", action="store_true",
                        help="Include the original operator's public root CA; this is still their trust/backend")
    args = parser.parse_args()
    config_path = ROOT / "config.json"
    config = json.loads(config_path.read_text(encoding="utf-8-sig"))
    token_file = ROOT / ".doh-token"
    token = token_file.read_text(encoding="ascii").strip() if token_file.exists() else secrets.token_urlsafe(32)
    try:
        ca = None
        if args.with_original_ca:
            original = plistlib.loads((ROOT / "reference" / "original-profile.xml").read_bytes())
            ca = next(p["PayloadContent"] for p in original["PayloadContent"]
                      if p["PayloadType"] == "com.apple.security.root")
        host, profile = generate(args.domain, token, config["match_domains"], ca)
        redirect_ip = str(ipaddress.IPv4Address(args.redirect_ip)) if args.redirect_ip else None
    except ValueError as exc:
        parser.error(str(exc))
    # Validation above is complete before writing any files.
    if redirect_ip:
        config["redirect_ipv4"] = redirect_ip
        config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    token_file.write_text(token + "\n", encoding="ascii")
    token_file.chmod(0o600)
    env = ROOT / ".env"
    env.write_text(f"DNS_HOST={host}\nDOH_TOKEN={token}\n", encoding="ascii")
    env.chmod(0o600)
    (ROOT / "personal-dns.mobileconfig").write_bytes(profile)
    (ROOT / "personal-dns.mobileconfig").chmod(0o600)
    print("Created .env, .doh-token, personal-dns.mobileconfig")
    print(f"DNS hostname: {host}; redirect destination: {config['redirect_ipv4']}")
    print("Profile includes the ORIGINAL OPERATOR's CA." if ca else "Profile has no root CA.")
    print("Redirected HTTPS apps need a compatible API backend; no backend source is included.")
    print("If the destination is 103.252.93.74, redirected traffic still goes to the original operator.")


if __name__ == "__main__":
    main()
