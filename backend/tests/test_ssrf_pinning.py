"""SSRF: DNS-rebinding-proof IP pinning, redirect re-validation, and coverage of
every user/admin/operator-influenced outbound fetch.

The harness fakes the network at the lowest layer httpx uses — DNS
(socket.getaddrinfo) and httpcore's SyncBackend.connect_tcp — so the real
httpx/httpcore client, redirect handling and the app's fetch code all run.
`FakeNet.connect_tcp` behaves like socket.create_connection: given a hostname
it resolves it (again) through the fake DNS, which is exactly the window a
rebinding attacker uses. Every connection is recorded by the IP it reached.
"""
import ipaddress
import json
import socket

import httpcore
import pytest

PUBLIC = "93.184.216.34"


def _addrinfo(ip: str, port: int = 443):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sockaddr = (ip, port, 0, 0) if family == socket.AF_INET6 else (ip, port)
    return [(family, socket.SOCK_STREAM, 6, "", sockaddr)]


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_public(ip: str) -> bool:
    return ipaddress.ip_address(ip).is_global


class FakeDNS:
    """host → list of successive answers (the last answer repeats)."""

    def __init__(self, answers: dict[str, list[list[str]]]):
        self.answers = {h: [list(a) for a in seq] for h, seq in answers.items()}
        self.lookups: list[str] = []

    def __call__(self, host, port, *args, **kwargs):
        if _is_ip(host):
            return _addrinfo(host, port or 443)
        self.lookups.append(host)
        seq = self.answers.get(host)
        if not seq:
            raise socket.gaierror(f"NXDOMAIN {host}")
        ips = seq.pop(0) if len(seq) > 1 else seq[0]
        return [i for ip in ips for i in _addrinfo(ip, port or 443)]


def _http(status: str, body: bytes = b"", headers: dict | None = None) -> bytes:
    hdrs = {"Content-Length": str(len(body)), **(headers or {})}
    head = "".join(f"{k}: {v}\r\n" for k, v in hdrs.items())
    return f"HTTP/1.1 {status}\r\n{head}\r\n".encode() + body


def _json(obj) -> bytes:
    return _http("200 OK", json.dumps(obj).encode(), {"Content-Type": "application/json"})


SECRET = _json({"secret": "instance-metadata-credentials"})


class FakeStream(httpcore.NetworkStream):
    def __init__(self, net, ip, port):
        self.net, self.ip, self.port = net, ip, port
        self.sent = b""
        self.pending: bytes | None = None

    def write(self, buffer, timeout=None):
        self.sent += buffer

    def read(self, max_bytes, timeout=None):
        if self.pending is None:
            self.net.requests.append((self.ip, self.sent))
            handler = self.net.routes.get(self.ip)
            self.pending = handler(self.sent) if handler else _http("404 Not Found")
        chunk, self.pending = self.pending[:max_bytes], self.pending[max_bytes:]
        return chunk

    def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        self.net.tls.append((self.ip, server_hostname))
        return self

    def close(self):
        pass

    def get_extra_info(self, info):
        return None


class FakeNet:
    def __init__(self, routes):
        self.routes = routes          # ip → fn(request_bytes) → response bytes
        self.connects: list[tuple[str, str, int]] = []  # (host arg, ip reached, port)
        self.tls: list[tuple[str, str]] = []
        self.requests: list[tuple[str, bytes]] = []

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        # Like socket.create_connection: a hostname is (re-)resolved here.
        ip = host if _is_ip(host) else socket.getaddrinfo(host, port)[0][4][0]
        self.connects.append((host, ip, port))
        return FakeStream(self, ip, port)

    @property
    def reached(self) -> list[str]:
        return [ip for _h, ip, _p in self.connects]


@pytest.fixture
def net(monkeypatch):
    def install(dns: dict, routes: dict) -> FakeNet:
        fake_dns = FakeDNS(dns)
        fake_net = FakeNet(routes)
        fake_net.dns = fake_dns
        monkeypatch.setattr(socket, "getaddrinfo", fake_dns)
        monkeypatch.setattr(
            httpcore.SyncBackend, "connect_tcp",
            lambda self, *a, **k: fake_net.connect_tcp(*a, **k),
        )
        for var in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
            monkeypatch.delenv(var, raising=False)
        return fake_net
    return install


RSS = b"""<?xml version="1.0"?><rss><channel>
<item><title>Acme PLC sample advisory</title><link>https://feeds.example.com/a</link></item>
</channel></rss>"""
RSS_OK = _http("200 OK", RSS, {"Content-Type": "application/rss+xml"})
FEED = {"name": "Acme", "url": "https://feeds.example.com/all.xml", "format": "rss"}


# ---------------------------------------------------------------------------
# Custom advisory feeds (company-admin configured) — strict policy
# ---------------------------------------------------------------------------

class TestCustomFeedPinning:
    def test_dns_rebinding_public_then_private_never_reaches_private(self, net):
        from services.feeds_custom import CustomFeedError, fetch_custom_feed
        n = net({"feeds.example.com": [[PUBLIC], ["127.0.0.1"]]},
                {PUBLIC: lambda r: RSS_OK, "127.0.0.1": lambda r: SECRET})
        try:
            fetch_custom_feed(FEED)
        except CustomFeedError:
            pass
        assert all(_is_public(ip) for ip in n.reached), \
            f"connected to a non-public address after rebinding: {n.connects}"

    def test_connects_to_the_validated_ip_with_original_sni_and_host(self, net):
        from services.feeds_custom import fetch_custom_feed
        n = net({"feeds.example.com": [[PUBLIC]]}, {PUBLIC: lambda r: RSS_OK})
        items = fetch_custom_feed(FEED)
        assert [a["title"] for a in items] == ["Acme PLC sample advisory"]
        # The TCP connect got the pinned IP literal — nothing left to re-resolve.
        assert [h for h, _ip, _p in n.connects] == [PUBLIC]
        # TLS SNI / certificate verification and the Host header keep the hostname.
        assert n.tls == [(PUBLIC, "feeds.example.com")]
        assert b"host: feeds.example.com" in n.requests[0][1].lower()

    @pytest.mark.parametrize("ip", ["10.0.0.5", "169.254.169.254", "100.64.0.9", "fd00::1", "::ffff:127.0.0.1"])
    def test_private_answer_refused_without_connecting(self, net, ip):
        from services.feeds_custom import CustomFeedError, fetch_custom_feed
        n = net({"feeds.example.com": [[ip]]}, {})
        with pytest.raises(CustomFeedError):
            fetch_custom_feed(FEED)
        assert n.connects == []

    def test_mixed_answer_set_refused(self, net):
        from services.feeds_custom import CustomFeedError, fetch_custom_feed
        n = net({"feeds.example.com": [[PUBLIC, "10.0.0.5"]]}, {PUBLIC: lambda r: RSS_OK})
        with pytest.raises(CustomFeedError):
            fetch_custom_feed(FEED)
        assert n.connects == []

    def test_redirect_to_private_not_followed(self, net):
        from services.feeds_custom import CustomFeedError, fetch_custom_feed
        n = net({"feeds.example.com": [[PUBLIC]], "internal.example.com": [["10.0.0.5"]]},
                {PUBLIC: lambda r: _http("302 Found", headers={"Location": "https://internal.example.com/x"}),
                 "10.0.0.5": lambda r: SECRET})
        with pytest.raises(CustomFeedError):
            fetch_custom_feed(FEED)
        assert "10.0.0.5" not in n.reached


# ---------------------------------------------------------------------------
# Vendor PSIRT providers (operator env; public vendor endpoints) — strict
# ---------------------------------------------------------------------------

PSIRT_META = "https://psirt.example.com/.well-known/csaf/provider-metadata.json"


class TestPsirtPinning:
    @pytest.fixture(autouse=True)
    def _provider(self, monkeypatch):
        monkeypatch.setenv("ATHORIZE_PSIRT_PROVIDERS", PSIRT_META)

    def _fetch(self):
        from services.feeds_psirt import PsirtFeedError, fetch_psirt
        try:
            return fetch_psirt(live=True)
        except PsirtFeedError:
            return None

    def test_redirect_to_private_refused(self, net):
        n = net({"psirt.example.com": [[PUBLIC]], "internal.example.com": [["10.0.0.5"]]},
                {PUBLIC: lambda r: _http("302 Found", headers={"Location": "https://internal.example.com/meta.json"}),
                 "10.0.0.5": lambda r: SECRET})
        self._fetch()
        assert PUBLIC in n.reached
        assert "10.0.0.5" not in n.reached, f"followed a redirect into the private network: {n.connects}"

    def test_redirect_downgrade_to_http_refused(self, net):
        n = net({"psirt.example.com": [[PUBLIC]]},
                {PUBLIC: lambda r: _http("301 Moved", headers={"Location": "http://psirt.example.com/meta.json"})})
        self._fetch()
        assert all(port == 443 for _h, _ip, port in n.connects), n.connects

    def test_provider_resolving_to_metadata_refused(self, net):
        n = net({"psirt.example.com": [["169.254.169.254"]]}, {"169.254.169.254": lambda r: SECRET})
        assert not self._fetch()
        assert n.connects == []

    def test_dns_rebinding_refused(self, net):
        n = net({"psirt.example.com": [[PUBLIC], ["10.0.0.5"]]},
                {PUBLIC: lambda r: _json({"distributions": []}), "10.0.0.5": lambda r: SECRET})
        self._fetch()
        assert "10.0.0.5" not in n.reached


# ---------------------------------------------------------------------------
# OIDC discovery + JWKS (operator-configured issuer; on-prem IdPs allowed)
# ---------------------------------------------------------------------------

class TestOidcPinning:
    ISSUER = "https://idp.example.com"

    @pytest.fixture(autouse=True)
    def _cfg(self, monkeypatch):
        from config import settings
        from services import oidc
        monkeypatch.setattr(settings, "oidc_issuer", self.ISSUER)
        oidc._DISCOVERY_CACHE.clear()
        oidc._JWKS_CACHE.clear()

    def _doc(self, jwks_uri="https://idp.example.com/jwks"):
        return _json({"issuer": self.ISSUER, "authorization_endpoint": f"{self.ISSUER}/auth",
                      "token_endpoint": f"{self.ISSUER}/token", "jwks_uri": jwks_uri})

    def test_issuer_resolving_to_metadata_refused(self, net):
        from services import oidc
        n = net({"idp.example.com": [["169.254.169.254"]]}, {"169.254.169.254": lambda r: SECRET})
        with pytest.raises(oidc.OidcError):
            oidc.discover()
        assert n.connects == []

    def test_on_prem_idp_on_private_network_still_works(self, net):
        from services import oidc
        n = net({"idp.example.com": [["10.1.2.3"]]}, {"10.1.2.3": lambda r: self._doc()})
        assert oidc.discover()["issuer"] == self.ISSUER
        assert [h for h, _ip, _p in n.connects] == ["10.1.2.3"]  # pinned literal
        assert n.tls == [("10.1.2.3", "idp.example.com")]

    def test_jwks_uri_pointing_at_metadata_refused(self, net):
        from services import oidc
        n = net({"meta.example.com": [["169.254.169.254"]]}, {"169.254.169.254": lambda r: SECRET})
        with pytest.raises(oidc.OidcError):
            oidc._jwks("https://meta.example.com/latest/meta-data/")
        assert n.connects == []


# ---------------------------------------------------------------------------
# Tanium / Cisco ISE (operator-configured, on-prem by design)
# ---------------------------------------------------------------------------

class TestConnectorPinning:
    @pytest.fixture(autouse=True)
    def _cfg(self, monkeypatch):
        monkeypatch.setenv("TANIUM_URL", "https://tanium.corp.example")
        monkeypatch.setenv("TANIUM_API_TOKEN", "t")
        monkeypatch.setenv("TANIUM_SAVED_QUESTION_ID", "1")
        monkeypatch.setenv("CISCO_ISE_URL", "https://ise.corp.example")
        monkeypatch.setenv("CISCO_ISE_USER", "u")
        monkeypatch.setenv("CISCO_ISE_PASSWORD", "p")

    def test_tanium_resolving_to_metadata_refused(self, net):
        from services.asset_connectors import ConnectorError, fetch_tanium
        n = net({"tanium.corp.example": [["169.254.169.254"]]}, {"169.254.169.254": lambda r: SECRET})
        with pytest.raises(ConnectorError):
            fetch_tanium()
        assert n.connects == []

    def test_tanium_on_private_network_works_and_is_pinned(self, net):
        from services.asset_connectors import fetch_tanium
        n = net({"tanium.corp.example": [["10.20.30.40"], ["169.254.169.254"]]},
                {"10.20.30.40": lambda r: _json({"data": {"result_sets": []}}),
                 "169.254.169.254": lambda r: SECRET})
        assert fetch_tanium() == []
        assert n.reached == ["10.20.30.40"]

    def test_ise_resolving_to_metadata_refused(self, net):
        from services.asset_connectors import ConnectorError, fetch_cisco_ise
        n = net({"ise.corp.example": [["fd00:ec2::254"]]}, {"fd00:ec2::254": lambda r: SECRET})
        with pytest.raises(ConnectorError):
            fetch_cisco_ise()
        assert n.connects == []


# ---------------------------------------------------------------------------
# Policy table
# ---------------------------------------------------------------------------

STRICT_DENY = [
    "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.1.1",
    "0.0.0.0", "224.0.0.1", "240.0.0.1", "255.255.255.255", "::1", "::", "fe80::1", "fc00::1",
    "fd00:ec2::254", "ff02::1", "::ffff:10.0.0.1", "::ffff:169.254.169.254",
    "2002:a00:1::", "64:ff9b::a9fe:a9fe", "100.100.100.200",
]
INTERNAL_ALLOW = ["10.0.0.1", "192.168.1.1", "172.16.0.1", "100.64.1.1", "fc00::1", "127.0.0.1"]
ALWAYS_DENY = ["169.254.169.254", "fd00:ec2::254", "100.100.100.200", "64:ff9b::a9fe:a9fe",
               "::ffff:169.254.169.254", "fe80::1", "0.0.0.0", "::", "224.0.0.1", "ff02::1"]


@pytest.mark.parametrize("ip", STRICT_DENY)
def test_strict_policy_denies(ip):
    from services.safe_http import STRICT, ip_rejection
    assert ip_rejection(ipaddress.ip_address(ip), STRICT)


@pytest.mark.parametrize("ip", INTERNAL_ALLOW)
def test_internal_policy_allows_on_prem(ip):
    from services.safe_http import INTERNAL, ip_rejection
    assert ip_rejection(ipaddress.ip_address(ip), INTERNAL) is None


@pytest.mark.parametrize("ip", ALWAYS_DENY)
def test_internal_policy_still_denies_metadata_and_link_local(ip):
    from services.safe_http import INTERNAL, ip_rejection
    assert ip_rejection(ipaddress.ip_address(ip), INTERNAL)


def test_public_allowed_by_both():
    from services.safe_http import INTERNAL, STRICT, ip_rejection
    for ip in (PUBLIC, "2606:4700:4700::1111"):
        assert ip_rejection(ipaddress.ip_address(ip), STRICT) is None
        assert ip_rejection(ipaddress.ip_address(ip), INTERNAL) is None


# ---------------------------------------------------------------------------
# Real TLS on loopback: the pinned connect still verifies the certificate
# against the HOSTNAME (SNI), not the IP it connected to.
# ---------------------------------------------------------------------------

@pytest.fixture
def tls_server(tmp_path):
    import datetime
    import ssl
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "athorize-test.internal")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("athorize-test.internal")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    seen_hosts: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen_hosts.append(self.headers.get("Host", ""))
            body = b'{"ok": true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(cert_path, key_path)
    srv.socket = sctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    client_ctx = ssl.create_default_context(cafile=str(cert_path))
    yield srv.server_address[1], client_ctx, seen_hosts
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def loopback_dns(monkeypatch):
    real = socket.getaddrinfo

    def fake(host, port, *a, **k):
        if host in ("athorize-test.internal", "wrong-name.internal"):
            return _addrinfo("127.0.0.1", port)
        return real(host, port, *a, **k)
    monkeypatch.setattr(socket, "getaddrinfo", fake)


def test_real_tls_pinned_connect_verifies_hostname(tls_server, loopback_dns):
    from services.safe_http import INTERNAL, guarded_client
    port, ctx, seen_hosts = tls_server
    with guarded_client(INTERNAL, verify=ctx, timeout=5) as c:
        r = c.get(f"https://athorize-test.internal:{port}/x")
    assert r.status_code == 200 and r.json() == {"ok": True}
    assert seen_hosts == [f"athorize-test.internal:{port}"]


def test_real_tls_wrong_hostname_fails_verification(tls_server, loopback_dns):
    import httpx
    from services.safe_http import INTERNAL, guarded_client
    port, ctx, _ = tls_server
    with guarded_client(INTERNAL, verify=ctx, timeout=5) as c, pytest.raises(httpx.ConnectError, match="(?i)certificate|hostname"):
        c.get(f"https://wrong-name.internal:{port}/x")


def test_real_loopback_refused_under_strict(tls_server, loopback_dns):
    import httpx
    from services.safe_http import STRICT, guarded_client
    port, ctx, seen_hosts = tls_server
    with guarded_client(STRICT, verify=ctx, timeout=5) as c, pytest.raises(httpx.ConnectError, match="loopback"):
        c.get(f"https://athorize-test.internal:{port}/x")
    assert seen_hosts == []
