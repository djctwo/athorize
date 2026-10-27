"""Outbound HTTP with an SSRF guard that cannot be bypassed by DNS rebinding.

Checking a hostname's DNS answer and then letting httpx connect leaves a
window: httpx resolves the name AGAIN at connect time, so a hostile resolver
can answer "public" to the check and "169.254.169.254" to the connect. Here
the check and the connect are the same step: a custom httpcore network
backend resolves the name once, validates EVERY A/AAAA record against the
policy, and opens the TCP connection to one of those already-validated IPs.
TLS still uses the original hostname for SNI and certificate verification
(httpcore passes the URL host to start_tls), and the Host header is the URL
host, so virtual hosting and cert checks are unchanged.

Every connection goes through the backend — including each hop of a followed
redirect — so a redirect to a private address is refused at connect time.
Clients built here ignore the standard proxy env vars (a proxy would do its
own DNS and defeat the pin). Installs that can only reach the internet through
a proxy opt in explicitly with ATHORIZE_OUTBOUND_PROXY: requests then go via
that proxy, and every request (and redirect hop) still has its target host
resolved and checked against the policy first (a name local DNS cannot
resolve is left to the proxy — proxy-only networks often have no public
DNS) — but the proxy resolves the
name again itself, so the pin is not airtight there: the proxy is the egress
control in that mode (docs/INSTALL.md §5).

Policies:
- STRICT ("public internet only") — for URLs a company admin can set (custom
  feeds) and public vendor endpoints (PSIRT providers): rejects loopback,
  RFC1918, link-local (incl. 169.254.169.254), CGNAT, ULA, multicast,
  unspecified, reserved, IPv4-mapped/6to4/Teredo/NAT64-embedded private v4.
- INTERNAL ("on-prem service") — for operator-configured integrations that by
  design live on the customer's network (Tanium, Cisco ISE, an on-prem OIDC
  IdP): private ranges are allowed, but cloud-metadata, link-local,
  multicast, unspecified and reserved addresses are still refused, and the
  rebinding pin still applies.
"""
from __future__ import annotations

import ipaddress
import socket
import ssl
import typing
from dataclasses import dataclass

import httpcore
import httpx

IPAddress = typing.Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
# Cloud instance-metadata endpoints that are NOT link-local (AWS IPv6 IMDS,
# Alibaba). Refused under every policy.
_METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("fd00:ec2::254"),
    ipaddress.ip_address("100.100.100.200"),
}


@dataclass(frozen=True)
class OutboundPolicy:
    name: str
    allow_private: bool  # loopback, RFC1918, CGNAT, ULA


STRICT = OutboundPolicy("public-only", allow_private=False)
INTERNAL = OutboundPolicy("internal-service", allow_private=True)


class BlockedAddressError(httpcore.ConnectError):
    """Raised inside the transport; httpx surfaces it as httpx.ConnectError."""


class UnresolvableHostError(BlockedAddressError):
    """Local DNS has no answer for the name (not a policy verdict)."""


def as_ip(host: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


def _embedded_ipv4(ip: IPAddress) -> ipaddress.IPv4Address | None:
    if not isinstance(ip, ipaddress.IPv6Address):
        return None
    if ip.ipv4_mapped is not None:      # ::ffff:10.0.0.1
        return ip.ipv4_mapped
    if ip.sixtofour is not None:        # 2002:0a00:0001::
        return ip.sixtofour
    if ip.teredo is not None:           # (server, client)
        return ip.teredo[1]
    if ip in _NAT64:                    # 64:ff9b::a9fe:a9fe → 169.254.169.254
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def ip_rejection(ip: IPAddress, policy: OutboundPolicy = STRICT) -> str | None:
    """Reason string if `policy` forbids connecting to `ip`, else None."""
    inner = _embedded_ipv4(ip)
    if inner is not None:
        return ip_rejection(inner, policy)
    if ip in _METADATA_IPS:
        return "link-local/metadata"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_link_local:  # 169.254.0.0/16, fe80::/10 — includes cloud metadata
        return "link-local/metadata"
    if ip.is_multicast:
        return "multicast"
    if ip.is_loopback:
        return None if policy.allow_private else "loopback"
    if ip.is_reserved:
        return "reserved"
    if ip in _CGNAT:
        return None if policy.allow_private else "carrier-grade NAT"
    if ip.is_private:  # RFC1918, ULA fc00::/7, documentation ranges, ...
        return None if policy.allow_private else "private"
    if not ip.is_global:
        return None if policy.allow_private else "non-public"
    return None


def resolve_validated(host: str, port: int, policy: OutboundPolicy = STRICT) -> list[str]:
    """Resolve `host` ONCE and return its addresses, refusing if ANY record is
    forbidden by `policy` (a mixed answer set is treated as hostile)."""
    literal = as_ip(host)
    if literal is not None:
        reason = ip_rejection(literal, policy)
        if reason:
            raise BlockedAddressError(f"{host} is a {reason} address; refusing to connect")
        return [str(literal)]
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise UnresolvableHostError(f"DNS resolution failed for {host}: {exc}") from exc
    if not infos:
        raise UnresolvableHostError(f"DNS resolution returned no addresses for {host}")
    addrs: list[str] = []
    for info in infos:
        ip = as_ip(str(info[4][0]).split("%", 1)[0])
        if ip is None:
            raise BlockedAddressError(f"Unparseable resolved address for {host}")
        reason = ip_rejection(ip, policy)
        if reason:
            raise BlockedAddressError(f"{host} resolves to a {reason} address; refusing to connect")
        if str(ip) not in addrs:
            addrs.append(str(ip))
    return addrs


class PinnedBackend(httpcore.NetworkBackend):
    """httpcore network backend: validate-then-connect to the resolved IP."""

    def __init__(self, policy: OutboundPolicy, inner: httpcore.NetworkBackend | None = None):
        self.policy = policy
        self._inner = inner or httpcore.SyncBackend()

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        last_exc: Exception | None = None
        for ip in resolve_validated(host, port, self.policy):
            try:
                # An IP literal: the inner backend does no further DNS lookup.
                return self._inner.connect_tcp(
                    ip, port, timeout=timeout, local_address=local_address, socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_exc = exc
        assert last_exc is not None
        raise last_exc

    def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise BlockedAddressError("Unix sockets are not allowed for outbound fetches")

    def sleep(self, seconds: float) -> None:
        self._inner.sleep(seconds)


class PinnedTransport(httpx.HTTPTransport):
    def __init__(self, policy: OutboundPolicy = STRICT, *, verify: bool | ssl.SSLContext = True, inner_backend=None):
        super().__init__(verify=verify, trust_env=False)
        self._pool = httpcore.ConnectionPool(
            ssl_context=httpx.create_ssl_context(verify=verify, trust_env=False),
            network_backend=PinnedBackend(policy, inner_backend),
        )


def _https_only_hook(request: httpx.Request) -> None:
    # Fires for the initial request AND every redirect hop.
    if request.url.scheme != "https":
        raise httpx.UnsupportedProtocol(f"Refusing non-https URL {request.url}", request=request)
    if request.url.username or request.url.password:
        raise httpx.UnsupportedProtocol("Refusing URL with embedded credentials", request=request)


def _policy_precheck_hook(policy: OutboundPolicy):
    def hook(request: httpx.Request) -> None:
        host = request.url.host
        port = request.url.port or (443 if request.url.scheme == "https" else 80)
        try:
            resolve_validated(host, port, policy)
        except UnresolvableHostError:
            # Proxy-only networks often have no public DNS: the proxy resolves
            # the name, and is the egress control in this mode (R2SEC-10).
            # Literal IPs and names that DO resolve locally are still checked.
            return
        except BlockedAddressError as exc:
            raise httpx.ConnectError(str(exc), request=request) from exc
    return hook


def guarded_client(
    policy: OutboundPolicy = STRICT,
    *,
    https_only: bool = True,
    follow_redirects: bool = False,
    max_redirects: int = 5,
    verify: bool | ssl.SSLContext = True,
    **kwargs,
) -> httpx.Client:
    """httpx.Client whose every connection (and redirect hop) passes the
    SSRF guard for `policy`. Proxy env vars are ignored (see module doc)."""
    from config import settings
    hooks = kwargs.pop("event_hooks", {}) or {}
    if https_only:
        hooks = {**hooks, "request": [*hooks.get("request", []), _https_only_hook]}
    proxy = (settings.outbound_proxy or "").strip()
    if proxy:
        hooks = {**hooks, "request": [*hooks.get("request", []), _policy_precheck_hook(policy)]}
        transport: httpx.BaseTransport = httpx.HTTPTransport(proxy=httpx.Proxy(proxy), verify=verify, trust_env=False)
    else:
        transport = PinnedTransport(policy, verify=verify)
    return httpx.Client(
        transport=transport,
        trust_env=False,
        follow_redirects=follow_redirects,
        max_redirects=max_redirects,
        event_hooks=hooks,
        **kwargs,
    )
