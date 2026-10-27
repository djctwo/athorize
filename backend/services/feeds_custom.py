"""Admin-configured custom threat-advisory feeds (RSS or CSAF).

Feeds are stored per-organization in Organization.settings["custom_feeds"]
(mirrors the "risk_context" pattern): a list of {name, url, format} where
format is "rss" (advisory list feed, parsed with defusedxml) or "csaf"
(a CSAF provider-metadata.json URL, walked with the same hardened walker
as the vendor PSIRT feeds). They are pulled during the normal feed refresh
and each advisory is labeled with the feed's configured name as its source.

Hardening (non-negotiable, mirrors the existing feed clients):
- HTTPS only, no credentials in the URL.
- Per-feed host lock: every request made while walking a feed (provider
  metadata, ROLIE feed, CSAF documents) may only hit the configured feed's
  host. Redirects are NOT followed.
- DNS is resolved and private/loopback/link-local/metadata/reserved ranges
  are rejected BEFORE any connection is made (SSRF guard), and the connection
  itself is pinned to the validated IP (services/safe_http.py) so a DNS
  rebind between the check and the connect cannot reach a private address.
- 16 MiB streamed body cap, short timeouts.
- Per-feed fault isolation: one broken feed never kills the refresh.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
from datetime import date, datetime
from urllib.parse import urlparse

import defusedxml.ElementTree as ET  # stdlib ET is XXE/billion-laughs vulnerable
import httpx

from services.safe_http import STRICT, guarded_client, ip_rejection

from services.ics_advisory_cisa import (
    HTTP_TIMEOUT,
    IcsFeedError,
    _safe_json,
    parse_csaf_document,
)

MAX_FEEDS = 10
MAX_NAME_LEN = 100
MAX_URL_LEN = 500
PER_FEED_LIMIT = 25
_MAX_BODY_BYTES = 16 * 1024 * 1024
ALLOWED_FORMATS = ("rss", "csaf")

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
_TAG_STRIP = re.compile(r"<[^>]+>")
_RANSOM_HINT = re.compile(r"ransomware|extortion|lockbit|alphv|akira", re.IGNORECASE)


class CustomFeedError(Exception):
    pass


# ---------------------------------------------------------------------------
# Settings validation (used by the PUT /api/advisories/custom-feeds endpoint)
# ---------------------------------------------------------------------------

def validate_feed_entries(entries: list[dict]) -> list[dict]:
    """Validate + normalize a custom-feed list. Raises ValueError on bad input.

    Syntactic checks only (https, host present, no credentials, IP literals
    screened) — full DNS resolution happens again at fetch time, so a host
    that later starts resolving to a private address is still rejected.
    """
    if not isinstance(entries, list):
        raise ValueError("custom_feeds must be a list")
    if len(entries) > MAX_FEEDS:
        raise ValueError(f"At most {MAX_FEEDS} custom feeds are supported")
    seen_names: set[str] = set()
    normalized: list[dict] = []
    for i, entry in enumerate(entries):
        label = f"Feed #{i + 1}"
        name = str(entry.get("name") or "").strip()
        url = str(entry.get("url") or "").strip()
        fmt = str(entry.get("format") or "").strip().lower()
        if not name:
            raise ValueError(f"{label}: name is required")
        if len(name) > MAX_NAME_LEN:
            raise ValueError(f"{label}: name exceeds {MAX_NAME_LEN} characters")
        if name.lower() in seen_names:
            raise ValueError(f"{label}: duplicate feed name '{name}'")
        seen_names.add(name.lower())
        if fmt not in ALLOWED_FORMATS:
            raise ValueError(f"{label}: format must be one of {', '.join(ALLOWED_FORMATS)}")
        problem = _syntactic_url_problem(url)
        if problem:
            raise ValueError(f"{label}: {problem}")
        normalized.append({"name": name, "url": url, "format": fmt})
    return normalized


def _syntactic_url_problem(url: str) -> str | None:
    if not url:
        return "URL is required"
    if len(url) > MAX_URL_LEN:
        return f"URL exceeds {MAX_URL_LEN} characters"
    try:
        parsed = urlparse(url)
    except ValueError:
        return "URL could not be parsed"
    if parsed.scheme != "https":
        return "URL must use https"
    if not parsed.hostname:
        return "URL has no host"
    if parsed.username is not None or parsed.password is not None:
        return "URL must not embed credentials"
    ip = _as_ip(parsed.hostname)
    if ip is not None:
        reason = _ip_rejection(ip)
        if reason:
            return f"host is a {reason} address"
    return None


# ---------------------------------------------------------------------------
# SSRF guard — resolve DNS and reject non-public ranges BEFORE connecting
# ---------------------------------------------------------------------------

def _as_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


def _ip_rejection(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """Reason string if this address must never be connected to, else None.
    Same table the pinned transport enforces at connect time (safe_http.STRICT)."""
    return ip_rejection(ip, STRICT)


def assert_public_host(host: str) -> None:
    """Resolve `host` and refuse if ANY resolved address is non-public.

    Called immediately before connecting. IP literals are judged directly.
    """
    ip = _as_ip(host)
    if ip is not None:
        reason = _ip_rejection(ip)
        if reason:
            raise CustomFeedError(f"Feed host {host} is a {reason} address; refusing to connect")
        return
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise CustomFeedError(f"DNS resolution failed for {host}: {exc}") from exc
    if not infos:
        raise CustomFeedError(f"DNS resolution returned no addresses for {host}")
    for info in infos:
        addr = _as_ip(str(info[4][0]))
        if addr is None:
            raise CustomFeedError(f"Unparseable resolved address for {host}")
        reason = _ip_rejection(addr)
        if reason:
            raise CustomFeedError(
                f"Feed host {host} resolves to a {reason} address; refusing to connect"
            )


def _require_locked_url(url: str, host: str) -> None:
    """Every URL touched during a feed walk must be https on the feed's host."""
    try:
        parsed = urlparse(url)
    except ValueError:
        raise CustomFeedError(f"Unparseable URL in feed: {url}")
    if parsed.scheme != "https":
        raise CustomFeedError(f"Feed URL must be https: {url}")
    if parsed.username is not None or parsed.password is not None:
        raise CustomFeedError(f"Feed URL must not embed credentials: {url}")
    if (parsed.hostname or "").lower() != host:
        raise CustomFeedError(
            f"Feed URL {url} leaves the configured host {host}; refusing"
        )


def _is_locked_url(url: str, host: str) -> bool:
    try:
        _require_locked_url(url, host)
        return True
    except CustomFeedError:
        return False


# ---------------------------------------------------------------------------
# Capped fetching (redirects refused — a redirect could hop hosts)
# ---------------------------------------------------------------------------

def _fetch_capped_text(client: httpx.Client, url: str, host: str) -> str:
    _require_locked_url(url, host)
    with client.stream("GET", url) as resp:
        if resp.is_redirect:
            raise CustomFeedError(f"Redirects are not followed for custom feeds: {url}")
        resp.raise_for_status()
        chunks: list[bytes] = []
        total = 0
        for chunk in resp.iter_bytes():
            total += len(chunk)
            if total > _MAX_BODY_BYTES:
                raise CustomFeedError(f"Response body exceeded {_MAX_BODY_BYTES} bytes: {url}")
            chunks.append(chunk)
    body = b"".join(chunks)
    encoding = resp.charset_encoding or "utf-8"
    try:
        return body.decode(encoding, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def _fetch_locked_json(client: httpx.Client, url: str, host: str) -> dict:
    _require_locked_url(url, host)
    return _safe_json(client, url)


# ---------------------------------------------------------------------------
# RSS parsing (defusedxml, follows services/feeds_aa.py)
# ---------------------------------------------------------------------------

def parse_custom_rss(xml_text: str, feed_name: str) -> list[dict]:
    try:
        root = ET.fromstring(xml_text)
    except (ET.ParseError, ValueError) as exc:
        raise CustomFeedError(f"Invalid RSS: {exc}") from exc
    out: list[dict] = []
    for item in root.iter("item"):
        title = (item.findtext("title") or "").strip()
        if not title:
            continue
        desc = _TAG_STRIP.sub(" ", item.findtext("description") or "").strip()
        link = (item.findtext("link") or "").strip()
        guid = (item.findtext("guid") or "").strip()
        stable_key = guid or link or title
        digest = hashlib.sha256(f"{feed_name}|{stable_key}".encode()).hexdigest()[:10].upper()
        cve_ids = list(dict.fromkeys(_CVE_RE.findall(f"{title} {desc}")))[:50]
        if _RANSOM_HINT.search(f"{title} {desc}"):
            severity = "CRITICAL"
        elif cve_ids:
            severity = "HIGH"
        else:
            severity = "MEDIUM"
        published = _parse_rss_date(item.findtext("pubDate") or "")
        out.append({
            "advisory_id": f"CF-{digest}",
            "title": title[:500],
            "summary": desc[:2000],
            "severity": severity,
            "cvss_score": None,
            "cve_ids": cve_ids,
            "affected_vendor": "",
            "affected_product": "",
            "affected_firmware_range": "",
            "recommended_mitigations": (
                "Review the source advisory for mitigations; validate the mapped controls below are operating."
            ),
            "published_date": published,
            # Only carry the link through if it is a well-formed https URL —
            # it is rendered as a hyperlink in the UI.
            "source_url": link if _safe_source_url(link) else "",
        })
    return out


def _safe_source_url(link: str) -> bool:
    try:
        parsed = urlparse(link)
    except ValueError:
        return False
    return parsed.scheme == "https" and bool(parsed.hostname)


def _parse_rss_date(raw: str) -> date | None:
    raw = raw.strip()
    if not raw:
        return None
    try:  # RFC 822: "Sun, 07 Jun 2026 12:00:00 EST"
        return datetime.strptime(raw[:25].strip(), "%a, %d %b %Y %H:%M:%S").date()
    except ValueError:
        pass
    try:  # ISO 8601 fallback
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).date()
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# CSAF provider walk (hardened walker shared with the PSIRT feed, but with
# the custom-feed host lock + no-redirect client)
# ---------------------------------------------------------------------------

def _walk_csaf_provider(client: httpx.Client, metadata_url: str, host: str) -> list[dict]:
    provider = _fetch_locked_json(client, metadata_url, host)
    feed_url = None
    for dist in provider.get("distributions") or []:
        for feed in (dist.get("rolie") or {}).get("feeds") or []:
            if (feed.get("tlp_label") or "").upper() in ("WHITE", "CLEAR"):
                url = feed.get("url")
                if url and _is_locked_url(url, host):
                    feed_url = url
                    break
        if feed_url:
            break
    if not feed_url:
        raise CustomFeedError(f"No public ROLIE feed advertised by {host}")

    feed = _fetch_locked_json(client, feed_url, host)
    feed_obj = feed.get("feed") if isinstance(feed, dict) else None
    entries = feed_obj.get("entry") if isinstance(feed_obj, dict) else None
    entries = [e for e in entries if isinstance(e, dict)] if isinstance(entries, list) else []
    entries = sorted(
        entries,
        key=lambda e: str(e.get("updated") or e.get("published") or ""),
        reverse=True,
    )[:PER_FEED_LIMIT]

    advisories: list[dict] = []
    for entry in entries:
        doc_url = None
        links = entry.get("link")
        for link in links if isinstance(links, list) else []:
            if not isinstance(link, dict):
                continue
            href = str(link.get("href") or "")
            if str(link.get("rel") or "").lower() in ("self", "alternate") and href.endswith(".json"):
                if _is_locked_url(href, host):
                    doc_url = href
                    break
        if not doc_url:
            continue
        try:
            doc = _fetch_locked_json(client, doc_url, host)
        except (httpx.HTTPError, IcsFeedError, CustomFeedError):
            continue  # one bad document never kills the feed
        try:
            parsed_doc = parse_csaf_document(doc)
        except Exception:  # noqa: BLE001 — malformed upstream JSON skips this document only
            continue
        if parsed_doc is not None:
            advisories.append(parsed_doc)
    return advisories


# ---------------------------------------------------------------------------
# Public fetch API
# ---------------------------------------------------------------------------

def fetch_custom_feed(feed: dict) -> list[dict]:
    """Fetch and parse a single configured feed. Raises CustomFeedError."""
    name = str(feed.get("name") or "").strip() or "Custom feed"
    url = str(feed.get("url") or "").strip()
    fmt = str(feed.get("format") or "").strip().lower()
    problem = _syntactic_url_problem(url)
    if problem:
        raise CustomFeedError(f"{name}: {problem}")
    if fmt not in ALLOWED_FORMATS:
        raise CustomFeedError(f"{name}: unsupported format '{fmt}'")
    host = (urlparse(url).hostname or "").lower()
    assert_public_host(host)  # early, friendly rejection; the transport re-checks atomically
    try:
        # Pinned transport: resolve once, validate every record, connect to that IP.
        with guarded_client(STRICT, timeout=HTTP_TIMEOUT, follow_redirects=False) as client:
            if fmt == "rss":
                return parse_custom_rss(_fetch_capped_text(client, url, host), name)[:PER_FEED_LIMIT]
            return _walk_csaf_provider(client, url, host)
    except httpx.HTTPError as exc:
        raise CustomFeedError(f"{name}: {exc}") from exc
    except IcsFeedError as exc:
        raise CustomFeedError(f"{name}: {exc}") from exc


def fetch_custom_feeds(feeds: list[dict]) -> tuple[list[tuple[dict, str]], list[str]]:
    """Fetch every configured feed with per-feed fault isolation.

    Returns ([(advisory_dict, source_label), ...], [error strings]).
    The source label is the feed's configured name.
    """
    results: list[tuple[dict, str]] = []
    errors: list[str] = []
    for feed in feeds or []:
        name = str(feed.get("name") or "").strip() or "Custom feed"
        try:
            advisories = fetch_custom_feed(feed)
        except CustomFeedError as exc:
            errors.append(str(exc) if str(exc).startswith(name) else f"{name}: {exc}")
            continue
        except Exception as exc:  # noqa: BLE001 — malformed upstream data must not abort the other feeds
            errors.append(f"{name}: the feed returned content that could not be read ({type(exc).__name__})")
            continue
        results.extend((adv, name[:MAX_NAME_LEN]) for adv in advisories)
    return results, errors
