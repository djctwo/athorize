"""Vendor PSIRT CSAF feeds.

Vendors that publish CSAF 2.0 (Siemens, Cisco, Red Hat, …) expose a
provider-metadata.json exactly like CISA's. Live mode walks each provider
configured in ATHORIZE_PSIRT_PROVIDERS (comma-separated provider-metadata
URLs — operator-configured, HTTPS-only, locked to each provider's own host)
and reuses the hardened CSAF document parser. Default is a bundled fixture.
"""
from __future__ import annotations

import json
import os
from datetime import date
from urllib.parse import urlparse

import httpx

from services.safe_http import STRICT, guarded_client
from services.ics_advisory_cisa import (
    HTTP_TIMEOUT,
    IcsFeedError,
    _safe_json,
    parse_csaf_document,
)
from _appbase import bundle_root

PSIRT_FIXTURE = bundle_root() / "backend" / "data" / "psirt_mock.json"
PER_PROVIDER_LIMIT = 10


class PsirtFeedError(Exception):
    pass


def _same_host(url: str, host: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    return parsed.scheme == "https" and (parsed.hostname or "").lower() == host


def _walk_provider(client: httpx.Client, metadata_url: str) -> list[dict]:
    parsed = urlparse(metadata_url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise PsirtFeedError(f"PSIRT provider URL must be https: {metadata_url}")
    host = parsed.hostname.lower()

    provider = _safe_json(client, metadata_url)
    feed_url = None
    for dist in provider.get("distributions") or []:
        for feed in (dist.get("rolie") or {}).get("feeds") or []:
            if (feed.get("tlp_label") or "").upper() in ("WHITE", "CLEAR"):
                url = feed.get("url")
                if url and _same_host(url, host):
                    feed_url = url
                    break
        if feed_url:
            break
    if not feed_url:
        raise PsirtFeedError(f"No public ROLIE feed advertised by {host}")

    feed = _safe_json(client, feed_url)
    entries = (feed.get("feed") or {}).get("entry") or []
    entries = sorted(
        entries,
        key=lambda e: e.get("updated") or e.get("published") or "",
        reverse=True,
    )[:PER_PROVIDER_LIMIT]

    advisories = []
    for entry in entries:
        doc_url = None
        for link in entry.get("link") or []:
            href = link.get("href", "")
            if (link.get("rel") or "").lower() in ("self", "alternate") and href.endswith(".json"):
                if _same_host(href, host):
                    doc_url = href
                    break
        if not doc_url:
            continue
        try:
            doc = _safe_json(client, doc_url)
        except (httpx.HTTPError, IcsFeedError):
            continue
        parsed_doc = parse_csaf_document(doc)
        if parsed_doc is not None:
            advisories.append(parsed_doc)
    return advisories


def fetch_psirt(live: bool = False) -> list[dict]:
    if not live:
        raw = json.loads(PSIRT_FIXTURE.read_text())
        out = []
        for adv in raw:
            if adv.get("published_date"):
                try:
                    adv["published_date"] = date.fromisoformat(adv["published_date"])
                except ValueError:
                    adv["published_date"] = None
            out.append(adv)
        return out

    providers = [u.strip() for u in (os.getenv("ATHORIZE_PSIRT_PROVIDERS") or "").split(",") if u.strip()]
    if not providers:
        return []
    advisories: list[dict] = []
    errors: list[str] = []
    # SSRF guard: every connection — including each followed redirect hop — is
    # pinned to a validated public IP, and redirects may not leave https.
    with guarded_client(STRICT, timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
        for url in providers:
            try:
                advisories.extend(_walk_provider(client, url))
            except (httpx.HTTPError, IcsFeedError, PsirtFeedError) as exc:
                errors.append(f"{url}: {exc}")
    if not advisories and errors:
        raise PsirtFeedError("; ".join(errors))
    return advisories
