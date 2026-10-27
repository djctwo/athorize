"""Live CISA CSAF 2.0 advisory feed.

Pulled in behind the `ICS_FEED=live` (or `ICS_FEED=CISA`) environment variable.
"""
from __future__ import annotations

import json
import re
from datetime import date, datetime
from typing import Any
from urllib.parse import urlparse

import httpx

from services.safe_http import STRICT, guarded_client


PROVIDER_METADATA_URL = (
    "https://www.cisa.gov/.well-known/csaf/provider-metadata.json"
)

DEFAULT_LIMIT = 25
HTTP_TIMEOUT = httpx.Timeout(10.0, connect=5.0)
_MAX_BRANCH_DEPTH = 20
_MAX_STRING_LEN = 2000
_MAX_BODY_BYTES = 16 * 1024 * 1024
_ALLOWED_HOST_RE = re.compile(r"^([a-z0-9-]+\.)*cisa\.gov$", re.IGNORECASE)


def _validate_cisa_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme != "https":
        return False
    return bool(parsed.hostname and _ALLOWED_HOST_RE.match(parsed.hostname))


def _cap(s: str | None, max_len: int = _MAX_STRING_LEN) -> str:
    if not s:
        return ""
    return s[:max_len]

_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}


class IcsFeedError(RuntimeError):
    pass


def _safe_json(client: httpx.Client, url: str) -> Any:
    with client.stream("GET", url) as resp:
        resp.raise_for_status()
        ct = (resp.headers.get("content-type") or "").lower()
        if not ct.startswith("application/json"):
            raise IcsFeedError(f"Unexpected content-type for {url}: {ct or '(none)'}")
        chunks: list[bytes] = []
        total = 0
        for chunk in resp.iter_bytes():
            total += len(chunk)
            if total > _MAX_BODY_BYTES:
                raise IcsFeedError(
                    f"Response body exceeded {_MAX_BODY_BYTES} bytes: {url}"
                )
            chunks.append(chunk)
    try:
        return json.loads(b"".join(chunks))
    except ValueError as exc:
        raise IcsFeedError(f"Malformed JSON from {url}: {exc}") from exc


def _cisa_host_lock(request: httpx.Request) -> None:
    # Fires for the first request AND every redirect hop: never leave *.cisa.gov.
    if not _validate_cisa_url(str(request.url)):
        raise httpx.UnsupportedProtocol(f"Refusing non-CISA URL {request.url}", request=request)


def _client() -> httpx.Client:
    """SSRF-guarded (public internet only, IP-pinned, https-only) and locked to
    *.cisa.gov on every hop, including redirects (KNOWN-6). Honors
    ATHORIZE_OUTBOUND_PROXY like the other guarded fetches."""
    return guarded_client(STRICT, timeout=HTTP_TIMEOUT, follow_redirects=True,
                          event_hooks={"request": [_cisa_host_lock]})


def fetch_cisa_advisories(limit: int = DEFAULT_LIMIT) -> list[dict]:
    with _client() as client:
        try:
            provider = _safe_json(client, PROVIDER_METADATA_URL)
        except httpx.HTTPError as exc:
            raise IcsFeedError(
                f"Could not load CISA provider metadata: {exc}"
            ) from exc

        feed_url = _rolie_feed_url(provider)
        if not feed_url:
            raise IcsFeedError(
                "CISA provider metadata did not advertise a ROLIE feed"
            )

        try:
            feed = _safe_json(client, feed_url)
        except httpx.HTTPError as exc:
            raise IcsFeedError(f"Could not load ROLIE feed {feed_url}: {exc}") from exc

        entries = (feed.get("feed") or {}).get("entry") or []
        entries = sorted(
            entries,
            key=lambda e: e.get("updated") or e.get("published") or "",
            reverse=True,
        )[:limit]

        advisories: list[dict] = []
        for entry in entries:
            csaf_url = _csaf_url_from_entry(entry)
            if not csaf_url:
                continue
            try:
                doc = _safe_json(client, csaf_url)
            except (httpx.HTTPError, IcsFeedError):
                continue
            try:
                parsed = parse_csaf_document(doc)
            except Exception:  # noqa: BLE001 — one bad document never kills the feed
                continue
            if parsed is not None:
                advisories.append(parsed)

        if not advisories:
            raise IcsFeedError(
                "CISA feed returned no parseable advisories"
            )
        return advisories


def _rolie_feed_url(provider: dict) -> str | None:
    for dist in provider.get("distributions") or []:
        rolie = dist.get("rolie") or {}
        for feed in rolie.get("feeds") or []:
            tlp = ((feed.get("tlp_label") or "").upper())
            if tlp in ("WHITE", "CLEAR"):
                url = feed.get("url")
                if url and _validate_cisa_url(url):
                    return url
    return None


def _csaf_url_from_entry(entry: dict) -> str | None:
    for link in entry.get("link") or []:
        rel = (link.get("rel") or "").lower()
        href = link.get("href", "")
        if rel in ("self", "alternate") and href.endswith(".json"):
            if _validate_cisa_url(href):
                return href
    return None


def _d(value) -> dict:
    return value if isinstance(value, dict) else {}


def _l(value) -> list:
    return value if isinstance(value, list) else []


def _list_of_objects(value) -> bool:
    return value is None or (isinstance(value, list) and all(isinstance(v, dict) for v in value))


def _well_formed(doc: dict, document: dict) -> bool:
    """The CSAF arrays this parser reads must be arrays of objects."""
    vulns = doc.get("vulnerabilities")
    if not _list_of_objects(vulns) or not _list_of_objects(document.get("notes")):
        return False
    for v in vulns or []:
        if not _list_of_objects(v.get("scores")) or not _list_of_objects(v.get("remediations")):
            return False
    tree = doc.get("product_tree")
    return tree is None or (isinstance(tree, dict) and _branches_ok(tree.get("branches"), 0))


def _branches_ok(branches, depth: int) -> bool:
    if depth >= _MAX_BRANCH_DEPTH:
        return True
    if not _list_of_objects(branches):
        return False
    return all(_branches_ok(b.get("branches"), depth + 1) for b in branches or [])


def parse_csaf_document(doc: dict) -> dict | None:
    """One CSAF document → advisory dict, or None when it is not a usable
    advisory. Upstream JSON is untrusted: every nested value is type-checked,
    so a malformed document is skipped instead of aborting the feed."""
    document = _d(_d(doc).get("document"))
    tracking = _d(document.get("tracking"))
    advisory_id = tracking.get("id")
    title = document.get("title")
    if not isinstance(advisory_id, str) or not isinstance(title, str) or not advisory_id or not title:
        return None
    if not _well_formed(doc, document):
        return None  # violates the CSAF structure — never import a half-understood advisory

    summary = _extract_note(document, "summary") or _extract_note(document, "general")

    vulnerabilities = [v for v in _l(doc.get("vulnerabilities")) if isinstance(v, dict)]
    cve_ids = [v["cve"] for v in vulnerabilities if isinstance(v.get("cve"), str) and v.get("cve")]
    severity, cvss_score = _max_cvss(vulnerabilities)
    mitigations = _extract_remediations(vulnerabilities)

    vendor, product, firmware_range = _extract_affected(_d(doc.get("product_tree")))

    published = _parse_date(
        tracking.get("initial_release_date") or tracking.get("current_release_date")
    )

    return {
        "advisory_id": _cap(advisory_id, 100),
        "title": _cap(title, 500),
        "summary": _cap(summary, _MAX_STRING_LEN) if summary else "",
        "severity": severity,
        "cvss_score": cvss_score,
        "cve_ids": cve_ids[:50],
        "affected_vendor": _cap(vendor, 200),
        "affected_product": _cap(product, 200),
        "affected_firmware_range": _cap(firmware_range, 200),
        "recommended_mitigations": _cap(mitigations, 5000),
        "published_date": published,
        "source_url": _advisory_url(_cap(advisory_id, 100)),
    }


def _extract_note(document: dict, category: str) -> str | None:
    for note in _l(document.get("notes")):
        if not isinstance(note, dict):
            continue
        if str(note.get("category") or "").lower() == category:
            text = str(note.get("text") or "").strip()
            if text:
                return text
    return None


def _max_cvss(vulnerabilities: list[dict]) -> tuple[str | None, str | None]:
    best_rank = -1
    best_severity: str | None = None
    best_score: float | None = None
    for vuln in vulnerabilities:
        for score in _l(vuln.get("scores")):
            for key in ("cvss_v4", "cvss_v3", "cvss_v31", "cvss_v30"):
                block = _d(_d(score).get(key))
                if not block:
                    continue
                severity = str(block.get("baseSeverity") or "").upper() or None
                numeric = block.get("baseScore")
                rank = _SEVERITY_ORDER.get(severity or "", 0)
                if rank > best_rank or (rank == best_rank and (numeric or 0) > (best_score or 0)):
                    best_rank = rank
                    best_severity = severity
                    if isinstance(numeric, (int, float)):
                        best_score = float(numeric)
    score_str = f"{best_score:.1f}" if best_score is not None else None
    return best_severity, score_str


def _extract_remediations(vulnerabilities: list[dict]) -> str:
    pieces: list[str] = []
    seen: set[str] = set()
    for vuln in vulnerabilities:
        for rem in _l(vuln.get("remediations")):
            text = str(_d(rem).get("details") or "").strip()
            if text and text not in seen:
                seen.add(text)
                pieces.append(text)
    return "\n\n".join(pieces)


def _extract_affected(product_tree: dict) -> tuple[str | None, str | None, str | None]:
    vendor = product = fw_range = None
    for branch in _iter_branches(_l(product_tree.get("branches"))):
        category = str(branch.get("category") or "").lower()
        name = branch.get("name")
        name = name if isinstance(name, str) else None
        if category == "vendor" and vendor is None:
            vendor = name
        elif category in ("product_family", "product_name") and product is None:
            product = name
        elif category == "product_version_range" and fw_range is None:
            fw_range = name
        elif category == "product_version" and fw_range is None:
            fw_range = name
    return vendor, product, fw_range


def _iter_branches(branches: list[dict], _depth: int = 0) -> list[dict]:
    if _depth >= _MAX_BRANCH_DEPTH:
        return []
    out: list[dict] = []
    for b in branches:
        if not isinstance(b, dict):
            continue
        out.append(b)
        out.extend(_iter_branches(_l(b.get("branches")), _depth + 1))
    return out


def _parse_date(value: str | None) -> date | None:
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date()
    except ValueError:
        return None


def _advisory_url(advisory_id: str) -> str:
    slug = advisory_id.lower()
    return f"https://www.cisa.gov/news-events/ics-advisories/{slug}"
