"""CISA Cybersecurity Advisories (AA-series) feed.

Campaign-level advisories (joint CISA/FBI/NSA alerts). These rarely name a
single vendor/product, so they typically carry no asset matches — their value
is the inferred control obligations and analyst awareness. Live mode parses
the public RSS feed; default is a bundled fixture.

Feed: https://www.cisa.gov/cybersecurity-advisories/all.xml
"""
from __future__ import annotations

import re
import defusedxml.ElementTree as ET  # stdlib ET is XXE/billion-laughs vulnerable
from datetime import date, datetime

import httpx

from _appbase import bundle_root

AA_FEED_URL = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
AA_FIXTURE = bundle_root() / "backend" / "data" / "aa_mock.xml"
_MAX_BODY = 8 * 1024 * 1024

_AA_ID = re.compile(r"\b(AA\d{2}-\d{3}[A-Z]?)\b")
_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,7}")
# The bundled fixture is FICTIONAL sample data in a reserved DEMO- namespace
# (services/sample_advisories.py); only the fixture path recognizes it.
_SAMPLE_AA_ID = re.compile(r"(?<![\w-])(DEMO-AA\d{2}-\d{3}[A-Z]?)\b")
_SAMPLE_VULN_ID = re.compile(r"DEMO-\d{4}-\d{4,7}")
_TAG_STRIP = re.compile(r"<[^>]+>")
_RANSOM_HINT = re.compile(r"ransomware|extortion|lockbit|alphv|akira", re.IGNORECASE)


class AaFeedError(Exception):
    pass


def _parse_rss(xml_text: str, sample: bool = False) -> list[dict]:
    id_re = _SAMPLE_AA_ID if sample else _AA_ID
    vuln_re = _SAMPLE_VULN_ID if sample else _CVE_ID
    try:
        root = ET.fromstring(xml_text)
    except (ET.ParseError, ValueError) as exc:
        raise AaFeedError(f"Invalid RSS: {exc}") from exc
    out = []
    for item in root.iter("item"):
        title = (item.findtext("title") or "").strip()
        m = id_re.search(title)
        if not m:
            continue  # only AA-series entries
        aa_id = m.group(1)
        desc = _TAG_STRIP.sub(" ", item.findtext("description") or "").strip()
        link = (item.findtext("link") or "").strip()
        pub = item.findtext("pubDate") or ""
        published: date | None = None
        try:
            published = datetime.strptime(pub[:25].strip(), "%a, %d %b %Y %H:%M:%S").date()
        except ValueError:
            published = None
        severity = "CRITICAL" if _RANSOM_HINT.search(f"{title} {desc}") else "HIGH"
        out.append({
            "advisory_id": aa_id,
            "title": title[:500],
            "summary": desc[:2000],
            "severity": severity,
            "cvss_score": None,
            "cve_ids": list(dict.fromkeys(vuln_re.findall(f"{title} {desc}")))[:50],
            "affected_vendor": "",
            "affected_product": "",
            "affected_firmware_range": "",
            "recommended_mitigations": "Review the full advisory for IOCs and mitigations; validate the mapped controls below are operating.",
            "published_date": published,
            "source_url": link,
        })
    return out


def fetch_aa(live: bool = False, limit: int = 10) -> list[dict]:
    if live:
        try:
            with httpx.Client(timeout=30, follow_redirects=True) as client:
                resp = client.get(AA_FEED_URL)
                resp.raise_for_status()
                if len(resp.content) > _MAX_BODY:
                    raise AaFeedError("AA feed exceeded size cap")
                text = resp.text
        except httpx.HTTPError as exc:
            raise AaFeedError(str(exc)) from exc
    else:
        return _parse_rss(AA_FIXTURE.read_text(), sample=True)[:limit]
    return _parse_rss(text)[:limit]
