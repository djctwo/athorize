"""CISA Known Exploited Vulnerabilities (KEV) feed.

Public-domain JSON catalog of vulnerabilities with confirmed in-the-wild
exploitation — the highest-signal patching feed available. Live pull is
opt-in (THREAT_FEEDS=live); the default is a bundled fixture so demos and
air-gapped installs work without network access. The fixture is FICTIONAL
sample data (made-up vendors, DEMO- ids) — see services/sample_advisories.py.

Live feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""
from __future__ import annotations

import json
from datetime import date

import httpx

from _appbase import bundle_root
from services.sample_advisories import is_real_cve_id

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_FIXTURE = bundle_root() / "backend" / "data" / "kev_mock.json"
_MAX_BODY = 32 * 1024 * 1024  # 32 MiB cap — the live catalog is ~3 MiB


class KevFeedError(Exception):
    pass


def fetch_kev(live: bool = False) -> list[dict]:
    """Return normalized advisory dicts from the KEV catalog."""
    if live:
        try:
            with httpx.Client(timeout=30, follow_redirects=False) as client:
                resp = client.get(KEV_URL)
                resp.raise_for_status()
                if len(resp.content) > _MAX_BODY:
                    raise KevFeedError("KEV feed exceeded size cap")
                raw = resp.json()
        except httpx.HTTPError as exc:
            raise KevFeedError(str(exc)) from exc
    else:
        raw = json.loads(KEV_FIXTURE.read_text())
    return normalize_kev(raw.get("vulnerabilities", []))


def normalize_kev(items: list[dict]) -> list[dict]:
    out = []
    for v in items:
        cve = (v.get("cveID") or "").strip()
        if not cve:
            continue
        ransomware = (v.get("knownRansomwareCampaignUse") or "").strip().lower() == "known"
        published = None
        if v.get("dateAdded"):
            try:
                published = date.fromisoformat(v["dateAdded"])
            except ValueError:
                published = None
        out.append({
            "advisory_id": f"KEV-{cve}",
            "title": v.get("vulnerabilityName") or cve,
            "summary": (v.get("shortDescription") or "").strip(),
            # KEV carries no CVSS; exploitation is confirmed by definition.
            "severity": "CRITICAL" if ransomware else "HIGH",
            "cvss_score": None,
            "cve_ids": [cve],
            "affected_vendor": v.get("vendorProject") or "",
            "affected_product": v.get("product") or "",
            "affected_firmware_range": "",
            "recommended_mitigations": (v.get("requiredAction") or "").strip(),
            "published_date": published,
            # Only a genuine CVE id gets a catalog link; the bundled fixture's
            # fictional DEMO- ids must never point at a real record.
            "source_url": (
                f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve}"
                if is_real_cve_id(cve) else ""
            ),
        })
    return out
