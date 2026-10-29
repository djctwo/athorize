#!/usr/bin/env python3
"""Weekly integration watch for Athorize's outside feeds (no API keys needed).

Athorize reads four public feeds (backend/services/feeds_kev.py, feeds_aa.py,
feeds_nvd.py, ics_advisory_cisa.py). When a publisher moves a URL or changes a
field the parsers read, the live import quietly returns nothing. This script
asks each feed what the parser would ask, compares the answer with the last
run (state file), and opens or updates one GitHub issue per feed when
something changed, so the change announces itself.

Rules
- Contract / shape changes (moved URL, missing field, new content type, new
  field layout) alert immediately.
- Availability problems (timeouts, DNS, 5xx, 429) are retried, and alert only
  after two consecutive weekly runs fail.
- One issue per feed, labelled ``integration-watch``; an open issue is updated,
  never duplicated, and closed with a comment when the feed recovers.

Python standard library only. Usage:
  python scripts/integration_watch.py --state .github/integration-watch/state.json \
      [--summary FILE] [--issues] [--repo OWNER/NAME]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta

# The URLs the app uses. tests/test_integration_watch.py checks they match the
# constants in backend/services so the two cannot drift apart.
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
AA_FEED_URL = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PROVIDER_METADATA_URL = "https://www.cisa.gov/.well-known/csaf/provider-metadata.json"

# Reference points the app does not read, used only to explain a change.
AA_REFERENCE_URL = "https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml"
CISA_SECURITY_TXT = "https://www.cisa.gov/.well-known/security.txt"

USER_AGENT = "athorize-integration-watch (+https://github.com/djctwo/athorize)"
MAX_BODY = 64 * 1024 * 1024
LABEL = "integration-watch"
ISSUE_PREFIX = "[integration-watch]"
AVAILABILITY_STRIKES = 2

SERVICES = {
    "kev": "CISA KEV catalog",
    "aa": "CISA cybersecurity advisories (AA) RSS",
    "csaf": "CISA CSAF advisories",
    "nvd": "NVD CVE API 2.0",
}
APP_FILES = {
    "kev": "backend/services/feeds_kev.py",
    "aa": "backend/services/feeds_aa.py",
    "csaf": "backend/services/ics_advisory_cisa.py",
    "nvd": "backend/services/feeds_nvd.py",
}

_CISA_HOST = re.compile(r"^([a-z0-9-]+\.)*cisa\.gov$", re.IGNORECASE)  # same lock as the app
_AA_ID = re.compile(r"\b(AA\d{2}-\d{3}[A-Z]?)\b")  # feeds_aa._AA_ID
_AA_LINK = re.compile(r"/(aa\d{2}-\d{3}[a-z]?)(?:[/?#]|$)", re.IGNORECASE)
_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")


# ---------------------------------------------------------------------------
# HTTP


class Unavailable(Exception):
    """Transient: network error, timeout, 5xx or rate limit (after retries)."""


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes
    location: str = ""  # redirect target when redirects were not followed

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").lower()

    def json(self):
        return json.loads(self.body)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401 — keep the 3xx
        return None


def http_get(url: str, follow: bool = True, retries: int = 3, backoff: float = 10.0,
             headers: dict | None = None) -> Response:
    """GET with retries for transient failures. Any HTTP status that is not a
    transient failure (including 3xx when ``follow`` is False, and 4xx) is
    returned, not raised: it is a contract answer the caller judges."""
    handlers = [] if follow else [_NoRedirect()]
    opener = urllib.request.build_opener(*handlers)
    last = ""
    for attempt in range(retries):
        if attempt:
            time.sleep(backoff * attempt)
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
        try:
            with opener.open(req, timeout=60) as resp:
                body = resp.read(MAX_BODY + 1)
                return Response(resp.geturl(), resp.status, _lower(resp.headers), body[:MAX_BODY])
        except urllib.error.HTTPError as exc:
            status = exc.code
            if status in (429, 500, 502, 503, 504) or (status == 403 and "nvd.nist.gov" in url):
                last = f"HTTP {status}"  # NVD answers 403 when rate limited
                continue
            body = exc.read(1024 * 1024) if exc.fp else b""
            return Response(url, status, _lower(exc.headers or {}), body, (exc.headers or {}).get("Location", ""))
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            last = f"{type(exc).__name__}: {getattr(exc, 'reason', exc)}"
            continue
    raise Unavailable(f"{url}: {last} (after {retries} attempts)")


def _lower(headers) -> dict[str, str]:
    return {k.lower(): v for k, v in dict(headers).items()}


Fetch = Callable[..., Response]


# ---------------------------------------------------------------------------
# Results


@dataclass
class Result:
    service: str
    problems: list[str] = field(default_factory=list)  # breaking: the app's import is (or will be) wrong
    signature: dict = field(default_factory=dict)      # shape fingerprint; a change is reported
    info: dict = field(default_factory=dict)           # printed only
    unavailable: str = ""                              # transient failure text

    def problem(self, text: str) -> None:
        self.problems.append(text[:600])  # feed-supplied text is capped before it reaches an issue


def _keys(obj) -> list[str]:
    return sorted(obj.keys()) if isinstance(obj, dict) else []


def _present(obj, wanted: tuple[str, ...]) -> list[str]:
    return sorted(k for k in wanted if isinstance(obj, dict) and k in obj)


def _share(n: int, total: int) -> float:
    return n / total if total else 0.0


def _host_ok(url: str) -> bool:
    try:
        p = urllib.parse.urlparse(url)
    except ValueError:
        return False
    return p.scheme == "https" and bool(p.hostname and _CISA_HOST.match(p.hostname))


def _xml(body: bytes):
    """Parse feed XML; documents with a DTD or entities are refused (no
    expansion attacks, and a real RSS feed never needs them)."""
    head = body[:4096].lower()
    if b"<!doctype" in head or b"<!entity" in body.lower():
        raise ValueError("feed declares a DTD/entities")
    return ET.fromstring(body)


# ---------------------------------------------------------------------------
# Checks — each mirrors what the app's parser reads


KEV_FIELDS = ("cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded",
              "shortDescription", "requiredAction", "knownRansomwareCampaignUse")


def check_kev(fetch: Fetch = http_get) -> Result:
    r = Result("kev")
    resp = fetch(KEV_URL, follow=False)  # the app does not follow redirects
    if 300 <= resp.status < 400:
        r.problem(f"The KEV URL now redirects (HTTP {resp.status}) to {resp.location or '?'}; "
                  "the app does not follow redirects, so the live pull fails.")
        return r
    if resp.status != 200:
        r.problem(f"The KEV URL answered HTTP {resp.status} (expected 200).")
        return r
    try:
        doc = resp.json()
    except ValueError:
        r.problem(f"The KEV feed is no longer valid JSON (content-type {resp.content_type or 'none'}).")
        return r
    vulns = doc.get("vulnerabilities") if isinstance(doc, dict) else None
    if not isinstance(vulns, list) or not vulns:
        r.problem("The KEV document has no `vulnerabilities` array (the app reads only that array).")
        r.signature = {"top_keys": _keys(doc)}
        return r
    records = [v for v in vulns if isinstance(v, dict)]
    record_keys: set[str] = set()
    for v in records:
        record_keys.update(v.keys())
    for f in KEV_FIELDS:
        missing = sum(1 for v in records if not v.get(f))
        if _share(missing, len(records)) > (0.01 if f in ("cveID", "dateAdded", "vulnerabilityName") else 0.25):
            r.problem(f"KEV field `{f}` is missing or empty in {missing:,} of {len(records):,} records.")
    bad_cve = sum(1 for v in records if v.get("cveID") and not _CVE.match(str(v["cveID"])))
    if _share(bad_cve, len(records)) > 0.01:
        r.problem(f"{bad_cve:,} KEV `cveID` values are not CVE-YYYY-NNNN ids.")
    bad_date = 0
    for v in records:
        try:
            date.fromisoformat(str(v.get("dateAdded")))
        except ValueError:
            bad_date += 1
    if _share(bad_date, len(records)) > 0.01:
        r.problem(f"{bad_date:,} KEV `dateAdded` values are not YYYY-MM-DD dates.")
    ransomware = sorted({str(v.get("knownRansomwareCampaignUse", "")) for v in records})
    r.signature = {
        "top_keys": _keys(doc),
        "record_keys": sorted(record_keys),
        "ransomware_values": ransomware,
    }
    r.info = {"catalogVersion": doc.get("catalogVersion"), "count": len(records),
              "content_type": resp.content_type}
    return r


def _app_pubdate(pub: str) -> date | None:
    """feeds_aa._parse_rss date logic, verbatim."""
    try:
        return datetime.strptime(pub[:25].strip(), "%a, %d %b %Y %H:%M:%S").date()
    except ValueError:
        return None


def _items(root) -> list:
    return list(root.iter("item"))


def check_aa(fetch: Fetch = http_get) -> Result:
    r = Result("aa")
    resp = fetch(AA_FEED_URL, follow=True)
    if resp.status != 200:
        r.problem(f"The AA feed URL answered HTTP {resp.status} (expected 200).")
        return r
    try:
        root = _xml(resp.body)
    except (ET.ParseError, ValueError) as exc:
        r.problem(f"The AA feed is no longer parseable RSS/XML ({exc}).")
        return r
    items = _items(root)
    if not items:
        r.problem(f"The AA feed has no <item> elements (root element <{root.tag}>).")
        r.signature = {"root": root.tag}
        return r
    child_tags: set[str] = set()
    for it in items:
        child_tags.update(c.tag for c in it)
    for tag in ("title", "link", "description", "pubDate"):
        missing = sum(1 for it in items if not (it.findtext(tag) or "").strip())
        if _share(missing, len(items)) > 0.1:
            r.problem(f"AA feed items lack <{tag}> ({missing} of {len(items)}).")
    pubs = [(it.findtext("pubDate") or "").strip() for it in items]
    unparsed = [p for p in pubs if p and _app_pubdate(p) is None]
    if _share(len(unparsed), len(items)) > 0.5:
        r.problem(f"The app cannot read the AA feed's dates: {len(unparsed)} of {len(items)} <pubDate> values "
                  f"do not match \"%a, %d %b %Y %H:%M:%S\" (example: \"{unparsed[0][:40]}\"), "
                  "so imported advisories get no published date.")
    title_ids = sum(1 for it in items if _AA_ID.search(it.findtext("title") or ""))
    link_ids = sum(1 for it in items if _AA_LINK.search(it.findtext("link") or ""))
    r.info = {"items": len(items), "items_the_app_imports": title_ids, "aa_items_by_link": link_ids}

    # Reference: CISA's AA-only feed shows how AA advisories are titled today.
    ref_total = ref_titled = None
    try:
        ref = fetch(AA_REFERENCE_URL, follow=True)
        if ref.status == 200:
            ref_items = [it for it in _items(_xml(ref.body)) if _AA_LINK.search(it.findtext("link") or "")]
            ref_total = len(ref_items)
            ref_titled = sum(1 for it in ref_items if _AA_ID.search(it.findtext("title") or ""))
            r.info.update({"reference_aa_items": ref_total, "reference_aa_items_with_id_in_title": ref_titled})
    except (Unavailable, ET.ParseError, ValueError):
        pass
    if ref_total and ref_titled == 0:
        r.problem(f"CISA's AA advisories no longer carry the AA id in the title (0 of {ref_total} in the AA-only "
                  "feed); the app keeps only items whose TITLE matches AA##-###, so the live AA import "
                  "returns nothing. The id is now only in the link (…/cybersecurity-advisories/aa26-…).")
    if link_ids and not title_ids:
        r.problem(f"{link_ids} AA advisories are in the feed but none has the AA id in its title, so the app "
                  "imports none of them.")
    r.signature = {
        "root": root.tag,
        "item_tags": sorted(child_tags),
        "pubdate_readable": not unparsed,
        "aa_id_in_title": bool(ref_titled) if ref_total else None,
    }
    return r


def _security_txt_csaf(fetch: Fetch) -> list[str]:
    try:
        resp = fetch(CISA_SECURITY_TXT, follow=True)
    except Unavailable:
        return []
    if resp.status != 200:
        return []
    text = resp.body.decode("utf-8", "replace")
    return [line.split(":", 1)[1].strip() for line in text.splitlines() if line.lower().startswith("csaf:")]


def check_csaf(fetch: Fetch = http_get) -> Result:
    r = Result("csaf")
    meta_url = PROVIDER_METADATA_URL
    resp = fetch(meta_url, follow=True)
    if resp.status != 200 or not _host_ok(resp.url):
        hints = _security_txt_csaf(fetch)
        where = f" CISA's security.txt now points to: {', '.join(hints)}." if hints else ""
        r.problem(f"The app's CSAF provider-metadata URL answered HTTP {resp.status} "
                  f"({meta_url}).{where} The live ICS advisory feed (ICS_FEED=live) fails at its first step.")
        if not hints:
            r.signature = {"metadata_url_status": resp.status}
            return r
        meta_url = hints[0]
        resp = fetch(meta_url, follow=True)  # keep going so every later change is reported at once
        if resp.status != 200:
            r.signature = {"metadata_url_status": resp.status}
            return r
    if not resp.content_type.startswith("application/json"):
        r.problem(f"Provider metadata is served as `{resp.content_type or 'none'}`; the app requires application/json.")
    try:
        meta = resp.json()
    except ValueError:
        r.problem("Provider metadata is not valid JSON.")
        return r
    feeds = []
    for dist in meta.get("distributions") or []:
        for feed in ((dist or {}).get("rolie") or {}).get("feeds") or []:
            feeds.append(feed)
    public = [f for f in feeds if str(f.get("tlp_label") or "").upper() in ("WHITE", "CLEAR") and f.get("url")]
    allowed = [f for f in public if _host_ok(f["url"])]
    hosts = sorted({urllib.parse.urlparse(f["url"]).hostname or "" for f in public})
    r.info = {"metadata_url": meta_url, "public_rolie_feeds": len(public), "feed_hosts": hosts}
    if not public:
        r.problem("Provider metadata advertises no TLP:WHITE/CLEAR ROLIE feed.")
    elif not allowed:
        r.problem(f"The public ROLIE feeds are now hosted on {', '.join(hosts)}; the app only follows "
                  "*.cisa.gov URLs (SSRF host lock), so it finds no feed.")
    feed_url = (allowed or public or [{}])[0].get("url")
    entry_keys: set[str] = set()
    doc_sig: dict = {}
    if feed_url:
        fresp = fetch(feed_url, follow=True)
        if fresp.status != 200:
            r.problem(f"The ROLIE feed answered HTTP {fresp.status} ({feed_url}).")
        else:
            if not fresp.content_type.startswith("application/json"):
                r.problem(f"The ROLIE feed is served as `{fresp.content_type or 'none'}`; the app requires "
                          "application/json and rejects it.")
            try:
                feed = fresp.json()
            except ValueError:
                feed = None
                r.problem("The ROLIE feed is not valid JSON.")
            entries = ((feed or {}).get("feed") or {}).get("entry") or []
            r.info["feed_entries"] = len(entries)
            if feed is not None and not entries:
                r.problem("The ROLIE feed has no `feed.entry` array.")
            for e in entries[:200]:
                if isinstance(e, dict):
                    entry_keys.update(e.keys())
            newest = sorted((e for e in entries if isinstance(e, dict)),
                            key=lambda e: e.get("updated") or e.get("published") or "", reverse=True)[:1]
            doc_url = None
            for e in newest:
                for link in e.get("link") or []:
                    rel = str(link.get("rel") or "").lower()
                    if rel in ("self", "alternate") and str(link.get("href", "")).endswith(".json"):
                        doc_url = link["href"]
                        break
            if newest and not doc_url:
                r.problem("ROLIE entries no longer carry a `self`/`alternate` link to a .json CSAF document.")
            if doc_url:
                doc_sig = _check_csaf_document(fetch, doc_url, r)
    r.signature = {
        "metadata_keys": _keys(meta),
        "feed_hosts": hosts,
        "entry_keys": sorted(entry_keys),
        **doc_sig,
    }
    return r


def _check_csaf_document(fetch: Fetch, url: str, r: Result) -> dict:
    resp = fetch(url, follow=True)
    if resp.status != 200:
        r.problem(f"The newest CSAF document answered HTTP {resp.status}.")
        return {}
    try:
        doc = resp.json()
    except ValueError:
        r.problem("The newest CSAF document is not valid JSON.")
        return {}
    document = doc.get("document") or {}
    tracking = document.get("tracking") or {}
    if not isinstance(tracking.get("id"), str) or not isinstance(document.get("title"), str):
        r.problem("CSAF documents no longer have `document.tracking.id` + `document.title` "
                  "(the app skips every advisory without them).")
    vulns = doc.get("vulnerabilities")
    if vulns is not None and not (isinstance(vulns, list) and all(isinstance(v, dict) for v in vulns)):
        r.problem("CSAF `vulnerabilities` is not an array of objects (the app skips the document).")
    score_keys: set[str] = set()
    for v in vulns or []:
        for s in v.get("scores") or []:
            if isinstance(s, dict):
                score_keys.update(k for k in s if k.startswith("cvss"))
    if vulns and not score_keys & {"cvss_v4", "cvss_v3", "cvss_v31", "cvss_v30"}:
        r.info["csaf_score_keys"] = sorted(score_keys)
    r.info["sample_document"] = tracking.get("id")
    r.info["sample_score_keys"] = sorted(score_keys)
    # Only the keys the parser reads: optional CSAF sections vary per document
    # and would make every run look like a change.
    return {
        "document_top_keys": _present(doc, ("document", "vulnerabilities", "product_tree")),
        "document_keys": _present(document, ("title", "tracking", "notes", "csaf_version")),
        "tracking_keys": _present(tracking, ("id", "initial_release_date", "current_release_date")),
        "csaf_version": document.get("csaf_version"),
    }


def check_nvd(fetch: Fetch = http_get, now: datetime | None = None) -> Result:
    r = Result("nvd")
    end = now or datetime.now(UTC)
    start = end - timedelta(days=7)
    params = {  # the app's query (feeds_nvd.fetch_nvd), one result only
        "cvssV3Severity": "CRITICAL",
        "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 1,
    }
    resp = fetch(f"{NVD_URL}?{urllib.parse.urlencode(params)}", follow=False)
    if 300 <= resp.status < 400:
        r.problem(f"The NVD API now redirects (HTTP {resp.status}) to {resp.location or '?'}; "
                  "the app does not follow redirects.")
        return r
    if resp.status != 200:
        msg = resp.headers.get("message", "")
        r.problem(f"The NVD API answered HTTP {resp.status} to the app's query{f' ({msg})' if msg else ''}.")
        return r
    try:
        doc = resp.json()
    except ValueError:
        r.problem("The NVD API answer is not valid JSON.")
        return r
    vulns = doc.get("vulnerabilities")
    if not isinstance(vulns, list):
        r.problem("The NVD answer has no `vulnerabilities` array.")
        return r
    r.info = {"version": doc.get("version"), "format": doc.get("format"), "totalResults": doc.get("totalResults")}
    sig = {"top_keys": _keys(doc), "format": doc.get("format"), "version": doc.get("version")}
    if vulns:
        cve = (vulns[0] or {}).get("cve") or {}
        sig["cve_keys"] = _present(cve, ("id", "descriptions", "metrics", "configurations", "published"))
        if not cve.get("id"):
            r.problem("NVD records no longer have `cve.id` (the app skips every record).")
        descs = cve.get("descriptions") or []
        if not any(isinstance(d, dict) and d.get("lang") == "en" and "value" in d for d in descs):
            r.problem("NVD `cve.descriptions` has no {lang: en, value} entry (the app's summary is empty).")
        metrics = cve.get("metrics") or {}
        r.info["sample_metric_keys"] = _keys(metrics)
        m = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
        data = (m[0] or {}).get("cvssData") or {} if m else {}
        if not m:
            r.problem(f"A CRITICAL CVE has no cvssMetricV31/V30 (metrics present: {', '.join(_keys(metrics)) or 'none'}); "
                      "the app's severity and score come only from those.")
        elif "baseScore" not in data or "baseSeverity" not in data:
            r.problem("NVD `cvssData` lacks baseScore/baseSeverity.")
        try:
            datetime.fromisoformat(str(cve.get("published")))
        except ValueError:
            r.problem(f"NVD `cve.published` is not ISO-8601 ({str(cve.get('published'))[:40]!r}).")
        cpes = [mt.get("criteria", "") for c in cve.get("configurations") or [] for n in c.get("nodes") or []
                for mt in n.get("cpeMatch") or []]
        if cpes and not any(str(c).startswith("cpe:2.3:") for c in cpes):
            r.problem("NVD CPE `criteria` no longer use the cpe:2.3: form the app splits for vendor/product.")
    else:
        r.info["note"] = "no CRITICAL CVE modified in the last 7 days; record shape not checked this run"
    r.signature = sig
    return r


CHECKS: dict[str, Callable[..., Result]] = {"kev": check_kev, "aa": check_aa, "csaf": check_csaf, "nvd": check_nvd}


# ---------------------------------------------------------------------------
# Evaluation against last-seen state


def _diff_signature(old: dict, new: dict) -> list[str]:
    out = []
    for key in sorted(new):  # a key absent this run = the check stopped early, not a change
        a, b = old.get(key), new.get(key)
        if a == b or key not in old:
            continue
        if isinstance(a, list) and isinstance(b, list):
            added = [x for x in b if x not in a]
            removed = [x for x in a if x not in b]
            parts = []
            if added:
                parts.append("added " + ", ".join(f"`{x}`" for x in added[:20]))
            if removed:
                parts.append("removed " + ", ".join(f"`{x}`" for x in removed[:20]))
            if parts:
                out.append(f"`{key}`: " + "; ".join(parts))
        else:
            out.append(f"`{key}`: was `{json.dumps(a)}`, now `{json.dumps(b)}`")
    return out


@dataclass
class Verdict:
    service: str
    alert: bool
    reasons: list[str]
    changes: list[str]
    result: Result
    strikes: int

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256("\n".join(self.reasons + self.changes).encode()).hexdigest()[:12]


def evaluate(result: Result, prev: dict) -> tuple[Verdict, dict]:
    """Compare one check with its last-seen state → (verdict, new state)."""
    prev = prev or {}
    if result.unavailable:
        strikes = int(prev.get("consecutive_unavailable", 0)) + 1
        new = {**prev, "consecutive_unavailable": strikes, "last_status": "unavailable"}
        reasons = []
        if strikes >= AVAILABILITY_STRIKES:
            reasons = [f"Unreachable for {strikes} consecutive weekly runs: {result.unavailable}"]
        return Verdict(result.service, bool(reasons), reasons, [], result, strikes), new
    old_sig = prev.get("signature") or {}
    # A broken feed is reported by its problems; a shape diff is only meaningful
    # (and only reported) on a run that read the whole feed.
    changes = _diff_signature(old_sig, result.signature) if old_sig and not result.problems else []
    keep_old = result.problems and len(result.signature) < len(old_sig)
    new = {
        "consecutive_unavailable": 0,
        "last_status": "problem" if result.problems else "ok",
        "signature": old_sig if keep_old else result.signature,
    }
    alert = bool(result.problems or changes)
    return Verdict(result.service, alert, list(result.problems), changes, result, 0), new


# ---------------------------------------------------------------------------
# Reporting + issues


def issue_title(service: str, verdict: Verdict) -> str:
    what = "unreachable" if verdict.result.unavailable else ("import broken or at risk" if verdict.reasons else "format changed")
    return f"{ISSUE_PREFIX} {SERVICES[service]}: {what}"


def issue_body(v: Verdict, run_url: str) -> str:
    lines = [
        f"The weekly integration watch found a change in **{SERVICES[v.service]}**, a feed Athorize "
        f"reads in `{APP_FILES[v.service]}`.",
        "",
    ]
    if v.reasons:
        lines += ["### What breaks", *[f"- {x}" for x in v.reasons], ""]
    if v.changes:
        lines += ["### Shape changes since the last run", *[f"- {x}" for x in v.changes], ""]
    if v.result.info:
        lines += ["### Seen this run", "```json", json.dumps(v.result.info, indent=2, default=str), "```", ""]
    lines += [
        "### What to do",
        f"Update the parser in `{APP_FILES[v.service]}` (and its fixture/tests) to the new layout, or confirm "
        "the change is harmless and close this issue. The watch closes it by itself once the problem is gone.",
        "",
        f"Run: {run_url}" if run_url else "",
        f"<!-- integration-watch service={v.service} fingerprint={v.fingerprint} -->",
    ]
    return "\n".join(lines)


def _gh(args: list[str], repo: str) -> str:
    out = subprocess.run(["gh", *args, "--repo", repo], check=True, capture_output=True, text=True)
    return out.stdout


def sync_issue(v: Verdict, repo: str, run_url: str) -> str:
    """Open, update or close the one issue for this service. Returns what was done."""
    prefix = f"{ISSUE_PREFIX} {SERVICES[v.service]}:"
    found = json.loads(_gh(["issue", "list", "--label", LABEL, "--state", "open", "--limit", "100",
                            "--json", "number,title,body"], repo))
    mine = [i for i in found if i["title"].startswith(prefix)]
    if not v.alert:
        if mine and not v.result.unavailable:
            for i in mine:
                _gh(["issue", "comment", str(i["number"]), "--body",
                     f"Recovered: the weekly watch found {SERVICES[v.service]} working as the app expects. {run_url}"], repo)
                _gh(["issue", "close", str(i["number"])], repo)
            return f"closed #{', #'.join(str(i['number']) for i in mine)} (recovered)"
        return "no issue"
    body = issue_body(v, run_url)
    if mine:
        issue = mine[0]
        if f"fingerprint={v.fingerprint}" in (issue.get("body") or ""):
            return f"#{issue['number']} already open (unchanged)"
        _gh(["issue", "edit", str(issue["number"]), "--title", issue_title(v.service, v), "--body", body], repo)
        _gh(["issue", "comment", str(issue["number"]), "--body", f"The watch saw a further change; the description is updated. {run_url}"], repo)
        return f"updated #{issue['number']}"
    url = _gh(["issue", "create", "--label", LABEL, "--title", issue_title(v.service, v), "--body", body], repo).strip()
    return f"opened {url}"


def render_summary(verdicts: list[Verdict], actions: dict[str, str]) -> str:
    out = ["## Integration watch", "", "| Feed | Status | Issue |", "|---|---|---|"]
    for v in verdicts:
        if v.result.unavailable:
            status = f"unreachable ({v.strikes}/{AVAILABILITY_STRIKES})"
        elif v.reasons:
            status = f"PROBLEM ({len(v.reasons)})"
        elif v.changes:
            status = f"changed ({len(v.changes)})"
        else:
            status = "ok"
        out.append(f"| {SERVICES[v.service]} | {status} | {actions.get(v.service, '-')} |")
    for v in verdicts:
        out += ["", f"### {SERVICES[v.service]}"]
        out += [f"- PROBLEM: {x}" for x in v.reasons] + [f"- change: {x}" for x in v.changes]
        if v.result.unavailable:
            out.append(f"- unavailable: {v.result.unavailable}")
        out.append(f"- seen: `{json.dumps(v.result.info, default=str)}`")
    return "\n".join(out) + "\n"


def run(state_path: str, services: list[str], fetch: Fetch = http_get) -> tuple[list[Verdict], dict]:
    try:
        with open(state_path) as fh:
            state = json.load(fh)
    except (FileNotFoundError, ValueError):
        state = {}
    feeds = dict(state.get("feeds") or {})
    verdicts = []
    for name in services:
        try:
            result = CHECKS[name](fetch)
        except Unavailable as exc:
            result = Result(name, unavailable=str(exc))
        verdict, feeds[name] = evaluate(result, feeds.get(name, {}))
        verdicts.append(verdict)
    return verdicts, {"schema": 1, "feeds": feeds}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--state", default=".github/integration-watch/state.json")
    ap.add_argument("--summary", help="append a Markdown summary to this file (e.g. $GITHUB_STEP_SUMMARY)")
    ap.add_argument("--issues", action="store_true", help="open/update/close GitHub issues with `gh`")
    ap.add_argument("--repo", default=os.getenv("GITHUB_REPOSITORY", "djctwo/athorize"))
    ap.add_argument("--only", nargs="*", choices=sorted(CHECKS), help="run only these checks")
    args = ap.parse_args(argv)

    verdicts, new_state = run(args.state, args.only or list(CHECKS))
    run_url = ""
    if os.getenv("GITHUB_RUN_ID"):
        run_url = f"{os.getenv('GITHUB_SERVER_URL', 'https://github.com')}/{args.repo}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
    actions: dict[str, str] = {}
    if args.issues:
        for v in verdicts:
            actions[v.service] = sync_issue(v, args.repo, run_url)
    summary = render_summary(verdicts, actions)
    print(summary)
    if args.summary:
        with open(args.summary, "a") as fh:
            fh.write(summary)
    os.makedirs(os.path.dirname(args.state) or ".", exist_ok=True)
    with open(args.state, "w") as fh:
        json.dump(new_state, fh, indent=2, sort_keys=True, default=str)
        fh.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
