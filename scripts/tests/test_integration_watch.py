"""Unit tests for scripts/integration_watch.py (standard library only, no network).

Run: python -m unittest discover -s scripts/tests -t .
"""
from __future__ import annotations

import importlib.util
import json
import re
import sys
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("integration_watch", ROOT / "scripts" / "integration_watch.py")
W = importlib.util.module_from_spec(_spec)
sys.modules["integration_watch"] = W  # dataclasses look the module up while building classes
_spec.loader.exec_module(W)


def resp(url, status=200, body=b"", ctype="application/json", location=""):
    if not isinstance(body, bytes):
        body = json.dumps(body).encode() if not isinstance(body, str) else body.encode()
    return W.Response(url, status, {"content-type": ctype}, body, location)


def fake(routes: dict):
    """fetch() stand-in: the first route whose key is a prefix of the URL."""
    def fetch(url, follow=True, **_):
        for prefix, answer in routes.items():
            if url.startswith(prefix):
                if isinstance(answer, Exception):
                    raise answer
                return answer if isinstance(answer, W.Response) else resp(url, *answer)
        return resp(url, 404, "not found", "text/html")
    return fetch


KEV_GOOD = {
    "title": "KEV", "catalogVersion": "2026.01.01", "count": 2,
    "vulnerabilities": [
        {"cveID": "CVE-2026-0001", "vendorProject": "Acme", "product": "Widget", "vulnerabilityName": "Acme RCE",
         "dateAdded": "2026-01-01", "shortDescription": "x", "requiredAction": "patch",
         "knownRansomwareCampaignUse": "Unknown"},
        {"cveID": "CVE-2026-0002", "vendorProject": "Acme", "product": "Gadget", "vulnerabilityName": "Acme SQLi",
         "dateAdded": "2026-01-02", "shortDescription": "y", "requiredAction": "patch",
         "knownRansomwareCampaignUse": "Known"},
    ],
}


def rss(items: list[tuple[str, str, str]], doctype: str = "") -> str:
    body = "".join(f"<item><title>{t}</title><link>{l}</link><description>d</description><pubDate>{p}</pubDate></item>"
                   for t, l, p in items)
    return f'<?xml version="1.0"?>{doctype}<rss version="2.0"><channel><title>x</title>{body}</channel></rss>'


AA_LINK = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-001a"
GOOD_DATE = "Mon, 19 Oct 2026 15:18:07 EDT"


class AppConstants(unittest.TestCase):
    def test_urls_match_the_app(self):
        pairs = {
            "backend/services/feeds_kev.py": ("KEV_URL", W.KEV_URL),
            "backend/services/feeds_aa.py": ("AA_FEED_URL", W.AA_FEED_URL),
            "backend/services/feeds_nvd.py": ("NVD_URL", W.NVD_URL),
        }
        for path, (name, value) in pairs.items():
            src = (ROOT / path).read_text()
            m = re.search(rf'^{name} = "([^"]+)"', src, re.M)
            self.assertIsNotNone(m, f"{name} not found in {path}")
            self.assertEqual(m.group(1), value, path)
        src = (ROOT / "backend/services/ics_advisory_cisa.py").read_text()
        m = re.search(r'PROVIDER_METADATA_URL = \(\s*"([^"]+)"', src)
        self.assertEqual(m.group(1), W.PROVIDER_METADATA_URL)

    def test_aa_id_regex_matches_the_app(self):
        src = (ROOT / "backend/services/feeds_aa.py").read_text()
        self.assertIn(W._AA_ID.pattern, src)


class Kev(unittest.TestCase):
    def test_good(self):
        r = W.check_kev(fake({W.KEV_URL: (200, KEV_GOOD)}))
        self.assertEqual(r.problems, [])
        self.assertIn("cveID", r.signature["record_keys"])

    def test_missing_field_is_a_problem(self):
        doc = json.loads(json.dumps(KEV_GOOD))
        for v in doc["vulnerabilities"]:
            v["dateAdded"] = "01/02/2026"
            del v["cveID"]
        r = W.check_kev(fake({W.KEV_URL: (200, doc)}))
        self.assertTrue(any("cveID" in p for p in r.problems))
        self.assertTrue(any("dateAdded" in p for p in r.problems))

    def test_redirect_is_a_problem(self):
        r = W.check_kev(fake({W.KEV_URL: resp(W.KEV_URL, 301, "", "text/html", "https://new.example/kev.json")}))
        self.assertIn("redirects", r.problems[0])
        self.assertIn("new.example", r.problems[0])

    def test_not_json(self):
        r = W.check_kev(fake({W.KEV_URL: (200, "<html>", "text/html")}))
        self.assertIn("no longer valid JSON", r.problems[0])


class Aa(unittest.TestCase):
    def test_good(self):
        feed = rss([("AA26-001A: Acme campaign", AA_LINK, GOOD_DATE)])
        r = W.check_aa(fake({W.AA_FEED_URL: (200, feed, "application/rss+xml"),
                             W.AA_REFERENCE_URL: (200, feed, "application/rss+xml")}))
        self.assertEqual(r.problems, [])
        self.assertEqual(r.info["items_the_app_imports"], 1)

    def test_id_only_in_link_and_two_digit_years(self):
        feed = rss([("#StopRansomware: Acme", AA_LINK, "Thu, 29 Oct 26 12:00:00 +0000")])
        r = W.check_aa(fake({W.AA_FEED_URL: (200, feed, "application/rss+xml"),
                             W.AA_REFERENCE_URL: (200, feed, "application/rss+xml")}))
        text = " ".join(r.problems)
        self.assertIn("dates", text)
        self.assertIn("no longer carry the AA id in the title", text)

    def test_dtd_is_refused(self):
        feed = rss([("AA26-001A", AA_LINK, GOOD_DATE)], '<!DOCTYPE rss [<!ENTITY a "aaaa">]>')
        r = W.check_aa(fake({W.AA_FEED_URL: (200, feed, "application/rss+xml")}))
        self.assertIn("no longer parseable", r.problems[0])


def csaf_routes(meta_url=W.PROVIDER_METADATA_URL, feed_url="https://www.cisa.gov/csaf/feed.json",
                feed_ctype="application/json"):
    doc_url = "https://www.cisa.gov/csaf/2026/icsa-26-001-01.json"
    return {
        meta_url: (200, {"canonical_url": meta_url, "distributions": [
            {"rolie": {"feeds": [{"tlp_label": "WHITE", "url": feed_url}]}}]}),
        feed_url: (200, {"feed": {"entry": [{"id": "ICSA-26-001-01", "updated": "2026-01-01",
                                            "link": [{"rel": "self", "href": doc_url}]}]}}, feed_ctype),
        doc_url: (200, {"document": {"title": "Acme PLC", "csaf_version": "2.0",
                                     "tracking": {"id": "ICSA-26-001-01"}},
                        "vulnerabilities": [{"cve": "CVE-2026-0001",
                                             "scores": [{"cvss_v3": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}]}),
    }


class Csaf(unittest.TestCase):
    def test_good(self):
        r = W.check_csaf(fake(csaf_routes()))
        self.assertEqual(r.problems, [])
        self.assertEqual(r.info["sample_score_keys"], ["cvss_v3"])
        self.assertEqual(r.signature["tracking_keys"], ["id"])

    def test_moved_metadata_off_host_feed_wrong_type(self):
        new_meta = "https://www.cisa.gov/sites/default/files/csaf/provider-metadata.json"
        routes = csaf_routes(new_meta, "https://raw.example.org/csaf/feed.json", "text/plain")
        routes[W.CISA_SECURITY_TXT] = (200, f"Contact: x\nCSAF: {new_meta}\n", "text/plain")
        r = W.check_csaf(fake(routes))
        text = " ".join(r.problems)
        self.assertIn("HTTP 404", text)
        self.assertIn(new_meta, text)
        self.assertIn("raw.example.org", text)
        self.assertIn("text/plain", text)


class Nvd(unittest.TestCase):
    NOW = datetime(2026, 1, 8, tzinfo=UTC)
    GOOD = {"format": "NVD_CVE", "version": "2.0", "totalResults": 1, "vulnerabilities": [{"cve": {
        "id": "CVE-2026-0001", "published": "2026-01-01T00:00:00.000",
        "descriptions": [{"lang": "en", "value": "x"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
        "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"}]}]}],
    }}]}

    def test_good_and_query_mirrors_the_app(self):
        seen = []

        def fetch(url, follow=True, **_):
            seen.append((url, follow))
            return resp(url, 200, self.GOOD)
        r = W.check_nvd(fetch, now=self.NOW)
        self.assertEqual(r.problems, [])
        url, follow = seen[0]
        self.assertFalse(follow)
        self.assertIn("cvssV3Severity=CRITICAL", url)
        self.assertIn("resultsPerPage=1", url)
        self.assertIn("lastModStartDate=2026-01-01T00%3A00%3A00.000", url)

    def test_missing_metrics(self):
        doc = json.loads(json.dumps(self.GOOD))
        doc["vulnerabilities"][0]["cve"]["metrics"] = {"cvssMetricV40": []}
        r = W.check_nvd(fake({W.NVD_URL: (200, doc)}), now=self.NOW)
        self.assertIn("cvssMetricV31/V30", r.problems[0])

    def test_empty_window_is_not_a_problem(self):
        doc = {**self.GOOD, "vulnerabilities": [], "totalResults": 0}
        r = W.check_nvd(fake({W.NVD_URL: (200, doc)}), now=self.NOW)
        self.assertEqual(r.problems, [])
        self.assertIn("note", r.info)


class Evaluate(unittest.TestCase):
    def test_availability_needs_two_strikes(self):
        v1, s1 = W.evaluate(W.Result("kev", unavailable="timeout"), {})
        self.assertFalse(v1.alert)
        v2, s2 = W.evaluate(W.Result("kev", unavailable="timeout"), s1)
        self.assertTrue(v2.alert)
        self.assertEqual(s2["consecutive_unavailable"], 2)
        v3, s3 = W.evaluate(W.Result("kev", signature={"a": [1]}), s2)
        self.assertFalse(v3.alert)
        self.assertEqual(s3["consecutive_unavailable"], 0)

    def test_unavailable_keeps_last_signature(self):
        _, s = W.evaluate(W.Result("kev", unavailable="dns"), {"signature": {"a": [1]}})
        self.assertEqual(s["signature"], {"a": [1]})

    def test_shape_change_alerts_once(self):
        prev = {"signature": {"record_keys": ["a", "b"], "version": "2.0"}}
        v, s = W.evaluate(W.Result("nvd", signature={"record_keys": ["a", "c"], "version": "2.1"}), prev)
        self.assertTrue(v.alert)
        text = " ".join(v.changes)
        self.assertIn("added `c`", text)
        self.assertIn("removed `b`", text)
        self.assertIn('"2.1"', text)
        v2, _ = W.evaluate(W.Result("nvd", signature={"record_keys": ["a", "c"], "version": "2.1"}), s)
        self.assertFalse(v2.alert)

    def test_problem_alerts_immediately_without_noise_diff(self):
        prev = {"signature": {"x": [1], "y": [2]}}
        v, s = W.evaluate(W.Result("csaf", problems=["moved"], signature={"x": [9]}), prev)
        self.assertTrue(v.alert)
        self.assertEqual(v.changes, [])
        self.assertEqual(s["signature"], prev["signature"])  # partial read does not overwrite

    def test_fingerprint_is_stable(self):
        a, _ = W.evaluate(W.Result("aa", problems=["p"]), {})
        b, _ = W.evaluate(W.Result("aa", problems=["p"]), {})
        self.assertEqual(a.fingerprint, b.fingerprint)


class Issues(unittest.TestCase):
    def _verdict(self, problems):
        v, _ = W.evaluate(W.Result("kev", problems=problems, info={"count": 1}), {})
        return v

    def test_open_then_unchanged_then_recover(self):
        calls = []
        existing = []

        def gh(args, repo):
            calls.append(args[:2])
            if args[:2] == ["issue", "list"]:
                return json.dumps(existing)
            return "https://github.com/o/r/issues/7\n"
        with mock.patch.object(W, "_gh", gh):
            v = self._verdict(["broken"])
            self.assertTrue(W.sync_issue(v, "o/r", "").startswith("opened"))
            self.assertIn(["issue", "create"], calls)
            existing.append({"number": 7, "title": W.issue_title("kev", v), "body": W.issue_body(v, "")})
            calls.clear()
            self.assertIn("unchanged", W.sync_issue(v, "o/r", ""))
            self.assertEqual(calls, [["issue", "list"]])
            v2 = self._verdict(["broken differently"])
            self.assertIn("updated", W.sync_issue(v2, "o/r", ""))
            ok, _ = W.evaluate(W.Result("kev"), {})
            self.assertIn("closed", W.sync_issue(ok, "o/r", ""))
            self.assertIn(["issue", "close"], calls)

    def test_body_names_the_app_file_and_marker(self):
        v = self._verdict(["broken"])
        body = W.issue_body(v, "https://run")
        self.assertIn("backend/services/feeds_kev.py", body)
        self.assertIn(f"fingerprint={v.fingerprint}", body)


if __name__ == "__main__":
    unittest.main()
