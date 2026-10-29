# Integration watch

Athorize's live threat feeds depend on files other organisations publish. When a publisher moves a URL or
renames a field, the live import does not crash: it quietly returns nothing. The integration watch makes those
changes announce themselves.

## What runs

`.github/workflows/watch.yml` runs `scripts/integration_watch.py` every Monday (06:23 UTC) on the default
branch, and on demand (Actions → integration-watch → Run workflow). It needs no API keys.

| Feed | App code | What the watch checks |
|---|---|---|
| CISA KEV catalog | `backend/services/feeds_kev.py` | 200 without a redirect (the app does not follow redirects); JSON with a `vulnerabilities` array; every record carries `cveID` (CVE id form), `vendorProject`, `product`, `vulnerabilityName`, `dateAdded` (YYYY-MM-DD), `shortDescription`, `requiredAction`, `knownRansomwareCampaignUse`; record keys and ransomware values compared with the last run |
| CISA AA advisories RSS (`all.xml`) | `backend/services/feeds_aa.py` | 200; RSS without a DTD; items carry `title`, `link`, `description`, `pubDate`; `pubDate` readable with the app's date format; AA ids where the parser looks for them (the title), compared with CISA's AA-only feed |
| CISA CSAF advisories | `backend/services/ics_advisory_cisa.py` | provider metadata at the app's URL (with CISA's `security.txt` as the fallback hint); `application/json`; a TLP:WHITE/CLEAR ROLIE feed on a `*.cisa.gov` host (the app's host lock); the feed's content type and `feed.entry[].link` to a `.json` document; the newest CSAF document's `document.tracking.id`, `document.title`, `vulnerabilities[]` and score keys |
| NVD CVE API 2.0 | `backend/services/feeds_nvd.py` | the app's own query (CRITICAL, last 7 days) with `resultsPerPage=1`, no redirect; `vulnerabilities[].cve.id`, English `descriptions`, `metrics.cvssMetricV31/V30[0].cvssData.baseScore/baseSeverity`, ISO `published`, `cpe:2.3:` criteria; `format`/`version` compared with the last run |

Operator-configured feeds (vendor PSIRT CSAF providers, custom RSS/CSAF feeds, Tanium / Cisco ISE
connectors) are not watched: their URLs live in each installation's settings, not in this repository.

## How alerts arrive

- A **contract change** (moved URL, new content type, missing field, field-layout change) alerts on the first
  run that sees it.
- An **outage** (timeout, DNS, 5xx, 429 after three tries) alerts only after **two consecutive weekly runs**
  fail, so one bad night is never an issue.
- Each feed has at most one open issue, labelled `integration-watch`. A further change updates it (and adds a
  comment); when the feed works again the watch comments and closes it. GitHub notifies the repository owner of
  every new issue and comment.
- If the watch itself fails, the workflow run fails and GitHub emails the owner.

Last-seen shapes and outage counters are kept in `.github/integration-watch/state.json`; the workflow commits
it to the default branch only when it changes. A keepalive step re-enables the workflow every run so GitHub
never disables the schedule after 60 days without commits.

## Tests

`python -m unittest discover -s scripts/tests -t .` (standard library only, no network). They also check that
the watched URLs are the ones in `backend/services`, so the watch cannot drift from the app.
