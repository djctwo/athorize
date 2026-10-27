# Framework sources

Where every bundled framework's control catalog and crosswalk come from, so
anyone can check that Athorize redistributes only content it is allowed to.

## Control catalogs

| Framework | Catalog text | Basis |
|---|---|---|
| NIST SP 800-53 Rev 5 | From the official publication | U.S. Government work, public domain |
| NIST SP 800-82 Rev 3 (OT overlay) | From the official publication, OT-tailored | U.S. Government work, public domain |
| NIST CSF 2.0 | From or based on the official publication | U.S. Government work, public domain |
| FedRAMP | 800-53 control text, as selected by FedRAMP | U.S. Government work, public domain |
| CMMC 2.0 | NIST SP 800-171 requirement text | U.S. Government work, public domain |
| IRS Publication 1075 | From or based on the official publication | U.S. Government work, public domain |
| CJIS Security Policy | From or based on the official publication | U.S. Government work, public domain |
| StateRAMP | 800-53-based control text | Built on U.S. Government 800-53 text |
| HIPAA Security Rule | From 45 CFR Part 164 | U.S. federal regulation, public domain |
| GLBA Safeguards Rule | Summaries of 16 CFR Part 314 | U.S. federal regulation, public domain |
| CCPA / CPRA | From the California Civil Code | U.S. state statute |
| SOX (IT general controls) | Original control statements written for Athorize | Athorize |
| GDPR | From Regulation (EU) 2016/679 | EU legislation, reusable with attribution (source: EUR-Lex) |
| DORA | From Regulation (EU) 2022/2554 | EU legislation, reusable with attribution (source: EUR-Lex) |
| **ISO/IEC 27001:2022** | **Original plain-language summaries** written for Athorize | Control IDs and short titles only from the standard; no ISO text |
| **PCI DSS v4** | **Original titles and summaries** written for Athorize | Requirement numbers only from the standard; no PCI SSC text |
| **IEC 62443** | **Original summaries, guidance and assessment objectives** written for Athorize | Requirement IDs and short titles only; no IEC/ISA text |
| **NERC CIP** | **Original plain-language summaries** written for Athorize | Requirement IDs and standard names only; no NERC text |

The four standards in bold are copyrighted by their publishers. Athorize does
not include their text. To work against the authoritative wording, buy the
standard from its publisher and use the summaries here as a guide to it.

## Crosswalk mappings

| Framework | Mapping source |
|---|---|
| CSF 2.0 → 800-53 | NIST OLIR #186 (public domain) |
| ISO/IEC 27001:2022 → 800-53 | NIST OLIR #155 (public domain) |
| HIPAA Security Rule → 800-53 | NIST OLIR #110 (public domain) |
| PCI DSS v4 → 800-53 | Composed from OLIR #183, CSF 2.0 ↔ PCI DSS v4.0.1 (CC0), through the CSF → 800-53 mapping |
| CMMC 2.0 → 800-53 | NIST SP 800-171r2 Appendix D (public domain) |
| CJIS → 800-53 | FBI CJIS ISO Program Office control mapping (U.S. Government work) |
| FedRAMP, StateRAMP, IRS 1075, 800-82 | Identity mappings (these are 800-53 control selections) |
| IEC 62443 → 800-53 | Athorize editorial mapping, informed by the NIST SP 800-82r3 correspondence |
| NERC CIP, GDPR, CCPA/CPRA, SOX, GLBA, DORA → 800-53 | Athorize editorial (advisory) mappings; no official crosswalk exists |

Editorial mappings carry `confidence: vendor` and never auto-propagate a
compliance status; they are navigation and evidence hints only. The scripts that
generate every mapping file are in `scripts/build_mappings/`.

## Not included

CIS Controls v8, HITRUST CSF and SOC 2 (AICPA Trust Services Criteria) are not
bundled: their licenses do not allow redistribution. You can author your own
version of any framework with **Framework Builder**.
