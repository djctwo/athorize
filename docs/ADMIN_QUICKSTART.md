# Athorize — Administrator Quickstart

A day-one guide for the person standing the platform up for their organization.
It picks up **after** the software is installed and running (see
[`INSTALL.md`](INSTALL.md) for the server install). If you can reach the login
page in a browser, start here.

> **Audience:** the first admin. **Time:** ~30 minutes to a working instance.

---

## 1. First run — create the first administrator

On a brand-new instance there are no users yet, so the platform protects the
setup screen with a **one-time setup token** generated at first startup.

1. **Get the token.** It's written to two places by the backend on first boot:
   - the service log (`journalctl -u athorize-universal | grep setup`), and
   - the file `<DATA_DIR>/setup-token` (default `~/.athorize-universal/setup-token`, mode `600`).
2. Open the app — it redirects to **Setup**.
3. Enter the **setup token**, then your admin **username**, **email**, and a
   **password** (min 12 chars, 3 character classes).
4. Submit. You're now the admin, and the setup token is **deleted automatically**
   — the setup screen can never be used again.

**Just want to look around first?** On the same screen, after the token, choose
**Explore with demo data** instead. It loads three fictional companies (Acme,
Northwind, Contoso) and signs you in as `admin`; every demo account's password
is its username (`manager`, `auditor`, `operator`, ...). When you are ready for
real use, open **Settings → Start fresh**, enter your password and type
`START FRESH`. Everything on the instance is deleted (including anything you
added during the demo) and you are back at the setup screen. It needs a **new**
token: read the service log or `<DATA_DIR>/setup-token` again.

> If you ever see "Setup already complete," an admin already exists — use the
> normal login.

---

## 2. Orientation

The left sidebar is grouped: **Dashboard**, **Systems / Controls / Crosswalk**,
**Findings / Evidence / ConMon**, **Assets / Topology**, **Risk / Red Team /
Inspection Prep**, **Reports / Audit Log**, and **Settings**. In-app help lives
under **Help** (workflows + keyboard shortcuts; press `⌘K` / `Ctrl-K` for the
command palette).

**Roles** (high → low privilege): `admin` ▸ `compliance_manager` ▸ `assessor` ▸
`system_owner` ▸ `evidence_contributor` ▸ `auditor`. Give people the least role
that lets them do their job; only admins manage users and backups.

What each role can do, in short:
- **Findings** are created, edited and closed by `admin` and `compliance_manager`.
  This includes findings filed from Red Team results, threat advisories and the
  risk register. Moving a finding to Closed, Risk Accepted or False Positive is
  a separate *approve close* permission, which today goes to the same two roles.
  The person a finding is **assigned to** (any role except `auditor`, with
  access to its system) can move it between Open, In Progress and Delayed and
  manage its milestones; the owner picker lists only such people.
- **Frameworks** are activated and deactivated by `admin` only.
- **Assessors** assess controls, run Red Team analyses and manage assessments,
  but they do not file findings.
- **Evidence contributors** upload and link evidence.
- **Auditors** are read-only. They can read comment threads but not post.
- **Assigning systems** to an assessor, system owner, evidence contributor or
  auditor limits that person to those systems everywhere: lists, dashboards,
  exports, search, the audit log (entries for other systems and org-level
  entries are hidden), Red Team reports and the asset matches on threat
  advisories. @mentions only notify people who can see the item.
- **Multi-company installs:** a custom framework is private to the company
  that built it. Live asset connectors (Tanium / Cisco ISE) belong to the
  company the scheduled sync targets (`ASSET_SYNC_ORG_SLUG`, else the first
  company). Instance operators can use both from any company.

---

## 3. Day-one setup checklist

### a. Activate your frameworks — **Frameworks** (admin)
Open **Frameworks** (the Framework Marketplace) and Activate the frameworks
you're assessed against (NIST 800-53, CMMC, ISO 27001, PCI, HIPAA, FedRAMP,
StateRAMP, IRS 1075, CJIS, CSF, 800-82, IEC 62443, and the regulation set — 18 in
all, 1,077 controls). Activating loads that framework's
control catalog and its cross-framework mappings. No license or entitlement is
needed for any included framework.

### b. Register your first system — **Systems**
Click **Add System** (or **Guided setup**) and enter the system(s) you're
authorizing: name, acronym, description, environment, criticality, and the OT
toggle if it's a facility/industrial system. This is the unit everything else
hangs off. Registering the first system also starts the ConMon clock: an
activity never logged becomes overdue one interval later.

### c. Add your team — **Users** (admin)
Create accounts and assign roles. Share initial passwords over a secure channel
and ask each user to change theirs under **Settings → Your Profile → Change
password** (it is not forced). (Prefer SSO? See step **d** — then most users
never need a password at all.)

### d. (Optional) Single sign-on — **OIDC**
Set these env vars and restart (full reference in `INSTALL.md §5`):
`OIDC_ENABLED=true`, `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`,
`OIDC_REDIRECT_URI=https://<your-host>/api/auth/oidc/callback`. A **Sign in with
SSO** button then appears on the login page.

- Configure your IdP to assert `email_verified` — the platform requires a
  **verified** email. The first SSO sign-in links the IdP identity (issuer +
  `sub`) to the one account in the company holding that email (or provisions
  one); afterwards it always signs in to that account. **Users** shows
  "SSO linked"; **Unlink SSO** (or changing the email / de- or reactivating the
  user) removes the link and signs them out.
- Several companies on one install: set `OIDC_PROVISION_ORG_SLUG` to the company
  your IdP belongs to. Without it SSO only signs in already-linked accounts (a
  startup warning says so).
- New SSO users are auto-provisioned at `OIDC_DEFAULT_ROLE` (default `auditor`;
  never `admin` — promote trusted users manually under **Users**).
- Password login always remains available alongside SSO.

### e. (Optional) Email digests — **Settings → Email Digest** (admin)
Set `SMTP_HOST`/`SMTP_FROM` (+ auth if needed) and restart, then set
`DIGEST_INTERVAL_HOURS=24` to email a daily summary of overdue findings,
expiring evidence, and overdue monitoring cadences to admins and compliance
managers. Use **Send test digest to me** to verify delivery before scheduling.

### f. Take your first backup — **Settings → Backup & Restore** (admin)
Click **Download Backup** (optionally passphrase-encrypted) — it archives the
database and all evidence files. Then schedule recurring backups (`INSTALL.md
§10`). Test a restore once, on a throwaway instance, so you trust the process.

---

## 4. The daily workflow

The loop the platform is built around:

1. **Controls** — record implementation status + a narrative per control, per
   system. Each control's **Crosswalk** section shows what it maps to in every
   active framework; equivalent mappings are proposed in **Crosswalk Review**,
   partial overlaps ("intersects") are shown for reference only.
2. **Evidence** — upload artifacts and link them to the controls they satisfy;
   the platform tracks freshness and warns before expiry. Crosswalk suggests
   where the same evidence applies in other frameworks.
3. **Findings** — track weaknesses through their lifecycle (open → in-progress →
   closed/accepted), with owners and due dates. Import from a scanner/SIEM under
   **Findings → Import** (17 formats incl. Nessus CSV and `.nessus`, Qualys,
   Tenable, OpenVAS).
4. **Crosswalk Review** — accept propagation suggestions to claim work you've
   already done in one framework against another.
5. **Continuous Monitoring** — log ongoing activities; the platform flags
   overdue cadences. The **Calendar** shows every deadline (findings,
   milestones, evidence expiry, assessments, cadences) next to your own events.
6. **Inspection Prep** — generate a per-framework readiness package + punch list
   before an audit. **Red Team** quantifies your risk exposure in dollars.
7. **Reports** — CSV exports + the **Executive Briefing** (PPTX) for leadership.

---

## 5. Ongoing operations

| Task | Where |
|---|---|
| Add/remove users, change roles | Users (admin) |
| Rotate a forgotten password | Users → (user) → set new password |
| Change your own password | Settings → Your Profile → Change password |
| API tokens for automation/integration | Settings → API Tokens |
| Backups | Settings → Backup & Restore + scheduled (`INSTALL.md §10`) |
| **Upgrades** | Package a release tarball → run `update.sh` (`INSTALL.md §11`); migrations apply on restart |
| Integrity / who-did-what | Audit Log (hash-chained) |

---

## 6. Quick troubleshooting

| Symptom | Check |
|---|---|
| Can't reach Setup / "token required" | Read `<DATA_DIR>/setup-token` or the service log (after **Start fresh** there is a new token) |
| Compliance scores show 0% | Activate frameworks (Marketplace) and record implementations |
| SSO button missing | `OIDC_ENABLED=true` + issuer/client set, service restarted |
| SSO login fails | IdP must assert `email_verified=true`; redirect URI must match exactly |
| No digest emails | `SMTP_HOST`/`SMTP_FROM` set; use **Send test digest**; recipients need an email + admin/manager role |
| A framework won't activate | All 18 included frameworks activate without a key — only an `admin` can activate them |

Everything here is also covered, with screenshots-by-workflow, under **Help** in
the app. For deployment, TLS, env vars, backups, and upgrades, see
[`INSTALL.md`](INSTALL.md).
