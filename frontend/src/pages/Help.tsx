import { useMemo, useState } from 'react'
import {
  Keyboard, BookOpen, Shield, AlertTriangle, FileCheck, Activity, Server,
  ArrowLeftRight, ClipboardCheck, ChevronDown, ChevronRight, Settings as SettingsIcon,
  Crosshair, Search, Users as UsersIcon, Wrench, GraduationCap, X, KeyRound,
} from 'lucide-react'
import { useCurrentRole } from '../hooks/useRole'
import { can, type Action } from '../lib/permissions'

// ---------------------------------------------------------------------------
// Data
// ---------------------------------------------------------------------------

const SHORTCUTS = [
  { keys: ['⌘', 'K'], label: 'Open Command Palette — search and jump to any page' },
  { keys: ['ESC'], label: 'Close panel / dialog' },
  { keys: ['↑', '↓'], label: 'Navigate lists' },
  { keys: ['Enter'], label: 'Open selected item' },
  { keys: ['Tab'], label: 'Next field' },
]

const ALL_ROLES = ['admin', 'compliance_manager', 'assessor', 'system_owner', 'evidence_contributor', 'auditor'] as const
type RoleName = (typeof ALL_ROLES)[number]

const ROLE_LABELS: Record<RoleName, string> = {
  admin: 'Admin',
  compliance_manager: 'Compliance Manager',
  assessor: 'Assessor',
  system_owner: 'System Owner',
  evidence_contributor: 'Evidence Contributor',
  auditor: 'Auditor',
}

// Derived from lib/permissions.ts (the same table the UI and server guards use),
// so this page can't drift from what each role can actually do (R2USER-19).
const rolesFor = (action: Action): RoleName[] => ALL_ROLES.filter(r => can(r, action))
const PERMISSION_ROWS: { capability: string; roles: RoleName[] }[] = [
  { capability: 'View everything (dashboards, findings, evidence, reports)', roles: rolesFor('read:any') },
  { capability: 'Create / edit / close findings', roles: rolesFor('edit:finding') },
  { capability: 'Work a finding assigned to you (status up to Delayed, milestones)', roles: rolesFor('work:own_finding') },
  { capability: 'Upload and link evidence', roles: rolesFor('upload:evidence') },
  { capability: 'Log ConMon activity & edit cadences', roles: rolesFor('edit:conmon') },
  { capability: 'Create / edit risks', roles: rolesFor('edit:risk') },
  { capability: 'Create / edit systems & assets', roles: rolesFor('edit:system') },
  { capability: 'Set control implementation status & assess', roles: rolesFor('assess:control') },
  { capability: 'Accept crosswalk propagation suggestions', roles: rolesFor('assess:control') },
  { capability: 'Activate / deactivate frameworks', roles: rolesFor('manage:frameworks') },
  { capability: 'Manage users (create, roles, password resets)', roles: rolesFor('manage:users') },
  { capability: 'Backup / restore, org settings', roles: rolesFor('manage:settings') },
  { capability: 'Start fresh (demo instances: delete the demo data)', roles: rolesFor('manage:settings') },
  { capability: 'Change your own password', roles: [...ALL_ROLES] },
]

interface Task {
  title: string
  steps: string[]
  tip?: string
  roles?: RoleName[] // minimum roles that can perform this task; omitted = everyone
}

interface Section {
  title: string
  icon: typeof BookOpen
  intro: string
  tasks: Task[]
}

const WRITE: RoleName[] = ['admin', 'compliance_manager']

const SECTIONS: Section[] = [
  {
    title: 'Getting Started',
    icon: BookOpen,
    intro: 'First-time setup, in the order a new organization should do it.',
    tasks: [
      {
        title: 'Choose: set up your company, or explore demo data',
        steps: [
          'A new install opens the Setup screen. Paste the one-time setup token: it is in the server log (the desktop app\'s console window; docker compose logs for Docker) and in the file setup-token in the data folder.',
          'Set up my company creates your organization and its first admin account.',
          'Explore with demo data loads three sample companies (Acme, Northwind, Contoso) and signs you in as admin. Every demo account\'s password is its username (admin, operator, manager, analyst, owner, contributor, auditor, northwind, contoso).',
          'Done exploring? An admin can delete all of the demo in Settings → Start fresh (see Administration). You get the Setup screen again, with a new setup token.',
        ],
        tip: 'Demo data is only ever loaded into an empty instance, never mixed into real data.',
      },
      {
        title: 'Read your dashboard',
        steps: [
          'The Dashboard is home: compliance posture per framework, KPI cards (open findings, overdue items, evidence freshness), and a recent-activity feed.',
          'Use the system selector at the top to focus on one system or view the whole portfolio.',
          'Everything zero? You haven\'t activated a framework or recorded implementations yet — follow the steps below in order.',
        ],
      },
      {
        title: 'Activate your compliance frameworks',
        roles: ['admin'],
        steps: [
          'Open Frameworks in the sidebar (the Framework Marketplace). Only an admin can activate or deactivate frameworks.',
          'Find each framework your organization needs (e.g. CMMC 2.0, PCI DSS, ISO 27001) and click Activate.',
          'Activation loads that framework\'s control catalog and crosswalk mappings from local files — it works offline and takes a few seconds.',
        ],
        tip: 'Activate every framework you report against, even secondary ones — the crosswalk can only connect frameworks that are active.',
      },
      {
        title: 'Register a system',
        roles: WRITE,
        steps: [
          'Open Systems and click Add System (or Guided setup for a step-by-step wizard).',
          'Give it a name, acronym, description, environment, and criticality. Tick "OT / industrial system" if it includes industrial control assets — you can change it later with Edit.',
          'Save. The system now appears in every framework-scoped view (Controls, Findings, Dashboard).',
        ],
      },
      {
        title: 'Record control implementations',
        roles: ['admin', 'assessor'],
        steps: [
          'Open Controls and pick a Framework AND a System at the top — selecting a system switches the page into assessment mode (without one, it\'s a read-only catalog).',
          'Each control shows an editable status dropdown — set it inline (Implemented, Partially, Not Implemented, Not Applicable, Inherited, or Planned).',
          'Expand a control to write the implementation narrative and responsible party, then Save. Assessors read the narrative first.',
          'Select multiple controls (checkboxes, or Select all) and use the bulk bar: "Set status…" applies any status to all of them at once — fast for baselining a whole family — and "Assign to me" / "Assign owner…" set the owner.',
        ],
        tip: 'Narratives under ~80 characters are flagged as weak by Inspection Prep and the Red Team — write at least a sentence or two.',
      },
      {
        title: 'Import your existing POA&M and SSP (migration)',
        roles: WRITE,
        steps: [
          'Open Migration (Admin group). Pick the target system and framework.',
          'POA&M \u2192 Findings: upload your POA&M as CSV (Excel: File \u2192 Save As \u2192 CSV). Column names are matched flexibly \u2014 Weakness/Finding, Risk/Severity, POC/Owner, Scheduled Completion, Mitigation all work, as do the FedRAMP POA&M template columns (Controls, Adjusted/Original Risk Rating) even with its title rows above the header.',
          'SSP \u2192 Control Implementations: upload an implementation workbook; control ids are validated against the catalog and statuses map automatically (In Place \u2192 Implemented, etc.).',
          'Preview first \u2014 it shows exactly what will be created, what is a duplicate, and what will be skipped, with a reason for every skipped or adjusted row. Each row is identified by its POA&M ID when the file has one, otherwise by its title: rows sharing an identity merge into one finding (the same weakness on different assets with different POA&M IDs stays separate), and re-importing the same file creates nothing new. A finding that already exists without a POA&M ID (imported earlier or entered by hand) is linked to the first row with the same title instead of being duplicated. Nothing a human already assessed is ever overwritten.',
        ],
        tip: 'This is the fastest way off spreadsheets: years of POA&M history lands as findings with milestones in minutes.',
      },
      {
        title: 'Add your team',
        roles: ['admin'],
        steps: [
          'Open Users and click Add User.',
          'Pick a role — see the "Who can do what" table above for exactly what each role can do.',
          'Passwords must be 12+ characters with at least 3 character classes (upper, lower, digit, symbol); the form enforces this.',
        ],
      },
    ],
  },
  {
    title: 'Findings & Remediation',
    icon: Shield,
    intro: 'The finding is the universal issue record — POA&M item, non-conformity, or deficiency, depending on your framework.',
    tasks: [
      {
        title: 'Log a finding',
        roles: WRITE,
        steps: [
          'Open Findings and click New Finding.',
          'Pick the system, framework, and the control it violates; set severity and a due date.',
          'Add an owner and a remediation plan — both feed the aging KPIs and the Executive Briefing.',
        ],
      },
      {
        title: 'Work a finding through its lifecycle',
        roles: WRITE,
        steps: [
          'Click the finding to open its detail panel.',
          'Move it OPEN → IN PROGRESS while remediating; add milestones to track interim steps.',
          'Close it as CLOSED (fixed), RISK ACCEPTED (documented rationale required), or FALSE POSITIVE.',
          'Use DELAYED with a new scheduled completion date when remediation slips.',
          'Reopening a closed finding requires a reason — it\'s kept on the record.',
          'Assigned a finding but not a manager? As its owner (any role except Auditor) you can move it between Open, In Progress and Delayed and manage its milestones from its detail panel. Closing, risk acceptance and false positive still need a compliance manager or admin.',
        ],
        tip: 'The Aging column tracks due dates automatically: Overdue, Due 7, Due 30, On Track. Closed findings show Resolved.',
      },
      {
        title: 'Import findings from your SIEM or scanner',
        roles: WRITE,
        steps: [
          'On Findings, click Import.',
          'Drop in an export file — 17 formats auto-detect: Splunk, Suricata, Snort, YARA, Nessus (CSV or native .nessus), CEF, Sentinel, CrowdStrike, Elastic ECS, Wazuh, GuardDuty, syslog RFC 5424, Qualys VM, Tenable, OpenVAS/Greenbone, Windows Event Log.',
          'Nessus informational plugins (Risk = None — scan info, traceroute, port lists) are not vulnerabilities: they are skipped and counted in the preview.',
          'Review the preview, pick the target system, and confirm. Duplicates are skipped by content hash — including rows repeated inside the same file (e.g. a Nessus row per CVE), which merge into one finding. The preview and result list every row that was skipped and why, and warn if a file holds more than 5,000 findings (split it and import the rest).',
          'Imported findings carry their source — filter by it with the Source dropdown.',
        ],
      },
      {
        title: 'See a finding\'s cross-framework impact',
        steps: [
          'Open any finding\'s detail panel and scroll to Cross-Framework Impact.',
          'It lists every other framework whose mapped control is put at risk by this finding — and which satisfied implementations are affected.',
          'Fixing the finding clears the risk everywhere at once; the Executive Briefing shows this as "Also Satisfies When Fixed".',
        ],
      },
    ],
  },
  {
    title: 'Crosswalk — Implement Once, Comply Many',
    icon: ArrowLeftRight,
    intro: 'Control mappings connect your frameworks through the NIST 800-53 hub (3,494 mappings, mostly from official NIST OLIR and Appendix-D sources).',
    tasks: [
      {
        title: 'See what a control maps to',
        steps: [
          'Open Controls and expand any control.',
          'The Crosswalk section lists equivalent/related controls in every other active framework, with relationship and confidence badges.',
          '"via hub" means the mapping is composed through 800-53; a red badge means an open finding threatens that mapped control.',
        ],
      },
      {
        title: 'Claim work you\'ve already done (propagation)',
        roles: ['admin', 'assessor'],
        steps: [
          'Open Crosswalk in the sidebar and pick a system.',
          'The queue lists controls you\'ve satisfied in one framework that map to unimplemented controls in another.',
          'Only "equivalent" and "superset" mappings are proposed. Partial overlaps ("intersects", "related") are shown in each control\'s Crosswalk section for reference — if your frameworks share only those, the queue says so instead of looking finished.',
          'Review each suggestion and click Accept as Planned. This creates a PLANNED implementation pre-filled with the source narrative — an assessor then confirms it.',
          'Nothing is ever auto-accepted; every propagation is a human decision and is audit-logged.',
        ],
        tip: 'PLANNED implementations don\'t count toward compliance scores until an assessor upgrades them — the score never inflates itself.',
      },
      {
        title: 'Let evidence suggest its own reuse',
        roles: ['admin', 'compliance_manager', 'evidence_contributor'],
        steps: [
          'Open any evidence artifact\'s detail panel.',
          'The "Suggested by Crosswalk" section lists controls in other frameworks this artifact likely satisfies, based on its current linkage.',
          'Click Link to attach it — one artifact can satisfy controls across many frameworks.',
        ],
      },
    ],
  },
  {
    title: 'Evidence',
    icon: FileCheck,
    intro: 'Evidence artifacts prove your narratives. Freshness is tracked automatically.',
    tasks: [
      {
        title: 'Upload and link evidence',
        roles: ['admin', 'compliance_manager', 'evidence_contributor'],
        steps: [
          'Open Evidence and click Upload.',
          'Pick the system, the artifact type (Policy, Scan Result, Screenshot, Log, Diagram, Attestation, Other) and the file.',
          'Set "Expires in (days)": it defaults by type — scans, logs and screenshots 90 days, documents a year. Change the date later with Edit Linkage. The dashboard tracks fresh / expiring / expired.',
          'Link it to the controls it proves — in one or several frameworks.',
        ],
      },
      {
        title: 'Keep evidence fresh',
        steps: [
          'Watch the Evidence Freshness donut on the Dashboard, or filter the Evidence page by status.',
          'Expiring artifacts show an amber badge 30 days out; expired ones show red.',
          'Re-collect and re-upload before an inspection — Inspection Prep counts stale evidence against your readiness score.',
        ],
      },
    ],
  },
  {
    title: 'Threat Operations',
    icon: AlertTriangle,
    intro: 'Five threat feeds, matched against your actual assets, with the controls each item implicates.',
    tasks: [
      {
        title: 'Triage threat advisories',
        roles: WRITE,
        steps: [
          'Open Advisories. Items arrive from CISA ICS, the KEV catalog, NVD, CISA AA-series alerts, and vendor PSIRTs.',
          'Matched items show which of your IT/OT assets are affected and at what confidence (exact, firmware range, vendor/product, vendor only).',
          'Each advisory lists the 800-53 controls it implicates — the crosswalk fans those into your other frameworks.',
          'Triage each item: mark Triaged, spawn a Finding or ConMon entry from it, or Dismiss it (dismissals are reversible).',
        ],
        tip: 'Feeds refresh on the schedule set by THREAT_FEEDS_INTERVAL_HOURS; the page header shows when data was last refreshed. Offline installs use bundled fixtures.',
      },
      {
        title: 'Add custom advisory feeds',
        roles: ['admin'],
        steps: [
          'Open Advisories and click Custom feeds (admins only).',
          'Add a feed: give it a name (that becomes the advisory source label), paste an https URL, and pick the format — RSS for an advisory list feed, CSAF for a vendor\'s provider-metadata.json.',
          'Save. Custom feeds are pulled on every refresh alongside the built-in feeds; their items appear in the Source filter under the name you gave them.',
        ],
        tip: 'Feeds are locked down: https only, requests never leave the configured host, and hosts resolving to private/internal addresses are refused. A feed that fails is reported in the refresh result but never blocks the others.',
      },
      {
        title: 'Track organizational risk',
        roles: WRITE,
        steps: [
          'Open Risk Register and click New Risk.',
          'Score likelihood × impact to get the risk level; assign a treatment: Mitigate, Accept, Transfer, or Avoid.',
          'Link a risk to a finding to connect strategy to remediation; statuses run Open → Mitigating → Accepted/Transferred/Closed.',
        ],
      },
    ],
  },
  {
    title: 'Red Team & Dollar Exposure',
    icon: Crosshair,
    intro: 'Adversarial analysis of your own compliance data, with every gap priced from cited industry benchmarks.',
    tasks: [
      {
        title: 'Run a compliance red team analysis',
        roles: ['admin', 'compliance_manager', 'assessor'],
        steps: [
          'Open Red Team, pick a system and framework, and click Run Analysis.',
          'Seven checks probe evidence coverage, narrative quality, implementation gaps, finding hygiene, assessments, and deadlines.',
          'Each finding carries a dollar exposure range with an expandable cost breakdown citing its sources (IBM/Ponemon benchmarks, statutory penalties).',
          'Attack chains show how individual gaps combine into audit failure, compliance debt, or program failure — with a combined estimate that uses the same probable-loss model as the report total, so a chain never exceeds its report.',
        ],
        tip: 'Set your Risk Context (industry, revenue, contract value, record count) first — estimates calibrate to your organization instead of global averages.',
      },
      {
        title: 'Start with the highest-ROI fixes',
        steps: [
          'Use the Start Here tab — it sorts low-effort findings by exposure-per-hour of remediation.',
          'The "Fix Top 5, Save" KPI shows what the five highest-priority fixes are worth.',
        ],
      },
    ],
  },
  {
    title: 'Inspection Prep',
    icon: ClipboardCheck,
    intro: 'A readiness package for a real audit date, generated from your live data.',
    tasks: [
      {
        title: 'Generate a readiness package',
        steps: [
          'Open Inspection Prep; pick the framework, system(s), and the inspection date.',
          'Readiness = ready controls ÷ (controls × selected systems, minus Not Applicable ones). A control is ready on a system when it is Implemented or Inherited, has a narrative of ~80+ characters, and has evidence uploaded for THAT system that is still unexpired on the inspection date (today when no date is set). Not Applicable controls are left out, exactly as in the compliance score.',
          'The punch list ranks what to fix first: Implement gaps, then missing evidence, then stale evidence, then weak narratives — each with an owner.',
          'The 90/60/30 timeline tells you what must be done by when, anchored on the inspection date.',
          'Print the package or export the punch list as CSV for the team.',
        ],
      },
      {
        title: 'Record an assessment and print its report',
        roles: ['admin', 'compliance_manager', 'assessor'],
        steps: [
          'Open Assessments and click New Assessment: pick the system, framework and assessment type, and add notes.',
          'Move it from Planned to In Progress to Complete as the work happens — the start and completion dates are recorded and appear on the Calendar.',
          'The control-by-control results live on the Controls page (status, narrative, evidence); there is no separate objective-by-objective questionnaire.',
          'Click Report for a print-ready assessment report: the controls in scope with their status, narrative and evidence, the findings open in the assessment window, and a sign-off block.',
        ],
      },
    ],
  },
  {
    title: 'Assets & Topology',
    icon: Server,
    intro: 'IT and OT inventory, connected into a network picture.',
    tasks: [
      {
        title: 'Build your asset inventory',
        roles: WRITE,
        steps: [
          'Open Assets — one list for IT and OT; the Type column and filter switch between them. Add entries with Add Asset (choose IT or OT).',
          'Set vendor, model, firmware/OS version, IP, and patch status — threat feed matching uses these.',
          'Use the Connected To field to record network links; OT assets also carry a Purdue level.',
        ],
      },
      {
        title: 'Import assets from Tanium or Cisco ISE',
        roles: WRITE,
        steps: [
          'On Assets, click Import.',
          'Upload a Tanium or Cisco ISE CSV export — the source auto-detects and columns map to asset fields (name, OS, IP, MAC, role).',
          'Or, if a live connector is configured (Tanium / Cisco ISE), click Pull to fetch the inventory directly over the API.',
          'Review the preview, then confirm. Existing assets are skipped — matching is by MAC, then hostname, then name — so re-importing is safe.',
          'Optional scheduled sync: set ASSET_SYNC_INTERVAL_HOURS (e.g. 12) on the server to pull every configured connector automatically on that interval — same dedup as a manual pull, so it never duplicates assets. On multi-company installs, ASSET_SYNC_ORG_SLUG picks the company (assets land in its first system). The Import panel shows the current mode ("Auto-sync every Nh" or "Manual pull only").',
          'Import history (and who ran it) is in the Audit Log under ASSET_IMPORT; scheduled runs appear as actor asset-sync-scheduler with an ASSET_SYNC summary per run.',
        ],
      },
      {
        title: 'Visualize and export the topology',
        steps: [
          'Open Topology and switch between Purdue, Enterprise, OSI, and TCP/IP views.',
          'Download SVG produces a standalone diagram file; Print formats it for assessment packages.',
        ],
      },
    ],
  },
  {
    title: 'Monitoring, Reports & Audit',
    icon: Activity,
    intro: 'Prove the program runs continuously — to assessors and to yourself.',
    tasks: [
      {
        title: 'Log continuous monitoring and manage cadences',
        roles: WRITE,
        steps: [
          'Open ConMon and click Log Activity for each completed task (vulnerability scan, access review, log review…).',
          'The Cadence Requirements table shows every required activity, its interval, when it was last done, and when it\'s next due.',
          'Cadences resolve in order: your org override → the framework\'s shipped requirement → the built-in default. Edit any interval inline.',
          'Overdue cadences raise a banner here and a KPI on the Dashboard. The clock starts when you register your first system: an activity never logged becomes overdue one interval after that, not on day one.',
        ],
      },
      {
        title: 'Track deadlines on the calendar',
        steps: [
          'Open Calendar: the events you add (audits, reviews, kickoffs) plus deadlines pulled in automatically — open findings\' due dates and milestones, evidence expiry dates, assessments and ConMon cadences.',
          'Automatic items are marked Auto and link to their record; change them there (they can\'t be deleted from the calendar). Untick "Show deadlines from…" to see only the events you added.',
        ],
      },
      {
        title: 'Generate reports and the Executive Briefing',
        steps: [
          'Open Reports for CSV exports: findings, evidence, risks, compliance summary, ConMon — filterable by system and framework.',
          'Click Executive Briefing (PPTX) for an 8-slide deck: title, posture, dollar exposure with cited sources (before a Red Team run it says how to get one), open findings with the controls that fix them, crosswalk leverage, program health, a 30/60/90 way forward, and recommendations.',
        ],
      },
      {
        title: 'Export an Audit Binder',
        steps: [
          'On Reports, select a system AND a framework, then click ZIP on the Audit Binder card.',
          'You get a print-ready binder.html (cover, compliance progress over time, control-by-control status with narratives and owners, findings/POA&M with milestones, evidence inventory) plus the actual evidence files under evidence/.',
          'Open binder.html in a browser and print to PDF — that is the package you hand the auditor.',
        ],
        tip: 'Evidence files that only exist as records (no uploaded file) are listed as "not archived" — the binder never fails because of them.',
      },
      {
        title: 'Read the compliance trend',
        steps: [
          'The Dashboard\'s Compliance Trend chart plots average score, open findings, and overdue findings over time.',
          'Snapshots are recorded automatically once a day (and at startup) — no setup required.',
          'The same history appears in the Audit Binder, so you can show an assessor the trajectory, not just today.',
        ],
      },
      {
        title: 'Review the audit trail',
        steps: [
          'Open Audit Log — every create, update, delete, login, and crosswalk accept is recorded with actor and timestamp.',
          'Entries are hash-chained (HMAC): tampering with any record breaks the chain. The page re-verifies the whole chain every time it opens and shows the result at the top.',
        ],
      },
    ],
  },
  {
    title: 'Frameworks',
    icon: KeyRound,
    intro: '18 compliance frameworks (1,077 controls) ship in the box — an admin activates the ones you assess against on the Frameworks page.',
    tasks: [
      {
        title: 'What\'s included',
        steps: [
          'NIST 800-53 r5, 800-82 r3, CMMC 2.0, FedRAMP, StateRAMP, IRS 1075, NIST CSF 2.0, ISO 27001:2022, PCI DSS v4, IEC 62443, HIPAA Security Rule, and CJIS — full control catalogs with cross-framework mappings (ISO, PCI DSS and IEC 62443 as our own plain-language summaries).',
          'Plus advisory crosswalks for the regulations NERC CIP, GDPR, CCPA/CPRA, SOX, GLBA, and DORA.',
          'Activate any of them in the Marketplace; no extra license or entitlement is needed.',
        ],
        tip: 'Why advisory crosswalks for NERC/GDPR/CCPA/SOX/GLBA/DORA? No standards body publishes a control-level map from those regulations to 800-53, so those edges are our editorial judgment — labeled "vendor / related," used for see-also navigation and evidence hints only, never to auto-claim compliance.',
      },
    ],
  },
  {
    title: 'Administration',
    icon: SettingsIcon,
    intro: 'Backup, users, and organization settings (admin only).',
    tasks: [
      {
        title: 'Back up and restore',
        roles: ['admin'],
        steps: [
          'Open Settings → Backup & Restore.',
          'Download Backup archives the database, all evidence files and your custom frameworks; add a passphrase to encrypt it.',
          'Restore replaces everything with an archive\'s contents — a timestamped rollback copy is kept, all users are signed out and API tokens in the backup are revoked.',
          'A backup covers every company on the instance, so in a multi-company install only an operator can back up or restore.',
        ],
        tip: 'Schedule filesystem-level backups too (see the install guide) — the in-app backup is for on-demand snapshots and migrations.',
      },
      {
        title: 'Start fresh after exploring the demo',
        roles: ['admin'],
        steps: [
          'Shown only on a demo instance, to an admin who can manage the whole instance (the same people who can restore a backup).',
          'Open Settings → Start fresh, enter your password and type START FRESH.',
          'It deletes everything on the instance, including anything you added during the demo: every company, user, evidence file, custom framework, the backups made with demo data, sessions and API tokens. Keys and settings files in the data folder are kept.',
          'You land on the Setup screen. It needs the new setup token, printed in the server log and saved as setup-token in the data folder.',
        ],
        tip: 'The Demo desktop app and the demo Docker setup always run with demo data: there the button is Reset demo data and gives you a clean copy of the demo.',
      },
      {
        title: 'Reset a user\'s password',
        roles: ['admin'],
        steps: [
          'Open Users and click the user.',
          'Type a new password in the password field (12+ chars, 3 character classes) and save.',
          'Their existing sessions are signed out immediately; share the new password through a secure channel and have them change it (next task).',
        ],
      },
      {
        title: 'Change your own password',
        steps: [
          'Open Settings → Your Profile and click Change password.',
          'Enter your current password and the new one twice (12+ characters, three of: lowercase, uppercase, digits, symbols).',
          'You stay signed in here; your other sessions are signed out and your API tokens are revoked — create new tokens afterwards if you use them.',
        ],
      },
      {
        title: 'Create an API token for automation',
        steps: [
          'Open Settings → API Tokens. Give it a name (e.g. "ci-pipeline") and an optional expiry (up to 365 days; only admins can choose longer or never), then Create.',
          'Copy the token immediately — it is shown once and stored only as a hash. If you lose it, revoke it and create a new one.',
          'Send it as an "Authorization: Bearer <token>" header. The token acts as you (your role and system access).',
          'Revoke any token from the same panel. Admins can see and revoke every token in the organization. Changing your password revokes all of yours. Creating and revoking tokens needs a signed-in session: a token cannot mint new tokens.',
        ],
        tip: 'Tokens are for scripts and integrations. For a person, use SSO or a password account.',
      },
      {
        title: 'Set up the email digest',
        roles: ['admin'],
        steps: [
          'The digest emails admins and compliance managers a summary of overdue findings, expiring evidence, and overdue monitoring cadences.',
          'The operator sets SMTP on the server (SMTP_HOST / SMTP_FROM — install guide §5) and DIGEST_INTERVAL_HOURS (e.g. 24) to schedule it.',
          'In Settings → Email Digest, confirm SMTP shows "configured", check the recipient list, and use "Send test digest to me" to verify delivery.',
          'Recipients are every active admin / compliance-manager who has an email address set (under Users).',
        ],
      },
      {
        title: 'Enable single sign-on (SSO)',
        roles: ['admin'],
        steps: [
          'SSO uses OpenID Connect. The operator sets OIDC_ENABLED plus your IdP details (issuer, client id/secret, redirect URI) on the server and restarts — install guide §5.',
          'Configure your IdP to assert a verified email (email_verified=true). The first SSO sign-in links the IdP identity to the one account in your company with that email (or creates one); after that the person always signs in to that account, even if their email changes at the IdP.',
          'Users shows "SSO linked" for linked accounts. Unlink SSO removes the link (and signs the user out); changing a user\'s email or deactivating/reactivating them removes it too. Emails must be unique within the company.',
          'Several companies on one install? The operator must set OIDC_PROVISION_ORG_SLUG to the company your IdP belongs to — without it SSO only signs in accounts that are already linked.',
          'New SSO users are auto-provisioned at the lowest role (auditor, never admin) — promote trusted users under Users.',
          'Once enabled, a "Sign in with SSO" button appears on the login page. Password login keeps working alongside it.',
        ],
      },
      {
        title: 'Ship a fix to a deployment',
        roles: ['admin'],
        steps: [
          'The patch loop: fix → package_release.sh 1.x.y → send the tarball → customer runs update.sh → live in minutes, with automatic rollback if it doesn\'t come up.',
          'On the build host, scripts/package_release.sh builds the UI, stages the code, and emits a versioned tarball + checksum (add --with-wheelhouse for offline servers).',
          'On the server, sudo scripts/update.sh --release <tarball> verifies the checksum, snapshots the current install for rollback, swaps in the new code (your data directory is never touched), refreshes dependencies, and restarts.',
          'Schema migrations apply automatically on restart — there is no separate database step.',
        ],
        tip: 'If the service doesn\'t come back up, update.sh prints the exact one-line rollback command. Full details are in docs/INSTALL.md §11.',
      },
    ],
  },
  {
    title: 'Your Work Queue',
    icon: BookOpen,
    intro: 'Assignments, reminders, and personal tools that keep the work moving.',
    tasks: [
      {
        title: 'See everything assigned to you (My Work)',
        steps: [
          'The "Your work" card at the top of the Dashboard lists your open findings, controls you\'ve been assigned to implement, and evidence you own that needs a refresh.',
          'Each line links straight to the filtered page. The card hides itself when you have nothing assigned.',
          'If email is configured, assignees also get a reminder email listing their findings due within 7 days (or overdue) and evidence expiring within 14 days.',
        ],
      },
      {
        title: 'Assign owners to controls and evidence',
        steps: [
          'Controls (admins and assessors): expand a control (with a system selected), pick an Owner in the implementation editor — or select many controls and use "Assign to me" or "Assign owner…" in the bulk bar.',
          'Evidence (anyone who can upload evidence): open an artifact and set its Refresh Owner — the person responsible for keeping it fresh.',
          'Owners see these items in My Work and in their reminder emails.',
        ],
      },
      {
        title: 'Break a finding into milestones (POA&M)',
        steps: [
          'Open a finding\'s detail panel — the Milestones section shows remediation steps with due dates and checkboxes.',
          'Add steps, check them off as they complete, and the progress count (e.g. 2/3 complete) updates. Milestones appear in the Audit Binder\'s POA&M section and on the Calendar.',
          'Who: compliance managers and admins on any finding, and the finding\'s assigned owner on their own finding.',
        ],
      },
      {
        title: 'Save filter views and search everything (⌘K)',
        steps: [
          'On Findings, Evidence, Controls, or Assets, set your filters and click "Save view" to name them; re-apply any saved view from the Views dropdown. Views are per-user, per-page, and stored server-side.',
          'Press ⌘K (Ctrl+K) anywhere to search pages AND content: findings, systems, controls, evidence, risks, and advisories. Selecting a finding opens it directly.',
        ],
      },
      {
        title: 'Scope a framework to your baseline',
        roles: ['admin', 'assessor'],
        steps: [
          'On Controls (system + framework selected), click "Scope to baseline…" and pick your level (e.g. LEVEL_1 for the 17 CMMC Level 1 practices, SL2 for IEC 62443, LOW for 800-53).',
          'Everything outside the baseline is marked Not Applicable in one pass. Controls you already assessed are never overwritten — they\'re skipped and reported.',
        ],
        tip: 'Do this right after activating a framework — it turns a 200-control catalog into just the ones that actually apply.',
      },
    ],
  },
  {
    title: 'Multi-Company & Access Control',
    icon: BookOpen,
    intro: 'Run several companies from one install, and limit users to specific systems.',
    tasks: [
      {
        title: 'Switch between companies (operators)',
        steps: [
          'Operators get a company dropdown in the sidebar header — pick a company and every page re-scopes to its data. The + button creates a new company.',
          'The Portfolio page (Overview group) shows every company\'s score, open/overdue findings, and stale evidence on one screen; click a row to switch into it.',
          'Regular users have no switcher — they see only their own company.',
        ],
        tip: 'All companies share one install with row-level separation. Customers requiring hard data isolation should run their own install.',
      },
      {
        title: 'Limit a user to specific systems',
        roles: WRITE,
        steps: [
          'On Users, click the server icon next to a user and check the systems they may access.',
          'A scoped user sees only those systems\' findings, evidence, controls, assets, risks, and dashboards — everything else 404s.',
          'No selection = unrestricted. Admins and compliance managers are always org-wide by role.',
        ],
        tip: 'The classic use: an external contractor assigned to one plant\'s SCADA system and nothing else.',
      },
      {
        title: 'Brand a company with its logo',
        roles: ['admin'],
        steps: [
          'Switch to the company you want to brand (operators: sidebar dropdown), then open Settings → Branding.',
          'Upload a PNG or JPEG up to 300 KB — you get a preview before saving. The logo appears in the sidebar next to the company name and on Audit Binder covers.',
          'Remove it any time from the same panel; the sidebar falls back to the company name.',
        ],
        tip: 'Each company carries its own logo, so an operator\'s exported Audit Binders are branded per client.',
      },
      {
        title: 'Build a custom framework',
        roles: ['admin'],
        steps: [
          'Frameworks page → "Build custom framework" (or open /framework-builder).',
          'Create the framework (name, description, publisher), then add controls by hand or import a CSV (id,family,family_name,title,description).',
          'Save, then activate it from the Marketplace like any framework. It works with findings, evidence, assessments, the crosswalk view, and the Audit Binder.',
        ],
        tip: 'Custom frameworks are your own content — they are never license-gated and survive product updates (they live in the data directory).',
      },
    ],
  },
]

// ---------------------------------------------------------------------------
// Troubleshooting — the problems that otherwise become support calls.
// ---------------------------------------------------------------------------

interface Faq {
  problem: string
  solution: string[]
}

const FAQS: Faq[] = [
  {
    problem: 'I can\'t log in — my password is rejected',
    solution: [
      'After 5 failed attempts within 15 minutes the account locks temporarily. Wait out the window, then try again carefully.',
      'If you\'ve genuinely forgotten the password, any admin can set a new one: Users → click your account → enter a new password → save. You\'ll be signed out everywhere and can sign in with the new one.',
      'If the admin is the one locked out and no other admin exists, the operator can reset from the server — see the install guide.',
    ],
  },
  {
    problem: 'I keep getting signed out',
    solution: [
      'Sessions idle out after 30 minutes without activity by default (the operator can change IDLE_TIMEOUT_MINUTES). Activity resets the clock.',
      'Each account can hold at most 5 concurrent sessions — signing in on a 6th device silently drops the oldest one.',
      'A password change, role change, deactivation, or a backup restore signs you out everywhere by design.',
    ],
  },
  {
    problem: 'How do I sign in with SSO / the "Sign in with SSO" button is missing',
    solution: [
      'If your organization has enabled SSO, a "Sign in with SSO" button appears on the login page — click it and authenticate with your identity provider.',
      'No button? SSO isn\'t enabled (or the server is still starting). An admin enables it: Help → Administration → Enable single sign-on. You can always use a password account.',
      'SSO login failed? Your IdP must report your email as verified, and your account email must be unique in your company — if two accounts share your email, SSO refuses to guess; ask an admin to fix it. "Linked to a different SSO identity": an admin can Unlink SSO on the Users page.',
    ],
  },
  {
    problem: 'A button or page I need is missing or greyed out',
    solution: [
      'That\'s almost always your role, not a bug. Check the "Who can do what" table at the top of this page.',
      'Example: auditors are read-only everywhere; evidence contributors can upload evidence but not edit findings; assessors set implementation status but don\'t close findings.',
      'If your duties changed, ask an admin to change your role under Users — it takes effect at your next sign-in.',
    ],
  },
  {
    problem: 'My compliance score shows 0%',
    solution: [
      'Score = (Implemented + Inherited) ÷ (controls in the framework catalog − Not Applicable), per system × framework. Planned and Partially don\'t count. 0% means no controls have been set to Implemented or Inherited yet.',
      'Open Controls, select that system and framework, and record statuses. The score updates immediately.',
      'Also confirm the framework is actually activated (Frameworks page) — an inactive framework has no catalog loaded.',
    ],
  },
  {
    problem: 'My SIEM import did nothing / imported 0 findings',
    solution: [
      'If the import is refused, the message says why — e.g. which rows were skipped and for what reason. If the format was misdetected, pick it under Format Override; it must be one of the 16 supported formats.',
      'If the preview showed rows but the result says "skipped", those findings were already imported — duplicates are detected by content hash and skipped on purpose.',
      'Import history (and who ran it) is in the Audit Log under SIEM_IMPORT.',
    ],
  },
  {
    problem: 'The Advisories page shows old data or says "demo fixtures"',
    solution: [
      'Live feed pulls require the operator to set THREAT_FEEDS=live (and ICS_FEED=live for CISA ICS); offline installs intentionally run on bundled fixture data.',
      'Bundled fixture advisories are fictional sample data (made-up vendors, DEMO- identifiers) and are marked Sample — they never describe real products.',
      'The header shows the last refresh time, who/what triggered it, and whether auto-refresh is on (THREAT_FEEDS_INTERVAL_HOURS).',
      'Click Refresh Feeds to pull on demand. One unreachable feed never blocks the others; per-feed errors are reported.',
    ],
  },
  {
    problem: 'An advisory matched the wrong asset (or missed one)',
    solution: [
      'Matching uses your asset inventory\'s vendor, product/model, and firmware/OS fields — verify those are filled and spelled the way the vendor writes them.',
      'Each match shows its confidence tier (exact, firmware range, vendor/product, vendor only). Low-confidence matches are expected to need human review.',
      'Dismiss a wrong match from the advisory panel — dismissals are reversible.',
    ],
  },
  {
    problem: 'Crosswalk shows no mappings for my control',
    solution: [
      'Mappings exist for frameworks that ship them: 800-53 (hub), CMMC, FedRAMP, 800-82, CSF 2.0, ISO 27001, and PCI DSS. Other frameworks display but don\'t carry edges yet.',
      'Both frameworks must be active for an edge to display — activate the counterpart under Frameworks.',
      'Concept crosswalks (CSF, ISO, PCI) are intentionally marked "intersects" — they widen views but never feed automatic propagation.',
    ],
  },
  {
    problem: 'Inspection Prep readiness looks too low',
    solution: [
      'The score is strict on purpose — a control only counts as ready when it\'s Implemented/Inherited AND has a real narrative (~80+ chars) AND fresh evidence uploaded for that same system. Evidence for another system doesn\'t count; Not Applicable controls are excluded.',
      'Open the punch list: it tells you exactly which of the three is missing for every control, in priority order.',
      'Expired evidence is the most common silent deduction — check the Evidence freshness filter.',
    ],
  },
  {
    problem: 'I restored a backup and now I can\'t sign in',
    solution: [
      'A restore replaces the entire database — your credentials are whatever they were when that backup was taken.',
      'All sessions are intentionally invalidated; sign in again with the credentials from the backup era.',
      'API tokens from the backup are revoked by the restore — issue new ones for your integrations.',
      'If the restore went wrong, the previous database was kept as a timestamped rollback copy on the server — the operator can swap it back.',
    ],
  },
  {
    problem: 'CSV exports look wrong in Excel',
    solution: [
      'Cells that start with =, +, -, or @ are prefixed with an apostrophe on export. That\'s deliberate — it blocks formula-injection attacks. The data is intact.',
      'Use "Data → From Text/CSV" in Excel for clean column typing rather than double-clicking the file.',
    ],
  },
  {
    problem: 'The audit chain verification failed',
    solution: [
      'This means an audit row was modified or deleted outside the application — exactly what the hash chain exists to detect.',
      'The verify result reports the first broken entry ID; everything before it is still trustworthy.',
      'Treat it as a security event: preserve the database file and investigate who has direct DB access.',
    ],
  },
  {
    problem: 'Dollar exposure numbers look too high or too low',
    solution: [
      'Estimates calibrate from your Risk Context (Red Team → Risk Context): industry, revenue, contract value, and record count. Unset context falls back to global industry averages, which can be far off.',
      'Every number shows an expandable breakdown citing its sources (IBM/Ponemon benchmarks, statutory penalty schedules) — these are planning estimates, not actuarial predictions.',
      'Totals use probable-loss weighting, not a straight sum: the largest estimate counts in full, the next four add 35% each, every further one adds 10%, and the high end is capped at 1.5× annual revenue when revenue is set. Report totals, attack-chain combined figures and the Executive Briefing\'s company total all use this same model.',
    ],
  },
  {
    problem: 'Demo data is in the way — how do I start clean?',
    solution: [
      'Demo data only exists if the operator seeded it; production installs start empty after the first-run setup screen.',
      'To wipe a demo install, the operator deletes the data directory and restarts — the setup screen reappears (it requires the one-time setup token from the server log).',
    ],
  },
]

const GLOSSARY: { term: string; def: string }[] = [
  { term: 'Finding', def: 'The universal issue record. Your framework may call it a POA&M item (RMF), a non-conformity (ISO), or a deficiency — the page label adapts to the framework\'s vocabulary.' },
  { term: 'Control implementation', def: 'Your answer to one control for one system: a status, a narrative, and linked evidence.' },
  { term: 'Inherited', def: 'A control satisfied by another system or a common-control provider (e.g. enterprise SSO satisfies IA-2 for every system behind it). Counts toward compliance.' },
  { term: 'Planned (crosswalk)', def: 'A review state created when you accept a crosswalk suggestion. Pre-filled from the source framework but NOT counted in compliance scores until an assessor confirms it.' },
  { term: 'Crosswalk / hub', def: 'The mapping web between frameworks. NIST 800-53 is the hub: a CMMC control maps to 800-53, which maps onward to FedRAMP — so work in one framework is visible from all of them.' },
  { term: 'Relationship types', def: 'equivalent (same requirement), subset/superset (one contains the other), intersects (overlap — typical for concept crosswalks like CSF/ISO/PCI), related (adjacent).' },
  { term: 'Confidence tiers', def: 'official = from a NIST/framework-author mapping; derived = composed through the hub (two hops); vendor = shipped by a third party. Propagation only ever uses official/derived equivalent-or-superset edges.' },
  { term: 'Evidence freshness', def: 'Every artifact carries an expiration. Fresh → Expiring (30 days out) → Expired. Stale evidence drags down Inspection Prep readiness.' },
  { term: 'Open finding', def: 'Any finding not Closed, Risk Accepted or False Positive — Delayed and In Progress findings are open. Every Open / Critical / Overdue count (Dashboard tiles and charts, the Findings page tiles, score cards, Portfolio, trend, Executive Briefing) uses this one definition, and the Open tiles say how many of them are Delayed ("incl. 1 delayed"). Overdue = open with a due date before today.' },
  { term: 'Average score', def: 'The Portfolio and trend average is the plain mean of the per-system × framework scores (frameworks with a loaded catalog). Today\'s trend point and the Portfolio are live; earlier points are the daily snapshots.' },
  { term: 'Aging buckets', def: 'Overdue / Due 7 / Due 30 / On Track, computed from a finding\'s due date. Terminal findings (closed, risk-accepted, false positive) show Resolved.' },
  { term: 'ConMon cadence', def: 'How often a monitoring activity must recur (e.g. PCI quarterly scans). Resolution order: your org override → framework requirement → built-in default.' },
  { term: 'KEV', def: 'CISA\'s Known Exploited Vulnerabilities catalog — vulnerabilities confirmed exploited in the wild. KEV items matching your assets deserve top priority.' },
  { term: 'Purdue level', def: 'OT network hierarchy (0 = process, 4/5 = enterprise). Drives the Purdue view on the Topology page.' },
  { term: 'Attack chain', def: 'A Red Team construct: individual compliance gaps that combine into a compound failure mode (e.g. missing evidence + weak narratives = audit failure), priced together.' },
  { term: 'Hash-chained audit log', def: 'Each audit entry includes an HMAC of the previous one. Any tampering with history breaks the chain; the Audit Log page re-verifies the chain each time it opens.' },
]

// ---------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------

// Sanitize the raw query once: cap length and strip anything outside
// letters/digits/space/'/-. Plain-substring search after this — no RegExp
// ever sees user input.
function sanitizeQuery(q: string): string {
  let out = ''
  const lower = q.slice(0, 100).toLowerCase()
  for (const ch of lower) {
    out += (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch === ' ' || ch === "'" || ch === '-' ? ch : ' '
  }
  return out.trim()
}

// Pre-joined lowercase haystacks (static content, computed once at module load)
const SECTION_HAYSTACKS: string[][] = SECTIONS.map(sec =>
  sec.tasks.map(t => [t.title, t.tip ?? '', sec.title, ...t.steps].join(' ').toLowerCase()))
const FAQ_HAYSTACKS: string[] = FAQS.map(f => [f.problem, ...f.solution].join(' ').toLowerCase())
const GLOSSARY_HAYSTACKS: string[] = GLOSSARY.map(g => `${g.term} ${g.def}`.toLowerCase())
const ROLE_HAYSTACK = 'role permission who can access admin auditor assessor manager owner contributor'

// ---------------------------------------------------------------------------
// Components
// ---------------------------------------------------------------------------

function RoleBadges({ roles }: { roles?: RoleName[] }) {
  if (!roles || roles.length === ALL_ROLES.length) return null
  return (
    <span className="flex flex-wrap gap-1 ml-auto shrink-0">
      {roles.map(r => (
        <span key={r} className="px-1.5 py-px text-[9px] uppercase tracking-wide border border-[var(--border)] bg-[var(--bg-tertiary)] text-[var(--text-secondary)] rounded-sm">
          {ROLE_LABELS[r]}
        </span>
      ))}
    </span>
  )
}

function TaskBlock({ task, forceOpen, myRole }: { task: Task; forceOpen: boolean; myRole: string }) {
  const [open, setOpen] = useState(false)
  const expanded = forceOpen || open
  const canDo = !task.roles || task.roles.includes(myRole as RoleName)
  return (
    <div className="border border-[var(--border)] rounded-sm">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2 px-3 py-2 text-left hover:bg-[var(--bg-tertiary)] transition-colors"
      >
        {expanded ? <ChevronDown size={13} className="text-[var(--text-secondary)] shrink-0" /> : <ChevronRight size={13} className="text-[var(--text-secondary)] shrink-0" />}
        <span className="text-xs font-medium text-[var(--text-primary)]">{task.title}</span>
        <RoleBadges roles={task.roles} />
      </button>
      {expanded && (
        <div className="px-3 pb-3 pt-1">
          {!canDo && task.roles && (
            <p className="mb-2 text-[11px] text-[var(--text-secondary)] border border-[var(--border)] bg-[var(--bg-tertiary)] px-2 py-1.5 rounded-sm">
              Your role can’t perform this — it requires {task.roles.map(r => ROLE_LABELS[r]).join(' or ')}. You can still read how it works below.
            </p>
          )}
          <ol className="space-y-1.5 list-none">
            {task.steps.map((step, i) => (
              <li key={i} className="text-xs text-[var(--text-primary)] flex items-start gap-2">
                <span className="text-[var(--accent)] font-mono shrink-0 mt-px">{i + 1}.</span>
                {step}
              </li>
            ))}
          </ol>
          {task.tip && (
            <p className="mt-2 text-xs text-[var(--text-secondary)] border-l-2 border-[var(--accent)] pl-2">
              <span className="font-medium text-[var(--accent)]">Tip:</span> {task.tip}
            </p>
          )}
        </div>
      )}
    </div>
  )
}

function FaqBlock({ faq, forceOpen }: { faq: Faq; forceOpen: boolean }) {
  const [open, setOpen] = useState(false)
  const expanded = forceOpen || open
  return (
    <div className="border border-[var(--border)] rounded-sm">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2 px-3 py-2 text-left hover:bg-[var(--bg-tertiary)] transition-colors"
      >
        {expanded ? <ChevronDown size={13} className="text-[var(--text-secondary)] shrink-0" /> : <ChevronRight size={13} className="text-[var(--text-secondary)] shrink-0" />}
        <span className="text-xs font-medium text-[var(--text-primary)]">{faq.problem}</span>
      </button>
      {expanded && (
        <ul className="px-3 pb-3 pt-1 space-y-1.5">
          {faq.solution.map((line, i) => (
            <li key={i} className="text-xs text-[var(--text-primary)] flex items-start gap-2">
              <span className="text-[var(--accent)] mt-0.5 shrink-0">•</span>
              {line}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function Help() {
  const [query, setQuery] = useState('')
  const myRole = useCurrentRole() ?? 'auditor'
  const needle = useMemo(() => sanitizeQuery(query), [query])
  const searching = needle.length >= 2

  const filteredSections = useMemo(() => {
    if (!searching) return SECTIONS
    return SECTIONS
      .map((sec, si) => ({
        ...sec,
        tasks: sec.tasks.filter((_, ti) => SECTION_HAYSTACKS[si][ti].indexOf(needle) !== -1),
      }))
      .filter(sec => sec.tasks.length > 0)
  }, [needle, searching])

  const filteredFaqs = useMemo(() => {
    if (!searching) return FAQS
    return FAQS.filter((_, i) => FAQ_HAYSTACKS[i].indexOf(needle) !== -1)
  }, [needle, searching])

  const filteredGlossary = useMemo(() => {
    if (!searching) return GLOSSARY
    return GLOSSARY.filter((_, i) => GLOSSARY_HAYSTACKS[i].indexOf(needle) !== -1)
  }, [needle, searching])

  const hitCount = searching
    ? filteredSections.reduce((n, s) => n + s.tasks.length, 0) + filteredFaqs.length + filteredGlossary.length
    : 0

  return (
    <div>
      <h2 className="text-xl font-bold text-[var(--text-primary)] mb-1">Help</h2>
      <p className="text-xs text-[var(--text-secondary)] mb-4">
        Guides, troubleshooting, and reference for every workflow — searchable, and role-aware.
        You’re signed in as <span className="text-[var(--text-primary)] font-medium">{ROLE_LABELS[myRole as RoleName] ?? myRole}</span>.
      </p>

      {/* Search */}
      <div className="relative mb-6 max-w-xl">
        <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-secondary)]" />
        <input
          value={query}
          onChange={e => setQuery(e.target.value)}
          placeholder="Search help — e.g. 'password', 'import', 'crosswalk', 'locked out'…"
          className="w-full pl-9 pr-9 py-2 text-xs bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-primary)] placeholder:text-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent)]"
        />
        {query && (
          <button onClick={() => setQuery('')} className="absolute right-3 top-1/2 -translate-y-1/2 text-[var(--text-secondary)] hover:text-[var(--text-primary)]">
            <X size={13} />
          </button>
        )}
        {searching && (
          <p className="mt-1.5 text-[11px] text-[var(--text-secondary)]">
            {hitCount === 0 ? 'No matches — try a different word, or browse the sections below.' : `${hitCount} matching topic${hitCount === 1 ? '' : 's'} — expanded below.`}
          </p>
        )}
      </div>

      {/* Who can do what */}
      {(!searching || ROLE_HAYSTACK.indexOf(needle) !== -1) && (
        <div className="bg-[var(--bg-secondary)] border border-[var(--border)] p-4 mb-6">
          <h3 className="text-xs uppercase tracking-wider text-[var(--text-secondary)] mb-1 flex items-center gap-2">
            <UsersIcon size={14} /> Who Can Do What
          </h3>
          <p className="text-xs text-[var(--text-secondary)] mb-3">
            If a button is missing or greyed out, check here first — it’s the role, not a bug. Your column is highlighted.
          </p>
          <div className="overflow-x-auto">
            <table className="w-full text-[11px]">
              <thead>
                <tr className="text-left text-[var(--text-secondary)]">
                  <th className="py-1.5 pr-3 font-medium">Capability</th>
                  {ALL_ROLES.map(r => (
                    <th key={r} className={`py-1.5 px-2 font-medium text-center ${r === myRole ? 'text-[var(--accent)]' : ''}`}>
                      {ROLE_LABELS[r]}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {PERMISSION_ROWS.map(row => (
                  <tr key={row.capability} className="border-t border-[var(--border)]">
                    <td className="py-1.5 pr-3 text-[var(--text-primary)]">{row.capability}</td>
                    {ALL_ROLES.map(r => (
                      <td key={r} className={`py-1.5 px-2 text-center ${r === myRole ? 'bg-[var(--bg-tertiary)]' : ''}`}>
                        {row.roles.includes(r)
                          ? <span className="text-[var(--risk-low)]">✓</span>
                          : <span className="text-[var(--text-secondary)] opacity-40">—</span>}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Shortcuts */}
      {!searching && (
        <div className="bg-[var(--bg-secondary)] border border-[var(--border)] p-4 mb-6">
          <h3 className="text-xs uppercase tracking-wider text-[var(--text-secondary)] mb-3 flex items-center gap-2">
            <Keyboard size={14} /> Keyboard Shortcuts
          </h3>
          <div className="grid grid-cols-2 gap-2">
            {SHORTCUTS.map(s => (
              <div key={s.label} className="flex items-center gap-3">
                <div className="flex gap-1">
                  {s.keys.map(k => (
                    <kbd key={k} className="px-1.5 py-0.5 text-[10px] border border-[var(--border)] bg-[var(--bg-tertiary)] text-[var(--text-secondary)] font-mono">
                      {k}
                    </kbd>
                  ))}
                </div>
                <span className="text-xs text-[var(--text-primary)]">{s.label}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Troubleshooting */}
      {filteredFaqs.length > 0 && (
        <div className="bg-[var(--bg-secondary)] border border-[var(--border)] p-4 mb-6">
          <h3 className="text-xs uppercase tracking-wider text-[var(--text-secondary)] mb-1 flex items-center gap-2">
            <Wrench size={14} /> Troubleshooting
          </h3>
          <p className="text-xs text-[var(--text-secondary)] mb-3">
            The most common problems and their fixes — check here before contacting support.
          </p>
          <div className="space-y-1.5">
            {filteredFaqs.map(f => <FaqBlock key={f.problem} faq={f} forceOpen={searching} />)}
          </div>
        </div>
      )}

      {/* How-to sections */}
      <div className="grid grid-cols-2 gap-4 items-start mb-6">
        {filteredSections.map(section => {
          const Icon = section.icon
          return (
            <div key={section.title} className="bg-[var(--bg-secondary)] border border-[var(--border)] p-4">
              <h3 className="text-xs uppercase tracking-wider text-[var(--text-secondary)] mb-1 flex items-center gap-2">
                <Icon size={14} /> {section.title}
              </h3>
              <p className="text-xs text-[var(--text-secondary)] mb-3">{section.intro}</p>
              <div className="space-y-1.5">
                {section.tasks.map(task => (
                  <TaskBlock key={task.title} task={task} forceOpen={searching} myRole={myRole} />
                ))}
              </div>
            </div>
          )
        })}
      </div>

      {/* Glossary */}
      {filteredGlossary.length > 0 && (
        <div className="bg-[var(--bg-secondary)] border border-[var(--border)] p-4">
          <h3 className="text-xs uppercase tracking-wider text-[var(--text-secondary)] mb-3 flex items-center gap-2">
            <GraduationCap size={14} /> Glossary
          </h3>
          <dl className="grid grid-cols-2 gap-x-6 gap-y-2">
            {filteredGlossary.map(g => (
              <div key={g.term} className="text-xs">
                <dt className="font-medium text-[var(--text-primary)]">{g.term}</dt>
                <dd className="text-[var(--text-secondary)] mt-0.5">{g.def}</dd>
              </div>
            ))}
          </dl>
        </div>
      )}
    </div>
  )
}
