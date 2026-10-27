# Athorize — Installation Guide

This guide walks your IT team through installing Athorize on a server
inside your own network. The product is fully self-hosted: **no data ever
leaves your network**, there is no cloud component, and no internet connection
is required to run it (an offline install path is included below).

Audience: a system administrator comfortable with Linux, a terminal, and your
organization's reverse-proxy/TLS conventions. Estimated time: 30–60 minutes.

> Once the software is running, the person setting it up for the organization
> should follow the **[Administrator Quickstart](ADMIN_QUICKSTART.md)** —
> first-run, framework activation, users, SSO, digests, and the daily workflow.

> **Have Docker?** §14 is a one-command install (one container serves the API
> and the web UI). Sections 3–7 are the bare-metal path (systemd + nginx).

---

## 1. How it fits together

```
 Users' browsers ──HTTPS──▶ nginx (TLS, port 443)
                              ├── serves the web UI (static files)
                              └── proxies /api ──▶ backend (127.0.0.1:8001)
                                                     └── SQLite database + evidence
                                                         files on local disk
```

Three pieces run on one server:

1. **Backend** — a Python (FastAPI) API service, listening only on localhost.
2. **Frontend** — a pre-built React web UI, served as static files.
3. **Reverse proxy** — nginx (or your standard equivalent) terminating TLS and
   putting both behind one HTTPS address.

All application data lives in one directory on the server (database, uploaded
evidence files, backups). Nothing phones home; threat-intelligence feeds ship
as bundled fixtures and only go live if you explicitly opt in (§9).

## 2. Server requirements

| Requirement | Minimum |
|---|---|
| OS | Linux x86_64 (Ubuntu 22.04+/Debian 12+/RHEL 9+ tested patterns) |
| Python | 3.11 or newer |
| Node.js | 20+ — **build step only**; not needed on the server if you deploy a pre-built UI bundle |
| Reverse proxy | nginx (examples below) or organizational equivalent |
| CPU / RAM | 2 vCPU / 4 GB |
| Disk | 10 GB to start — evidence uploads (up to 100 MiB per file) are the main growth driver |
| Network | Inbound 443 from your user population only. No outbound access required. |

The UI is desktop-oriented (minimum 1280 px wide browser window).

> **Windows Server:** not currently a supported production target. Run on a
> Linux VM. The double-click Windows desktop `.exe` (`desktop/README.md`) is a
> **beta** for trying Athorize on one machine; Docker (§14) and Linux (this
> guide) are the primary install paths.

## 3. Create the service account and directories

Run the application as a dedicated, unprivileged user:

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin athorize
sudo install -d -m 755 -o root -g root /opt/athorize-universal
sudo install -d -m 700 -o athorize -g athorize /var/lib/athorize-universal
```

- `/opt/athorize-universal` — application code and its Python virtualenv.
  Owned by **root**; the service user and nginx can read it but not change it
  (the code is public; nothing secret lives there except `backend/.env`, which
  §5 makes readable by the service only). Root runs the installer and
  `scripts/update.sh` here, so the service account must never be able to write
  this tree.
- `/var/lib/athorize-universal` — all data (database, evidence, backups,
  generated keys). The only place the service writes. Keep mode `700`;
  evidence files and the database are sensitive.

## 4. Install the application code

### 4a. Standard install (server can reach your internal mirror or the internet)

Install from a release archive, `athorize-<version>.tar.gz`. It holds the
backend, the framework catalogs, the scripts, these docs and the **pre-built
web UI** (`frontend/dist/`), so the server needs no Node.js. Everything here
runs as root and stays owned by root:

```bash
sudo tar --no-same-owner -xzf athorize-<version>.tar.gz \
    -C /opt/athorize-universal --strip-components=1

# Python environment (root-owned; the service only reads it)
cd /opt/athorize-universal
sudo python3 -m venv .venv
sudo .venv/bin/pip install -r backend/requirements.txt
```

**Working from a git checkout instead?** Build the archive on a build machine
with Node 20+ — `scripts/package_release.sh <version>` writes
`dist/athorize-<version>.tar.gz` (+ `.sha256`) — and install that. The UI
build's `npm ci` reports a handful of advisories in build-time tooling (the
Tailwind 3 toolchain); none of that code ships in `frontend/dist/` or runs on
the server.

### 4b. Offline install

Nothing in the runtime requires internet access — only the dependency
download and the UI build do. Do those once on a **staging machine** that has
internet access and matches the target server's OS family, CPU architecture
and Python minor version (e.g. both Ubuntu 22.04 / Python 3.12):

```bash
scripts/package_release.sh <version> --with-wheelhouse
# → dist/athorize-<version>.tar.gz, with every Python wheel under wheelhouse/
```

**On the target server** (after transferring the archive per your media
policy):

```bash
sudo tar --no-same-owner -xzf athorize-<version>.tar.gz \
    -C /opt/athorize-universal --strip-components=1
cd /opt/athorize-universal
sudo python3 -m venv .venv
sudo .venv/bin/pip install --no-index \
    --find-links wheelhouse/ -r backend/requirements.txt
```

The `frameworks/` directory ships every control catalog and crosswalk mapping
as local JSON files — framework activation (§8) works fully offline.

## 5. Configuration

The backend reads configuration from environment variables and from
`backend/.env` (environment variables win). No other `.env` file is read — in
particular not one in the directory the process happens to start from. Every
setting has exactly one name, listed below; values in `.env` are also visible
to the optional integrations (feeds, connectors, SMTP). Create
`/opt/athorize-universal/backend/.env` owned by root, group `athorize`, mode
`640` (the service can read it, not change it; nobody else can read it):

```bash
sudo install -m 640 -o root -g athorize /dev/null /opt/athorize-universal/backend/.env
sudoedit /opt/athorize-universal/backend/.env
```

```bash
# Session secret and the key for the tamper-evident audit-log hash chain.
# Generate each separately. If you leave them out, Athorize generates both on
# first start and saves them to <DATA_DIR>/secrets.env (mode 600) — keeping them
# here instead keeps key material out of the data directory. Decide once: the
# audit key must stay the same for the life of the instance.
SECRET_KEY=<output of: openssl rand -hex 32>
ATHORIZE_AUDIT_HMAC_KEY=<output of: openssl rand -hex 32>

# Data location (recommended explicit path instead of the service user's home).
# EVIDENCE_DIR and BACKUP_DIR default to <DATA_DIR>/evidence and <DATA_DIR>/backups.
DATA_DIR=/var/lib/athorize-universal

# REQUIRED when TLS terminates at the reverse proxy (it does, in this guide).
# Lets the app trust X-Forwarded-Proto so session cookies are marked Secure.
ATHORIZE_TRUST_XFF=1

# The public host name users type (the app rejects other Host headers) — the
# same name as nginx's server_name in §7.
ATHORIZE_ALLOWED_HOSTS=compliance.internal.example.com
```

Full reference. Athorize-specific settings are named `ATHORIZE_*`; the names
used before the 2026-10 release (`UNIVERSAL_*`, `AUDIT_HMAC_KEY`, `BACKUP_KEEP*`)
still work and log a one-time deprecation warning.

| Variable | Default | Purpose |
|---|---|---|
| `SECRET_KEY` | generated | Application secret. Generated on first start and saved to `<DATA_DIR>/secrets.env` if unset. Every way of starting Athorize (service, `run-eval.sh`, the desktop app, Docker) reads that same file, so switching between them never switches keys. |
| `ATHORIZE_AUDIT_HMAC_KEY` | generated | HMAC key for the audit-log integrity chain. Generated on first start and saved to `<DATA_DIR>/secrets.env` if unset; a configured value shorter than 32 characters is refused (except in demo mode). Changing it later breaks verification of older entries — store it with your key material, separately from data backups. If a configured key does not match the key that signed the existing audit log while the matching key is still in a saved secrets file, startup stops and names that file (so one misconfigured start can't fork the log). The old names `UNIVERSAL_AUDIT_HMAC_KEY` and `AUDIT_HMAC_KEY` still work but log a deprecation warning. |
| `ATHORIZE_ENV_FILE` | `backend/.env` | Environment only: read this file instead of `backend/.env` (e.g. `/etc/athorize/athorize.env`). Same format and permissions. |
| `DATA_DIR` | `~/.athorize-universal` | Root data directory; the SQLite database lives at `<DATA_DIR>/data.db`. Created automatically. `~` is expanded. |
| `EVIDENCE_DIR` | `<DATA_DIR>/evidence` | Uploaded evidence files. Must be a folder of its own: not `DATA_DIR` itself, not a parent of it, and not containing `BACKUP_DIR` (backup and restore treat this whole tree as evidence) — startup refuses such a layout. |
| `BACKUP_DIR` | `<DATA_DIR>/backups` | In-app backup archives and the rollback copies a restore keeps (§10). |
| `ATHORIZE_BACKUP_KEEP` | `10` | Newest completed in-app backups kept in `BACKUP_DIR`; older ones are deleted after each successful backup. `0` = keep all. (Old name `BACKUP_KEEP` still works.) |
| `ATHORIZE_BACKUP_KEEP_ROLLBACKS` | `3` | Newest restore rollback copies (`BACKUP_DIR/rollback-*`) kept; older ones are deleted after each successful restore. `0` = keep all. (Old name `BACKUP_KEEP_ROLLBACKS` still works.) |
| `ATHORIZE_TRUST_XFF` | off | Set `1` only when behind a reverse proxy that sets `X-Forwarded-Proto`. Never set it if browsers can reach the backend directly. (Old name `UNIVERSAL_TRUST_XFF` still works.) |
| `ATHORIZE_ALLOWED_HOSTS` | unset | Comma-separated host names the app answers to, in addition to `localhost`, `127.0.0.1`, `[::1]` and the hosts in `CORS_ORIGINS`. Requests with any other `Host` header get `400` (blocks DNS-rebinding attacks on a local instance). Set it to the name users browse to; `*` disables the check. |
| `FORWARDED_ALLOW_IPS` | `127.0.0.1` | Read by uvicorn, not the app: the proxy addresses whose `X-Forwarded-For` / `X-Forwarded-Proto` are trusted. Login rate limiting keys on the resulting client address, so set it to your proxy's address only (see §7 and §14d). |
| `ATHORIZE_OUTBOUND_PROXY` | unset | HTTP(S) proxy URL for outbound fetches made through the SSRF guard (custom feeds, PSIRT, CISA, OIDC, Tanium/ISE). Without it those fetches connect directly to an IP the app has resolved and checked. With it, the app still checks every target it can resolve (and every literal IP) before each request; a name the server's own DNS cannot resolve is passed to the proxy, which does its own DNS — so the proxy becomes your egress control. The standard `HTTPS_PROXY` variables are deliberately ignored by those clients. |
| `API_TOKEN_DEFAULT_EXPIRY_DAYS` | `90` | Expiry for API tokens created without one. `0` = never expire. |
| `DEBUG` | `false` | Verbose logging + SQL echo. Leave off in production. |
| `CORS_ORIGINS` | `http://localhost:3000` | Comma-separated (or a JSON list). Only relevant if the UI is served from a *different* origin than the API. With the single-nginx layout in this guide, leave it alone. |
| `DATABASE_URL` | unset | SQLite by default. A PostgreSQL URL (`postgresql://…`) is honored — the engine drops SQLite-only connect args/PRAGMAs automatically. SQLite is the tested path for this release; Postgres is supported but lightly exercised, and **in-app backup/restore is SQLite-only** (it refuses with an explanation on Postgres — use `pg_dump`, §10). |
| `IDLE_TIMEOUT_MINUTES` | `30` | Sessions idle longer than this are revoked. `0` disables idle timeout (the absolute 30-day expiry still applies). |
| `THREAT_FEEDS_INTERVAL_HOURS` | unset | Set (e.g. `6`) to auto-refresh all threat feeds for every org on an interval. Leave unset for manual-only / offline. |
| `ATHORIZE_PSIRT_PROVIDERS` | unset | Comma-separated CSAF provider-metadata URLs (HTTPS) for vendor PSIRT feeds; live-feed mode only. |
| `THREAT_FEEDS` / `ICS_FEED` | `mock` | Threat-feed mode — see §9 before changing. |
| `NVD_API_KEY` | unset | Optional but recommended for live feeds — raises NVD rate limit 5→50 req/30s. Free key + setup: §9. |
| `SMTP_HOST` | unset | SMTP server for email digests. No email is sent until this and `SMTP_FROM` are set. |
| `SMTP_PORT` | `587` | SMTP port (587 = STARTTLS). |
| `SMTP_USER` / `SMTP_PASSWORD` | unset | SMTP auth credentials; omit for an unauthenticated relay. |
| `SMTP_FROM` | unset | From-address for digest emails. Required to enable email. |
| `SMTP_USE_TLS` | `true` | STARTTLS. Set `false` only for a plaintext internal relay. |
| `DIGEST_INTERVAL_HOURS` | unset | Set (e.g. `24`) to email the compliance digest to each org's admins/compliance-managers on an interval. Requires SMTP. Leave unset for offline / on-demand only. |
| `OIDC_ENABLED` | `false` | Enable OpenID Connect single sign-on. Password login always remains available. |
| `OIDC_ISSUER` | unset | IdP issuer base URL; discovery happens at `{issuer}/.well-known/openid-configuration`. |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | unset | OAuth client registered with your IdP. Secret omitted for public/PKCE clients. |
| `OIDC_REDIRECT_URI` | unset | Must equal `https://<your-host>/api/auth/oidc/callback` and be registered at the IdP. |
| `OIDC_SCOPES` | `openid email profile` | Requested scopes (must yield an `email` claim). |
| `OIDC_DEFAULT_ROLE` | `auditor` | Role assigned to auto-provisioned SSO users. |
| `OIDC_AUTO_PROVISION` | `true` | Create an account on first SSO login (matched by email). Set `false` to require pre-created users. |
| `OIDC_ALLOWED_DOMAINS` | unset | Comma-separated email domains allowed to sign in with SSO (e.g. `example.com`). Blank = any verified email the IdP asserts. |
| `OIDC_PROVISION_ORG_SLUG` | unset | Multi-company installs: the company (slug) SSO links and provisions accounts in. **Required there** for new SSO sign-ins — blank on a multi-company install = only already-linked accounts can use SSO. Single-company installs ignore it. SSO users are never operators. |
| `TANIUM_URL` | unset | Base URL (`https://`) of your Tanium server for the live asset connector. Off until set. |
| `TANIUM_API_TOKEN` | unset | Tanium persistent API token (sent as the `session` header). |
| `TANIUM_SAVED_QUESTION_ID` | unset | ID of the saved question whose result columns map to assets (Computer Name, Operating System, IP Address, MAC Address, Manufacturer, Model, Chassis Type). |
| `TANIUM_VERIFY_TLS` | `true` | Set `false` only for a self-signed on-prem Tanium cert. |
| `CISCO_ISE_URL` | unset | Base URL (`https://`, ERS port `:9060`) of your Cisco ISE for the live asset connector. Off until set. |
| `CISCO_ISE_USER` / `CISCO_ISE_PASSWORD` | unset | ERS (External RESTful Services) admin credentials. ERS must be enabled in ISE. |
| `CISCO_ISE_VERIFY_TLS` | `true` | Set `false` only for a self-signed on-prem ISE cert. |
| `ASSET_SYNC_INTERVAL_HOURS` | unset | Set (e.g. `12`) to pull every configured live asset connector on an interval and import new assets automatically (same dedup as a manual Pull — by MAC, then hostname, then name — so it never duplicates). Runs are audit-logged as `asset-sync-scheduler`. Leave unset for manual Pull only. |
| `ASSET_SYNC_ORG_SLUG` | unset | Multi-company installs only: the company (slug) scheduled connector imports land in. Blank = the first company (mirrors `OIDC_PROVISION_ORG_SLUG`). Assets are imported into that company's first system. |

> **How SSO finds the account.** The first SSO sign-in links the IdP identity (issuer + `sub`) to an account; from then on that identity signs in to that account only, whatever email the IdP sends later. A new identity links by email, and only inside ONE company: the only company on a single-company install, otherwise the `OIDC_PROVISION_ORG_SLUG` company — **without that setting a multi-company install links and provisions nobody by email** (already-linked users still sign in; a startup warning says so). Inside that company the IdP must assert `email_verified`, exactly one account may hold the address (case-insensitive) and it must be active; accounts in other companies are ignored. Emails are unique per company for new and edited users. Admins see "SSO linked" on the Users page and can **Unlink SSO**; changing a user's email or de/reactivating them also removes the link and revokes their sessions and API tokens.

> **Asset connectors (Tanium / Cisco ISE).** File-based CSV import (Assets → Import) always works with no configuration. The *live* connectors are optional and off by default — set the vars above to enable a one-click Pull from Assets → Import, and optionally `ASSET_SYNC_INTERVAL_HOURS` to run that same pull on a schedule (the Import panel shows "Auto-sync every Nh" vs "Manual pull only"). They call **your own** Tanium/ISE over your network (no third party, same self-hosted posture as the threat feeds). The request shapes follow documented Tanium REST v2 and Cisco ISE ERS APIs but vary by product version — validate against your instance before relying on them.

## 6. Run the backend as a service

`/etc/systemd/system/athorize-universal.service`:

```ini
[Unit]
Description=Athorize backend
After=network.target

[Service]
User=athorize
Group=athorize
WorkingDirectory=/opt/athorize-universal/backend
ExecStart=/opt/athorize-universal/.venv/bin/uvicorn main:app \
    --host 127.0.0.1 --port 8001 --workers 1
Restart=on-failure
# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/athorize-universal
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now athorize-universal
curl -s http://127.0.0.1:8001/api/health     # → {"status":"ok","version":"1.0.0"}
```

Notes:

- `ProtectSystem=strict` makes `/opt/athorize-universal` read-only to the
  service even if its ownership were wrong; `ReadWritePaths` must name your
  `DATA_DIR` (and `EVIDENCE_DIR`/`BACKUP_DIR` if you moved them elsewhere).
- **Keep `--host 127.0.0.1`.** Only nginx should reach the backend.
- **Keep `--workers 1`.** The SQLite engine is configured for a single
  process; one worker comfortably serves a compliance team. Scaling out would
  need a different database setup, not just a config change.
- Database schema is created and migrated automatically at startup — there is
  no separate migration step, on first install or on upgrades.

## 7. Reverse proxy with TLS (nginx)

Use a certificate from your internal CA (preferred on corporate networks) or
your standard cert process. `/etc/nginx/sites-available/athorize-universal`:

```nginx
server {
    listen 443 ssl;
    server_name compliance.internal.example.com;

    ssl_certificate     /etc/ssl/certs/athorize-universal.crt;
    ssl_certificate_key /etc/ssl/private/athorize-universal.key;

    # Evidence uploads are accepted up to 100 MiB by the application
    client_max_body_size 100m;

    # Web UI — the pre-built static files from §4
    root /opt/athorize-universal/frontend/dist;
    index index.html;
    location / {
        try_files $uri /index.html;
        # The same browser hardening the app sends on /api (main.py). nginx
        # serves these files itself, so it has to add them here.
        add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'" always;
        add_header X-Frame-Options "DENY" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
        add_header Strict-Transport-Security "max-age=31536000" always;
    }

    # API
    location /api {
        proxy_pass http://127.0.0.1:8001;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}

server {
    listen 80;
    server_name compliance.internal.example.com;
    return 301 https://$host$request_uri;
}
```

```bash
sudo ln -s /etc/nginx/sites-available/athorize-universal /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

The `X-Forwarded-Proto` header is what `ATHORIZE_TRUST_XFF=1` (§5) trusts —
they work as a pair. Set `ATHORIZE_ALLOWED_HOSTS` (§5) to the same name as
`server_name`. (Installs that predate the Host check keep working without it,
with a startup warning, as long as `ATHORIZE_TRUST_XFF=1` is set.) nginx can
read `frontend/dist/` because §3 leaves the code tree world-readable (`755`); if
your policy requires a closed `/opt`, copy `frontend/dist/` somewhere nginx can
read (e.g. `/var/www/athorize`) and point `root` there instead.

## 8. First run

1. **Retrieve the first-run setup token.** On first startup (no users yet)
   the service prints a one-time **setup token** to its log and writes it to
   `<DATA_DIR>/setup-token`:
   ```bash
   sudo journalctl -u athorize-universal | grep "FIRST-RUN SETUP TOKEN"
   #   or:
   sudo cat /var/lib/athorize-universal/setup-token
   ```
   This token gates the setup screen so it cannot be hijacked by anyone who
   reaches the server before you do.
2. Browse to `https://compliance.internal.example.com`. The one-time **setup
   screen** asks for the setup token, then offers two choices:
   - **Set up my company**: your organization name and the first
     administrator account. Passwords must be at least 12 characters and include
     three of: lowercase, uppercase, digit, symbol (common passwords and the
     username are rejected).
   - **Explore with demo data**: loads three fictional sample companies and
     signs you in as `admin`. Every demo account's password is its username, so
     only use this where nobody else can reach the server. When you are done,
     an admin deletes all of it in **Settings → Start fresh** (password plus
     typing `START FRESH`), which brings back the setup screen with a **new**
     setup token in the log and in `<DATA_DIR>/setup-token`. Demo data is only
     ever loaded into an empty instance.

   On success the token is deleted and the screen disables itself.
3. Open **Marketplace** in the sidebar and **activate the frameworks you assess
   against** (e.g. CMMC 2.0, PCI DSS v4, ISO 27001). Activation
   loads that framework's control catalog and crosswalk mappings from local
   files — offline, a few seconds per framework.
4. Create your additional users under **Users** (roles: admin,
   compliance_manager, assessor, system_owner, evidence_contributor,
   auditor), then define your first **System** and start working.

Built-in protections you don't need to configure: login rate-limiting with
lockout persistence, CSRF protection, per-user session caps (5), 30-day
session expiry, and a hash-chained audit log.

## 9. Threat-intelligence feeds (optional internet egress)

By default the Advisories module uses **bundled fixture data** and makes no
network calls — correct for offline networks. The fixture data is **fictional
sample data**: made-up vendors and products, identifiers in a reserved `DEMO-`
namespace (never real CVE or CISA IDs), no links to advisory sites, and every
item is labelled *Sample* in the UI. If your security policy allows outbound
HTTPS and you want live data:

| Setting | Enables | Destination |
|---|---|---|
| `ICS_FEED=live` (or `CISA`) | CISA ICS advisories (CSAF) | `*.cisa.gov` (HTTPS only, enforced in code) |
| `THREAT_FEEDS=live` | CISA KEV catalog, NVD recent CVEs, CISA AA-series alerts, vendor PSIRT advisories | `www.cisa.gov`, `services.nvd.nist.gov`, plus any hosts you list in `ATHORIZE_PSIRT_PROVIDERS` |
| `ATHORIZE_PSIRT_PROVIDERS` | Vendor PSIRT (CSAF) pulls — comma-separated provider-metadata URLs | Only the hosts you configure (each provider is host-locked) |

These are the only external destinations the product will ever contact, and
only when you opt in. Restart the service after changing them.

### NVD API key (recommended for live mode)

The NVD feed works without any key, but NIST rate-limits anonymous clients to
about **5 requests per 30 seconds**; with a free API key the limit rises to
**50 per 30 seconds**. On a shared corporate egress IP, the anonymous tier can
throttle — get the key:

1. Request one at **https://nvd.nist.gov/developers/request-an-api-key**
   (free; enter name + email, confirm the activation email).
2. Set it for the service and restart:
   ```bash
   NVD_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
   ```
3. Verify on **Advisories → Refresh Feeds** — the per-feed status in the
   response should show NVD succeeding. No key-related errors are logged when
   the key is valid.

Treat the key like any credential (it identifies your organization to NIST):
keep it in the service's environment file with `0600` permissions, not in
shell history or the repo. If feeds run on a schedule
(`THREAT_FEEDS_INTERVAL_HOURS`), the key is used automatically on every pull.

One cosmetic note for fully offline networks: control IDs in the UI link
to public NIST reference pages (`csrc.nist.gov`); those links simply won't
resolve without internet. Everything functional is local.

## 10. Backups

### In-app (recommended for ad-hoc / pre-upgrade)
The instance operator (the first admin created at setup; in a single-company
install, any admin) can use **Settings → Backup & Restore**. A backup holds
every company on the instance, so company admins of a multi-company install
cannot use it.
- **Download backup** produces a single archive of a consistent database
  snapshot (taken with SQLite's online-backup API while the app keeps running),
  all evidence files and your custom frameworks, optionally AES-encrypted with
  a passphrase. The archive is re-read and checked before it is offered; a copy
  is kept under `BACKUP_DIR`.
- **Restore** uploads such an archive (up to 512 MB), validates it completely
  first (it must contain an intact Athorize database), brings an older backup up
  to the current schema, and then replaces the database, evidence store and
  custom frameworks, keeping a timestamped rollback copy under
  `BACKUP_DIR/rollback-*`. Everyone is signed out, every API token in the
  backup is revoked (issue new ones for integrations), and each company's audit
  log gets a RESTORE entry. Requires a one-time in-page confirmation.
- **Retention.** After each successful backup the oldest archives beyond
  `ATHORIZE_BACKUP_KEEP` (default 10) are deleted, and after each successful restore the
  oldest rollback copies beyond `ATHORIZE_BACKUP_KEEP_ROLLBACKS` (default 3); `0` keeps
  everything. Only files the app itself wrote (`universal-backup-*.tar.gz[.enc]`,
  `rollback-*`) are ever pruned — never the one just written, never an
  in-progress `*.partial`, never anything else you keep in `BACKUP_DIR` (such as
  the nightly `data-*.db` copies below). Copy archives you must keep longer
  somewhere else. Settings → Backup & Restore shows the current retention.
- A restore is crash-safe: if the server is killed or loses power part-way, the
  next start puts the previous data back (or finishes a restore that had
  already committed). The instance is never left without a database.
- If the backup was taken with a different `ATHORIZE_AUDIT_HMAC_KEY`, the
  restore says so: the data is restored, but Audit Log → Verify only passes when
  the instance runs with the key that signed the history.

Restore is global and destructive — it replaces the entire deployment's data.
Keep the encryption passphrase with your key material; without it an encrypted
archive cannot be restored.

**Large archives / offline use.** For an archive over the 512 MB upload limit,
or with the server stopped, use the same code from the command line (as the
service user, with the same environment variables as the service, from the
`backend` directory):

```bash
python -m services.backup backup  [--passphrase-env BACKUP_PASSPHRASE]
python -m services.backup restore /path/to/universal-backup-….tar.gz[.enc] [--passphrase-env BACKUP_PASSPHRASE]
```

A command-line backup can run while the service is up. A command-line restore
refuses to start while any server process is using the data directory — stop
the service first (changes made through a running server during an offline
restore would be lost); a server started during the restore waits for it.
Encrypted archives of any size work (they are encrypted in fixed-size chunks);
encrypted archives made by earlier versions still restore.

**PostgreSQL (`DATABASE_URL`).** In-app backup and restore work with the
built-in SQLite database only and refuse with an explanation otherwise. Back up
the database with `pg_dump`, plus the `evidence/` and `custom_frameworks/`
folders under the data directory.

### Scheduled (filesystem-level, for automated nightly backups)

Back up two things, on whatever schedule your data-protection policy requires
(daily is typical):

1. **The database** — use SQLite's online-backup command so you get a
   consistent copy without stopping the service:
   ```bash
   sqlite3 /var/lib/athorize-universal/data.db \
       ".backup /var/lib/athorize-universal/backups/data-$(date +%F).db"
   ```
2. **Evidence files** — `/var/lib/athorize-universal/evidence/` (plain files;
   any file-level backup tool works).
3. **Custom frameworks** — `/var/lib/athorize-universal/custom_frameworks/`
   (if you built any).

Also escrow, once, with your key material (not alongside the backups):
`backend/.env` — losing `SECRET_KEY`/`ATHORIZE_AUDIT_HMAC_KEY` means losing
audit-chain verifiability.

Example cron (as the `athorize` user) keeping 14 days:

```cron
30 2 * * * sqlite3 /var/lib/athorize-universal/data.db ".backup /var/lib/athorize-universal/backups/data-$(date +\%F).db" && find /var/lib/athorize-universal/backups -name 'data-*.db' -mtime +14 -delete
```

**Restore:** stop the service, delete `data.db-wal` and `data.db-shm` if they
exist (a stale WAL would be replayed over the restored file), replace `data.db`
with the backup copy, restore the evidence and custom_frameworks directories,
start the service.

## 11. Upgrades

### Scripted (recommended — fastest path to apply a fix)

Package a release with `scripts/package_release.sh` (on a build host):

```bash
scripts/package_release.sh 1.4.2 [--with-wheelhouse]
# → dist/athorize-1.4.2.tar.gz (+ .sha256)
```

`--with-wheelhouse` vendors Python deps for offline servers (build it on a
host matching the server's arch/OS). Deliver the tarball + `.sha256`, then on
the server:

```bash
sha256sum -c athorize-1.4.2.tar.gz.sha256
# Run the update.sh that ships in the NEW release (not the copy inside the
# install, which an older layout may have let the service account change):
tar -xzf athorize-1.4.2.tar.gz athorize-1.4.2/scripts/update.sh
sudo athorize-1.4.2/scripts/update.sh --release athorize-1.4.2.tar.gz
#   [--install-dir /opt/athorize-universal] [--service athorize-universal] [--venv <path>]
#   [--health-url http://127.0.0.1:8001/api/health] [--stop-user-processes]
```

`update.sh` runs as root and never trusts or runs anything from the old
install (older instructions let the service account write it). It verifies the
checksum, stops the service, builds the complete new version — the release's
files plus a **fresh** virtualenv made with the system `python3`, dependencies
read from the release itself (offline from its wheelhouse when present) — in a
root-only staging folder next to the install, copies `backend/.env` across as
`root:athorize 640` (it refuses a `.env` that is a symlink or has other hard
links), then renames the old install to `<install-dir>.bak-<timestamp>` and the
staging folder into place. It starts the service, waits for `/api/health`
(`--health-url`, default `http://127.0.0.1:8001/api/health`) and **rolls back
automatically** (reverse rename) if the new version doesn't answer. Your data
directory is never touched. The update stops before changing anything if the
install folder holds files that aren't part of a release (data belongs in
`DATA_DIR`), or if processes of the service user are still running after the
service stops (`--stop-user-processes` kills them, for a dedicated `athorize`
account). The unit's venv is `<install-dir>/.venv` (or `backend/.venv` if that
is where an older install has it; `--venv` to choose). The last three `.bak-*`
copies are kept (`KEEP_BACKUPS`). **Take a backup first anyway (§10).**

Pass `--skip-service` (or run where `systemctl` is absent — macOS, CI, a
container) to do the file-swap + dependency refresh without touching systemd;
the swap, data-preservation, and rollback-snapshot logic is exercised by the
`release-tooling` GitHub Actions workflow on every push, so it's validated on a
real Linux runner without a dedicated box.

### Manual

1. Take a backup (§10).
2. Stop the service: `sudo systemctl stop athorize-universal`.
3. Replace the application code in `/opt/athorize-universal` with the new
   release (as root, `tar --no-same-owner`), keeping `backend/.env` (your data
   directory is untouched — never store anything else under `/opt`).
4. Update Python dependencies, as root:
   `sudo .venv/bin/pip install -r backend/requirements.txt`
   (offline: against the new release's wheelhouse, as in §4b).
5. Deploy the new `frontend/dist/` (pre-built in the release).
6. Start the service. Schema migrations apply automatically at startup.
7. Verify: `curl -s http://127.0.0.1:8001/api/health` and a browser login.

### Upgrading to the 2026-10 security release

One-time effects, all automatic:

- **Everyone signs in again.** Session ids are now stored hashed; sessions
  from before the upgrade are dropped at the first start.
- **Audit log.** New entries use a hash that covers every field (including
  the summary), and each company's chain is anchored so deleted entries are
  detected. Existing entries keep verifying. If your install never set
  `ATHORIZE_AUDIT_HMAC_KEY`, its older entries were signed with a public
  default key: Verify still passes but reports them as *unauthenticated
  legacy entries*, and the Audit Log page shows that in amber. If an anchor
  is ever found missing or not matching the log when a new entry is written,
  the chain is re-anchored for new entries but Verify keeps reporting it as
  broken at that entry permanently — a later write never hides tampering.
- **Secrets.** If `SECRET_KEY` / `ATHORIZE_AUDIT_HMAC_KEY` are not set, they
  are generated once and saved to `<DATA_DIR>/secrets.env`. A configured audit
  key shorter than 32 characters now stops startup with a clear message.
- **Settings.** `backend/.env` is read reliably (it used to crash on some
  documented keys); `EVIDENCE_DIR` and `BACKUP_DIR` default to folders under
  `DATA_DIR` — if you relied on the old `~/.athorize-universal/evidence`
  default while `DATA_DIR` pointed elsewhere, set them explicitly.
- **Host check.** Set `ATHORIZE_ALLOWED_HOSTS` (§5) to your public host name.
  Proxy installs without it keep working, with a startup warning.
- **API tokens** created without an expiry from now on expire after 90 days;
  existing tokens are unchanged. Creating or revoking a token needs a signed-in
  session (`POST`/`DELETE /api/tokens` refuse bearer tokens), and only admins
  can pick a lifetime over 365 days.
- **Usernames** must be unique across companies for new accounts; existing
  duplicates keep working.
- **Ownership (bare-metal).** The code and venv now belong to root (§3) and
  `backend/.env` is `root:athorize 640`. `update.sh` converts an existing
  install automatically; after a manual upgrade run
  `sudo chown -R root:root /opt/athorize-universal && sudo chmod 755 /opt/athorize-universal`
  then `sudo chown root:athorize /opt/athorize-universal/backend/.env && sudo chmod 640 /opt/athorize-universal/backend/.env`.
- **Retired frameworks.** CIS Controls v8, SOC 2 and HITRUST CSF are no longer
  included. If a company still had one active, it is deactivated at the first
  start (its catalog is unloaded so dashboards stop counting it; your
  implementation records are kept) and each affected company's audit log gets
  a DEACTIVATE entry saying why (the start-up log prints a NOTICE line too).
  Restoring an older backup does the same — its response lists it — and also
  brings the other catalogs up to the shipped release straight away, without a
  restart.
- **`run-eval.sh` with `ATHORIZE_DATA_DIR`.** Versions before 2026-10 kept
  only the keys (`eval-secrets.env`) in that folder and wrote the database,
  evidence and backups to `~/.athorize-universal`. The new script notices that
  layout, stops, and prints the commands that move the data next to its keys.
- **Keys in one place.** `run-eval.sh` and the desktop app no longer write
  their own `eval-secrets.env` / `desktop-secrets.env`; like the service and
  Docker they use `<DATA_DIR>/secrets.env` (existing files of the old names are
  still read).
- **Stray `.env` files** in the directory Athorize is started from are no
  longer read — only `backend/.env`.
- **Data folder permissions.** The server now creates everything owner-only
  (umask 077) and restricts `DATA_DIR`, `EVIDENCE_DIR` and `BACKUP_DIR` to
  `0700` at start (logged once). If another local account (e.g. a separate
  backup agent) read those folders, grant it access explicitly.

## 12. Security checklist

- [ ] `SECRET_KEY` and `ATHORIZE_AUDIT_HMAC_KEY` set to unique random values; `backend/.env` is `root:athorize`, mode `640`
- [ ] `/opt/athorize-universal` (code + venv) owned by root; the service user cannot write it
- [ ] Backend bound to `127.0.0.1` only; host firewall allows inbound 443 (and nothing else app-related)
- [ ] TLS certificate from your internal CA; port 80 redirects to 443
- [ ] `ATHORIZE_TRUST_XFF=1` set (and only because nginx is in front)
- [ ] `ATHORIZE_ALLOWED_HOSTS` set to the public host name
- [ ] Data directory `/var/lib/athorize-universal` is mode `700`, owned by the service user
- [ ] First-run setup completed using the setup token (printed to the log / `<DATA_DIR>/setup-token`); token auto-deleted afterward
- [ ] Backups scheduled and a restore tested once
- [ ] `DEBUG` not set in production
- [ ] Feeds left on `mock` unless egress to `*.cisa.gov` is approved

## 13. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `413 Request Entity Too Large` uploading evidence | nginx `client_max_body_size` below 100m. |
| Login works but a security scan flags non-Secure cookies | `ATHORIZE_TRUST_XFF=1` not set, or nginx isn't sending `X-Forwarded-Proto`. |
| `403` on saves/edits (CSRF) | Browser blocked cookies, or the UI is being served from a different hostname than the API. Serve both through the same nginx server name. |
| Setup screen says "Setup already complete" | An admin account already exists. Use **Users** (as an existing admin) to add accounts; there is no re-running setup short of restoring an empty database (on a demo instance: **Settings → Start fresh**). |
| Setup token rejected after **Start fresh** | Start fresh writes a **new** token: read the log again (`grep "FIRST-RUN SETUP TOKEN"`) or `<DATA_DIR>/setup-token`. |
| Locked out after failed logins | Rate limiting backs off automatically; wait, then retry. Lockouts survive restarts by design. |
| Service won't start, `.env` ignored | `.env` must sit in `backend/` and be readable by the `athorize` user (`root:athorize`, mode `640`). |
| `500` on every page, nginx log says `Permission denied` | nginx can't traverse to `frontend/dist/` — `/opt/athorize-universal` and its subfolders must be `755` (§3). |
| White page after upgrade | Stale UI bundle — confirm the new `frontend/dist/` deployed, then hard-refresh (Ctrl+Shift+R). |

## 14. Docker install

One container runs the backend **and** serves the web UI on the same origin
(no nginx needed to try it). Requirements: Docker Engine 24+ with the Compose
plugin, or Docker Desktop (macOS / Windows), on x86_64 or ARM64. The first
build downloads the Node and Python base images and dependencies; after that
no internet access is needed.

### 14a. Keep-it install (blank instance → Setup screen)

From the root of a checkout of the repository (the release archive of §4 is
for bare-metal installs and has no UI sources to build from):

```bash
docker compose up -d
```

That builds the image, starts it with `restart: unless-stopped`, and keeps all
data in the named volume `athorize-data`. Then:

1. **Get the one-time setup token** — it is printed in a banner on every start
   until setup is completed:
   ```bash
   docker compose logs athorize | grep "SETUP TOKEN"
   #   or:
   docker compose exec athorize cat /data/setup-token
   ```
2. Browse to **http://localhost:8001** and complete the Setup screen (token,
   organization name, first administrator), then continue with §8 step 3
   (activate frameworks) and the [Administrator Quickstart](ADMIN_QUICKSTART.md).
   Or choose **Explore with demo data** there (§8 step 2); **Settings → Start
   fresh** later deletes the demo and prints a new setup token to
   `docker compose logs athorize`.

`docker compose ps` shows the container as `healthy` once `/api/health` answers.

### 14b. Demo instance (fake data, `admin` / `admin`)

```bash
docker compose -f docker-compose.demo.yml up -d
```

Open **http://localhost:8002** and log in as `admin` / `admin` (also
`manager`, `analyst`, `owner`, `contributor`, `auditor`, `operator` — each
password equals the username). The demo is a separate Compose project with its
own volume, published on `127.0.0.1` only, and its log prints a warning banner.

> **Never put real data in the demo instance** and never expose it to a
> network: every account's password is public. Reset it with
> `docker compose -f docker-compose.demo.yml down -v`, or in the app with
> **Settings → Reset demo data** (this compose file always runs a demo, so it
> loads a clean copy instead of showing the Setup screen).

### 14c. What lives where

| Item | Location |
|---|---|
| Database, evidence, backups | Volume `athorize-data` → `/data` (`data.db`, `evidence/`, `backups/`) |
| `SECRET_KEY` + `ATHORIZE_AUDIT_HMAC_KEY` | Generated on first start, saved to `/data/secrets.env` (mode 600) and reused on every restart and upgrade |
| Setup token | `/data/setup-token` until setup completes, then deleted |
| Process user | Unprivileged `athorize` (uid/gid 10001) |

The audit-log hash chain is keyed by `ATHORIZE_AUDIT_HMAC_KEY`; if that key
changes, older entries no longer verify. The generated key lives **in the same
volume** as the database. To keep it elsewhere (your secret store), set
`SECRET_KEY` and `ATHORIZE_AUDIT_HMAC_KEY` in `athorize.env` (14d) — and keep
them set from then on. To escrow the generated
ones: `docker compose exec athorize cat /data/secrets.env`.

### 14d. Configuration

| Setting | Where | Default |
|---|---|---|
| Host port | `ATHORIZE_PORT` (shell env or a `.env` file next to `docker-compose.yml`) | `8001` |
| Host address | `ATHORIZE_BIND` | `127.0.0.1` — only this machine can connect |
| Image | `ATHORIZE_IMAGE` | `athorize:local` (built from source) |
| App settings (§5: `ATHORIZE_ALLOWED_HOSTS`, `ATHORIZE_TRUST_XFF`, `FORWARDED_ALLOW_IPS`, `SMTP_*`, `OIDC_*`, …) | `athorize.env` next to `docker-compose.yml` (one `NAME=value` per line; passed into the container) | as §5 |

The two files do different jobs: `.env` is read by Docker Compose itself (port,
bind address, image), `athorize.env` is handed to the app. Both are yours —
neither is tracked in git, so `git pull` upgrades (14e) never conflict with
them. Don't edit `docker-compose.yml` for settings. (`env_file` with
`required: false` needs Docker Compose 2.24 or newer.)

**Letting other machines connect.** The default publishes on `127.0.0.1` only,
because the container speaks plain HTTP. For a team install, put your TLS
reverse proxy (§7) in front and point it at the container port; then set
(in `athorize.env`) `ATHORIZE_TRUST_XFF=1` (Secure cookies), `FORWARDED_ALLOW_IPS`
to the proxy's address (so the app sees real client IPs for login
rate-limiting), and `ATHORIZE_ALLOWED_HOSTS` to the name users browse to. With
`ATHORIZE_BIND=0.0.0.0` and no proxy, set `ATHORIZE_ALLOWED_HOSTS` to the
server's name or address — otherwise the app answers `400 Host header not
allowed` (it accepts only `localhost` / `127.0.0.1` by default, which blocks
DNS-rebinding attacks). `ATHORIZE_BIND=0.0.0.0` publishes on every interface — note that Docker's
published ports bypass host firewalls such as `ufw`. Do not set
`FORWARDED_ALLOW_IPS` when clients reach the container directly (they could
spoof their IP).

**Bind-mounting a host folder** instead of the named volume
(`- /srv/athorize:/data`): the folder must be writable by uid 10001
(`sudo chown -R 10001:10001 /srv/athorize`); the container prints that hint and
exits otherwise.

### 14e. Day-2 operations

```bash
docker compose logs -f athorize           # follow the log
docker compose restart athorize           # restart (data and keys persist)
docker compose down                       # stop + remove the container; the volume stays
docker compose up -d                      # start again — same data
git pull && docker compose up -d --build  # upgrade; schema migrates at startup
docker compose down -v                    # DELETES the volume: database, evidence, keys
```

**Command-line backup and restore** (§10 — e.g. archives over the 512 MB
upload limit):

```bash
docker compose exec athorize python -m services.backup backup
# restore: stop the app first, then run the restore in a one-off container
docker compose stop athorize
docker compose run --rm athorize python -m services.backup restore /data/backups/<file>
docker compose start athorize
```

**Backups.** The in-app **Settings → Backup & Restore** (§10) works unchanged.
For a filesystem-level copy of the whole volume (database, evidence *and*
`secrets.env`):

```bash
docker compose stop athorize
docker run --rm -v athorize_athorize-data:/data -v "$PWD":/backup alpine \
    tar -czf /backup/athorize-data-$(date +%F).tgz -C /data .
docker compose start athorize
```

**Pre-built images.** Each release publishes a multi-arch image (amd64 and
arm64) to `ghcr.io/djctwo/athorize`, tagged with the version (`1.0.0`, `1.0`)
and `latest`. To run one instead of building from source, set the image in the
`.env` file next to `docker-compose.yml` (14d), then pull and start:

```bash
echo "ATHORIZE_IMAGE=ghcr.io/djctwo/athorize:latest" >> .env
docker compose pull && docker compose up -d   # also the upgrade command
```

### 14f. Docker troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `ERROR: /data is not writable by the container user` | Bind-mounted folder owned by another user — `chown -R 10001:10001` it, or use the named volume. |
| No `SETUP TOKEN` in the log | Setup was already completed (the token is deleted), or this is the demo compose file. |
| Setup token rejected after `down -v` | `down -v` wiped the volume and a **new** token was generated — read the log again. |
| Port already in use | Set `ATHORIZE_PORT` (or `ATHORIZE_DEMO_PORT` for the demo) to a free port. |
| "Too many login attempts" | Five wrong passwords for one account from one address lock that account *from that address* for 15 minutes; an account under attack from many addresses only accepts sign-ins from addresses it has used before. Behind Docker's port publishing every client shares one address, so someone mistyping another person's password locks that person out too — for team installs use a reverse proxy with `FORWARDED_ALLOW_IPS` (14d). Thirty failed sign-ins from one address (password spraying) lock the address: from then on only a user with no failed attempts of their own from it, typing the correct password, gets in; every wrong guess is refused for 15 minutes. |
| `400 Host header not allowed` | You reach the container by a name other than `localhost`/`127.0.0.1` — add it to `ATHORIZE_ALLOWED_HOSTS` (14d). |
| Windows: port 8001 "forbidden by its access permissions" / "address already in use" | Windows reserves some port ranges (`netsh interface ipv4 show excludedportrange protocol=tcp`). Set `ATHORIZE_PORT` to a port outside them. |

---

*Athorize is free and open-source software (GNU AGPL v3.0), © 2026 Douglas Cleary.
For help, open an issue at https://github.com/djctwo/athorize/issues.*
