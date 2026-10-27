# Live SSO + Email smoke test (10 minutes)

The OIDC and SMTP code paths are unit-tested (incl. a real RS256 sign/verify
harness), but the one thing tests can't prove is talking to a **real** IdP and a
**real** mail server. This stack does exactly that locally — no cloud accounts —
using Keycloak (an OIDC IdP) and MailHog (a catch-all SMTP server with a web
inbox). Run it on any machine with Docker (your laptop, or a throwaway VM).

## 1. Start the IdP + mail server

```bash
docker compose -f scripts/smoketest/docker-compose.yml up
```

- Keycloak admin: http://localhost:8080 (admin / admin) — realm `athorize`,
  client `athorize-universal`, and a verified test user are auto-imported.
- MailHog inbox: http://localhost:8025

## 2. Point the app at them

Add to `backend/.env` (or your environment), then restart the backend:

```ini
# OIDC (http://localhost is allowed by the HTTPS pin for local dev)
OIDC_ENABLED=true
OIDC_ISSUER=http://localhost:8080/realms/athorize
OIDC_CLIENT_ID=athorize-universal
OIDC_CLIENT_SECRET=athorize-smoketest-secret
OIDC_REDIRECT_URI=http://localhost:8001/api/auth/oidc/callback
OIDC_DEFAULT_ROLE=auditor

# Email via MailHog (no TLS, no auth)
SMTP_HOST=localhost
SMTP_PORT=1025
SMTP_FROM=digest@athorize.local
SMTP_USE_TLS=false
```

> If you reach the app through the Vite dev server on `:3001`, set
> `OIDC_REDIRECT_URI=http://localhost:3001/api/auth/oidc/callback` instead — both
> are pre-registered on the client.

## 3. Verify SSO  ✅

1. Open the app's login page — a **Sign in with SSO** button now appears.
2. Click it → you're sent to Keycloak. Log in as **`pilot` / `pilot-pass-12345`**.
3. You land back in the app, signed in. Confirm under **Users** that a new
   account `pilot` exists with role **auditor** (auto-provisioned by verified
   email) — this proves discovery, code exchange, JWKS signature verification,
   the `email_verified` gate, and provisioning all work against a real IdP.

Negative check (optional): in Keycloak, set the pilot user's email to
*unverified* and retry — login must be **rejected**.

## 4. Verify email digests  ✅

1. As an admin, open **Settings → Email Digest**.
2. SMTP should read **configured**. Click **Send test digest to me** (your admin
   account needs an email address set).
3. Open the MailHog inbox at http://localhost:8025 — the digest email is there,
   rendered HTML, listing overdue findings / expiring evidence / overdue
   cadences. (Run against the demo seed so there's content to report.)

This proves the SMTP path end-to-end: connection, STARTTLS toggle, message
construction, and the escaped HTML body.

## 5. Tear down

```bash
docker compose -f scripts/smoketest/docker-compose.yml down
```

Then remove the OIDC/SMTP lines from `backend/.env` (or set `OIDC_ENABLED=false`)
to return to password-only auth.

---

**What this validates that CI/units don't:** real OIDC discovery + JWKS over the
wire, a real authorization-code round-trip through a browser, and a real SMTP
delivery. After this passes once, SSO and email are proven for the pilot.
