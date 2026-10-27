# Security policy

## Reporting a vulnerability

Please report security vulnerabilities **privately**, not in a public issue,
discussion or pull request.

Use GitHub's private vulnerability reporting: open the repository's
**Security** tab and choose **Report a vulnerability**
(https://github.com/djctwo/athorize/security/advisories/new). Only the
maintainer can see the report.

Please include:

- the Athorize version (or commit) and how it is installed (Docker, Linux
  service, Windows `.exe`, or from source);
- what an attacker can do, and what access they need first (for example, an
  unauthenticated visitor, or a signed-in user with a given role);
- steps to reproduce, ideally against the built-in demo data. Never send real
  compliance data, credentials or system names.

The maintainer aims to acknowledge reports within a week. Confirmed issues are
fixed in a new release and disclosed through a GitHub Security Advisory, with
credit to the reporter if they want it.

## Supported versions

| Version | Supported |
|---|---|
| 1.x (latest release) | Yes |
| Older | No |

Fixes are released as a new 1.x version. Please upgrade to the latest release
before reporting, in case the issue is already fixed.

## Scope

Athorize is self-hosted software. In scope: vulnerabilities in the code in
this repository and in the Docker image and Windows `.exe` built from it, such
as authentication or authorization bypass, data exposure across organizations
or systems, injection, and tampering with the audit log.

Out of scope:

- How a particular deployment is run. The operator is responsible for securing
  their server, network, TLS reverse proxy, backups, secrets and accounts
  (see the [security checklist](docs/INSTALL.md#12-security-checklist) in
  `docs/INSTALL.md`).
- The demo instance and demo builds, whose account passwords are public by
  design. Never expose a demo to a network.
- Vulnerabilities in third-party dependencies with no demonstrated impact on
  Athorize. Please report those to the upstream project.
