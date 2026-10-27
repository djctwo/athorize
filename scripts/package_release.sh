#!/usr/bin/env bash
# Package a deployable Athorize release bundle.
#
# Runs on the BUILD machine (your dev box). Produces a single versioned tarball
# containing the backend source, framework plugins, scripts, docs, the licence
# files and the pre-built frontend — everything a self-hosted install needs to update.
# Pair with scripts/update.sh on the server.
#
# Usage:
#   scripts/package_release.sh [VERSION] [--with-wheelhouse] [--demo]
#
#   VERSION           defaults to `git describe`/short SHA
#   --with-wheelhouse also vendors Python deps for offline (§4b) installs.
#                     NOTE: wheels are platform-specific — run this on a host
#                     matching the target server's arch/OS, or the wheelhouse
#                     won't install there. Omit to let the server pip-install.
#   --demo            DEMO build: adds the DEMO_BUILD marker, so the first
#                     start auto-loads the demo data into the empty database,
#                     and keeps the command-line demo helpers (seed_demo.py,
#                     reset-demo.sh). WITHOUT this flag (the default) the
#                     instance starts blank and those helpers are left out;
#                     the Setup screen still offers "Explore with demo data"
#                     (the seed is part of the backend and only ever loads
#                     into an EMPTY instance, never into real data).
#
# Output: dist/athorize-<VERSION>.tar.gz  (+ .sha256)
#
# bash 3.2-safe (no associative arrays / mapfile / ${var^^}).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

VERSION=""
WITH_WHEELHOUSE=0
DEMO_BUILD=0
while [ $# -gt 0 ]; do
  case "$1" in
    --with-wheelhouse) WITH_WHEELHOUSE=1; shift ;;
    --demo) DEMO_BUILD=1; shift ;;
    -*) echo "Unknown flag: $1" >&2; exit 2 ;;
    *) VERSION="$1"; shift ;;
  esac
done
if [ -z "$VERSION" ]; then
  VERSION="$(git describe --tags --always --dirty 2>/dev/null || git rev-parse --short HEAD)"
fi

NAME="athorize-${VERSION}"
STAGE="$(mktemp -d)/${NAME}"
OUT="${REPO}/dist"
trap 'rm -rf "$(dirname "$STAGE")"' EXIT

echo "==> Packaging ${NAME}"
mkdir -p "$STAGE" "$OUT"

echo "==> Building frontend (npm ci && npm run build)"
( cd frontend && npm ci --silent && npm run build >/dev/null )
if [ ! -d frontend/dist ]; then
  echo "ERROR: frontend/dist not produced" >&2; exit 1
fi

echo "==> Staging code"
# Code only — never the customer's runtime data (~/.athorize-universal lives
# outside the repo) and never local build artifacts.
cp -R backend "$STAGE/backend"
cp -R frameworks "$STAGE/frameworks"
cp -R scripts "$STAGE/scripts"
cp -R docs "$STAGE/docs"
# Licence and notices travel with every copy (AGPL-3.0), plus the README and
# the annotated settings example (copy it to backend/.env, INSTALL §5).
cp LICENSE NOTICE README.md .env.example "$STAGE/"
mkdir -p "$STAGE/frontend"
cp -R frontend/dist "$STAGE/frontend/dist"
# Prune things that must never ship in a release.
rm -rf "$STAGE/backend/.venv" "$STAGE"/backend/**/__pycache__ 2>/dev/null || true
find "$STAGE" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "$STAGE" -name '*.pyc' -delete 2>/dev/null || true
# Dev databases (incl. SQLite WAL/SHM, which can hold test/seed data fragments)
# and tool caches must never ship or bloat the air-gapped tarball.
find "$STAGE" \( -name '*.db' -o -name '*.db-wal' -o -name '*.db-shm' \) -delete 2>/dev/null || true
find "$STAGE" -type d \( -name '.pytest_cache' -o -name '.ruff_cache' -o -name '.mypy_cache' -o -name 'node_modules' \) -prune -exec rm -rf {} + 2>/dev/null || true
if [ "$DEMO_BUILD" -eq 0 ]; then
  # Standard build: leave out the command-line demo helpers. The demo seed
  # itself (backend/services/demo_seed.py) always ships: the Setup screen's
  # "Explore with demo data" loads it into an EMPTY instance only.
  rm -f "$STAGE/scripts/seed_demo.py" "$STAGE/scripts/reset-demo.sh" 2>/dev/null || true
  echo "==> Standard build — blank instance (Setup offers demo data), CLI demo helpers left out"
else
  # Demo build: keep the CLI demo helpers AND drop a marker so the app auto-populates
  # an EMPTY database on first boot — the recipient gets a fully-loaded instance
  # to evaluate, no commands to run.
  echo "demo" > "$STAGE/DEMO_BUILD"
  echo "==> DEMO build — seed scripts INCLUDED + auto-seed marker (first boot populates an empty DB)"
fi
rm -f "$STAGE/backend/.env" 2>/dev/null || true                            # local env, never ships
echo "$VERSION" > "$STAGE/VERSION"

if [ "$WITH_WHEELHOUSE" -eq 1 ]; then
  echo "==> Vendoring Python wheels (offline install support)"
  python3 -m pip download -q -r backend/requirements.txt -d "$STAGE/wheelhouse"
fi

echo "==> Creating tarball"
TARBALL="${OUT}/${NAME}.tar.gz"
# macOS bsdtar would add AppleDouble "._*" entries and xattr headers
# (com.apple.provenance): junk files on the Linux server, which update.sh
# rightly refuses as "not part of Athorize". Linux GNU tar takes --no-xattrs too.
export COPYFILE_DISABLE=1
TAR_FLAGS="--no-xattrs"
if tar --version 2>/dev/null | grep -q bsdtar; then TAR_FLAGS="--no-xattrs --no-mac-metadata"; fi
# shellcheck disable=SC2086
tar $TAR_FLAGS -czf "$TARBALL" -C "$(dirname "$STAGE")" "$NAME"
( cd "$OUT" && shasum -a 256 "${NAME}.tar.gz" > "${NAME}.tar.gz.sha256" )

echo ""
echo "Release ready:"
echo "  $TARBALL"
echo "  $(cat "${TARBALL}.sha256")"
echo ""
echo "Copy the tarball (+ .sha256) to the server and run scripts/update.sh there."
