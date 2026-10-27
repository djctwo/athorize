#!/usr/bin/env bash
# Athorize — one-command local evaluation runner.
#
# Stands the whole app up from a single process for evaluation on a laptop or VM
# (macOS / Linux / WSL). No nginx, no Node, no systemd. It:
#   1. finds python3, creates a virtualenv, installs the backend dependencies
#      (uses the bundled wheelhouse/ if present — offline; else pip from PyPI),
#   2. launches the backend with ATHORIZE_SERVE_FRONTEND=1 so it also serves the
#      pre-built web UI on the same origin.
#
# Then open the printed URL in a browser. Stop with Ctrl-C. Re-run any time —
# your data persists in $ATHORIZE_DATA_DIR (default ~/.athorize-universal).
# Keys: the app generates SECRET_KEY + ATHORIZE_AUDIT_HMAC_KEY on first start and
# keeps them in <data dir>/secrets.env, the same file every other way of
# starting Athorize uses, so switching between them never switches keys.
#
# Production installs do NOT use this script — see docs/INSTALL.md (nginx + service).
# bash 3.2-safe (ships on macOS).
set -eu
# The database and evidence are private to this user (other local accounts on a
# shared machine must not read them).
umask 077

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEFAULT_DATA_DIR="$HOME/.athorize-universal"
# ATHORIZE_DATA_DIR, or the app's own name DATA_DIR (same folder either way).
DATA_DIR="${ATHORIZE_DATA_DIR:-${DATA_DIR:-$DEFAULT_DATA_DIR}}"
PORT="${PORT:-8001}"
VENV="$ROOT/.venv"

echo "==> Athorize evaluation runner"
echo "    bundle: $ROOT"
echo "    data:   $DATA_DIR"

# --- 0. Data written by run-eval.sh before 2026-10 ----------------------------
# That version kept only its keys (eval-secrets.env) in $ATHORIZE_DATA_DIR; the
# database, evidence and backups went to ~/.athorize-universal. Starting here
# would open an empty instance and make that data look lost, so say where it is.
if [ "${ATHORIZE_IGNORE_LEGACY_DATA:-0}" != 1 ] && [ "$DATA_DIR" != "$DEFAULT_DATA_DIR" ] \
   && [ -f "$DATA_DIR/eval-secrets.env" ] && [ ! -f "$DATA_DIR/data.db" ] \
   && [ -f "$DEFAULT_DATA_DIR/data.db" ]; then
  cat >&2 <<MSG

STOP: your existing Athorize data is not in $DATA_DIR.
Older versions of this script kept only the keys (eval-secrets.env) there and
wrote the database, evidence and backups to $DEFAULT_DATA_DIR.
Starting now would open an EMPTY instance. Move the data next to its keys first:

  for f in data.db data.db-wal data.db-shm evidence backups custom_frameworks; do
    [ -e "$DEFAULT_DATA_DIR/\$f" ] && mv "$DEFAULT_DATA_DIR/\$f" "$DATA_DIR/"
  done

then run this script again. (To start an empty instance here anyway, set
ATHORIZE_IGNORE_LEGACY_DATA=1.) See docs/INSTALL.md section 11, "Upgrading".
MSG
  exit 3
fi

# --- 1. Python ---------------------------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 not found. Install Python 3.11+ first — see README.md." >&2
  exit 1
fi
PYV="$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
case "$PYV" in
  3.1[1-9]|3.[2-9][0-9]) : ;;  # 3.11+
  *) echo "ERROR: Python $PYV found, but 3.11+ is required. See README.md." >&2; exit 1 ;;
esac
echo "    python: $PYV ($(command -v python3))"

# --- 2. Virtualenv + dependencies -------------------------------------------
if [ ! -x "$VENV/bin/python" ]; then
  echo "==> Creating virtualenv (first run only)…"
  python3 -m venv "$VENV"
fi
if [ ! -x "$VENV/bin/uvicorn" ]; then
  echo "==> Installing backend dependencies (first run only)…"
  "$VENV/bin/python" -m pip install --quiet --upgrade pip
  if [ -d "$ROOT/wheelhouse" ]; then
    echo "    (offline install from bundled wheelhouse/)"
    "$VENV/bin/python" -m pip install --quiet --no-index --find-links "$ROOT/wheelhouse" -r "$ROOT/backend/requirements.txt"
  else
    echo "    (downloading from PyPI — needs internet this once)"
    "$VENV/bin/python" -m pip install --quiet -r "$ROOT/backend/requirements.txt"
  fi
fi

# --- 3. Data folder + settings -----------------------------------------------
mkdir -p "$DATA_DIR"
chmod go-rwx "$DATA_DIR" 2>/dev/null || true   # also tightens folders made by older versions
# Keys are NOT handled here: the app reuses <data dir>/secrets.env (or the
# eval-secrets.env older versions of this script wrote) and generates
# secrets.env on the first start. Exported SECRET_KEY / ATHORIZE_AUDIT_HMAC_KEY
# still win, as for every other start path.
export ATHORIZE_SERVE_FRONTEND=1
# Everything (DB, evidence, backups) lives under DATA_DIR unless overridden.
EVIDENCE_DIR="${EVIDENCE_DIR:-$DATA_DIR/evidence}"
BACKUP_DIR="${BACKUP_DIR:-$DATA_DIR/backups}"
export DATA_DIR EVIDENCE_DIR BACKUP_DIR
# No reverse proxy in eval mode: don't let any client (even a local one) choose
# its address via X-Forwarded-For (login throttling keys on it). Set
# FORWARDED_ALLOW_IPS yourself if you do put a proxy in front.
export FORWARDED_ALLOW_IPS="${FORWARDED_ALLOW_IPS-}"

# --- 4. Launch ---------------------------------------------------------------
echo ""
echo "============================================================"
echo "  Athorize is starting on:  http://localhost:${PORT}"
echo ""
echo "  • DEMO build  → log in with   admin / admin"
echo "  • BLANK build → it shows a Setup screen; the one-time token"
echo "    is printed below and saved to: $DATA_DIR/setup-token"
echo "    Choose \"Set up my company\" or \"Explore with demo data\"."
echo ""
echo "  Stop with Ctrl-C. Your data stays in $DATA_DIR."
echo "============================================================"
echo ""
cd "$ROOT/backend"
exec "$VENV/bin/python" -m uvicorn main:app --host 127.0.0.1 --port "$PORT"
