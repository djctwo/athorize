#!/bin/bash
# Start a throwaway single-process Athorize instance for the e2e suite.
#   usage: e2e/serve.sh demo|blank <data-dir> [port]
# The data dir is WIPED first, so never point it at a real install.
# PY defaults to `python3`; point it at a venv that has backend/requirements.txt.
set -eu
MODE="${1:?demo|blank}"
D="${2:?data dir}"
PORT="${3:-8042}"
PY="${PY:-python3}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
case "$D" in
  "$HOME/.athorize"*) echo "refusing to use a real data dir: $D" >&2; exit 1 ;;
esac
rm -rf "$D" && mkdir -p "$D"
echo "DATA_DIR=$D mode=$MODE port=$PORT"
cd "$ROOT/backend"
export DATA_DIR="$D" EVIDENCE_DIR="$D/evidence" BACKUP_DIR="$D/backups"
export SECRET_KEY="$(openssl rand -hex 32)" ATHORIZE_AUDIT_HMAC_KEY="$(openssl rand -hex 32)"
export ATHORIZE_SERVE_FRONTEND=1
if [ "$MODE" = demo ]; then export ATHORIZE_DEMO_SEED=1; else unset ATHORIZE_DEMO_SEED || true; fi
exec "$PY" -m uvicorn main:app --host 127.0.0.1 --port "$PORT"
