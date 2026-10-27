#!/bin/bash
# Re-make the README screenshots + demo video in one go.
#   usage: frontend/e2e/media/capture.sh <scratch-dir> [port]
# Starts a BLANK throwaway instance (data in <scratch-dir>/instance — wiped first), runs
# capture_media.mjs against it, and always stops the server. Needs frontend/dist (npm run build)
# and PY pointing at a Python with backend/requirements.txt (default python3).
# Writes docs/screenshots/*.png and docs/media/*; scratch files go to <scratch-dir>/work.
set -eu
S="${1:?scratch dir}"
PORT="${2:-8078}"
FRONT="$(cd "$(dirname "$0")/../.." && pwd)"
ROOT="$(cd "$FRONT/.." && pwd)"
mkdir -p "$S"
[ -f "$FRONT/dist/index.html" ] || { echo "build the UI first: cd frontend && npm ci && npm run build" >&2; exit 1; }

"$FRONT/e2e/serve.sh" blank "$S/instance" "$PORT" > "$S/server.log" 2>&1 &
PID=$!
trap 'kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true' EXIT

i=0
until curl -fsS "http://127.0.0.1:$PORT/api/auth/status" >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -gt 90 ]; then echo "server did not start — see $S/server.log" >&2; exit 1; fi
  sleep 1
done

cd "$FRONT"
node e2e/media/capture_media.mjs --base "http://127.0.0.1:$PORT" --data-dir "$S/instance" \
  --shots "$ROOT/docs/screenshots" --media "$ROOT/docs/media" --work "$S/work"
