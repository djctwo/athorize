#!/usr/bin/env bash
# Reset an Athorize DEMO instance: delete its database so the next start
# re-creates the demo data (ATHORIZE_DEMO_SEED=1 / demo builds seed an empty DB).
#
#   DATA_DIR=~/athorize-demo scripts/reset-demo.sh [--yes]
#   (ATHORIZE_DATA_DIR, the name run-eval.sh uses, works too)
#
# Safety rails — this script deletes data, so it:
#   * never guesses the data folder: DATA_DIR or ATHORIZE_DATA_DIR must be set;
#   * refuses unless every company in that database was created by the demo
#     seed (a real instance is never reset, even if pointed at by mistake);
#   * refuses while a running Athorize has the database open (when lsof exists);
#   * asks for confirmation unless --yes is given.
# Evidence files, backups and keys in the folder are left alone.
#
# bash 3.2-safe.
set -euo pipefail

YES=0
for arg in "$@"; do
  case "$arg" in
    --yes|-y) YES=1 ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "Unknown argument: $arg" >&2; exit 2 ;;
  esac
done

DIR="${DATA_DIR:-${ATHORIZE_DATA_DIR:-}}"
if [ -z "$DIR" ]; then
  echo "ERROR: set DATA_DIR (or ATHORIZE_DATA_DIR) to the demo instance's data folder." >&2
  echo "       This script never falls back to a default folder." >&2
  exit 2
fi
case "$DIR" in "~"*) DIR="$HOME${DIR#\~}" ;; esac
DB="$DIR/data.db"

if [ ! -f "$DB" ]; then
  echo "Nothing to reset: no database at $DB."
  echo "Start Athorize with ATHORIZE_DEMO_SEED=1 and this data folder to create the demo data."
  exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is needed to check that $DB is a demo database." >&2
  exit 1
fi
# Read-only check with the Python standard library (no app code is imported).
VERDICT="$(python3 - "$DB" <<'PY'
import json, sqlite3, sys
try:
    con = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
    rows = [r[0] for r in con.execute("SELECT settings FROM organizations")]
except sqlite3.Error as exc:
    print(f"unreadable ({exc})"); sys.exit(0)
def is_demo(raw):
    try:
        return bool((json.loads(raw) if isinstance(raw, str) else (raw or {})).get("demo_data"))
    except (ValueError, AttributeError):
        return False
if not rows:
    print("empty")
elif all(is_demo(r) for r in rows):
    print("demo")
else:
    print(f"real ({sum(not is_demo(r) for r in rows)} of {len(rows)} companies are not demo data)")
PY
)"
case "$VERDICT" in
  demo|empty) : ;;
  *)
    echo "REFUSING: $DB is not a demo database: $VERDICT." >&2
    echo "Only databases created by the demo seed can be reset with this script." >&2
    exit 1 ;;
esac

if command -v lsof >/dev/null 2>&1 && lsof -- "$DB" >/dev/null 2>&1; then
  echo "REFUSING: a running process has $DB open. Stop Athorize first." >&2
  exit 1
fi

if [ "$YES" != 1 ]; then
  if [ ! -t 0 ]; then
    echo "REFUSING: not a terminal; re-run with --yes to confirm deleting $DB." >&2
    exit 1
  fi
  printf 'Delete the demo database %s? Type RESET to confirm: ' "$DB"
  read -r answer
  [ "$answer" = "RESET" ] || { echo "Aborted; nothing deleted."; exit 1; }
fi

rm -f "$DB" "$DB-wal" "$DB-shm"
echo "Demo database removed from $DIR."
echo "Start Athorize with ATHORIZE_DEMO_SEED=1 and the same data folder to reseed, e.g.:"
echo "  ATHORIZE_DATA_DIR=\"$DIR\" ATHORIZE_DEMO_SEED=1 scripts/run-eval.sh"
