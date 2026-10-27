#!/usr/bin/env bash
# Apply an Athorize release bundle to an install (docs/INSTALL.md §11).
#
# Runs on the CUSTOMER'S SERVER, as root. Schema migrations apply automatically
# when the service starts, so there is no separate DB step.
#
# Design: stage and swap. Nothing in the old install is trusted or executed —
# the service account may have been able to write it (older instructions gave
# it the code), so its files are only read, never run, and never chowned.
#   1. take the install dir itself (root:root 755) and stop the service; refuse
#      if processes of the service user are still running;
#   2. build the complete new tree in a fresh root-only staging dir next to the
#      install: the release's files plus a NEW virtualenv made by the system
#      python3, with requirements read from the verified release, never from
#      the install dir;
#   3. copy backend/.env from the old tree (refused if it is a symlink or has
#      other hard links) as root:<service group> 640;
#   4. rename install -> <install>.bak-<time>, staging -> install (atomic
#      renames on one filesystem; rollback is the reverse rename);
#   5. start the service and check /api/health; roll back automatically if it
#      does not come up.
# The data dir (DATA_DIR, /var/lib/athorize-universal) lives outside the install
# dir and is never touched. Anything else found in the install dir that is not
# part of a release stops the update before any change (move it out first).
#
# Usage:
#   sudo scripts/update.sh --release athorize-<ver>.tar.gz \
#        [--install-dir /opt/athorize-universal] [--service athorize-universal] \
#        [--user athorize] [--venv /opt/athorize-universal/.venv] \
#        [--health-url http://127.0.0.1:8001/api/health] [--skip-service] \
#        [--stop-user-processes]
#   --venv               the venv the unit runs, inside the install dir
#                        (default: .venv, or backend/.venv if that is the one present)
#   --stop-user-processes  after stopping the unit, kill leftover processes of
#                        the (dedicated) service user instead of refusing
#
# bash 3.2-safe.
set -euo pipefail
umask 022   # new code + venv: readable, not writable, by the service user and nginx

RELEASE=""
INSTALL_DIR="/opt/athorize-universal"
SERVICE="athorize-universal"
SVC_USER="athorize"
VENV=""
HEALTH_URL="http://127.0.0.1:8001/api/health"
STOP_USER_PROCS=0
SKIP_SERVICE="${SKIP_SERVICE:-0}"   # 1 = swap files only, don't touch systemd

while [ $# -gt 0 ]; do
  case "$1" in
    --release)      RELEASE="$2"; shift 2 ;;
    --install-dir)  INSTALL_DIR="$2"; shift 2 ;;
    --service)      SERVICE="$2"; shift 2 ;;
    --user)         SVC_USER="$2"; shift 2 ;;
    --venv)         VENV="$2"; shift 2 ;;
    --health-url)   HEALTH_URL="$2"; shift 2 ;;
    --skip-service) SKIP_SERVICE=1; shift ;;
    --stop-user-processes) STOP_USER_PROCS=1; shift ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

die() { echo "ERROR: $*" >&2; exit 1; }

if [ -L "$INSTALL_DIR" ] || [ ! -d "$INSTALL_DIR" ]; then
  echo "ERROR: install dir not found (or is a symlink): $INSTALL_DIR" >&2; exit 2
fi
IS_ROOT=0; [ "$(id -u)" = 0 ] && IS_ROOT=1
# 1. The install dir itself becomes root's before anything else is looked at,
#    so the service user can no longer add, remove or rename entries in it.
if [ "$IS_ROOT" = 1 ]; then
  chown root:root "$INSTALL_DIR"
  chmod 755 "$INSTALL_DIR"
fi
INSTALL_DIR="$(cd "$INSTALL_DIR" && pwd -P)"
PARENT="$(dirname "$INSTALL_DIR")"

# Auto-skip service management where systemd isn't present (macOS, CI, containers
# without an init) so the file-swap/rollback logic can still be exercised.
if [ "$SKIP_SERVICE" = "0" ] && ! command -v systemctl >/dev/null 2>&1; then
  SKIP_SERVICE=1
  echo "==> systemctl not found — skipping service management (file swap + deps only)"
fi

if [ -z "$RELEASE" ] || [ ! -f "$RELEASE" ]; then
  echo "ERROR: --release <tarball> is required and must exist" >&2; exit 2
fi

# The venv the unit runs (INSTALL §4/§6: <install>/.venv). Older installs may
# keep it in backend/.venv. It is rebuilt fresh at the same place.
if [ -z "$VENV" ]; then
  if [ -d "${INSTALL_DIR}/backend/.venv" ] && [ ! -d "${INSTALL_DIR}/.venv" ]; then
    VENV="${INSTALL_DIR}/backend/.venv"
  else
    VENV="${INSTALL_DIR}/.venv"
  fi
fi
case "$VENV" in
  "${INSTALL_DIR}"/*) VENV_REL="${VENV#"${INSTALL_DIR}"/}" ;;
  *) die "--venv must be inside the install dir ($INSTALL_DIR): $VENV" ;;
esac

# sha256 -c that works on both minimal Linux (sha256sum) and macOS (shasum).
sha256_check() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum -c "$1"
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 -c "$1"
  else echo "WARNING: no sha256sum/shasum available — skipping checksum verify" >&2; fi
}
if [ -f "${RELEASE}.sha256" ]; then
  echo "==> Verifying checksum"
  ( cd "$(dirname "$RELEASE")" && sha256_check "$(basename "$RELEASE").sha256" )
fi

TMP="$(mktemp -d)"
STAGE=""
STOPPED=0
cleanup() {
  local rc=$?
  rm -rf "$TMP"; [ -n "$STAGE" ] && rm -rf "$STAGE"
  # Failed before the swap: nothing changed, so bring the old version back up.
  if [ "$rc" != 0 ] && [ "$STOPPED" = 1 ]; then
    echo "==> Update aborted before any change; starting $SERVICE again" >&2
    systemctl start "$SERVICE" || true
  fi
  return 0
}
trap cleanup EXIT
echo "==> Extracting release"
# --no-same-owner: files belong to root, never to the uid the build host recorded.
tar --no-same-owner -xzf "$RELEASE" -C "$TMP"
# Bundle dir is athorize-<ver> (renamed from athorize-universal-<ver> in the
# 2026-06-24 rebrand). Accept the current name, and the old one for back-compat.
SRC="$(find "$TMP" -mindepth 1 -maxdepth 1 -type d \( -name 'athorize-*' -o -name 'athorize-universal-*' \) | head -1)"
[ -n "$SRC" ] && [ -f "$SRC/backend/requirements.txt" ] && [ -d "$SRC/frontend/dist" ] \
  || die "bundle layout unexpected (no backend/requirements.txt or frontend/dist)"
NEW_VER="$(cat "$SRC/VERSION" 2>/dev/null || echo unknown)"
OLD_VER="$(cat "$INSTALL_DIR/VERSION" 2>/dev/null || echo unknown)"

if [ "$SKIP_SERVICE" = "0" ]; then
  echo "==> Stopping $SERVICE"
  systemctl stop "$SERVICE" || echo "  (service not running)"
  STOPPED=1
fi
# No process of the service user may run while root reads the old tree.
if id "$SVC_USER" >/dev/null 2>&1 && command -v pgrep >/dev/null 2>&1 \
   && pgrep -u "$SVC_USER" >/dev/null 2>&1; then
  if [ "$STOP_USER_PROCS" = 1 ]; then
    echo "==> Stopping leftover processes of $SVC_USER"
    pkill -u "$SVC_USER" || true
    sleep 2
    pkill -9 -u "$SVC_USER" 2>/dev/null || true
    sleep 1
  fi
  if pgrep -u "$SVC_USER" >/dev/null 2>&1; then
    die "processes of the service user '$SVC_USER' are still running (pgrep -u $SVC_USER).
       Stop them, or re-run with --stop-user-processes if '$SVC_USER' is the dedicated
       Athorize account (docs/INSTALL.md §3)."
  fi
fi

# Everything at the top of the install must be part of a release (or the venv);
# anything else (data, hand-made files) would silently move to the .bak copy.
VENV_TOP="${VENV_REL%%/*}"
UNKNOWN=""
for entry in "$INSTALL_DIR"/* "$INSTALL_DIR"/.[!.]*; do
  [ -e "$entry" ] || [ -L "$entry" ] || continue
  name="$(basename "$entry")"
  if [ -e "$SRC/$name" ] || [ "$name" = "$VENV_TOP" ] || [ "$name" = ".venv.prev" ]; then continue; fi
  case "$name" in backend|frameworks|scripts|docs|frontend|VERSION|LICENSE|NOTICE|README.md|.env.example|wheelhouse|DEMO_BUILD) continue ;; esac
  UNKNOWN="$UNKNOWN $name"
done
if [ -n "$UNKNOWN" ]; then
  die "the install dir holds files that are not part of Athorize:${UNKNOWN}
       Move them out of $INSTALL_DIR first (data belongs in DATA_DIR, docs/INSTALL.md §3)."
fi

# Old configuration: read as data only, and never through a link.
OLD_ENV="${INSTALL_DIR}/backend/.env"
if [ -L "$OLD_ENV" ]; then
  die "$OLD_ENV is a symlink; replace it with the file itself (root:${SVC_USER} 640) and re-run."
fi
link_count() { stat -c %h "$1" 2>/dev/null || stat -f %l "$1"; }
if [ -f "$OLD_ENV" ] && [ "$(link_count "$OLD_ENV")" != 1 ]; then
  die "$OLD_ENV has other hard links; copy its contents to a new file and re-run."
fi

# 2. Stage the complete new tree (root-only until it is ready).
STAGE="$(mktemp -d "${PARENT}/.athorize-stage.XXXXXX")"
chmod 700 "$STAGE"
echo "==> Staging ${NEW_VER} in $STAGE"
cp -R "$SRC/." "$STAGE/"
echo "==> Building a fresh Python virtualenv ($VENV_REL)"
python3 -m venv "$STAGE/$VENV_REL"
if [ -d "$SRC/wheelhouse" ]; then
  "$STAGE/$VENV_REL/bin/python" -m pip install -q --no-cache-dir --no-index \
      --find-links "$SRC/wheelhouse" -r "$SRC/backend/requirements.txt"
else
  "$STAGE/$VENV_REL/bin/python" -m pip install -q --no-cache-dir -r "$SRC/backend/requirements.txt"
fi
# The venv was built under the staging path; point its scripts (bin/uvicorn's
# shebang, activate) at the final path it will live at after the rename.
for f in "$STAGE/$VENV_REL"/bin/* "$STAGE/$VENV_REL/pyvenv.cfg"; do
  if [ -f "$f" ] && [ ! -L "$f" ] && grep -q "$STAGE" "$f" 2>/dev/null; then
    sed "s#${STAGE}#${INSTALL_DIR}#g" "$f" > "$f.tmp" && cat "$f.tmp" > "$f" && rm -f "$f.tmp"
  fi
done

# 3. Carry the configuration over: contents only, root-owned, readable by the service.
if [ -f "$OLD_ENV" ]; then
  NEW_ENV="$STAGE/backend/.env"
  ( umask 077; cat "$OLD_ENV" > "$NEW_ENV" )
  if [ "$IS_ROOT" = 1 ] && id "$SVC_USER" >/dev/null 2>&1; then
    chown "root:$(id -gn "$SVC_USER")" "$NEW_ENV"
    chmod 640 "$NEW_ENV"
  else
    chmod "$( (stat -c %a "$OLD_ENV" 2>/dev/null || stat -f %Lp "$OLD_ENV") )" "$NEW_ENV"
  fi
  echo "    kept backend/.env (configuration)"
fi

# 4. Swap.
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="${INSTALL_DIR}.bak-${STAMP}"
chmod 755 "$STAGE"
mv "$INSTALL_DIR" "$BACKUP"
mv "$STAGE" "$INSTALL_DIR"
STAGE=""
STOPPED=0   # from here on, failures roll back explicitly
echo "==> Swapped in ${NEW_VER}; previous install kept at $BACKUP"

rollback() {
  echo "==> Rolling back to $BACKUP" >&2
  [ "$SKIP_SERVICE" = "0" ] && systemctl stop "$SERVICE" 2>/dev/null || true
  mv "$INSTALL_DIR" "${INSTALL_DIR}.failed-${STAMP}"
  mv "$BACKUP" "$INSTALL_DIR"
  if [ "$SKIP_SERVICE" = "0" ]; then systemctl start "$SERVICE" || true; fi
  echo "    rolled back; the failed version is in ${INSTALL_DIR}.failed-${STAMP}" >&2
}

# Cap rollback copies (each is a full install incl. its venv). KEEP_BACKUPS (default 3).
KEEP_BACKUPS="${KEEP_BACKUPS:-3}"
ls -dt "${INSTALL_DIR}".bak-* 2>/dev/null | tail -n +"$((KEEP_BACKUPS + 1))" | while read -r old; do
  rm -rf "$old"
done

if [ "$SKIP_SERVICE" != "0" ]; then
  echo ""
  echo "Update complete (service not managed): ${OLD_VER}  ->  ${NEW_VER}"
  echo "Start/restart the service yourself. Rollback: mv ${INSTALL_DIR} ${INSTALL_DIR}.failed && mv ${BACKUP} ${INSTALL_DIR}"
  exit 0
fi

# 5. Start and verify.
echo "==> Starting $SERVICE (inline migrations apply on boot)"
healthy() {
  python3 - "$HEALTH_URL" "${ATHORIZE_UPDATE_HEALTH_TIMEOUT:-60}" <<'PY'
import sys, time, urllib.request
deadline = time.time() + float(sys.argv[2])
while time.time() < deadline:
    try:
        with urllib.request.urlopen(sys.argv[1], timeout=3) as r:
            if r.status == 200:
                sys.exit(0)
    except Exception:
        pass
    time.sleep(1)
sys.exit(1)
PY
}
if systemctl start "$SERVICE" && healthy; then
  echo ""
  echo "Update complete: ${OLD_VER}  ->  ${NEW_VER}"
  echo "Rollback if needed:  systemctl stop ${SERVICE} && mv ${INSTALL_DIR} ${INSTALL_DIR}.failed && mv ${BACKUP} ${INSTALL_DIR} && systemctl start ${SERVICE}"
else
  echo "ERROR: ${SERVICE} did not answer ${HEALTH_URL}." >&2
  rollback
  echo "Logs: journalctl -u ${SERVICE} -n 50 --no-pager" >&2
  exit 1
fi
