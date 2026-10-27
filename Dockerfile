# syntax=docker/dockerfile:1
#
# Athorize — single-container image (API + web UI in one process).
#
#   docker compose up -d            # blank instance -> Setup screen
#   docker compose -f docker-compose.demo.yml up -d   # demo data, admin/admin
#
# See docs/INSTALL.md §"Docker install".

# ---------------------------------------------------------------------------
# Stage 1 — build the web UI. The output is static JS/CSS, so it is built once
# on the build host's native platform even for multi-arch images.
# ---------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM node:20-slim AS ui
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---------------------------------------------------------------------------
# Stage 2 — runtime: Python + backend + frameworks + pre-built UI. No Node,
# no compilers, no tests, no .git.
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="Athorize" \
      org.opencontainers.image.description="Self-hosted multi-framework compliance platform" \
      org.opencontainers.image.licenses="AGPL-3.0-only"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    ATHORIZE_SERVE_FRONTEND=1 \
    DATA_DIR=/data \
    EVIDENCE_DIR=/data/evidence \
    BACKUP_DIR=/data/backups \
    PORT=8001

WORKDIR /app

COPY backend/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt

# Unprivileged runtime user. /data is created (and owned) here so a fresh
# named volume inherits the right ownership on first mount.
RUN groupadd --system --gid 10001 athorize \
 && useradd --system --uid 10001 --gid athorize --home-dir /data --shell /usr/sbin/nologin athorize \
 && mkdir -p /data/evidence /data/backups \
 && chown -R athorize:athorize /data && chmod 700 /data

# Application files (root-owned, read-only to the app user).
COPY LICENSE NOTICE /app/
COPY backend/ /app/backend/
COPY frameworks/ /app/frameworks/
COPY --from=ui /src/frontend/dist/ /app/frontend/dist/
COPY docker/entrypoint.sh /usr/local/bin/athorize-entrypoint
# Strip CRLF in case the source was checked out on Windows with autocrlf.
RUN sed -i 's/\r$//' /usr/local/bin/athorize-entrypoint && chmod 755 /usr/local/bin/athorize-entrypoint

USER athorize
VOLUME ["/data"]
# `docker compose exec athorize python -m services.backup ...` runs from here.
WORKDIR /app/backend
EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD ["python", "-c", "import os,sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/api/health' % os.environ.get('PORT','8001'), timeout=4).status == 200 else 1)"]

ENTRYPOINT ["athorize-entrypoint"]
