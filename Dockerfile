# syntax=docker/dockerfile:1.7
#
# ---------- Security Measures ----------
# - Multi-stage build: build tools excluded from runtime image
# - Dependency install uses uv.lock with uv --locked, not a hashless export
# - Non-root user (interlock, uid 1000) with /bin/false shell
# - No setuid/setgid binaries in runtime image (slim base)
# - PYTHONUNBUFFERED=1 prevents output buffering (helps log visibility)
# - No secrets or tracked config.yaml baked into image; use env vars or mounted secrets
# - For production: mount root filesystem read-only (docker run --read-only)
#
# Release builds should pass PYTHON_BASE_IMAGE as a digest-pinned reference, e.g.
# docker build --build-arg PYTHON_BASE_IMAGE=python:3.12-slim@sha256:<digest> .

# ---------- build stage ----------
ARG PYTHON_BASE_IMAGE=python:3.12-slim
FROM ${PYTHON_BASE_IMAGE} AS build

ARG UV_VERSION=0.9.21
ARG INTERLOCK_EXTRA=production

WORKDIR /app

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc g++ libpq-dev unixodbc-dev && \
    rm -rf /var/lib/apt/lists/* && \
    pip install --no-cache-dir "uv==${UV_VERSION}"

COPY pyproject.toml ./
COPY uv.lock ./
COPY README.md ./

RUN uv sync --locked --no-dev --extra "${INTERLOCK_EXTRA}" --no-install-project

COPY src/ ./src/
COPY migrations/ ./migrations/

RUN uv sync --locked --no-dev --extra "${INTERLOCK_EXTRA}"

# ---------- runtime stage ----------
FROM ${PYTHON_BASE_IMAGE}

WORKDIR /app

# Upgrade first: the base tag is rebuilt upstream on its own schedule, so a
# published Debian security fix can be missing from it for days.
RUN apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get install -y --no-install-recommends libpq5 ca-certificates curl libgssapi-krb5-2 && \
    . /etc/os-release && \
    test "$ID" = debian && \
    case "$VERSION_ID" in 11|12|13) ;; *) exit 1 ;; esac && \
    case "$(dpkg --print-architecture)" in amd64|arm64) ;; *) exit 1 ;; esac && \
    curl --fail --silent --show-error --location \
      "https://packages.microsoft.com/config/debian/${VERSION_ID}/packages-microsoft-prod.deb" \
      --output /tmp/packages-microsoft-prod.deb && \
    dpkg -i /tmp/packages-microsoft-prod.deb && \
    apt-get update && \
    ACCEPT_EULA=Y apt-get install -y --no-install-recommends msodbcsql18 && \
    apt-get purge -y --auto-remove curl && \
    rm -f /tmp/packages-microsoft-prod.deb && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --gid 1000 interlock && \
    useradd --uid 1000 --gid interlock --shell /bin/false --create-home interlock && \
    mkdir -p /tmp/interlock-hf-cache /var/lib/interlock/audit-spool && \
    chown -R interlock:interlock /tmp/interlock-hf-cache /home/interlock /var/lib/interlock

COPY --from=build /app/.venv /app/.venv
COPY --from=build /app/src /app/src
COPY --from=build /app/migrations /app/migrations

ENV VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1 \
    HOME=/home/interlock \
    HF_HOME=/tmp/interlock-hf-cache

USER interlock

# Default entrypoint: gateway. Override with admin or worker via command.
# Usage:
#   docker run <image>                     -> runs gateway
#   docker run <image> admin               -> runs admin
#   docker run <image> worker              -> runs worker
ENTRYPOINT ["python", "-m"]
CMD ["interlock.gateway"]
