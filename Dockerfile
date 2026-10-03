# syntax=docker/dockerfile:1
#
# One image for every Bouncer service (gateway, simulated upstream, demo MCP server, feed server,
# CPU judge) plus a test target. Built by `docker compose build`; see docs/RUNNING.md.
#
#   target runtime  production dependencies only, runs as an unprivileged user
#   target test     runtime + dev dependencies (pytest), runs `make test` equivalent
#
# The lockfile is universal: Linux wheels exist for every dependency, and mlx / mlx-lm /
# transformers are marked darwin-arm64 only, so they are skipped here. The Clef MLX judge therefore
# runs natively on a Mac (`make judge`); in containers the judge uses the ollama-guard backend.

ARG PYTHON_IMAGE=python:3.12-slim
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.8.9

FROM ${UV_IMAGE} AS uv

FROM ${PYTHON_IMAGE} AS base
COPY --from=uv /uv /uvx /usr/local/bin/
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app
WORKDIR /app
COPY pyproject.toml uv.lock .python-version ./

FROM base AS deps-runtime
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

FROM base AS deps-test
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project

FROM deps-runtime AS runtime
COPY . .
RUN useradd --system --uid 10001 --user-group --home-dir /app --shell /usr/sbin/nologin bouncer \
 && mkdir -p /app/data /app/models /tmp/bouncer-policy \
 && chown -R bouncer:bouncer /app/data /tmp/bouncer-policy
USER bouncer
EXPOSE 8700 8701 8702 8703 8704
# Default command: the gateway. docker-compose.yml sets the command per service.
CMD ["python", "docker/gateway_entrypoint.py"]

FROM deps-test AS test
COPY . .
RUN mkdir -p /app/reports/tests /app/data
ENV BOUNCER_WATCH=0
CMD ["sh", "-c", "pytest -m 'not live' --junitxml=reports/tests/junit.xml --html=reports/tests/report.html --self-contained-html; rc=$?; cat reports/tests/summary.md 2>/dev/null; exit $rc"]
