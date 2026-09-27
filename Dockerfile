FROM node:26.9.0-bookworm-slim AS frontend
WORKDIR /ui
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM ghcr.io/astral-sh/uv:0.12.17 AS uv
FROM python:3.13.15-slim-bookworm AS runtime
COPY --from=uv /uv /uvx /bin/
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy PATH="/app/.venv/bin:$PATH" PYTHONDONTWRITEBYTECODE=1
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
COPY evaluation/configs ./evaluation/configs
RUN uv sync --frozen --no-dev && useradd --uid 10001 --create-home hestia && mkdir -p data/raw data/manifests artifacts && chown -R hestia:hestia artifacts
COPY --from=frontend /ui/dist ./frontend/dist
USER hestia
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')"
CMD ["uvicorn", "hestia.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
