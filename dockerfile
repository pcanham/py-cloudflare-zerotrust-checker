FROM python:3.12-slim

COPY bootstrap/data/Cloudflare_CA.pem /usr/local/share/ca-certificates/Cloudflare_CA.crt

RUN update-ca-certificates \
  && apt-get update \
  && apt-get install -y --no-install-recommends curl \
  && rm -rf /var/lib/apt/lists/* \
  && groupadd --gid 1000 appuser \
  && useradd --uid 1000 --gid appuser --home /home/appuser --shell /bin/bash appuser \
  && mkdir -p /home/appuser /usr/src/app \
  && chown -R appuser:appuser /usr/src/app /home/appuser

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

USER appuser
WORKDIR /usr/src/app

COPY pyproject.toml uv.lock ./

RUN uv sync --frozen --no-dev --no-install-project

COPY . .

EXPOSE 8080
