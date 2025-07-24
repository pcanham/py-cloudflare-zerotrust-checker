FROM python:3.12-slim

# Install system deps & Poetry
RUN apt-get update \
  && apt-get install -y curl build-essential \
  && rm -rf /var/lib/apt/lists/* \
  && groupadd --gid 1000 appuser \
  && useradd --uid 1000 --gid appuser --home /home/appuser --shell /bin/bash appuser \
  && mkdir -p /home/appuser \
  && mkdir -p /usr/src/app \
  && chown -R appuser:appuser /usr/src/app \
  && chown -R appuser:appuser /home/appuser

USER appuser
WORKDIR /usr/src/app

# Copy only lockfiles for cache
COPY pyproject.toml poetry.lock ./

# Disable venvs, skip installing your root package:
RUN curl -sSL https://install.python-poetry.org | python3 - \
  && /home/appuser/.local/bin/poetry config virtualenvs.create false \
  && /home/appuser/.local/bin/poetry install --only main --no-root --no-interaction --no-ansi

# Copy your app code
COPY . .

EXPOSE 5000