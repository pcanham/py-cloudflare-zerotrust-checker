# Cloudflare Zero Trust IP Checker

A web application that checks whether an IP address appears in Cloudflare Zero Trust Gateway lists or firewall policies.

Given an IP, it will tell you:
- Which **Gateway lists** contain the IP (or a CIDR that covers it)
- Which **Gateway policies** reference the IP directly or via CIDR
- Which **policies** reference a list that matched the IP

---

## How it works

1. The web UI accepts an IP address (and optionally a port, if the port feature flag is enabled)
2. Flask queues an async Celery task and returns a `task_id`
3. The frontend polls `/status/<task_id>` every second, showing a progress bar
4. The Celery worker queries the Cloudflare API concurrently using a thread pool:
   - Fetches all Gateway lists, filters to IP-type lists, checks each for a match
   - Fetches all Gateway policies, scans `traffic` expressions for direct IP matches, CIDR matches, and list ID references
5. Results are returned and rendered as collapsible sections in the UI

Private RFC1918 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) are excluded from results.

---

## Requirements

- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/)
- [uv](https://docs.astral.sh/uv/) (for local development)
- [Task](https://taskfile.dev) (optional, for the task runner)

---

## Setup

### 1. Configure environment

Copy the example env file and fill in your Cloudflare credentials:

```bash
cp .env.example .env
```

| Variable | Description |
|---|---|
| `CLOUDFLARE_API_TOKEN` | Cloudflare API token with Zero Trust read access |
| `CLOUDFLARE_ACCOUNT_ID` | Your Cloudflare account ID |
| `FLASK_SECRET_KEY` | Random secret used to sign session cookies |
| `CELERY_BROKER_URL` | Redis URL, e.g. `redis://redis:6379/0` |
| `CELERY_RESULT_BACKEND` | Redis URL, e.g. `redis://redis:6379/0` |

### 2. Install dependencies (local development)

```bash
task deps:install
# or: uv sync
```

---

## Running with Docker (recommended)

```bash
task docker:up
# or: docker compose up --build
```

This starts three services: `redis`, `web` (Flask on port 8080), and `worker` (Celery).

Open [http://localhost:8080](http://localhost:8080) in your browser.

---

## Running locally (without Docker)

Start Redis, the Flask dev server, and the Celery worker in separate terminals:

```bash
task dev:redis
task dev:web
task dev:worker
```

---

## Taskfile reference

Run `task` with no arguments to list all available tasks.

### `deps` — dependency management

| Task | Description |
|---|---|
| `task deps:install` | Install all dependencies from `uv.lock` |
| `task deps:lock` | Regenerate `uv.lock` |
| `task deps:update` | Upgrade all dependencies to latest allowed versions |

### `docker` — container management

| Task | Description |
|---|---|
| `task docker:up` | Build and start all services |
| `task docker:up-detached` | Build and start all services in the background |
| `task docker:down` | Stop and remove all services |
| `task docker:build` | Build images without starting |
| `task docker:logs` | Tail logs from all services |
| `task docker:logs-web` | Tail logs from the web service |
| `task docker:logs-worker` | Tail logs from the worker service |

### `dev` — local development

| Task | Description |
|---|---|
| `task dev:web` | Run Flask dev server on port 8080 |
| `task dev:worker` | Run Celery worker |
| `task dev:redis` | Start a standalone Redis container |

### `code` — linting and formatting

| Task | Description |
|---|---|
| `task code:lint` | Lint with ruff |
| `task code:lint-fix` | Lint and auto-fix with ruff |
| `task code:format` | Format with ruff |
| `task code:format-check` | Check formatting without writing changes |
| `task code:check` | Run lint and format check together |

---

## Feature flags

Feature flags are defined in [`features_config.py`](features_config.py):

| Flag | Default | Description |
|---|---|---|
| `port` | `False` | Enables a port input field and checks whether the port appears in any policy traffic expression |

Set a flag to `True` to enable it. When `port` is enabled the UI switches to [`index_ports.html`](templates/index_ports.html) and the checker returns an additional `port_list` result section.

---

## Architecture

```
Browser
  │  POST /check (ip, port?)
  ▼
Flask (app.py)
  │  celery.apply_async → task_id
  ▼
Redis (broker + result backend)
  │
  ▼
Celery worker (tasks.py)
  ├─ scan_cloudflare_lists()    — ThreadPoolExecutor, parallel list-item fetches
  └─ scan_cloudflare_policies() — regex scan of traffic expressions
  │
  ▼
Cloudflare Gateway API
```

The HTTP client uses a persistent `requests.Session` with automatic retries (5 attempts, exponential backoff) on 502/503/504 responses. Celery tasks have a 600 s hard time limit and a 540 s soft limit.

---

## Project structure

```
.
├── app.py                  Flask application and routes
├── tasks.py                Celery task and Cloudflare API logic
├── features_config.py      Feature flag definitions
├── celeryconfig.py         Celery broker/backend configuration
├── pyproject.toml          Project metadata and dependencies (uv)
├── uv.lock                 Locked dependency versions
├── dockerfile              Container image build (uv, non-root user)
├── docker-compose.yml      Multi-service orchestration
├── Taskfile.yml            Task runner entry point
├── taskfiles/
│   ├── Taskfile.deps.yml
│   ├── Taskfile.docker.yml
│   ├── Taskfile.dev.yml
│   └── Taskfile.code.yml
└── templates/
    ├── base.html
    ├── index.html          Standard UI (IP only)
    └── index_ports.html    UI with port input (port feature flag)
```
