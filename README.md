# Domain Blacklist Checker

Web application and API for domain reputation audits based on the new 2026 specification.

## Implemented in this workspace

- Cookie-based auth with registration, login, language switch, and owner/admin panel
- Per-user isolation for scan history, proxy pool, watchlist, and webhooks
- FastAPI backend with the target API shape:
  - `POST /api/auth/register`
  - `POST /api/auth/login`
  - `GET /api/auth/me`
  - `GET /api/admin/users`
  - `GET/PUT /api/admin/provider-settings`
  - `POST /api/check`
  - `GET /api/status/{job_id}`
  - `GET /api/status/{job_id}/stream`
  - `GET /api/report/{job_id}?format=json|csv|pdf`
  - `GET /api/history`
  - `POST /api/webhook`
  - `GET/POST/PATCH/DELETE /api/proxies`
  - `GET/POST/PATCH/POST-run/DELETE /api/watchlist`
- Async job runner with progress tracking and bulk-ready concurrent processing
- Domain normalization and bulk input support
- 100+ DNSBL / URIBL / SURBL catalog scaffold
- Email auth checks: SPF, DKIM, DMARC
- Baseline risk score calculation from the technical specification
- Warm glassmorphism frontend redesigned for Domain Blacklist Checker
- Results-first dashboard with compact result cards, expandable details, filters, and inline help tooltips
- JSON / CSV / PDF export
- Proxy pool for outbound HTTP sources with rotation and failure tracking
- Signed webhook delivery for `job.completed` and `job.failed`
- Background watchlist scheduler for periodic re-checks

## Current integration status

- Live now:
  - DNS resolution
  - DNSBL queries
  - SPF / DKIM / DMARC checks
  - report generation and history
  - outbound proxy rotation for HTTP-based integrations
  - SSE progress streaming
  - live VirusTotal, PhishTank, and AbuseIPDB adapters when keys are configured
  - watchlist scheduler with manual run and automatic interval-based checks
- Graceful degradation:
  - Google Safe Browsing works when `GOOGLE_SAFE_BROWSING_API_KEY` is configured
  - Lumen works when `LUMEN_SEARCH_URL` is configured to a compatible JSON endpoint
  - URLhaus can be enabled with its API URL and auth key in the admin panel
  - Talos remains visible in the report, but stays manual until a supported machine-friendly API is available

## Proxy support

The app now supports proxy URLs like:

```text
http://host:port
http://login:password@host:port
https://host:port
socks5://host:port
socks5h://login:password@host:port
```

How it works:

- proxies are managed in the UI and through `/api/proxies`
- external HTTP providers rotate through active proxies
- success/failure counters are stored per proxy
- if all configured proxies fail, the app can optionally fall back to a direct request

Environment flags:

```env
PROXY_ATTEMPTS_PER_REQUEST=3
DIRECT_HTTP_FALLBACK=true
OWNER_LOGIN=
OWNER_PASSWORD=
VIRUSTOTAL_API_KEY=
PHISHTANK_APP_KEY=
PHISHTANK_USER_AGENT=domain-blacklist-checker/1.0
ABUSEIPDB_API_KEY=
URLHAUS_API_URL=https://urlhaus-api.abuse.ch/v1/host/
URLHAUS_AUTH_KEY=
WEBHOOK_SIGNING_SECRET=
WATCH_SCHEDULER_POLL_SECONDS=60
```

Webhook behavior:

- register subscribers through `POST /api/webhook`
- emitted events: `job.completed`, `job.failed`
- when `WEBHOOK_SIGNING_SECRET` is set, the app sends `X-Signature-256` with an HMAC-SHA256 of the raw JSON body

Note:

- DNSBL lookups are DNS-based and do not use HTTP proxies
- proxy rotation currently affects HTTP sources such as Safe Browsing and Lumen-style adapters

## Watchlist

The app includes a basic monitoring layer:

- add domains to `/api/watchlist` or from the UI
- choose intervals from 1 to 168 hours
- scheduler creates periodic check jobs in the background
- each watch item stores the last job id, last risk score, last status, and next run time
- manual trigger is available through `POST /api/watchlist/{id}/run`

## Backend setup

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Copy `backend/.env.example` to `backend/.env` if you need custom settings.

Default database:

```env
DB_URL=sqlite+aiosqlite:///./domain_blacklist_checker.db
```

## Frontend setup

```bash
cd frontend
npm install
npm run build
```

When `frontend/dist` exists, FastAPI serves the built UI automatically.

## Docker

Build and run:

```bash
docker compose up --build -d
```

Compose also starts a Redis container so the deployment layout is already close to a future worker/queue split.

Files included:

- `Dockerfile`
- `docker-compose.yml`
- `.github/workflows/ci.yml`

## Ubuntu 22.04 VPS notes

Included deployment templates:

- `deploy/domain-blacklist-checker.service`
- `deploy/nginx-domain-blacklist-checker.conf`
- `deploy/bootstrap-ubuntu.sh`

Suggested non-Docker rollout:

1. Clone the repo to `/opt/domain-blacklist-checker`.
2. Create `backend/.venv` and install backend dependencies.
3. Build the frontend in `frontend/dist`.
4. Copy the `systemd` file to `/etc/systemd/system/`.
5. Put Nginx in front of Uvicorn.
6. Enable HTTPS with Certbot or your preferred reverse proxy stack.

## Next recommended steps

- wire Redis into a dedicated worker queue if you want larger and more persistent bulk throughput
- add a production-safe URLhaus adapter and decide whether Talos should be scraped, linked, or left manual
- add PDF templating with WeasyPrint or Playwright for richer report layout
