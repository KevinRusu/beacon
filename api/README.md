# Beacon API

FastAPI backend for Tier 2 LLM-based phishing detection.

## Setup

```bash
cp .env.example .env   # fill in your values
pip3 install -r requirements.txt
python3 -m uvicorn main:app --port 3000
```

Run the tests with:

```bash
pip3 install -r requirements-dev.txt
python3 -m pytest tests/
```

## Score convention

Every score in Beacon is a **safety score**: an integer 0–10 where **10 = clearly
safe** and **0 = clearly a scam** (≥7 safe, 4–6 uncertain, ≤3 scam — the same
thresholds as the extension's `toVerdict()`). This applies to the
`heuristic_score` request field and the `safety_score` response field alike.
Nothing is ever inverted on the wire.

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `USE_MOCK` | No (default: `true`) | Skip Gemini and use a deterministic mock. No API key needed. |
| `GEMINI_API_KEY` | Only if `USE_MOCK=false` | Gemini API key for live LLM analysis. Server-side only — never ships to clients. |
| `GEMINI_MODEL` | No (default: `gemini-2.5-flash-lite`) | Gemini model name. Override to migrate to a newer model without a code change. |
| `ALLOWED_EXTENSION_ORIGINS` | Recommended in production | Comma-separated `Origin` allowlist, e.g. `chrome-extension://<id>`. Also used as the CORS allowlist. Empty = accept all origins (dev; a warning is logged). |
| `RATE_LIMIT` | No (default: `5/minute;60/day`) | Per-IP limits, `;`-separated (e.g. `10/minute;100/day`). |
| `FORWARDED_ALLOW_IPS` | Behind a proxy | IP/CIDR of the trusted reverse proxy, so rate limiting sees real client IPs. |

> **Tip:** Keep `USE_MOCK=true` while developing. Switch to `USE_MOCK=false` only when you need a real Gemini response.

## Endpoints

- `POST /v1/analyze` — Tier 2 analysis. Request/response schemas in `schemas.py`.
- `GET /health` — liveness probe, no auth, no rate limit.

> **Tip:** Keep `USE_MOCK=true` while developing. Switch to `USE_MOCK=false` only when you need a real Gemini response.
