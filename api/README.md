# Beacon API

FastAPI backend for Tier 2 LLM-based phishing detection.

## Setup

```bash
cp .env.example .env   # fill in your values
pip3 install -r requirements.txt
python3 -m uvicorn main:app --port 3000
```

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `USE_MOCK` | No (default: `true`) | Skip Gemini and use a deterministic mock. No API key needed. |
| `GEMINI_API_KEY` | Only if `USE_MOCK=false` | Gemini API key for live LLM analysis. |
| `GEMINI_MODEL` | No (default: `gemini-2.5-flash-lite`) | Gemini model name. Override to migrate to a newer model without a code change. |
| `BEACON_API_KEY` | **Required when `USE_MOCK=false`** | Secret shared with the extension. Server refuses to start without it in production mode. Leave empty in mock/dev mode (a warning is logged). |
| `RATE_LIMIT` | No (default: `1/minute`) | Max requests per IP per time window (e.g. `10/minute`, `100/hour`). |
| `ALLOWED_ORIGINS` | No (default: `*`) | Comma-separated list of allowed CORS origins. Set to your extension's `chrome-extension://<id>` once published to the Chrome Web Store. |

> **Tip:** Keep `USE_MOCK=true` while developing. Switch to `USE_MOCK=false` only when you need a real Gemini response.
