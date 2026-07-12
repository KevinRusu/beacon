import os
import logging
from urllib.parse import urlparse
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from schemas import AnalyzeRequest, AnalyzeResponse
from auth import verify_origin, allowed_origins
from exceptions import ProviderConfigError
from services.analyze_service import get_provider

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# –– Startup validation ––
# Fail fast so misconfigurations surface immediately, not on the first request.

def _validate_config() -> None:
    use_mock = os.getenv("USE_MOCK", "true").lower() == "true"

    if not allowed_origins():
        if use_mock:
            logger.warning(
                "ORIGIN CHECK DISABLED — ALLOWED_EXTENSION_ORIGINS not set (mock/dev mode only)"
            )
        else:
            logger.warning(
                "ALLOWED_EXTENSION_ORIGINS is not set with USE_MOCK=false: "
                "the API will accept requests from any origin. Set it to the "
                "extension origin (chrome-extension://<id>) before deploying."
            )

    # Eagerly initialise the provider so a missing GEMINI_API_KEY fails here
    # with a clear message rather than producing a 503 on the first request.
    get_provider()

_validate_config()

# –– App setup ––
# Rate limits are the primary abuse control (there is no client secret — see
# auth.py). Default allows a handful of re-checks per minute while the daily
# cap bounds worst-case Gemini spend per client IP. In production the server
# must run behind uvicorn --proxy-headers with FORWARDED_ALLOW_IPS set, so
# get_remote_address sees the real client IP instead of the proxy's.

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="Beacon API")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

_cors_origins = allowed_origins() or ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_methods=["POST"],
    allow_headers=["Content-Type"],
)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.post("/v1/analyze", response_model=AnalyzeResponse)
@limiter.limit(os.getenv("RATE_LIMIT", "5/minute;60/day"))
async def analyze(
    request: Request,
    body: AnalyzeRequest,
    _: None = Depends(verify_origin),
) -> AnalyzeResponse:
    # request: Request is required by slowapi — do not remove.
    domain = urlparse(body.url).netloc or body.url
    provider = get_provider()
    try:
        result = await provider.analyze(body)
        logger.info("verdict=%s safety_score=%d", result.label, result.safety_score)
        logger.debug("domain=%s verdict=%s safety_score=%d", domain, result.label, result.safety_score)
        return result
    except ProviderConfigError as e:
        logger.error("provider not configured: %s", e)
        raise HTTPException(status_code=503, detail="LLM provider not configured. Set USE_MOCK=true.")
    except Exception as e:
        # The exception detail comes from the provider client, never from page
        # content, so logging it does not leak user browsing data.
        logger.error("provider error: %s: %s", type(e).__name__, e)
        raise HTTPException(status_code=503, detail="AI provider unavailable. Try again later.")