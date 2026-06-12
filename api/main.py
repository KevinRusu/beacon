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
from auth import verify_api_key
from exceptions import ProviderConfigError
from services.analyze_service import get_provider

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# –– Startup validation ––
# Fail fast so misconfigurations surface immediately, not on the first request.

def _validate_config() -> None:
    use_mock = os.getenv("USE_MOCK", "true").lower() == "true"
    has_key = bool(os.getenv("BEACON_API_KEY", ""))

    if not use_mock and not has_key:
        raise RuntimeError(
            "BEACON_API_KEY must be set when USE_MOCK=false. "
            "Set it in api/.env or the environment."
        )
    if use_mock and not has_key:
        logger.warning("AUTH DISABLED — BEACON_API_KEY not set (mock/dev mode only)")

    # Eagerly initialise the provider so a missing GEMINI_API_KEY fails here
    # with a clear message rather than producing a 503 on the first request.
    get_provider()

_validate_config()

# –– App setup ––

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="Beacon API")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

_allowed_origins = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "*").split(",")]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_methods=["POST"],
    allow_headers=["Content-Type", "X-Beacon-Key"],
)


@app.post("/v1/analyze", response_model=AnalyzeResponse)
@limiter.limit(os.getenv("RATE_LIMIT", "1/minute"))
async def analyze(
    request: Request,
    body: AnalyzeRequest,
    _: None = Depends(verify_api_key),
) -> AnalyzeResponse:
    # request: Request is required by slowapi — do not remove.
    domain = urlparse(body.url).netloc or body.url
    provider = get_provider()
    try:
        result = await provider.analyze(body)
        logger.info("verdict=%s score=%d", result.label, result.risk_score)
        logger.debug("domain=%s verdict=%s score=%d", domain, result.label, result.risk_score)
        return result
    except ProviderConfigError as e:
        logger.error("provider not configured: %s", e)
        raise HTTPException(status_code=503, detail="LLM provider not configured. Set USE_MOCK=true.")
    except Exception as e:
        logger.debug("provider error domain=%s: %s", domain, type(e).__name__)
        logger.error("provider error: %s", type(e).__name__)
        raise HTTPException(status_code=503, detail="AI provider unavailable. Try again later.")
