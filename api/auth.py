import os
from typing import Optional
from fastapi import Header, HTTPException

def allowed_origins() -> list[str]:
    raw = os.getenv("ALLOWED_EXTENSION_ORIGINS", "")
    return [o.strip() for o in raw.split(",") if o.strip()]

async def verify_origin(origin: Optional[str] = Header(None)) -> None:
    allowed = allowed_origins()
    if not allowed:
        # Dev mode: no allowlist configured, accept everything.
        # main.py logs a warning about this at startup.
        return
    if origin not in allowed:
        raise HTTPException(status_code=401, detail="Unauthorized")
