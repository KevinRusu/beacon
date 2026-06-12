import os
import secrets
from typing import Optional
from fastapi import Header, HTTPException


async def verify_api_key(x_beacon_key: Optional[str] = Header(None)) -> None:
    expected = os.getenv("BEACON_API_KEY", "")
    if expected and not secrets.compare_digest(x_beacon_key or "", expected):
        raise HTTPException(status_code=401, detail="Unauthorized")
