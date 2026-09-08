"""Health and local-Ollama connectivity endpoints."""

import logging

import httpx
from fastapi import APIRouter, Depends, HTTPException, status

from config import settings
from models import User
from routers.auth import get_current_user

router = APIRouter(tags=["Health"])
logger = logging.getLogger(__name__)
OLLAMA_GENERATE_URL = "http://localhost:11434/api/generate"


@router.get("/api/health")
async def health_check() -> dict[str, str]:
    """Return a minimal liveness response."""
    return {"status": "ok"}


@router.post("/api/test-ollama")
async def test_ollama(current_user: User = Depends(get_current_user)) -> dict[str, str]:
    """Confirm the configured local Ollama model can generate a response."""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                OLLAMA_GENERATE_URL,
                json={
                    "model": settings.OLLAMA_MODEL,
                    "prompt": "Reply with the single word: connected",
                    "stream": False,
                },
            )
            response.raise_for_status()
            payload = response.json()
    except httpx.HTTPError:
        logger.warning("Local Ollama connectivity test failed", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Local Ollama service is unavailable.",
        ) from None

    return {
        "status": "ok",
        "model": settings.OLLAMA_MODEL,
        "response": str(payload.get("response", "")).strip(),
    }
