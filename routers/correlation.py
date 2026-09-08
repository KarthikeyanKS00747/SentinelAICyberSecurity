"""Correlation analysis endpoints - Phase 11.

Provides:
  GET /correlation            - IPs showing multi-stage activity, by score.
  GET /api/correlation/{ip}   - Inline note for one IP, loaded lazily by HTMX
                                on the alerts page.

Read-only: this scores existing alerts and never changes detection.
"""

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import User
from routers.auth import get_current_user
from utils.correlation import compute_correlation, correlated_ips

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Correlation"])
templates = Jinja2Templates(directory="templates")


def _tpl(name: str, request: Request, **ctx):
    """Compatibility wrapper for Starlette >=1.x TemplateResponse."""
    return templates.TemplateResponse(request=request, name=name, context=ctx)


# -- GET /correlation ------------------------------------------------
@router.get("/correlation", response_class=HTMLResponse)
async def correlation_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> HTMLResponse:
    """Rank source IPs that triggered more than one attack type."""
    results = await correlated_ips(db)
    return _tpl(
        "correlation.html",
        request,
        results=results,
        current_user=current_user,
    )


# -- GET /api/correlation/{ip} ---------------------------------------
@router.get("/api/correlation/{ip}", response_class=HTMLResponse)
async def correlation_note(
    ip: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> HTMLResponse:
    """Inline multi-stage note for one IP; empty when there is nothing to say."""
    result = await compute_correlation(db, ip)
    if result is None:
        return HTMLResponse(content="")
    return _tpl("partials/correlation_note.html", request, correlation=result)
