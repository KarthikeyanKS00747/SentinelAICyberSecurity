"""MITRE ATT&CK labelling endpoints - Phase 12.

Provides:
  GET /api/alerts/{alert_id}/mitre - Technique badge for one alert, loaded
                                     lazily by HTMX on display.

Pure labelling: the mapping is static and nothing here changes detection.
"""

import logging

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import Alert, User
from routers.auth import get_current_user
from utils.mitre_mapping import techniques_for

logger = logging.getLogger(__name__)

router = APIRouter(tags=["MITRE"])
templates = Jinja2Templates(directory="templates")


def _tpl(name: str, request: Request, **ctx):
    """Compatibility wrapper for Starlette >=1.x TemplateResponse."""
    return templates.TemplateResponse(request=request, name=name, context=ctx)


@router.get("/api/alerts/{alert_id}/mitre", response_class=HTMLResponse)
async def mitre_badge(
    alert_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> HTMLResponse:
    """ATT&CK technique badge(s) for one alert's rule."""
    alert = await db.get(Alert, alert_id)
    if alert is None:
        return HTMLResponse(content="", status_code=status.HTTP_404_NOT_FOUND)
    return _tpl(
        "partials/mitre_badge.html",
        request,
        techniques=techniques_for(alert.threat_name),
    )
