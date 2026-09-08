"""IP geolocation endpoints - Phase 8.

Provides:
  GET /api/geo/{ip}  - Geolocation for one IP as an HTML fragment, loaded
                       lazily by HTMX so a page render never blocks on the
                       upstream API and the rate limit is respected.
"""

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import User
from routers.auth import get_current_user
from utils.geolocation import get_or_lookup

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/geo", tags=["Geolocation"])
templates = Jinja2Templates(directory="templates")


def _tpl(name: str, request: Request, **ctx):
    """Compatibility wrapper for Starlette >=1.x TemplateResponse."""
    return templates.TemplateResponse(request=request, name=name, context=ctx)


@router.get("/{ip}", response_class=HTMLResponse)
async def geo_cell(
    ip: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> HTMLResponse:
    """Resolve one IP through the read-through cache and render the badge.

    Always answers 200: an unresolvable or failed lookup renders as "Unknown"
    rather than an error, so a geolocation outage cannot break the page.
    """
    result = await get_or_lookup(db, ip)
    return _tpl("partials/geo_cell.html", request, geo=result)
