"""IP reputation endpoints - Phase 9.

Provides:
  GET /api/abuse/{ip}  - AbuseIPDB reputation for one IP as an HTML fragment,
                         loaded lazily by HTMX so a page render never blocks
                         on the upstream API.

Display only: no blocking or remediation decisions are made here.
"""

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import User
from routers.auth import get_current_user
from utils.abuse_check import get_or_check

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/abuse", tags=["Reputation"])
templates = Jinja2Templates(directory="templates")


def _tpl(name: str, request: Request, **ctx):
    """Compatibility wrapper for Starlette >=1.x TemplateResponse."""
    return templates.TemplateResponse(request=request, name=name, context=ctx)


@router.get("/{ip}", response_class=HTMLResponse)
async def abuse_cell(
    ip: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> HTMLResponse:
    """Resolve one IP's reputation through the expiring cache and render it.

    Always answers 200: a missing key or an upstream failure renders as
    "not checked" rather than an error.
    """
    result = await get_or_check(db, ip)
    return _tpl("partials/abuse_cell.html", request, abuse=result)
