"""Application settings router - Phase 7.

Provides:
  GET  /settings              - Settings page, grouped by area.
  POST /api/settings/{key}    - Update one setting; returns the refreshed
                                row as an HTML fragment for an HTMX swap.
"""

import logging

from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import AppSetting, User
from routers.auth import get_current_user, require_csrf
from utils.settings_service import update_setting

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Settings"])
templates = Jinja2Templates(directory="templates")

# Settings are grouped in the UI by the prefix of their key.
SETTING_GROUPS = (
    ("detection", "Detection Thresholds", "Tune when the rule engine raises an alert.", "fa-shield-halved"),
    ("ollama", "AI Configuration", "Local Ollama behaviour for threat explanations.", "fa-robot"),
)
OTHER_GROUP = ("General", "Everything else.", "fa-sliders")


def _tpl(name: str, request: Request, status_code: int = 200, **ctx):
    """Compatibility wrapper for Starlette >=1.x TemplateResponse."""
    return templates.TemplateResponse(request=request, name=name, context=ctx, status_code=status_code)


def _group_settings(settings: list[AppSetting]) -> list[dict]:
    """Bucket settings by key prefix, preserving SETTING_GROUPS order."""
    grouped: list[dict] = []
    claimed: set[int] = set()

    for prefix, title, blurb, icon in SETTING_GROUPS:
        members = [s for s in settings if s.key.startswith(f"{prefix}.")]
        claimed.update(id(s) for s in members)
        if members:
            grouped.append({"title": title, "blurb": blurb, "icon": icon, "settings": members})

    leftovers = [s for s in settings if id(s) not in claimed]
    if leftovers:
        title, blurb, icon = OTHER_GROUP
        grouped.append({"title": title, "blurb": blurb, "icon": icon, "settings": leftovers})
    return grouped


# -- GET /settings ---------------------------------------------------
@router.get("/settings", response_class=HTMLResponse)
async def settings_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> HTMLResponse:
    """Render every configured setting, grouped by area."""
    settings = list((await db.scalars(select(AppSetting).order_by(AppSetting.key))).all())
    return _tpl(
        "settings.html",
        request,
        groups=_group_settings(settings),
        total_settings=len(settings),
        current_user=current_user,
    )


# -- POST /api/settings/{key} ----------------------------------------
@router.post("/api/settings/{key}", response_class=HTMLResponse)
async def update_setting_endpoint(
    key: str,
    request: Request,
    value: str = Form(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _csrf: None = Depends(require_csrf),
) -> HTMLResponse:
    """Validate and store one setting, returning the refreshed row."""
    try:
        setting = await update_setting(db, key, value)
    except LookupError:
        return HTMLResponse(
            content='<p class="text-red-400 text-xs p-3">Setting not found.</p>',
            status_code=status.HTTP_404_NOT_FOUND,
        )
    except ValueError as exc:
        # Type mismatch: re-render the row with the message and the rejected
        # input, so the operator can correct it without losing what they typed.
        current = await db.scalar(select(AppSetting).where(AppSetting.key == key))
        logger.info("Rejected %s=%r: %s", key, value, exc)
        return _tpl(
            "partials/setting_row.html",
            request,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            setting=current,
            error=str(exc),
            submitted=value,
        )

    return _tpl("partials/setting_row.html", request, setting=setting, saved=True)
