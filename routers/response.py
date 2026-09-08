"""Manual response actions - Phase 10.

Provides:
  GET  /blocked-ips                  - Audit page of every block ever applied.
  GET  /api/alerts/{id}/block-button - Current block state for one alert, as an
                                       HTML fragment loaded lazily by HTMX.
  POST /api/alerts/{id}/block        - Block the alert's source IP.
  POST /api/alerts/{id}/unblock      - Deactivate an existing block.

Blocking is always an explicit analyst action: nothing here blocks anything
automatically from a severity or reputation score. Unblocking flips
``is_active`` instead of deleting, so the audit trail survives.
"""

import ipaddress
import logging

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import Alert, BlockedIP, User, utc_now
from routers.auth import get_current_user, require_admin, require_csrf
from utils.audit import ACTION_IP_BLOCK, ACTION_IP_UNBLOCK, record_audit

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Response"])
templates = Jinja2Templates(directory="templates")


def _tpl(name: str, request: Request, status_code: int = 200, **ctx):
    """Compatibility wrapper for Starlette >=1.x TemplateResponse."""
    return templates.TemplateResponse(request=request, name=name, context=ctx, status_code=status_code)


def primary_ip(source_ip: str | None) -> str | None:
    """Return the first usable address from an alert's source_ip.

    Rule 1 alerts written before the String(45) fix hold a comma-joined list,
    so take the first entry the same way the geolocation badges do.
    """
    first = (source_ip or "").split(",")[0].strip()
    if not first:
        return None
    try:
        ipaddress.ip_address(first)
    except ValueError:
        return None
    return first


async def _active_block(db: AsyncSession, ip: str) -> BlockedIP | None:
    return await db.scalar(
        select(BlockedIP).where(BlockedIP.ip == ip, BlockedIP.is_active.is_(True))
    )


async def _render_button(
    request: Request, db: AsyncSession, alert: Alert, current_user: User
) -> HTMLResponse:
    """Render the block/unblock control plus an out-of-band row badge.

    ``current_user`` is passed through so the fragment can omit the controls
    entirely for an analyst, rather than rendering a button whose POST would
    only come back 403.
    """
    ip = primary_ip(alert.source_ip)
    block = await _active_block(db, ip) if ip else None
    return _tpl(
        "partials/block_button.html",
        request,
        alert=alert,
        ip=ip,
        block=block,
        current_user=current_user,
    )


# -- GET /api/alerts/{alert_id}/block-button -------------------------
@router.get("/api/alerts/{alert_id}/block-button", response_class=HTMLResponse)
async def block_button(
    alert_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> HTMLResponse:
    """Current block state for one alert, loaded lazily on display."""
    alert = await db.get(Alert, alert_id)
    if alert is None:
        return HTMLResponse(content="", status_code=status.HTTP_404_NOT_FOUND)
    return await _render_button(request, db, alert, current_user)


# -- POST /api/alerts/{alert_id}/block -------------------------------
@router.post("/api/alerts/{alert_id}/block", response_class=HTMLResponse)
async def block_ip(
    alert_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
) -> HTMLResponse:
    """Block this alert's source IP, recording who did it and when."""
    alert = await db.get(Alert, alert_id)
    if alert is None:
        return HTMLResponse(
            content='<span class="text-red-400 text-[10px]">Alert not found.</span>',
            status_code=status.HTTP_404_NOT_FOUND,
        )

    ip = primary_ip(alert.source_ip)
    if ip is None:
        return HTMLResponse(
            content='<span class="text-amber-400 text-[10px]">No usable source IP.</span>',
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    existing = await db.scalar(select(BlockedIP).where(BlockedIP.ip == ip))
    reason = f"{alert.threat_name} (alert #{alert.id})"
    if existing is None:
        db.add(BlockedIP(ip=ip, blocked_by=current_user.id, reason=reason, is_active=True))
    else:
        # ip is unique: re-blocking reactivates the existing record.
        existing.is_active = True
        existing.blocked_by = current_user.id
        existing.blocked_at = utc_now()
        existing.unblocked_at = None
        existing.reason = reason
    record_audit(db, current_user, ACTION_IP_BLOCK, target=ip, details=reason)
    await db.commit()
    logger.info("User #%d blocked %s via alert #%d", current_user.id, ip, alert.id)

    return await _render_button(request, db, alert, current_user)


# -- POST /api/alerts/{alert_id}/unblock -----------------------------
@router.post("/api/alerts/{alert_id}/unblock", response_class=HTMLResponse)
async def unblock_ip(
    alert_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
) -> HTMLResponse:
    """Deactivate the block on this alert's source IP, keeping the record."""
    alert = await db.get(Alert, alert_id)
    if alert is None:
        return HTMLResponse(
            content='<span class="text-red-400 text-[10px]">Alert not found.</span>',
            status_code=status.HTTP_404_NOT_FOUND,
        )

    ip = primary_ip(alert.source_ip)
    block = await _active_block(db, ip) if ip else None
    if block is not None:
        block.is_active = False
        block.unblocked_at = utc_now()
        record_audit(
            db, current_user, ACTION_IP_UNBLOCK,
            target=ip, details=f"block lifted via alert #{alert.id}",
        )
        await db.commit()
        logger.info("User #%d unblocked %s via alert #%d", current_user.id, ip, alert.id)

    return await _render_button(request, db, alert, current_user)


# -- GET /blocked-ips ------------------------------------------------
@router.get("/blocked-ips", response_class=HTMLResponse)
async def blocked_ips_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> HTMLResponse:
    """Audit view of every block, active first, newest first."""
    blocks = list(
        (
            await db.scalars(
                select(BlockedIP).order_by(BlockedIP.is_active.desc(), BlockedIP.blocked_at.desc())
            )
        ).all()
    )
    usernames: dict[int, str] = {}
    user_ids = {b.blocked_by for b in blocks if b.blocked_by is not None}
    if user_ids:
        for user in (await db.scalars(select(User).where(User.id.in_(user_ids)))).all():
            usernames[user.id] = user.username

    return _tpl(
        "blocked_ips.html",
        request,
        blocks=blocks,
        usernames=usernames,
        active_count=sum(1 for b in blocks if b.is_active),
        current_user=current_user,
    )
