"""Audit log viewer - admin only.

Provides:
  GET /audit-log - Every recorded admin action, newest first.

Read-only by design: the page offers no way to edit or delete an entry, and
nothing else in the app writes to these rows after they are created.
"""

import logging

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import AuditLog, User
from routers.auth import require_admin
from utils.audit import ACTION_LABELS, describe_action

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Audit"])
templates = Jinja2Templates(directory="templates")

# The history is small in a prototype, but unbounded growth would still make
# this page slower every time an admin touches anything.
PAGE_SIZE = 200


def _tpl(name: str, request: Request, **ctx):
    """Compatibility wrapper for Starlette >=1.x TemplateResponse."""
    return templates.TemplateResponse(request=request, name=name, context=ctx)


# -- GET /audit-log --------------------------------------------------
@router.get("/audit-log", response_class=HTMLResponse)
async def audit_log_page(
    request: Request,
    action_filter: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> HTMLResponse:
    """Show the most recent admin actions, newest first."""
    query = select(AuditLog).order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())
    if action_filter and action_filter in ACTION_LABELS:
        query = query.where(AuditLog.action == action_filter)

    entries = list((await db.scalars(query.limit(PAGE_SIZE))).all())
    total = (await db.scalar(select(func.count(AuditLog.id)))) or 0

    rows = []
    for entry in entries:
        label, icon, colour = describe_action(entry.action)
        rows.append(
            {
                "entry": entry,
                "label": label,
                "icon": icon,
                "colour": colour,
            }
        )

    return _tpl(
        "audit_log.html",
        request,
        rows=rows,
        total=total,
        shown=len(rows),
        page_size=PAGE_SIZE,
        action_filter=action_filter or "",
        actions=sorted(ACTION_LABELS),
        action_labels=ACTION_LABELS,
        current_user=current_user,
    )
