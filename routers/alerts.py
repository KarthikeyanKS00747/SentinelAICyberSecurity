"""Alerts management router – Phase 4.

Provides:
  GET  /alerts                     – Filtered/searched alerts list (full page or HTMX partial).
  POST /api/alerts/{id}/status     – Update alert status; returns refreshed HTML row for HTMX swap.
  POST /api/alerts/{id}/explain    – Phase 5 placeholder; returns a styled HTML snippet.
"""

import logging

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import Alert, AlertStatus

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Alerts"])
templates = Jinja2Templates(directory="templates")

# Map incoming string values to the AlertStatus enum
_STATUS_MAP: dict[str, AlertStatus] = {
    "open":          AlertStatus.OPEN,
    "investigating": AlertStatus.INVESTIGATING,
    "resolved":      AlertStatus.RESOLVED,
}


def _tpl(name: str, request: Request, **ctx):
    """Compatibility wrapper for Starlette >=1.x TemplateResponse."""
    return templates.TemplateResponse(request=request, name=name, context=ctx)


def _build_alert_query(search: str | None, severity_filter: str | None, status_filter: str | None):
    """Return a SQLAlchemy select() with optional WHERE clauses applied."""
    q = select(Alert).order_by(Alert.detected_at.desc())

    if search:
        term = f"%{search}%"
        q = q.where(
            Alert.threat_name.ilike(term)
            | Alert.source_ip.ilike(term)
            | Alert.description.ilike(term)
        )
    if severity_filter:
        q = q.where(Alert.severity == severity_filter)
    if status_filter:
        q = q.where(Alert.status == status_filter)

    return q


# ── GET /alerts ────────────────────────────────────────────────────
@router.get("/alerts", response_class=HTMLResponse)
async def alerts_page(
    request: Request,
    search: str | None = None,
    severity_filter: str | None = None,
    status_filter: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    """
    Render the full Alerts page.
    When called by HTMX (HX-Request header present), returns only the
    table partial so the rest of the page is not re-rendered.
    """
    alerts = (
        await db.execute(_build_alert_query(search, severity_filter, status_filter))
    ).scalars().all()

    open_alerts_count = (
        await db.scalar(select(func.count(Alert.id)).where(Alert.status == AlertStatus.OPEN))
    ) or 0

    ctx = dict(
        alerts=alerts,
        search=search or "",
        severity_filter=severity_filter or "",
        status_filter=status_filter or "",
        open_alerts_count=open_alerts_count,
    )

    # HTMX partial swap – return only the table fragment
    if request.headers.get("HX-Request"):
        return _tpl("partials/alerts_table.html", request, **ctx)

    return _tpl("alerts.html", request, **ctx)


# ── POST /api/alerts/{alert_id}/status ────────────────────────────
@router.post("/api/alerts/{alert_id}/status", response_class=HTMLResponse)
async def update_alert_status(
    alert_id: int,
    request: Request,
    new_status: str = Form(...),
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    """
    Update an alert's status field and return the refreshed table row
    as an HTML fragment for HTMX outerHTML swap.
    """
    alert: Alert | None = await db.get(Alert, alert_id)
    if alert is None:
        return HTMLResponse(
            content='<tr><td colspan="8" class="px-4 py-3 text-red-400 text-xs">Alert not found.</td></tr>',
            status_code=404,
        )

    mapped = _STATUS_MAP.get(new_status.lower())
    if mapped is None:
        return HTMLResponse(
            content='<tr><td colspan="8" class="px-4 py-3 text-red-400 text-xs">Invalid status value.</td></tr>',
            status_code=422,
        )

    alert.status = mapped
    await db.commit()
    await db.refresh(alert)

    logger.info("Alert #%d status updated to %s", alert_id, mapped.value)

    return _tpl("partials/alert_row.html", request, alert=alert)


# ── POST /api/alerts/{alert_id}/explain ───────────────────────────
@router.post("/api/alerts/{alert_id}/explain", response_class=HTMLResponse)
async def explain_alert(
    alert_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    """
    Phase 5 placeholder – returns a styled HTML snippet.
    Local LLM explanations will be generated via Ollama in Phase 5.
    """
    alert: Alert | None = await db.get(Alert, alert_id)
    if alert is None:
        return HTMLResponse(
            content='<p class="text-red-400 text-xs p-3">Alert not found.</p>',
            status_code=404,
        )

    snippet = f"""
    <div class="htmx-added my-2 mx-1 p-4 rounded-lg border border-purple-500/30
                bg-gradient-to-r from-purple-900/20 to-slate-900/20 backdrop-blur-sm">
      <div class="flex items-start gap-3">
        <div class="w-8 h-8 rounded-lg bg-purple-500/20 flex items-center justify-center flex-shrink-0 mt-0.5">
          <i class="fa-solid fa-robot text-purple-400 text-sm"></i>
        </div>
        <div class="flex-1">
          <p class="text-sm font-semibold text-purple-300 mb-1">
            AI Threat Explanation &mdash; Phase 5 Preview
          </p>
          <p class="text-xs text-slate-400 leading-relaxed">
            Local LLM explanation will be generated here in <strong class="text-purple-300">Phase 5</strong>
            using Ollama (<code class="text-cyan-300 bg-slate-800/50 px-1 rounded">llama3</code>).
            The model will analyse alert&nbsp;<strong class="text-white">#{alert_id}</strong>
            (<em>{alert.threat_name}</em>) and provide a human-readable threat summary,
            recommended remediation steps, and MITRE&nbsp;ATT&amp;CK mapping.
          </p>
          <div class="mt-3 flex items-center gap-2 text-xs text-slate-500">
            <i class="fa-solid fa-circle-info text-purple-500/60"></i>
            Awaiting Phase 5 implementation &mdash; Ollama integration pending.
          </div>
        </div>
      </div>
    </div>
    """
    return HTMLResponse(content=snippet)
