"""Alerts management router – Phase 4.

Provides:
  GET  /alerts                     – Filtered/searched alerts list (full page or HTMX partial).
  POST /api/alerts/{id}/status     – Update alert status; returns refreshed HTML row for HTMX swap.
  POST /api/alerts/{id}/explain    – Local-Ollama threat explanation (cached on the Alert row).
"""

import logging

import httpx
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import get_db
from models import Alert, AlertStatus, utc_now
from utils.ai_explain import (
    GENERATION_TIMEOUT_SECONDS,
    OLLAMA_GENERATE_URL,
    build_explanation_prompt,
    parse_explanation,
)

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
        is_partial=False,
    )

    # HTMX partial swap – return only the table fragment
    if request.headers.get("HX-Request"):
        ctx["is_partial"] = True
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
    alert.resolved_at = utc_now() if mapped is AlertStatus.RESOLVED else None
    await db.commit()
    await db.refresh(alert)

    logger.info("Alert #%d status updated to %s", alert_id, mapped.value)

    return _tpl("partials/alert_row.html", request, alert=alert)


# ── POST /api/alerts/{alert_id}/explain ─────────────────────────
@router.post("/api/alerts/{alert_id}/explain", response_class=HTMLResponse)
async def explain_alert(
    alert_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    """
    Ask the local Ollama model to explain one alert and cache the reply.

    A stored explanation is re-rendered without contacting Ollama. Generation
    failures render a styled fragment and persist nothing, so the next click
    retries.
    """
    alert: Alert | None = await db.get(Alert, alert_id)
    if alert is None:
        return HTMLResponse(
            content='<p class="text-red-400 text-xs p-3">Alert not found.</p>',
            status_code=404,
        )

    if alert.ai_explanation:
        logger.info("Serving cached AI explanation for alert #%d", alert_id)
        return _tpl(
            "partials/alert_explanation.html",
            request,
            alert=alert,
            explanation=parse_explanation(alert.ai_explanation),
            model=settings.OLLAMA_MODEL,
            cached=True,
        )

    try:
        async with httpx.AsyncClient(timeout=GENERATION_TIMEOUT_SECONDS) as client:
            response = await client.post(
                OLLAMA_GENERATE_URL,
                json={
                    "model": settings.OLLAMA_MODEL,
                    "prompt": build_explanation_prompt(alert),
                    "stream": False,
                },
            )
            response.raise_for_status()
            payload = response.json()
        generated = str(payload.get("response", "")).strip()
        if not generated:
            raise ValueError("Ollama returned an empty response")
    except (httpx.HTTPError, ValueError) as exc:
        # Nothing is written to the alert, so the button stays retryable.
        logger.exception("AI explanation failed for alert %s", alert_id, exc_info=exc)
        return _tpl(
            "partials/alert_explanation_error.html",
            request,
            alert=alert,
            model=settings.OLLAMA_MODEL,
            timeout=int(GENERATION_TIMEOUT_SECONDS),
        )

    alert.ai_explanation = generated
    await db.commit()
    logger.info("Stored AI explanation for alert #%d (%d chars)", alert_id, len(generated))

    return _tpl(
        "partials/alert_explanation.html",
        request,
        alert=alert,
        explanation=parse_explanation(generated),
        model=settings.OLLAMA_MODEL,
        cached=False,
    )
