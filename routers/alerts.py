"""Alerts management router – Phase 4.

Provides:
  GET  /alerts                        – Filtered/searched alerts list (full page or HTMX partial).
  POST /api/alerts/{id}/status        – Update alert status; returns refreshed HTML row for HTMX swap.
  POST /api/alerts/{id}/explain       – Local-Ollama threat explanation (cached on the Alert row).
  GET  /api/alerts/{id}/explain/stream – Server-Sent Events feed of that explanation as it generates.
"""

import json
import logging
from collections.abc import AsyncIterator

import httpx
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import AsyncSessionLocal, get_db
from models import Alert, AlertStatus, User, utc_now
from routers.auth import get_current_user, require_csrf
from utils.ai_explain import (
    GENERATION_TIMEOUT_SECONDS,
    OLLAMA_GENERATE_URL,
    build_generate_payload,
    parse_explanation,
)
from utils.settings_service import get_setting

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
    current_user: User = Depends(get_current_user),
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
        current_user=current_user,
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
    current_user: User = Depends(get_current_user),
    _csrf: None = Depends(require_csrf),
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
    current_user: User = Depends(get_current_user),
    _csrf: None = Depends(require_csrf),
) -> HTMLResponse:
    """
    Return one alert's explanation, or the shell that streams a fresh one.

    A stored explanation is re-rendered immediately without contacting Ollama.
    Otherwise this hands back a live region that opens the SSE endpoint below,
    so the analyst sees the first sentence in a second or two instead of
    staring at a spinner for the whole generation. Nothing is persisted here;
    the streaming endpoint owns that.
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

    return _tpl(
        "partials/alert_explanation_streaming.html",
        request,
        alert=alert,
        model=settings.OLLAMA_MODEL,
    )


# ── GET /api/alerts/{alert_id}/explain/stream ──────────────────────
def _sse(event: str, payload: str) -> str:
    """Frame one Server-Sent Event.

    The payload is JSON-encoded because model output contains newlines, and a
    raw newline inside an SSE ``data:`` line would terminate the event early.
    """
    return f"event: {event}\ndata: {json.dumps(payload)}\n\n"


@router.get("/api/alerts/{alert_id}/explain/stream")
async def explain_alert_stream(
    alert_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> StreamingResponse:
    """Stream one alert's explanation from Ollama token by token.

    Total generation time is bounded by the local model and the hardware; this
    endpoint cannot make the model faster. What it removes is the dead wait --
    text lands in the browser as it is produced rather than after the last
    token.

    Persisting the finished text is a cache fill, the same shape as the
    geolocation GET in ``routers/geo.py``, which is why a GET does it. It runs
    on its own session: FastAPI closes a ``yield`` dependency before the
    response body is streamed, so ``db`` is already gone by the time the last
    chunk arrives.
    """
    alert: Alert | None = await db.get(Alert, alert_id)
    if alert is None:
        return StreamingResponse(
            iter([_sse("fail", '<p class="text-red-400 text-xs p-3">Alert not found.</p>')]),
            media_type="text/event-stream",
        )

    # Operator-tunable via the settings page; the module constant is the
    # fallback when the row is missing or holds an unusable value.
    timeout_seconds = await get_setting(
        db, "ollama.explanation_timeout_seconds", GENERATION_TIMEOUT_SECONDS
    )
    payload = build_generate_payload(alert, settings.OLLAMA_MODEL, stream=True)

    # Rendered up front: the template needs no database access, and building it
    # inside the failure path would mean touching Jinja mid-stream.
    error_html = _tpl(
        "partials/alert_explanation_error.html",
        request,
        alert=alert,
        model=settings.OLLAMA_MODEL,
        timeout=int(timeout_seconds),
    ).body.decode("utf-8")

    async def event_stream() -> AsyncIterator[str]:
        pieces: list[str] = []
        try:
            async with httpx.AsyncClient(timeout=timeout_seconds) as client:
                async with client.stream("POST", OLLAMA_GENERATE_URL, json=payload) as response:
                    response.raise_for_status()
                    # Ollama streams newline-delimited JSON, one object per token.
                    async for line in response.aiter_lines():
                        if not line.strip():
                            continue
                        chunk = json.loads(line)
                        piece = str(chunk.get("response", ""))
                        if piece:
                            pieces.append(piece)
                            yield _sse("chunk", piece)
                        if chunk.get("done"):
                            break
            generated = "".join(pieces).strip()
            if not generated:
                raise ValueError("Ollama returned an empty response")
        except (httpx.HTTPError, ValueError, json.JSONDecodeError) as exc:
            # Nothing is written to the alert, so the button stays retryable.
            logger.exception("AI explanation failed for alert %s", alert_id, exc_info=exc)
            yield _sse("fail", error_html)
            return

        async with AsyncSessionLocal() as session:
            stored = await session.get(Alert, alert_id)
            if stored is not None:
                stored.ai_explanation = generated
                await session.commit()
        logger.info("Stored AI explanation for alert #%d (%d chars)", alert_id, len(generated))

        # The client re-requests the POST endpoint, which now hits the cache and
        # renders the parsed four-section card over the raw stream.
        yield _sse("done", "")

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # keep any reverse proxy from buffering the feed
        },
    )
