"""Dashboard view router – Phase 4.

Serves the main landing page at GET / with aggregated statistics
queried from the SQLite database and rendered via Jinja2.
"""

import logging
from collections import defaultdict
from datetime import timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import Alert, AlertStatus, LogFile, ParsedLogEntry, SeverityLevel, ThreatIntel, User
from routers.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Dashboard"])
templates = Jinja2Templates(directory="templates")


def _security_score(critical: int, high: int, medium: int) -> int:
    """Calculate a simple security score (0-100)."""
    raw = 100 - (critical * 10 + high * 5 + medium * 2)
    return max(0, min(100, raw))


def _tpl(name: str, request: Request, **ctx):
    """Compatibility wrapper for Starlette >=1.x TemplateResponse."""
    return templates.TemplateResponse(request=request, name=name, context=ctx)


@router.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> HTMLResponse:
    """Render the main dashboard with real aggregated statistics."""

    # ── Aggregate queries ──────────────────────────────────────────
    total_log_files: int = (await db.scalar(select(func.count(LogFile.id)))) or 0
    total_log_entries: int = (await db.scalar(select(func.count(ParsedLogEntry.id)))) or 0
    total_alerts: int = (await db.scalar(select(func.count(Alert.id)))) or 0
    active_alerts: int = (
        await db.scalar(select(func.count(Alert.id)).where(Alert.status == AlertStatus.OPEN))
    ) or 0

    # Severity counts
    severity_rows = (
        await db.execute(
            select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
        )
    ).fetchall()
    sev_map: dict[str, int] = {row[0].value: row[1] for row in severity_rows}
    severity_counts = {
        "critical": sev_map.get(SeverityLevel.CRITICAL.value, 0),
        "high":     sev_map.get(SeverityLevel.HIGH.value,     0),
        "medium":   sev_map.get(SeverityLevel.MEDIUM.value,   0),
        "low":      sev_map.get(SeverityLevel.LOW.value,       0),
    }

    security_score = _security_score(
        severity_counts["critical"],
        severity_counts["high"],
        severity_counts["medium"],
    )

    # Alerts over time (group by UTC date)
    alert_rows = (
        await db.execute(select(Alert.detected_at).order_by(Alert.detected_at))
    ).scalars().all()

    daily_counts: dict[str, int] = defaultdict(int)
    for dt in alert_rows:
        if dt:
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            daily_counts[dt.astimezone(timezone.utc).strftime("%Y-%m-%d")] += 1

    alerts_over_time = [
        {"date": date, "count": count}
        for date, count in sorted(daily_counts.items())
    ]

    # Newest log file - target for the PDF report download button
    latest_log_file_id = await db.scalar(select(LogFile.id).order_by(LogFile.id.desc()).limit(1))

    # Recent alerts (last 10)
    recent_alerts = (
        await db.execute(
            select(Alert).order_by(Alert.detected_at.desc()).limit(10)
        )
    ).scalars().all()

    stats = {
        "total_log_files":   total_log_files,
        "total_log_entries": total_log_entries,
        "total_alerts":      total_alerts,
        "active_alerts":     active_alerts,
        "severity_counts":   severity_counts,
        "security_score":    security_score,
        "alerts_over_time":  alerts_over_time,
        "recent_alerts":     recent_alerts,
        "latest_log_file_id": latest_log_file_id,
    }

    return _tpl("dashboard.html", request, stats=stats, open_alerts_count=active_alerts, current_user=current_user)


@router.get("/upload", response_class=HTMLResponse)
async def upload_page(
    request: Request,
    current_user: User = Depends(get_current_user),
) -> HTMLResponse:
    """Render the log-upload UI page."""
    return _tpl("upload.html", request, current_user=current_user)


@router.get("/threat-intel", response_class=HTMLResponse)
async def threat_intel_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> HTMLResponse:
    """Render the Threat Intelligence page."""
    threat_intel = (
        await db.execute(select(ThreatIntel).order_by(ThreatIntel.added_at.desc()))
    ).scalars().all()
    return _tpl("threat_intel.html", request, threat_intel=threat_intel, current_user=current_user)
