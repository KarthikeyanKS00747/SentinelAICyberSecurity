"""ML anomaly detection router - Isolation Forest results.

Provides:
  GET /anomalies  - Per-log-file Isolation Forest findings, including files
                    that were deliberately skipped for having too few IPs.

Read-only. Scoring happens once, during upload analysis; this page renders
what was stored then and never refits a model.
"""

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import AnomalyAlert, LogFile, ParsedLogEntry, User
from routers.auth import get_current_user
from utils.anomaly_detector import (
    DEFAULT_CONTAMINATION,
    DEFAULT_MIN_DISTINCT_IPS,
    N_ESTIMATORS,
    SKLEARN_AVAILABLE,
    parse_contributing_features,
)
from utils.settings_service import get_setting

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Anomalies"])
templates = Jinja2Templates(directory="templates")

# Score bands for the UI only. They colour the bar; they are not severities,
# and nothing downstream branches on them.
HIGH_SCORE_BAND = 65.0
MEDIUM_SCORE_BAND = 50.0


def _tpl(name: str, request: Request, **ctx):
    """Compatibility wrapper for Starlette >=1.x TemplateResponse."""
    return templates.TemplateResponse(request=request, name=name, context=ctx)


def _band(score: float) -> str:
    if score >= HIGH_SCORE_BAND:
        return "high"
    if score >= MEDIUM_SCORE_BAND:
        return "medium"
    return "low"


# -- GET /anomalies --------------------------------------------------
@router.get("/anomalies", response_class=HTMLResponse)
async def anomalies_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> HTMLResponse:
    """List Isolation Forest findings, newest log file first.

    Files with no findings are still listed, so "nothing was flagged" and
    "the model was never fit" stay distinguishable: the distinct-IP count is
    recomputed here and compared against the same minimum the detector used.
    """
    min_distinct_ips = await get_setting(db, "anomaly.min_distinct_ips", DEFAULT_MIN_DISTINCT_IPS)
    contamination = await get_setting(db, "anomaly.contamination", DEFAULT_CONTAMINATION)

    log_files = list((await db.scalars(select(LogFile).order_by(LogFile.uploaded_at.desc()))).all())

    ip_counts = dict(
        (
            await db.execute(
                select(
                    ParsedLogEntry.log_file_id,
                    func.count(func.distinct(ParsedLogEntry.source_ip)),
                )
                .where(ParsedLogEntry.source_ip.is_not(None))
                .group_by(ParsedLogEntry.log_file_id)
            )
        ).all()
    )

    alerts = list(
        (
            await db.scalars(
                select(AnomalyAlert).order_by(
                    AnomalyAlert.log_file_id.desc(), AnomalyAlert.anomaly_score.desc()
                )
            )
        ).all()
    )
    alerts_by_file: dict[int, list[dict]] = {}
    for alert in alerts:
        payload = parse_contributing_features(alert.contributing_features)
        alerts_by_file.setdefault(alert.log_file_id, []).append(
            {
                "source_ip": alert.source_ip,
                "anomaly_score": alert.anomaly_score,
                "band": _band(alert.anomaly_score),
                "summary": payload.get("summary") or "",
                "features": payload.get("features") or [],
                "all_features": payload.get("all_features") or {},
                "detected_at": alert.detected_at,
            }
        )

    groups = []
    for log_file in log_files:
        ip_count = ip_counts.get(log_file.id, 0)
        file_alerts = alerts_by_file.get(log_file.id, [])
        skipped = ip_count < min_distinct_ips
        if skipped:
            note = (
                f"Skipped: only {ip_count} distinct source "
                f"IP{'s' if ip_count != 1 else ''} in this file, and at least "
                f"{min_distinct_ips} are needed before an outlier model means anything."
            )
        elif not file_alerts:
            note = f"Scored {ip_count} source IPs; none stood out from the rest."
        else:
            note = f"Scored {ip_count} source IPs against each other."
        groups.append(
            {
                "log_file": log_file,
                "ip_count": ip_count,
                "skipped": skipped,
                "note": note,
                "alerts": file_alerts,
            }
        )

    return _tpl(
        "anomalies.html",
        request,
        groups=groups,
        total_anomalies=len(alerts),
        min_distinct_ips=min_distinct_ips,
        contamination=contamination,
        n_estimators=N_ESTIMATORS,
        sklearn_available=SKLEARN_AVAILABLE,
        current_user=current_user,
    )
