"""PDF security-report endpoints (Phase 5)."""

import asyncio
import logging
from io import BytesIO

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import Alert, LogFile, ParsedLogEntry, SeverityLevel, utc_now
from utils.pdf_report import ReportAlert, ReportData, build_report_pdf, report_filename

router = APIRouter(prefix="/api/reports", tags=["Reports"])
logger = logging.getLogger(__name__)

# CRITICAL first, then HIGH, MEDIUM, LOW; newest first inside each band.
_SEVERITY_RANK = case(
    (Alert.severity == SeverityLevel.CRITICAL, 0),
    (Alert.severity == SeverityLevel.HIGH, 1),
    (Alert.severity == SeverityLevel.MEDIUM, 2),
    (Alert.severity == SeverityLevel.LOW, 3),
    else_=4,
)


@router.get("/{log_file_id}/pdf")
async def download_report(log_file_id: int, db: AsyncSession = Depends(get_db)) -> StreamingResponse:
    """Render one log file's alerts as a downloadable PDF security report."""
    log_file = await db.get(LogFile, log_file_id)
    if log_file is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Log file not found.")

    alerts = (
        await db.scalars(
            select(Alert)
            .where(Alert.log_file_id == log_file_id)
            .order_by(_SEVERITY_RANK, Alert.detected_at.desc())
        )
    ).all()
    entries_parsed = (
        await db.scalar(
            select(func.count(ParsedLogEntry.id)).where(ParsedLogEntry.log_file_id == log_file_id)
        )
    ) or 0

    generated_at = utc_now()
    report = ReportData(
        log_file_id=log_file.id,
        filename=log_file.filename,
        uploaded_at=log_file.uploaded_at,
        log_status=log_file.status.value,
        entries_parsed=entries_parsed,
        alerts_generated=log_file.alerts_count,
        generated_at=generated_at,
        alerts=[
            ReportAlert(
                severity=alert.severity.value,
                threat_name=alert.threat_name,
                source_ip=alert.source_ip,
                risk_score=alert.risk_score,
                status=alert.status.value,
                detected_at=alert.detected_at,
                description=alert.description,
            )
            for alert in alerts
        ],
    )

    try:
        pdf_bytes = await asyncio.to_thread(build_report_pdf, report)
    except Exception:
        logger.exception("PDF report generation failed for log file %s", log_file_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to generate the PDF report.",
        ) from None

    filename = report_filename(log_file_id, generated_at)
    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(pdf_bytes)),
        },
    )
