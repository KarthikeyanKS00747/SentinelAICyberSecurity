"""Secure log-upload API endpoints (Phase 2/3)."""

import logging

from fastapi import APIRouter, Depends, File, UploadFile, status
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import LogFile, LogFileStatus, ParsedLogEntry, User
from routers.auth import get_current_user, require_csrf
from utils.anomaly_detector import run_anomaly_detection
from utils.detector import run_threat_detection
from utils.log_parser import parse_log
from utils.upload_handler import delete_saved_upload, validate_and_save_upload

router = APIRouter(prefix="/api/logs", tags=["Logs"])
logger = logging.getLogger(__name__)


@router.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_log(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _csrf: None = Depends(require_csrf),
) -> dict[str, object]:
    """Validate, securely save, parse, and record an uploaded log file."""
    saved_upload = await validate_and_save_upload(file)
    log_file = LogFile(
        filename=saved_upload.original_filename,
        file_path=str(saved_upload.storage_path),
        mime_type=saved_upload.mime_type,
        file_size_bytes=saved_upload.size_bytes,
        log_type="csv" if saved_upload.original_filename.lower().endswith(".csv") else "text",
        status=LogFileStatus.PARSING,
        owner_id=current_user.id,
    )
    try:
        db.add(log_file)
        await db.flush()
        records = parse_log(saved_upload.content, saved_upload.original_filename)
        db.add_all(
            ParsedLogEntry(
                log_file_id=log_file.id,
                line_number=record.line_number,
                timestamp=record.timestamp,
                source_ip=record.source_ip,
                destination_ip=record.destination_ip,
                source_port=record.source_port,
                destination_port=record.destination_port,
                username=record.username,
                event_type=record.event_type,
                status=record.status,
                message=record.message,
                raw_line=record.raw_line,
            )
            for record in records
        )
        await db.flush()
        await db.commit()
    except Exception:
        await delete_saved_upload(saved_upload)
        raise

    alerts_generated = 0
    try:
        alerts_generated = await run_threat_detection(db, log_file.id)
        log_file.alerts_count = alerts_generated
        log_file.status = LogFileStatus.ANALYZED
        await db.commit()
    except Exception:
        logger.exception("Threat detection failed for log file %s", log_file.id)
        await db.rollback()
        log_file.status = LogFileStatus.FAILED
        await db.commit()

    # Second pass: unsupervised ML outlier detection over the same entries.
    # It is strictly additive -- the rule-based alerts above are already
    # committed, and anything that goes wrong here is logged and dropped
    # rather than allowed to fail the upload, as with the geolocation and
    # AbuseIPDB lookups.
    ml_anomalies = 0
    ml_message = ""
    try:
        anomaly_result = await run_anomaly_detection(db, log_file.id)
        ml_anomalies = anomaly_result.anomalies_recorded
        ml_message = anomaly_result.message
        if anomaly_result.skipped:
            logger.info(
                "ML anomaly detection skipped for log file %s: %s",
                log_file.id,
                anomaly_result.skip_reason,
            )
    except Exception:
        # run_anomaly_detection already swallows its own failures; this guards
        # against anything unexpected on the way in or out of it.
        logger.exception("ML anomaly detection raised for log file %s", log_file.id)
        await db.rollback()
        ml_message = "ML anomaly detection failed; rule-based alerts are unaffected."

    return {
        "id": log_file.id,
        "filename": log_file.filename,
        "entries_parsed": len(records),
        "alerts_generated": alerts_generated,
        "ml_anomalies": ml_anomalies,
        "ml_status": ml_message,
        "status": log_file.status.value,
    }
