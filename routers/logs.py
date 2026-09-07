"""Secure log-upload API endpoints (Phase 2/3)."""

import logging

from fastapi import APIRouter, Depends, File, UploadFile, status
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import LogFile, LogFileStatus, ParsedLogEntry
from utils.detector import run_threat_detection
from utils.log_parser import parse_log
from utils.upload_handler import delete_saved_upload, validate_and_save_upload

router = APIRouter(prefix="/api/logs", tags=["Logs"])
logger = logging.getLogger(__name__)


@router.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_log(file: UploadFile = File(...), db: AsyncSession = Depends(get_db)) -> dict[str, object]:
    """Validate, securely save, parse, and record an uploaded log file."""
    saved_upload = await validate_and_save_upload(file)
    log_file = LogFile(
        filename=saved_upload.original_filename,
        file_path=str(saved_upload.storage_path),
        mime_type=saved_upload.mime_type,
        file_size_bytes=saved_upload.size_bytes,
        log_type="csv" if saved_upload.original_filename.lower().endswith(".csv") else "text",
        status=LogFileStatus.PARSING,
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

    return {
        "id": log_file.id,
        "filename": log_file.filename,
        "entries_parsed": len(records),
        "alerts_generated": alerts_generated,
        "status": log_file.status.value,
    }
