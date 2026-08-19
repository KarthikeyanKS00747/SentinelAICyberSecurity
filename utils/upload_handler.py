"""Secure handling for uploaded SentinelAI log files."""

import asyncio
import re
import uuid
from dataclasses import dataclass
from pathlib import Path

from fastapi import HTTPException, UploadFile, status

from config import settings

try:
    import magic  # type: ignore[import-not-found]
except ImportError:  # Windows installations may lack the native libmagic DLL.
    magic = None

ALLOWED_MIME_TYPES = {"text/plain", "text/csv", "application/csv"}
ALLOWED_SUFFIXES = {".log", ".txt", ".csv"}
READ_CHUNK_SIZE = 64 * 1024


@dataclass(frozen=True)
class SavedUpload:
    original_filename: str
    storage_path: Path
    mime_type: str
    size_bytes: int
    content: bytes


def sanitize_filename(filename: str | None) -> str:
    """Remove path components and retain safe display-name characters."""
    name = Path(filename or "upload.log").name
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name).strip(".")
    return name or "upload.log"


async def validate_and_save_upload(file: UploadFile) -> SavedUpload:
    """Validate a bounded upload fully before writing any bytes to disk."""
    original_filename = sanitize_filename(file.filename)
    suffix = Path(original_filename).suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail="Only .log, .txt, and .csv files are accepted.")

    chunks: list[bytes] = []
    total_size = 0
    while chunk := await file.read(READ_CHUNK_SIZE):
        total_size += len(chunk)
        if total_size > settings.MAX_UPLOAD_SIZE_BYTES:
            raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Uploaded file exceeds the allowed size limit.")
        chunks.append(chunk)
    content = b"".join(chunks)
    if not content:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file is empty.")

    detected_mime = _detect_mime(content[:2048], suffix)
    if detected_mime not in ALLOWED_MIME_TYPES:
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail="Uploaded content is not a supported text or CSV file.")
    try:
        content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail="Log files must be UTF-8 encoded text.") from None

    upload_dir = settings.UPLOAD_DIR.resolve()
    upload_dir.mkdir(parents=True, exist_ok=True)
    storage_path = (upload_dir / f"{uuid.uuid4().hex}{suffix}").resolve()
    if storage_path.parent != upload_dir:
        raise RuntimeError("Generated upload path escaped the upload directory.")
    await asyncio.to_thread(storage_path.write_bytes, content)
    return SavedUpload(original_filename, storage_path, detected_mime, total_size, content)


def _detect_mime(header: bytes, suffix: str) -> str:
    """Detect MIME from content; use libmagic where its native library exists."""
    if magic is not None:
        return magic.from_buffer(header, mime=True)
    if b"\x00" in header:
        return "application/octet-stream"
    try:
        text = header.decode("utf-8")
    except UnicodeDecodeError:
        return "application/octet-stream"
    if suffix == ".csv" and ("," in text or "\t" in text) and "\n" in text:
        return "text/csv"
    return "text/plain"


async def delete_saved_upload(saved_upload: SavedUpload) -> None:
    """Remove a saved upload after its dependent database work fails."""
    try:
        await asyncio.to_thread(saved_upload.storage_path.unlink, missing_ok=True)
    except OSError:
        pass
