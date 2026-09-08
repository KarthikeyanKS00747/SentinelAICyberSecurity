"""IP reputation via AbuseIPDB, with an expiring read-through cache.

Mirrors :mod:`utils.geolocation`: every path returns an :class:`AbuseResult`
instead of raising, private ranges are answered locally, and a missing API key
or an upstream failure degrades to "not checked" so alert rendering is never
blocked. Unlike geolocation, cached rows expire -- abuse scores change.

This module only fetches and caches. It deliberately makes no blocking or
remediation decisions.
"""

import ipaddress
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from models import AbuseCheck, utc_now
from utils.geolocation import is_private_ip

logger = logging.getLogger(__name__)

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
MAX_AGE_IN_DAYS = 90
LOOKUP_TIMEOUT_SECONDS = 10.0
# Reputation is volatile, so cached rows go stale and are re-checked.
CACHE_TTL_DAYS = 7

STATUS_OK = "ok"
STATUS_PRIVATE = "private"
STATUS_INVALID = "invalid"
STATUS_NOT_CHECKED = "not_checked"

# Badge thresholds: green below LOW, amber up to HIGH, red above it.
SCORE_LOW = 25
SCORE_HIGH = 75


@dataclass(frozen=True)
class AbuseResult:
    """One reputation answer. Score/reports are None unless status is ok."""

    ip: str
    status: str = STATUS_NOT_CHECKED
    abuse_confidence_score: int | None = None
    total_reports: int | None = None
    country_code: str | None = None
    checked_at: datetime | None = None

    @property
    def is_checked(self) -> bool:
        return self.status == STATUS_OK and self.abuse_confidence_score is not None

    @property
    def risk_band(self) -> str:
        """'low' | 'medium' | 'high' | 'none' - drives the badge colour."""
        if not self.is_checked:
            return "none"
        if self.abuse_confidence_score < SCORE_LOW:
            return "low"
        if self.abuse_confidence_score <= SCORE_HIGH:
            return "medium"
        return "high"

    @property
    def label(self) -> str:
        if self.status == STATUS_PRIVATE:
            return "Private network"
        if self.status == STATUS_INVALID:
            return "Invalid IP"
        if not self.is_checked:
            return "Not checked"
        return f"{self.abuse_confidence_score}% abuse"


def _classify(ip: str) -> str | None:
    """Terminal status for addresses that must not be sent upstream."""
    text = (ip or "").strip()
    if not text:
        return STATUS_INVALID
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return STATUS_INVALID
    if is_private_ip(text):  # reused from utils.geolocation, not duplicated
        return STATUS_PRIVATE
    return None


def _as_int(value: object) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


async def check_ip_reputation(ip: str, client: httpx.AsyncClient | None = None) -> AbuseResult:
    """Look up one IP's abuse reputation.

    Returns "not checked" without any request when the API key is unset or the
    address is private/malformed. Timeouts, HTTP errors (401, 429, ...) and
    malformed payloads degrade the same way.
    """
    text = (ip or "").strip()
    terminal = _classify(text)
    if terminal is not None:
        return AbuseResult(ip=text, status=terminal)

    api_key = (settings.ABUSEIPDB_API_KEY or "").strip()
    if not api_key:
        logger.debug("ABUSEIPDB_API_KEY is not configured; skipping reputation lookup for %s", text)
        return AbuseResult(ip=text, status=STATUS_NOT_CHECKED)

    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": text, "maxAgeInDays": str(MAX_AGE_IN_DAYS)}
    try:
        if client is None:
            async with httpx.AsyncClient(timeout=LOOKUP_TIMEOUT_SECONDS) as owned:
                response = await owned.get(ABUSEIPDB_URL, headers=headers, params=params)
        else:
            response = await client.get(ABUSEIPDB_URL, headers=headers, params=params)
        payload = response.json()
    except httpx.HTTPError:
        logger.warning("AbuseIPDB lookup for %s failed", text, exc_info=True)
        return AbuseResult(ip=text, status=STATUS_NOT_CHECKED)
    except ValueError:
        logger.warning("AbuseIPDB lookup for %s returned malformed JSON", text)
        return AbuseResult(ip=text, status=STATUS_NOT_CHECKED)

    if response.status_code >= 400 or not isinstance(payload, dict) or "data" not in payload:
        detail = None
        if isinstance(payload, dict):
            errors = payload.get("errors")
            if isinstance(errors, list) and errors and isinstance(errors[0], dict):
                detail = errors[0].get("detail")
        logger.warning(
            "AbuseIPDB lookup for %s was unsuccessful (HTTP %s): %s",
            text, response.status_code, detail,
        )
        return AbuseResult(ip=text, status=STATUS_NOT_CHECKED)

    data = payload.get("data")
    if not isinstance(data, dict):
        logger.warning("AbuseIPDB lookup for %s returned an unexpected payload shape", text)
        return AbuseResult(ip=text, status=STATUS_NOT_CHECKED)

    score = _as_int(data.get("abuseConfidenceScore"))
    if score is None:
        logger.warning("AbuseIPDB lookup for %s omitted abuseConfidenceScore", text)
        return AbuseResult(ip=text, status=STATUS_NOT_CHECKED)

    country_code = data.get("countryCode")
    return AbuseResult(
        ip=text,
        status=STATUS_OK,
        abuse_confidence_score=max(0, min(100, score)),
        total_reports=_as_int(data.get("totalReports")) or 0,
        country_code=str(country_code).upper()[:2] if country_code else None,
        checked_at=utc_now(),
    )


def _is_fresh(checked_at: datetime | None) -> bool:
    """True when a cached row is still inside the freshness window."""
    if checked_at is None:
        return False
    moment = checked_at if checked_at.tzinfo else checked_at.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - moment < timedelta(days=CACHE_TTL_DAYS)


def _from_row(row: AbuseCheck) -> AbuseResult:
    return AbuseResult(
        ip=row.ip,
        status=STATUS_OK,
        abuse_confidence_score=row.abuse_confidence_score,
        total_reports=row.total_reports,
        checked_at=row.checked_at,
    )


async def get_cached(db: AsyncSession, ip: str) -> AbuseResult | None:
    """Return a cached answer only while it is still fresh."""
    row = await db.scalar(select(AbuseCheck).where(AbuseCheck.ip == (ip or "").strip()))
    if row is None or not _is_fresh(row.checked_at):
        return None
    return _from_row(row)


async def get_or_check(db: AsyncSession, ip: str) -> AbuseResult:
    """Read-through cache with expiry: serve fresh rows, else re-check once.

    Only successful lookups are stored, so a missing key or an outage leaves
    the cache untouched and the next view retries.
    """
    text = (ip or "").strip()
    terminal = _classify(text)
    if terminal is not None:
        return AbuseResult(ip=text, status=terminal)

    cached = await get_cached(db, text)
    if cached is not None:
        logger.debug("AbuseIPDB cache hit for %s", text)
        return cached

    result = await check_ip_reputation(text)
    if not result.is_checked:
        return result

    row = await db.scalar(select(AbuseCheck).where(AbuseCheck.ip == text))
    if row is None:
        db.add(
            AbuseCheck(
                ip=text,
                abuse_confidence_score=result.abuse_confidence_score,
                total_reports=result.total_reports or 0,
            )
        )
        logger.info("Cached AbuseIPDB reputation for %s: %s", text, result.label)
    else:
        # Stale row: refresh in place rather than inserting a duplicate.
        row.abuse_confidence_score = result.abuse_confidence_score
        row.total_reports = result.total_reports or 0
        row.checked_at = utc_now()
        logger.info("Refreshed stale AbuseIPDB reputation for %s: %s", text, result.label)
    await db.commit()
    return result
