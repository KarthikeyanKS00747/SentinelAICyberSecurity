"""IP geolocation via ipwho.is, with a read-through database cache.

A geolocation failure must never break alert or threat-intel rendering, so
every path here returns a :class:`GeoResult` instead of raising. Private and
reserved ranges are answered locally and never leave the machine.
"""

import ipaddress
import logging
from dataclasses import dataclass

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import GeoLocation

logger = logging.getLogger(__name__)

GEO_API_URL = "https://ipwho.is/{ip}"
# ipwho.is returns every field by default, so no query string is needed.
# The cache keeps request volume low regardless of the upstream allowance.
LOOKUP_TIMEOUT_SECONDS = 10.0

STATUS_OK = "ok"
STATUS_PRIVATE = "private"
STATUS_INVALID = "invalid"
STATUS_UNKNOWN = "unknown"


@dataclass(frozen=True)
class GeoResult:
    """One geolocation answer. Every field is optional except ip/status."""

    ip: str
    status: str = STATUS_UNKNOWN
    country: str | None = None
    country_code: str | None = None
    region: str | None = None
    city: str | None = None
    isp: str | None = None
    lat: float | None = None
    lon: float | None = None

    @property
    def is_resolved(self) -> bool:
        return self.status == STATUS_OK and bool(self.country)

    @property
    def label(self) -> str:
        """Short human-readable location for the UI."""
        if self.status == STATUS_PRIVATE:
            return "Private network"
        if self.status == STATUS_INVALID:
            return "Invalid IP"
        if not self.is_resolved:
            return "Unknown"
        if self.city:
            return f"{self.city}, {self.country}"
        return self.country or "Unknown"


def is_private_ip(ip: str) -> bool:
    """True for any address that cannot resolve to a public location."""
    try:
        parsed = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return False
    return (
        parsed.is_private          # 10/8, 172.16/12, 192.168/16, fc00::/7, ...
        or parsed.is_loopback      # 127/8, ::1
        or parsed.is_link_local    # 169.254/16, fe80::/10
        or parsed.is_multicast
        or parsed.is_reserved
        or parsed.is_unspecified
    )


def _classify(ip: str) -> str | None:
    """Return a terminal status for addresses we must not send to the API."""
    text = (ip or "").strip()
    if not text:
        return STATUS_INVALID
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return STATUS_INVALID
    if is_private_ip(text):
        return STATUS_PRIVATE
    return None


async def lookup_ip(ip: str, client: httpx.AsyncClient | None = None) -> GeoResult:
    """Geolocate one IP over the network.

    Private, reserved and malformed addresses are answered locally without any
    request. Timeouts, rate limiting (HTTP 429) and malformed payloads all
    degrade to an "unknown" result.
    """
    text = (ip or "").strip()
    terminal = _classify(text)
    if terminal is not None:
        return GeoResult(ip=text, status=terminal)

    url = GEO_API_URL.format(ip=text)
    try:
        if client is None:
            async with httpx.AsyncClient(timeout=LOOKUP_TIMEOUT_SECONDS) as owned:
                response = await owned.get(url)
        else:
            response = await client.get(url)
        payload = response.json()
    except httpx.HTTPError:
        logger.warning("Geolocation lookup for %s failed", text, exc_info=True)
        return GeoResult(ip=text, status=STATUS_UNKNOWN)
    except ValueError:
        logger.warning("Geolocation lookup for %s returned malformed JSON", text)
        return GeoResult(ip=text, status=STATUS_UNKNOWN)

    # ipwho.is signals failure two ways: a non-2xx status (404 for a malformed
    # address) and HTTP 200 with success=false (e.g. "Reserved range").
    if not isinstance(payload, dict) or payload.get("success") is not True:
        message = payload.get("message") if isinstance(payload, dict) else payload
        logger.info(
            "Geolocation lookup for %s was unsuccessful (HTTP %s): %s",
            text, response.status_code, message,
        )
        return GeoResult(ip=text, status=STATUS_UNKNOWN)
    if response.status_code >= 400:
        logger.info("Geolocation lookup for %s returned HTTP %s", text, response.status_code)
        return GeoResult(ip=text, status=STATUS_UNKNOWN)

    def text_field(name: str) -> str | None:
        value = payload.get(name)
        return str(value).strip() or None if value is not None else None

    def float_field(name: str) -> float | None:
        try:
            return float(payload[name])
        except (KeyError, TypeError, ValueError):
            return None

    # ipwho.is nests the ISP one level deeper than ip-api did.
    connection = payload.get("connection")
    isp = None
    if isinstance(connection, dict) and connection.get("isp"):
        isp = str(connection["isp"]).strip() or None

    country_code = text_field("country_code")
    return GeoResult(
        ip=text,
        status=STATUS_OK,
        country=text_field("country"),
        country_code=country_code.upper()[:2] if country_code else None,
        region=text_field("region"),
        city=text_field("city"),
        isp=isp,
        lat=float_field("latitude"),
        lon=float_field("longitude"),
    )


def _from_row(row: GeoLocation) -> GeoResult:
    return GeoResult(
        ip=row.ip,
        status=STATUS_OK,
        country=row.country,
        country_code=row.country_code,
        region=row.region,
        city=row.city,
        isp=row.isp,
        lat=row.lat,
        lon=row.lon,
    )


async def get_cached(db: AsyncSession, ip: str) -> GeoResult | None:
    """Return a cached answer for ``ip``, or None when nothing is stored."""
    row = await db.scalar(select(GeoLocation).where(GeoLocation.ip == (ip or "").strip()))
    return _from_row(row) if row is not None else None


async def get_or_lookup(db: AsyncSession, ip: str) -> GeoResult:
    """Read-through cache: serve from the database, else call the API once.

    Only successful lookups are cached. Failures stay uncached so a transient
    outage or a rate-limit burst does not poison the cache permanently.
    """
    text = (ip or "").strip()
    terminal = _classify(text)
    if terminal is not None:
        return GeoResult(ip=text, status=terminal)

    cached = await get_cached(db, text)
    if cached is not None:
        logger.debug("Geolocation cache hit for %s", text)
        return cached

    result = await lookup_ip(text)
    if result.is_resolved:
        db.add(
            GeoLocation(
                ip=text,
                country=result.country,
                country_code=result.country_code,
                region=result.region,
                city=result.city,
                isp=result.isp,
                lat=result.lat,
                lon=result.lon,
            )
        )
        await db.commit()
        logger.info("Cached geolocation for %s: %s", text, result.label)
    return result
