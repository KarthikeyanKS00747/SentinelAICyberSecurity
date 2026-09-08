"""Attack map view router.

Provides:
  GET /map  - Leaflet map plotting every alert whose source IP already has a
              cached geolocation.

Read-only over the existing ``geo_locations`` cache. It deliberately never
calls :func:`utils.geolocation.get_or_lookup`: the cache is filled lazily by
the per-row HTMX badges on the Alerts page, and firing one upstream request per
alert on a page load would be both slow and a good way to hit the rate limit.
An IP with no cached row is simply left off the map.
"""

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import Alert, AlertStatus, GeoLocation, SeverityLevel, User
from routers.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Attack Map"])
templates = Jinja2Templates(directory="templates")

# Same swatches the dashboard charts and the severity badges use, so a red dot
# on the map means exactly what a red badge in the table means.
SEVERITY_COLOURS: dict[str, str] = {
    SeverityLevel.CRITICAL.value: "#ef4444",
    SeverityLevel.HIGH.value:     "#f97316",
    SeverityLevel.MEDIUM.value:   "#f59e0b",
    SeverityLevel.LOW.value:      "#64748b",
}

# Most severe first: a marker holding several alerts takes the worst one.
SEVERITY_RANK: dict[str, int] = {
    SeverityLevel.CRITICAL.value: 3,
    SeverityLevel.HIGH.value:     2,
    SeverityLevel.MEDIUM.value:   1,
    SeverityLevel.LOW.value:      0,
}


def _tpl(name: str, request: Request, **ctx):
    """Compatibility wrapper for Starlette >=1.x TemplateResponse."""
    return templates.TemplateResponse(request=request, name=name, context=ctx)


def _primary_ip(source_ip: str | None) -> str | None:
    """First address of an alert's source field.

    The detector records a comma-separated list when one alert covers several
    addresses; the alerts table geolocates the first one, so the map plots the
    same address rather than inventing a second convention.
    """
    if not source_ip:
        return None
    first = source_ip.split(",")[0].strip()
    return first or None


@router.get("/map", response_class=HTMLResponse)
async def attack_map_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> HTMLResponse:
    """Render the attack map with one marker per geolocated source IP."""
    alerts = (
        await db.execute(select(Alert).order_by(Alert.detected_at.desc()))
    ).scalars().all()

    wanted = {ip for alert in alerts if (ip := _primary_ip(alert.source_ip))}
    located: dict[str, GeoLocation] = {}
    if wanted:
        rows = (
            await db.execute(select(GeoLocation).where(GeoLocation.ip.in_(wanted)))
        ).scalars().all()
        # A cached row with no coordinates cannot be placed on a map.
        located = {row.ip: row for row in rows if row.lat is not None and row.lon is not None}

    # One marker per IP: several alerts from the same address stack into one
    # popup instead of piling invisible markers on the same pixel.
    markers: dict[str, dict] = {}
    skipped = 0
    for alert in alerts:
        ip = _primary_ip(alert.source_ip)
        geo = located.get(ip) if ip else None
        if geo is None:
            skipped += 1
            continue

        marker = markers.get(ip)
        if marker is None:
            marker = markers[ip] = {
                "ip": ip,
                "lat": geo.lat,
                "lon": geo.lon,
                "city": geo.city or "",
                "country": geo.country or "",
                "country_code": geo.country_code or "",
                "isp": geo.isp or "",
                "severity": alert.severity.value,
                "colour": SEVERITY_COLOURS[alert.severity.value],
                "alerts": [],
            }

        marker["alerts"].append(
            {
                "id": alert.id,
                "threat_name": alert.threat_name,
                "severity": alert.severity.value,
                "colour": SEVERITY_COLOURS[alert.severity.value],
                "risk_score": int(alert.risk_score or 0),
                "status": alert.status.value,
                "detected_at": alert.detected_at.strftime("%Y-%m-%d %H:%M") if alert.detected_at else "",
            }
        )

        if SEVERITY_RANK[alert.severity.value] > SEVERITY_RANK[marker["severity"]]:
            marker["severity"] = alert.severity.value
            marker["colour"] = SEVERITY_COLOURS[alert.severity.value]

    open_alerts_count = (
        await db.scalar(select(func.count(Alert.id)).where(Alert.status == AlertStatus.OPEN))
    ) or 0

    logger.info("Attack map: %d markers, %d alerts without cached geolocation", len(markers), skipped)

    return _tpl(
        "attack_map.html",
        request,
        markers=list(markers.values()),
        plotted_alerts=len(alerts) - skipped,
        total_alerts=len(alerts),
        skipped_alerts=skipped,
        severity_colours=SEVERITY_COLOURS,
        open_alerts_count=open_alerts_count,
        current_user=current_user,
    )
