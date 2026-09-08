"""Trend heuristic over recent alert volume.

This is NOT a predictive model. There is no training, no probability and no
extrapolation: it counts alerts per attack type in the last N hours, compares
that with the preceding N hours, and reports which types went up. Every number
it shows is a raw count the user can verify by filtering the alerts page.

Two honesty guards matter more than the arithmetic:

* a minimum recent count, so "1 alert vs 0" is not dressed up as a trend;
* an explicit insufficient-data result when there are no alerts or not enough
  history to have a baseline, instead of inventing confidence.

It reads ``Alert.detected_at``, which is when the alert was *raised* - i.e.
when a log file was uploaded and analysed - not when the logged activity
happened. In a project driven by manual uploads that measures upload cadence,
so treat it as "what has SentinelAI been seeing lately", not "what is
happening on the network right now".
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import Alert

logger = logging.getLogger(__name__)

# Comparison window: the last WINDOW_HOURS against the WINDOW_HOURS before it.
WINDOW_HOURS = 24
# Noise floor: below this many alerts in the recent window, a rise is not
# reported at all. Small numbers swing wildly and mean nothing.
MIN_ALERTS_FOR_TREND = 3

STATUS_TRENDS = "trends"
STATUS_NO_TREND = "no_trend"
STATUS_INSUFFICIENT = "insufficient_data"

METHOD_LABEL = "Trend-based forecast (heuristic, not ML)"


@dataclass(frozen=True)
class TrendItem:
    """One attack type's movement between the two windows."""

    threat_name: str
    recent: int
    prior: int

    @property
    def delta(self) -> int:
        return self.recent - self.prior

    @property
    def direction(self) -> str:
        if self.recent > self.prior:
            return "up"
        if self.recent < self.prior:
            return "down"
        return "flat"

    @property
    def summary(self) -> str:
        """Plain-language, fully explainable from the two raw counts."""
        return (
            f"{self.threat_name} activity trending up - "
            f"{self.recent} alert{'s' if self.recent != 1 else ''} in the last "
            f"{WINDOW_HOURS}h vs {self.prior} previously."
        )


@dataclass(frozen=True)
class ForecastResult:
    """Outcome of one trend comparison."""

    status: str
    window_hours: int = WINDOW_HOURS
    generated_at: datetime | None = None
    recent_total: int = 0
    prior_total: int = 0
    trends: list[TrendItem] = field(default_factory=list)
    reason: str | None = None
    history_hours: float | None = None

    @property
    def has_trends(self) -> bool:
        return self.status == STATUS_TRENDS and bool(self.trends)

    @property
    def is_insufficient(self) -> bool:
        return self.status == STATUS_INSUFFICIENT

    @property
    def method_label(self) -> str:
        return METHOD_LABEL

    @property
    def min_alerts(self) -> int:
        """Noise floor, surfaced so the UI can state it rather than imply it."""
        return MIN_ALERTS_FOR_TREND


def _as_naive_utc(moment: datetime | None) -> datetime | None:
    """SQLite hands back naive datetimes; normalise so comparisons are safe."""
    if moment is None:
        return None
    if moment.tzinfo is not None:
        return moment.astimezone(timezone.utc).replace(tzinfo=None)
    return moment


async def compute_forecast(db: AsyncSession) -> ForecastResult:
    """Compare alert volume per attack type across two adjacent windows.

    Returns an insufficient-data result when there is nothing to compare,
    rather than presenting a confident-looking forecast built on one or two
    data points.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    recent_start = now - timedelta(hours=WINDOW_HOURS)
    prior_start = now - timedelta(hours=2 * WINDOW_HOURS)

    rows = list(
        (await db.scalars(select(Alert).where(Alert.detected_at.is_not(None)))).all()
    )
    stamped = [(a.threat_name, _as_naive_utc(a.detected_at)) for a in rows]
    stamped = [(name, moment) for name, moment in stamped if moment is not None]

    if not stamped:
        return ForecastResult(
            status=STATUS_INSUFFICIENT,
            generated_at=now,
            reason="No alerts have been recorded yet, so there is nothing to compare.",
        )

    earliest = min(moment for _, moment in stamped)
    history_hours = (now - earliest).total_seconds() / 3600

    if earliest > prior_start:
        return ForecastResult(
            status=STATUS_INSUFFICIENT,
            generated_at=now,
            reason=(
                f"Only {history_hours:.1f}h of alert history exists; "
                f"{2 * WINDOW_HOURS}h are needed to compare two windows."
            ),
            history_hours=history_hours,
        )

    recent: dict[str, int] = {}
    prior: dict[str, int] = {}
    for name, moment in stamped:
        if moment >= recent_start:
            recent[name] = recent.get(name, 0) + 1
        elif moment >= prior_start:
            prior[name] = prior.get(name, 0) + 1

    trends = [
        TrendItem(threat_name=name, recent=count, prior=prior.get(name, 0))
        for name, count in recent.items()
        if count >= MIN_ALERTS_FOR_TREND and count > prior.get(name, 0)
    ]
    trends.sort(key=lambda t: (-t.delta, -t.recent, t.threat_name))

    recent_total = sum(recent.values())
    prior_total = sum(prior.values())
    logger.debug(
        "Forecast: %d alerts in the last %dh vs %d before; %d rising type(s)",
        recent_total, WINDOW_HOURS, prior_total, len(trends),
    )

    return ForecastResult(
        status=STATUS_TRENDS if trends else STATUS_NO_TREND,
        generated_at=now,
        recent_total=recent_total,
        prior_total=prior_total,
        trends=trends,
        history_hours=history_hours,
    )
