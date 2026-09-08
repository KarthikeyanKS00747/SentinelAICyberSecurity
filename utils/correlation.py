"""Correlation of multi-stage attack activity from a single source IP.

Reads existing alerts; it never changes what triggers them. The score is
computed live rather than stored -- see ``compute_correlation`` for why.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import Alert, ParsedLogEntry, SeverityLevel
from utils.detector import (
    DEFAULT_BRUTE_FORCE_THRESHOLD,
    DEFAULT_HIGH_VOLUME_THRESHOLD,
    DEFAULT_PORT_SCAN_THRESHOLD,
)
from utils.mitre_mapping import technique_ids
from utils.settings_service import get_setting

logger = logging.getLogger(__name__)

# An IP is only "correlated" once it has triggered more than one attack type.
MIN_DISTINCT_TYPES = 2

# Distinct attack types dominate the score; repeats of the same type add little.
# One IP that both port-scans and brute-forces should outrank one that
# brute-forces five times.
DISTINCT_TYPE_WEIGHT = 40
REPEAT_WEIGHT = 2
REPEAT_CAP = 5
MAX_SCORE = 100
SEVERITY_BONUS = {
    SeverityLevel.CRITICAL: 10,
    SeverityLevel.HIGH: 6,
    SeverityLevel.MEDIUM: 3,
    SeverityLevel.LOW: 0,
}

# Compact names for the chain display.
SHORT_LABELS = {
    "Malicious IP Activity": "Malicious IP",
    "Brute Force Attack": "Brute Force",
    "Potential Port Scan / High Volume": "Port Scan",
    "Credential Compromise Suspected": "Cred. Compromise",
}


@dataclass(frozen=True)
class CorrelationResult:
    """Multi-stage activity summary for one source IP."""

    source_ip: str
    score: int
    distinct_types: int
    total_alerts: int
    chain: list[str]
    # Raw threat_name values behind `chain`, in the same order, so display
    # layers can look up ATT&CK techniques without re-deriving the order.
    chain_raw: list[str] = field(default_factory=list)
    # Activity times from the parsed log, not alert-creation times.
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    max_severity: str | None = None

    @property
    def chain_text(self) -> str:
        return " → ".join(self.chain)

    @property
    def chain_text_with_techniques(self) -> str:
        """Chain annotated with ATT&CK IDs, e.g. "T1046 Port Scan → T1110 Brute Force".

        Purely a label: unmapped rules fall back to the plain name.
        """
        parts: list[str] = []
        for index, label in enumerate(self.chain):
            raw = self.chain_raw[index] if index < len(self.chain_raw) else None
            ids = technique_ids(raw)
            parts.append(f"{'/'.join(ids)} {label}" if ids else label)
        return " → ".join(parts)

    @property
    def band(self) -> str:
        """'high' | 'medium' | 'low' - drives the badge colour."""
        if self.score >= 80:
            return "high"
        if self.score >= 50:
            return "medium"
        return "low"


def normalize_ip(source_ip: str | None) -> str | None:
    """Reduce an alert's source_ip to the single address it is keyed on.

    Rule 1 alerts written before the String(45) fix hold a comma-joined list;
    grouping on the first entry keeps those aligned with newer rows.
    """
    first = (source_ip or "").split(",")[0].strip()
    return first or None


def short_label(threat_name: str) -> str:
    return SHORT_LABELS.get(threat_name, threat_name)


def _score(distinct_types: int, total_alerts: int, max_severity: SeverityLevel | None) -> int:
    """Weight distinct attack types far above repetition of one type."""
    distinct_part = (distinct_types - 1) * DISTINCT_TYPE_WEIGHT
    repeats = min(max(total_alerts - distinct_types, 0), REPEAT_CAP)
    severity_part = SEVERITY_BONUS.get(max_severity, 0) if max_severity else 0
    return min(MAX_SCORE, distinct_part + repeats * REPEAT_WEIGHT + severity_part)


def _as_naive_utc(moment: datetime | None) -> datetime | None:
    """Comparable form: parsed log times are naive, detected_at may be aware."""
    if moment is None:
        return None
    if moment.tzinfo is not None:
        return moment.astimezone(timezone.utc).replace(tzinfo=None)
    return moment


def _in_time_order(entries: list[ParsedLogEntry]) -> list[ParsedLogEntry]:
    """Entries sorted by parsed timestamp; undated ones last."""
    return sorted(
        entries,
        key=lambda e: (e.timestamp is None, _as_naive_utc(e.timestamp) or datetime.max),
    )


def _rule_satisfied_at(
    threat_name: str, entries: list[ParsedLogEntry], thresholds: dict[str, int]
) -> datetime | None:
    """When this rule's condition first became true for these entries.

    Alerts carry no link to the entries that produced them, so this replays
    each rule's own criterion over the IP's entries in time order and returns
    the moment the condition was met. Read-only: nothing here changes what
    the detector does.
    """
    ordered = _in_time_order(entries)
    if not ordered:
        return None

    if threat_name == "Brute Force Attack":
        needed = max(1, int(thresholds["brute_force"]))
        seen = 0
        for entry in ordered:
            status = (entry.status or "").lower()
            if status and any(token in status for token in ("fail", "denied")):
                seen += 1
                if seen >= needed:
                    return entry.timestamp
        return None

    if threat_name == "Potential Port Scan / High Volume":
        ports_needed = max(1, int(thresholds["port_scan"]))
        distinct: set[int] = set()
        for entry in ordered:
            if entry.destination_port is not None:
                distinct.add(entry.destination_port)
                if len(distinct) >= ports_needed:
                    return entry.timestamp
        if distinct:
            return None
        # High-volume branch: no ports were parsed at all.
        volume_needed = max(1, int(thresholds["high_volume"]))
        if len(ordered) >= volume_needed:
            return ordered[volume_needed - 1].timestamp
        return None

    # Malicious IP Activity (and anything new): true as soon as the IP appears.
    return ordered[0].timestamp


async def _load_thresholds(db: AsyncSession) -> dict[str, int]:
    """Same operator-tuned thresholds the detector used, read-only."""
    return {
        "brute_force": await get_setting(
            db, "detection.brute_force_threshold", DEFAULT_BRUTE_FORCE_THRESHOLD
        ),
        "port_scan": await get_setting(
            db, "detection.port_scan_threshold", DEFAULT_PORT_SCAN_THRESHOLD
        ),
        "high_volume": await get_setting(
            db, "detection.high_volume_threshold", DEFAULT_HIGH_VOLUME_THRESHOLD
        ),
    }


async def activity_times(db: AsyncSession, alerts: list[Alert]) -> dict[int, datetime | None]:
    """Map alert id -> the activity time that satisfied its rule."""
    if not alerts:
        return {}

    file_ids = {a.log_file_id for a in alerts if a.log_file_id is not None}
    ips = {ip for ip in (normalize_ip(a.source_ip) for a in alerts) if ip}
    if not file_ids or not ips:
        return {a.id: None for a in alerts}

    entries = list(
        (
            await db.scalars(
                select(ParsedLogEntry).where(
                    ParsedLogEntry.log_file_id.in_(file_ids),
                    ParsedLogEntry.source_ip.in_(ips),
                )
            )
        ).all()
    )
    grouped: dict[tuple[int, str], list[ParsedLogEntry]] = {}
    for entry in entries:
        grouped.setdefault((entry.log_file_id, entry.source_ip), []).append(entry)

    thresholds = await _load_thresholds(db)
    times: dict[int, datetime | None] = {}
    for alert in alerts:
        ip = normalize_ip(alert.source_ip)
        mine = grouped.get((alert.log_file_id, ip), []) if ip else []
        times[alert.id] = _rule_satisfied_at(alert.threat_name, mine, thresholds)
    return times


def _summarise(
    source_ip: str, alerts: list[Alert], activity: dict[int, datetime | None]
) -> CorrelationResult | None:
    """Build a result from one IP's alerts, or None when only one type exists.

    The chain is ordered by when each rule's activity actually happened, not by
    when the alert row was written: a single upload creates every alert
    milliseconds apart, so detected_at only reflects rule-evaluation order.
    """
    def order_key(alert: Alert):
        moment = _as_naive_utc(activity.get(alert.id))
        fallback = _as_naive_utc(alert.detected_at) or datetime.max
        return (moment is None, moment or datetime.max, fallback)

    ordered = sorted(alerts, key=order_key)

    chain: list[str] = []
    chain_raw: list[str] = []
    seen: set[str] = set()
    for alert in ordered:
        if alert.threat_name not in seen:
            seen.add(alert.threat_name)
            chain.append(short_label(alert.threat_name))
            chain_raw.append(alert.threat_name)

    if len(seen) < MIN_DISTINCT_TYPES:
        return None

    severities = [a.severity for a in ordered if a.severity is not None]
    worst = max(severities, key=lambda s: SEVERITY_BONUS.get(s, 0)) if severities else None

    # Same activity times the chain is ordered by, so the whole view agrees on
    # which clock it is showing: when the logged activity happened, not when
    # the alert row was written. None when no entry carried a usable timestamp.
    moments = [m for m in (activity.get(a.id) for a in ordered) if m is not None]

    return CorrelationResult(
        source_ip=source_ip,
        score=_score(len(seen), len(ordered), worst),
        distinct_types=len(seen),
        total_alerts=len(ordered),
        chain=chain,
        chain_raw=chain_raw,
        first_seen=min(moments, key=_as_naive_utc) if moments else None,
        last_seen=max(moments, key=_as_naive_utc) if moments else None,
        max_severity=worst.value if worst else None,
    )


async def compute_correlation(db: AsyncSession, source_ip: str) -> CorrelationResult | None:
    """Score multi-stage activity for one source IP.

    Returns ``None`` when the IP has triggered fewer than two distinct attack
    types, so a single repeated rule never reads as a correlated campaign.

    Computed live, not stored: the score is a property of *all* alerts for an
    IP, so it changes whenever any sibling alert is added or removed. A column
    on Alert would go stale on the next detection run -- and the detector
    deletes and recreates a file's alerts on re-analysis -- so persisting it
    would mean rewriting every sibling row, in code this feature is not
    allowed to touch. The query is a single indexed lookup.
    """
    target = normalize_ip(source_ip)
    if target is None:
        return None

    alerts = list((await db.scalars(select(Alert).where(Alert.source_ip.is_not(None)))).all())
    mine = [a for a in alerts if normalize_ip(a.source_ip) == target]
    if not mine:
        return None
    return _summarise(target, mine, await activity_times(db, mine))


async def correlated_ips(db: AsyncSession) -> list[CorrelationResult]:
    """Every IP showing 2+ distinct attack types, highest score first."""
    alerts = list((await db.scalars(select(Alert).where(Alert.source_ip.is_not(None)))).all())

    grouped: dict[str, list[Alert]] = {}
    for alert in alerts:
        key = normalize_ip(alert.source_ip)
        if key is not None:
            grouped.setdefault(key, []).append(alert)

    activity = await activity_times(db, alerts)
    results = [
        r
        for r in (_summarise(ip, group, activity) for ip, group in grouped.items())
        if r is not None
    ]
    results.sort(key=lambda r: (-r.score, r.source_ip))
    return results
