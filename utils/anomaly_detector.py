"""Unsupervised ML anomaly detection over parsed log entries (Isolation Forest).

This is a *second* detection layer that runs alongside -- never instead of --
the rule-based detector in :mod:`utils.detector`. The two answer different
questions:

* the rule engine asks "did this IP do a thing we already know is bad?"
* this module asks "does this IP behave unlike the other IPs in the same file?"

Everything is fit at analysis time on the file's own source-IP population, so
there is no pre-trained model, no external dataset, and no labels. The cost of
that is relativity: a score only means "unusual *for this upload*", and a file
whose IPs are all attackers will still report most of them as normal. Scores
are therefore never turned into severities or triage actions.

A failure here must not affect rule-based detection, so the public entry point
returns a result object describing what happened instead of raising, in the
same spirit as the geolocation and AbuseIPDB helpers.
"""

import json
import logging
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from models import AnomalyAlert, ParsedLogEntry
from utils.settings_service import get_setting

logger = logging.getLogger(__name__)

# scikit-learn is an optional heavyweight dependency: if the deployment has not
# installed it, ML detection reports itself unavailable and the rule engine is
# entirely unaffected.
try:  # pragma: no cover - exercised only by the absence of the package
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    SKLEARN_AVAILABLE = True
except ImportError:  # pragma: no cover
    IsolationForest = None  # type: ignore[assignment]
    StandardScaler = None  # type: ignore[assignment]
    SKLEARN_AVAILABLE = False

# Fallbacks used only when the matching setting row is missing or unusable.
DEFAULT_CONTAMINATION = 0.1
DEFAULT_MIN_DISTINCT_IPS = 5

# Isolation Forest sub-samples and randomises its splits, so a fixed seed is
# what makes two runs over the same file return the same scores. Change the
# file's IP population and the scores legitimately move -- they are relative.
RANDOM_STATE = 42
N_ESTIMATORS = 100

# Same failure vocabulary the rule engine uses, so "failed login" means the
# same thing in both layers.
FAILURE_MARKERS = ("fail", "denied")

FEATURE_NAMES = (
    "total_requests",
    "distinct_ports",
    "failed_login_count",
    "failed_login_ratio",
    "distinct_destination_ips",
    "hour_of_day",
    "entries_per_minute",
)

# Human-readable phrasing for the "what drove this" explanation.
FEATURE_LABELS = {
    "total_requests": "log entries",
    "distinct_ports": "distinct destination ports",
    "failed_login_count": "failed logins",
    "failed_login_ratio": "failed-login ratio",
    "distinct_destination_ips": "distinct destination IPs",
    "hour_of_day": "activity hour",
    "entries_per_minute": "entries per minute",
}

# Hours treated as "off-hours" when explaining an unusual hour_of_day.
OFF_HOURS = frozenset(range(0, 6))

# A feature is only worth naming once it is this many robust deviations from
# the population centre; below that it is noise, not an explanation.
MIN_DEVIATION_TO_REPORT = 1.0
MAX_CONTRIBUTING_FEATURES = 4

# Several features restate the same underlying behaviour -- an IP that sends a
# lot of traffic is high on all four "volume" features at once. Ranking purely
# by deviation therefore fills the whole explanation with one story and buries
# independent ones, so at most two features per family are named.
FEATURE_FAMILIES = {
    "total_requests": "volume",
    "failed_login_count": "volume",
    "failed_login_ratio": "volume",
    "entries_per_minute": "volume",
    "distinct_ports": "breadth",
    "distinct_destination_ips": "breadth",
    "hour_of_day": "timing",
}
MAX_PER_FAMILY = 2

# Skip reasons surfaced to the UI.
SKIP_NO_SKLEARN = "sklearn_unavailable"
SKIP_TOO_FEW_IPS = "too_few_ips"
SKIP_NO_ENTRIES = "no_entries"
SKIP_FAILED = "failed"


@dataclass(frozen=True)
class IPFeatures:
    """The behavioural fingerprint of one source IP within one log file."""

    source_ip: str
    total_requests: int
    distinct_ports: int
    failed_login_count: int
    failed_login_ratio: float
    distinct_destination_ips: int
    hour_of_day: int
    entries_per_minute: float

    def vector(self) -> list[float]:
        """Feature values in ``FEATURE_NAMES`` order, for the model matrix."""
        return [float(getattr(self, name)) for name in FEATURE_NAMES]

    def as_dict(self) -> dict[str, float]:
        return {name: getattr(self, name) for name in FEATURE_NAMES}


@dataclass(frozen=True)
class ContributingFeature:
    """One feature that pushed an IP away from the rest of the population."""

    feature: str
    value: float
    direction: str  # "high" or "low", relative to the population median
    deviation: float  # robust deviations from that median
    label: str  # ready-to-display phrasing

    def as_dict(self) -> dict[str, object]:
        return {
            "feature": self.feature,
            "value": self.value,
            "direction": self.direction,
            "deviation": round(self.deviation, 2),
            "label": self.label,
        }


@dataclass(frozen=True)
class AnomalyResult:
    """Per-IP verdict from one fitted model."""

    source_ip: str
    anomaly_score: float  # 0-100, higher means more unusual
    is_anomaly: bool
    features: IPFeatures
    contributing_features: list[ContributingFeature] = field(default_factory=list)

    @property
    def explanation(self) -> str:
        """One-line summary of why this IP stood out."""
        if not self.contributing_features:
            return "No single feature dominates; the overall combination is unusual."
        return " and ".join(item.label for item in self.contributing_features)


@dataclass(frozen=True)
class AnomalyDetectionResult:
    """Outcome of one ML pass over one log file."""

    log_file_id: int
    ip_count: int = 0
    results: list[AnomalyResult] = field(default_factory=list)
    anomalies_recorded: int = 0
    skipped: bool = False
    skip_reason: str | None = None
    message: str = ""


# -- feature extraction ----------------------------------------------
def _is_failed(entry: ParsedLogEntry) -> bool:
    """Whether one entry represents a rejected authentication/access attempt."""
    haystack = " ".join(part.lower() for part in (entry.status, entry.event_type) if part)
    return any(marker in haystack for marker in FAILURE_MARKERS)


def _entries_per_minute(timestamps: list[datetime], total: int) -> float:
    """Burst rate over the IP's own active window.

    An IP seen at a single instant (or with no usable timestamps) has no
    measurable window, so its whole volume is charged to one minute -- which is
    the honest reading of "all of it arrived at once".
    """
    if len(timestamps) < 2:
        return float(total)
    span_seconds = (max(timestamps) - min(timestamps)).total_seconds()
    if span_seconds <= 0:
        return float(total)
    return total / (span_seconds / 60.0)


def extract_features(entries: list[ParsedLogEntry]) -> list[IPFeatures]:
    """Build one feature row per source IP from a log file's parsed entries.

    Entries without a source IP are ignored: the whole feature set is defined
    per source IP, so there is nothing to attribute them to.
    """
    by_ip: dict[str, list[ParsedLogEntry]] = defaultdict(list)
    for entry in entries:
        if entry.source_ip:
            by_ip[entry.source_ip].append(entry)

    features: list[IPFeatures] = []
    for source_ip, ip_entries in sorted(by_ip.items()):
        total = len(ip_entries)
        failed = sum(1 for entry in ip_entries if _is_failed(entry))
        timestamps = sorted(entry.timestamp for entry in ip_entries if entry.timestamp)
        # Timestamps are optional in the parser; an IP with none gets hour 0,
        # which the population comparison then treats like any other hour.
        hour = timestamps[0].hour if timestamps else 0
        features.append(
            IPFeatures(
                source_ip=source_ip,
                total_requests=total,
                distinct_ports=len(
                    {e.destination_port for e in ip_entries if e.destination_port is not None}
                ),
                failed_login_count=failed,
                failed_login_ratio=round(failed / total, 4) if total else 0.0,
                distinct_destination_ips=len(
                    {e.destination_ip for e in ip_entries if e.destination_ip}
                ),
                hour_of_day=hour,
                entries_per_minute=round(_entries_per_minute(timestamps, total), 3),
            )
        )
    return features


# -- explanation -----------------------------------------------------
def _robust_spread(values: list[float], median: float) -> float:
    """Median absolute deviation, falling back to stdev and then to a floor.

    MAD is used rather than a plain standard deviation because the outlier we
    are explaining is itself in the sample and would inflate the latter.
    """
    mad = statistics.median(abs(value - median) for value in values)
    if mad > 0:
        return mad
    if len(values) > 1:
        spread = statistics.pstdev(values)
        if spread > 0:
            return spread
    return 1.0


def _format_value(value: float) -> str:
    """Show whole numbers whole and fractional values to two decimals."""
    return f"{int(value)}" if float(value).is_integer() else f"{value:.2f}"


def _phrase(feature: str, value: float, direction: str) -> str:
    """Readable phrasing for one contributing feature."""
    if feature == "hour_of_day":
        hour = int(value)
        suffix = "AM" if hour < 12 else "PM"
        display = hour % 12 or 12
        if hour in OFF_HOURS:
            return f"off-hours activity ({display} {suffix})"
        return f"unusual activity hour ({display} {suffix})"
    label = FEATURE_LABELS.get(feature, feature)
    qualifier = "unusually high" if direction == "high" else "unusually low"
    return f"{qualifier} {label} ({_format_value(value)})"


def explain_features(target: IPFeatures, population: list[IPFeatures]) -> list[ContributingFeature]:
    """Name the features on which ``target`` most departs from its peers.

    The forest itself gives a single opaque score; this reconstructs a plain
    reading of it by ranking each feature's robust deviation from the file's
    median. It explains *the same inputs*, not the forest's internal splits, so
    it is indicative rather than an exact attribution.
    """
    contributions: list[ContributingFeature] = []
    for name in FEATURE_NAMES:
        values = [float(getattr(item, name)) for item in population]
        median = statistics.median(values)
        value = float(getattr(target, name))
        deviation = abs(value - median) / _robust_spread(values, median)
        if deviation < MIN_DEVIATION_TO_REPORT:
            continue
        direction = "high" if value > median else "low"
        contributions.append(
            ContributingFeature(
                feature=name,
                value=value,
                direction=direction,
                deviation=deviation,
                label=_phrase(name, value, direction),
            )
        )
    contributions.sort(key=lambda item: item.deviation, reverse=True)

    chosen: list[ContributingFeature] = []
    used: dict[str, int] = defaultdict(int)
    for item in contributions:
        family = FEATURE_FAMILIES.get(item.feature, item.feature)
        if used[family] >= MAX_PER_FAMILY:
            continue
        used[family] += 1
        chosen.append(item)
        if len(chosen) == MAX_CONTRIBUTING_FEATURES:
            break
    return chosen


# -- model -----------------------------------------------------------
def _to_score(decision_value: float) -> float:
    """Map an Isolation Forest decision value onto a 0-100 "unusualness" scale.

    ``decision_function`` is negative for points the forest considers outliers
    and positive for inliers, roughly within +/-0.5. Mapping it absolutely
    rather than min-max normalising the batch keeps a quiet file from
    manufacturing a 100-scoring IP just because something has to be the worst.
    """
    return round(min(100.0, max(0.0, 50.0 - decision_value * 100.0)), 2)


def score_ips(
    features: list[IPFeatures], contamination: float = DEFAULT_CONTAMINATION
) -> list[AnomalyResult]:
    """Fit an Isolation Forest on this population and score every IP in it.

    Returns one :class:`AnomalyResult` per input IP, most unusual first. The
    caller is responsible for having checked the population is large enough to
    be worth fitting at all.
    """
    if not SKLEARN_AVAILABLE:
        raise RuntimeError("scikit-learn is not installed")

    matrix = [item.vector() for item in features]
    # Features live on wildly different scales (a port count of 18 next to a
    # ratio of 0.8); standardising stops raw magnitude from deciding the split.
    scaled = StandardScaler().fit_transform(matrix)
    model = IsolationForest(
        n_estimators=N_ESTIMATORS,
        contamination=contamination,
        random_state=RANDOM_STATE,
    )
    model.fit(scaled)
    decisions = model.decision_function(scaled)
    predictions = model.predict(scaled)

    results = [
        AnomalyResult(
            source_ip=item.source_ip,
            anomaly_score=_to_score(float(decision)),
            is_anomaly=bool(prediction == -1),
            features=item,
            contributing_features=explain_features(item, features),
        )
        for item, decision, prediction in zip(features, decisions, predictions)
    ]
    results.sort(key=lambda result: result.anomaly_score, reverse=True)
    return results


# -- entry point -----------------------------------------------------
async def run_anomaly_detection(db: AsyncSession, log_file_id: int) -> AnomalyDetectionResult:
    """Run the ML pass over one log file and persist the flagged IPs.

    Never raises: every failure path returns a skipped result carrying the
    reason, so the caller can log it and leave the rule-based alerts alone.
    Re-running replaces this file's previous anomaly rows rather than appending
    to them, matching the rule engine's re-analysis behaviour.
    """
    if not SKLEARN_AVAILABLE:
        return AnomalyDetectionResult(
            log_file_id=log_file_id,
            skipped=True,
            skip_reason=SKIP_NO_SKLEARN,
            message="ML anomaly detection skipped: scikit-learn is not installed.",
        )

    try:
        contamination = await get_setting(db, "anomaly.contamination", DEFAULT_CONTAMINATION)
        min_distinct_ips = await get_setting(
            db, "anomaly.min_distinct_ips", DEFAULT_MIN_DISTINCT_IPS
        )
        # IsolationForest rejects anything outside (0, 0.5]; a bad setting must
        # degrade to the default rather than take the whole layer offline.
        if not 0 < contamination <= 0.5:
            logger.warning(
                "anomaly.contamination %r is outside (0, 0.5]; using %r",
                contamination,
                DEFAULT_CONTAMINATION,
            )
            contamination = DEFAULT_CONTAMINATION

        entries = list(
            (
                await db.scalars(
                    select(ParsedLogEntry).where(ParsedLogEntry.log_file_id == log_file_id)
                )
            ).all()
        )
        features = extract_features(entries)
        ip_count = len(features)

        if ip_count == 0:
            return AnomalyDetectionResult(
                log_file_id=log_file_id,
                skipped=True,
                skip_reason=SKIP_NO_ENTRIES,
                message="ML anomaly detection skipped: no entries carry a source IP.",
            )
        if ip_count < min_distinct_ips:
            # Fitting an outlier model on a handful of points produces
            # confident-looking noise; refusing is the honest answer.
            return AnomalyDetectionResult(
                log_file_id=log_file_id,
                ip_count=ip_count,
                skipped=True,
                skip_reason=SKIP_TOO_FEW_IPS,
                message=(
                    f"ML anomaly detection skipped: only {ip_count} distinct source "
                    f"IP{'s' if ip_count != 1 else ''} in this file, and at least "
                    f"{min_distinct_ips} are needed to fit a meaningful model."
                ),
            )

        results = score_ips(features, contamination=contamination)

        await db.execute(delete(AnomalyAlert).where(AnomalyAlert.log_file_id == log_file_id))
        flagged = [result for result in results if result.is_anomaly]
        db.add_all(
            AnomalyAlert(
                log_file_id=log_file_id,
                source_ip=result.source_ip,
                anomaly_score=result.anomaly_score,
                contributing_features=json.dumps(
                    {
                        "summary": result.explanation,
                        "features": [item.as_dict() for item in result.contributing_features],
                        "all_features": result.features.as_dict(),
                    }
                ),
            )
            for result in flagged
        )
        await db.commit()
        return AnomalyDetectionResult(
            log_file_id=log_file_id,
            ip_count=ip_count,
            results=results,
            anomalies_recorded=len(flagged),
            message=(
                f"Isolation Forest scored {ip_count} source IPs and flagged "
                f"{len(flagged)} as anomalous."
            ),
        )
    except Exception:
        logger.exception("ML anomaly detection failed for log file %s", log_file_id)
        await db.rollback()
        return AnomalyDetectionResult(
            log_file_id=log_file_id,
            skipped=True,
            skip_reason=SKIP_FAILED,
            message="ML anomaly detection failed; rule-based alerts are unaffected.",
        )


def parse_contributing_features(raw: str | None) -> dict[str, object]:
    """Decode a stored ``contributing_features`` blob for display.

    Returns an empty structure for missing or malformed JSON so one bad row
    cannot break the page rendering it.
    """
    empty: dict[str, object] = {"summary": "", "features": [], "all_features": {}}
    if not raw:
        return empty
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        logger.warning("Unreadable contributing_features payload; rendering it as empty")
        return empty
    if not isinstance(data, dict):
        return empty
    for key, fallback in empty.items():
        data.setdefault(key, fallback)
    return data
