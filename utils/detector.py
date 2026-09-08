"""Rule-based threat detection for parsed SentinelAI log entries."""

import logging
from collections import defaultdict
from datetime import datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from models import Alert, AlertStatus, ParsedLogEntry, SeverityLevel, ThreatIntel
from utils.settings_service import get_setting

logger = logging.getLogger(__name__)

# Rule-based triage guidance stamped onto each alert at creation time.
RECOMMENDED_ACTIONS = {
    SeverityLevel.CRITICAL: "Block source IP immediately",
    SeverityLevel.HIGH: "Investigate and consider blocking",
    SeverityLevel.MEDIUM: "Monitor for repeated activity",
    SeverityLevel.LOW: "Log for reference",
}

# Credential compromise needs its own guidance: blocking the source address
# does nothing about an account whose password the attacker now knows.
CREDENTIAL_COMPROMISE_ACTION = "Immediately reset credentials and investigate for compromise."

# Fallbacks used only if a setting row is missing or holds an unusable value.
DEFAULT_BRUTE_FORCE_THRESHOLD = 5
DEFAULT_BRUTE_FORCE_WINDOW_MINUTES = 5
DEFAULT_PORT_SCAN_THRESHOLD = 10
DEFAULT_HIGH_VOLUME_THRESHOLD = 50

# How long after the last failed attempt a success still looks like the
# attacker finally guessing right, rather than the real user logging in later.
# A module constant rather than a setting: the operator-tunable knob for this
# rule is the failure threshold it already shares with brute force.
CREDENTIAL_SUCCESS_WINDOW = timedelta(minutes=30)

# Substrings that mark an entry as a rejected authentication attempt. Kept as
# the single definition used by both the brute-force and credential rules.
FAILURE_MARKERS = ("fail", "denied")
SUCCESS_MARKERS = ("success", "accepted")


def _is_failure(entry: ParsedLogEntry) -> bool:
    """Whether one entry is a rejected authentication attempt."""
    status = (entry.status or "").lower()
    return any(marker in status for marker in FAILURE_MARKERS)


def _is_success(entry: ParsedLogEntry) -> bool:
    """Whether one entry is an accepted authentication."""
    status = (entry.status or "").lower()
    return any(marker in status for marker in SUCCESS_MARKERS)


def max_failures_in_window(
    timestamps: list[datetime], window: timedelta
) -> tuple[int, datetime | None, datetime | None]:
    """Largest number of timestamps falling inside any ``window``-long span.

    Two pointers over the sorted list: ``start`` is advanced until the span
    back to ``timestamps[end]`` fits the window, so each entry is visited at
    most twice and the burstiest stretch is found in one pass.

    Returns the peak count along with the first and last timestamp of the
    window that achieved it, so the alert can say *when* the burst happened
    rather than only how big it was.
    """
    if not timestamps:
        return 0, None, None

    ordered = sorted(timestamps)
    best = 0
    best_span: tuple[datetime | None, datetime | None] = (None, None)
    start = 0
    for end in range(len(ordered)):
        while ordered[end] - ordered[start] > window:
            start += 1
        count = end - start + 1
        if count > best:
            best = count
            best_span = (ordered[start], ordered[end])
    return best, best_span[0], best_span[1]


def _credential_compromise(
    source_entries: list[ParsedLogEntry], failure_threshold: int
) -> dict[str, tuple[int, datetime, datetime]]:
    """Find accounts this IP failed on repeatedly and then logged into.

    Returns ``{username: (failures_before_success, last_failure, success_at)}``
    for every account where at least ``failure_threshold`` failures preceded a
    success that landed within :data:`CREDENTIAL_SUCCESS_WINDOW` of the most
    recent one.

    Grouped per username, not per IP: one address failing three times on
    ``alice`` and three times on ``bob`` before getting into ``carol`` is not
    evidence that carol's password was guessed, and pooling the counts would
    claim it was.

    Only timestamped entries are considered. The rule is a statement about how
    soon the success followed the failures, which cannot be made at all
    without times -- unlike brute force, there is no meaningful flat-count
    fallback, so an untimestamped log simply does not trigger this rule.
    """
    failures_by_user: dict[str, list[datetime]] = defaultdict(list)
    successes_by_user: dict[str, list[datetime]] = defaultdict(list)
    for entry in source_entries:
        if not entry.username or not entry.timestamp:
            continue
        if _is_failure(entry):
            failures_by_user[entry.username].append(entry.timestamp)
        elif _is_success(entry):
            successes_by_user[entry.username].append(entry.timestamp)

    findings: dict[str, tuple[int, datetime, datetime]] = {}
    for username, successes in successes_by_user.items():
        failures = sorted(failures_by_user.get(username, []))
        if len(failures) < failure_threshold:
            continue
        for success_at in sorted(successes):
            preceding = [stamp for stamp in failures if stamp <= success_at]
            if len(preceding) < failure_threshold:
                continue
            last_failure = preceding[-1]
            if success_at - last_failure <= CREDENTIAL_SUCCESS_WINDOW:
                # Earliest qualifying success is the moment of compromise;
                # later ones are the attacker reusing what already worked.
                findings[username] = (len(preceding), last_failure, success_at)
                break
    return findings


async def run_threat_detection(db: AsyncSession, log_file_id: int) -> int:
    """Apply all Phase 3 rules to one uploaded log file and persist alerts.

    Alerts are de-duplicated per rule and source/log file to prevent alert
    fatigue. Malicious-IP matches are combined into one alert for the file.
    """
    # Make re-analysis idempotent: replace this file's alerts rather than
    # accumulating duplicates across repeated detector runs.
    await db.execute(delete(Alert).where(Alert.log_file_id == log_file_id))
    await db.commit()

    entries = list(
        (await db.scalars(select(ParsedLogEntry).where(ParsedLogEntry.log_file_id == log_file_id))).all()
    )
    intel = list((await db.scalars(select(ThreatIntel))).all())
    blacklisted_ips = {record.indicator for record in intel if record.indicator_type == "ip"}

    # Thresholds are operator-tunable via the settings page.
    brute_force_threshold = await get_setting(
        db, "detection.brute_force_threshold", DEFAULT_BRUTE_FORCE_THRESHOLD
    )
    brute_force_window_minutes = await get_setting(
        db, "detection.brute_force_window_minutes", DEFAULT_BRUTE_FORCE_WINDOW_MINUTES
    )
    brute_force_window = timedelta(minutes=brute_force_window_minutes)
    port_scan_threshold = await get_setting(
        db, "detection.port_scan_threshold", DEFAULT_PORT_SCAN_THRESHOLD
    )
    high_volume_threshold = await get_setting(
        db, "detection.high_volume_threshold", DEFAULT_HIGH_VOLUME_THRESHOLD
    )

    alerts: list[Alert] = []
    processed_threats: set[str] = set()
    by_ip: dict[str, list[ParsedLogEntry]] = defaultdict(list)
    for entry in entries:
        if entry.source_ip:
            by_ip[entry.source_ip].append(entry)

    # Rule 1: aggregate blacklisted matches into one file-level alert.
    malicious_ips = sorted(ip for ip in by_ip if ip in blacklisted_ips)
    malicious_key = f"MALICIOUS_IP_FILE_{log_file_id}"
    if malicious_ips and malicious_key not in processed_threats:
        processed_threats.add(malicious_key)
        alerts.append(
            Alert(
                log_file_id=log_file_id,
                threat_name="Malicious IP Activity",
                severity=SeverityLevel.CRITICAL,
                risk_score=95,
                # source_ip is String(45): store one address here and keep the
                # full list in the description so the column cannot overflow.
                source_ip=malicious_ips[0],
                description=f"Activity detected from known malicious IPs: {', '.join(malicious_ips)}",
                recommended_action=RECOMMENDED_ACTIONS[SeverityLevel.CRITICAL],
                status=AlertStatus.OPEN,
            )
        )

    for source_ip, source_entries in by_ip.items():
        # Rule 2: brute force, scored over a rolling window rather than the
        # whole file. Six failures spread across a working day are a user who
        # keeps mistyping their password; six inside five minutes are an
        # attack. The old flat count could not tell those apart.
        key = f"BRUTE_FORCE_{source_ip}"
        failures = [entry for entry in source_entries if _is_failure(entry)]
        failure_timestamps = [entry.timestamp for entry in failures if entry.timestamp]
        burst_count, burst_start, burst_end = max_failures_in_window(
            failure_timestamps, brute_force_window
        )

        if failure_timestamps:
            triggered = burst_count >= brute_force_threshold
            detail = (
                f"{burst_count} failed authentication attempts from {source_ip} "
                f"within {brute_force_window_minutes} minute(s)"
            )
            if burst_start and burst_end:
                detail += f" ({burst_start:%Y-%m-%d %H:%M:%S} to {burst_end:%Y-%m-%d %H:%M:%S})"
            detail += "."
        else:
            # No parseable timestamp on any failure from this IP, so there is
            # no window to slide. Fall back to the previous flat count rather
            # than silently detecting nothing: an unparsed timestamp format is
            # a parser gap, not evidence that the traffic is benign. The
            # description says which basis was used so the alert is not
            # misread as windowed evidence.
            triggered = len(failures) >= brute_force_threshold
            detail = (
                f"{len(failures)} failed authentication attempts from {source_ip} "
                f"(no parseable timestamps; counted across the whole file)."
            )
            if triggered:
                logger.info(
                    "Brute force for %s fell back to a flat count: no timestamps on %d failures",
                    source_ip, len(failures),
                )

        if triggered and key not in processed_threats:
            processed_threats.add(key)
            alerts.append(
                Alert(
                    log_file_id=log_file_id,
                    threat_name="Brute Force Attack",
                    severity=SeverityLevel.HIGH,
                    risk_score=85,
                    source_ip=source_ip,
                    description=f"Detected {detail}",
                    recommended_action=RECOMMENDED_ACTIONS[SeverityLevel.HIGH],
                    status=AlertStatus.OPEN,
                )
            )

        # Rule 3: credential compromise -- the same account failing repeatedly
        # and then succeeding shortly afterwards. Reported separately from
        # brute force because the response differs: brute force is answered by
        # blocking the source, this by resetting the account.
        for username, outcome in _credential_compromise(
            source_entries, brute_force_threshold
        ).items():
            cred_key = f"CREDENTIAL_COMPROMISE_{source_ip}_{username}"
            if cred_key in processed_threats:
                continue
            processed_threats.add(cred_key)
            failure_count, last_failure, success_at = outcome
            alerts.append(
                Alert(
                    log_file_id=log_file_id,
                    threat_name="Credential Compromise Suspected",
                    severity=SeverityLevel.CRITICAL,
                    risk_score=95,
                    source_ip=source_ip,
                    description=(
                        f"Account {username!r} was accessed successfully from {source_ip} at "
                        f"{success_at:%Y-%m-%d %H:%M:%S}, "
                        f"{int((success_at - last_failure).total_seconds() // 60)} minute(s) after "
                        f"{failure_count} failed attempts for the same account "
                        f"(last failure {last_failure:%Y-%m-%d %H:%M:%S}). "
                        f"The credentials may now be known to the attacker."
                    ),
                    recommended_action=CREDENTIAL_COMPROMISE_ACTION,
                    status=AlertStatus.OPEN,
                )
            )

        distinct_ports = {entry.destination_port for entry in source_entries if entry.destination_port is not None}
        is_port_scan = len(distinct_ports) >= port_scan_threshold
        is_high_volume = len(source_entries) >= high_volume_threshold
        activity_count = len(distinct_ports) if is_port_scan else len(source_entries)
        if is_port_scan or is_high_volume:
            key = f"PORT_SCAN_{source_ip}"
            if key not in processed_threats:
                processed_threats.add(key)
                alerts.append(
                    Alert(
                        log_file_id=log_file_id,
                        threat_name="Potential Port Scan / High Volume",
                        severity=SeverityLevel.MEDIUM,
                        risk_score=60,
                        source_ip=source_ip,
                        description=f"IP {source_ip} interacted with {activity_count} distinct ports/events rapidly.",
                        recommended_action=RECOMMENDED_ACTIONS[SeverityLevel.MEDIUM],
                        status=AlertStatus.OPEN,
                    )
                )

    if alerts:
        db.add_all(alerts)
    await db.commit()
    return len(alerts)
