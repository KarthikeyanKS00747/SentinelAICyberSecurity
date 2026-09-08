"""Rule-based threat detection for parsed SentinelAI log entries."""

from collections import defaultdict

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from models import Alert, AlertStatus, ParsedLogEntry, SeverityLevel, ThreatIntel
from utils.settings_service import get_setting

# Rule-based triage guidance stamped onto each alert at creation time.
RECOMMENDED_ACTIONS = {
    SeverityLevel.CRITICAL: "Block source IP immediately",
    SeverityLevel.HIGH: "Investigate and consider blocking",
    SeverityLevel.MEDIUM: "Monitor for repeated activity",
    SeverityLevel.LOW: "Log for reference",
}

# Fallbacks used only if a setting row is missing or holds an unusable value.
DEFAULT_BRUTE_FORCE_THRESHOLD = 5
DEFAULT_PORT_SCAN_THRESHOLD = 10
DEFAULT_HIGH_VOLUME_THRESHOLD = 50


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
        key = f"BRUTE_FORCE_{source_ip}"
        failed_count = sum(
            1
            for entry in source_entries
            if entry.status and any(value in entry.status.lower() for value in ("fail", "denied"))
        )
        if failed_count >= brute_force_threshold and key not in processed_threats:
            processed_threats.add(key)
            alerts.append(
                Alert(
                    log_file_id=log_file_id,
                    threat_name="Brute Force Attack",
                    severity=SeverityLevel.HIGH,
                    risk_score=85,
                    source_ip=source_ip,
                    description=f"Detected {failed_count} failed authentication attempts from {source_ip}.",
                    recommended_action=RECOMMENDED_ACTIONS[SeverityLevel.HIGH],
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
