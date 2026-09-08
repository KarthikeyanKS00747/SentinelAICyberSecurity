"""Demo-only replay of a bundled fixture log, one line at a time.

This is a **simulation**, not log tailing. It exists so the live-push path is
visibly demonstrable without wiring up a real log source: it re-reads a fixture
that already ships with the repo, feeds it into the normal parse -> detect
pipeline one line at a time with an artificial pause, and lets the existing
broadcast carry each newly raised alert to connected browsers.

It reuses ``parse_log`` and ``run_threat_detection`` exactly as the upload path
does; no detection logic is duplicated or altered here. The only unusual part
is that detection re-runs after every line, because the rule engine works on a
whole file at a time.
"""

import asyncio
import logging
from pathlib import Path

from sqlalchemy import select

from database import AsyncSessionLocal
from models import Alert, LogFile, LogFileStatus, ParsedLogEntry
from utils.detector import run_threat_detection
from utils.live_bus import EVENT_SIMULATION, alert_event, manager
from utils.log_parser import parse_log

logger = logging.getLogger(__name__)

# Only these bundled fixtures may be replayed. A whitelist rather than a path
# parameter: the endpoint is authenticated, but there is still no reason to let
# a caller name an arbitrary file on disk.
FIXTURES: dict[str, Path] = {
    "correlation": Path("test_correlation.log"),
    "attack": Path("test_attack.log"),
}
DEFAULT_FIXTURE = "correlation"

# Slow enough to watch a second browser tab react, short enough that a demo of
# the 24-line correlation fixture finishes in about ten seconds.
LINE_DELAY_SECONDS = 0.4

# Prefix on the LogFile row so a replay is never mistaken for a real upload in
# the alerts list, the dashboard, or a PDF report.
SIMULATION_PREFIX = "[SIMULATED]"

# One replay at a time per process. Two concurrent replays would interleave
# their detection passes over different files and make the demo unreadable.
_simulation_lock = asyncio.Lock()


def is_running() -> bool:
    """Whether a replay is currently in progress."""
    return _simulation_lock.locked()


def _alert_key(alert: Alert) -> tuple[str, str]:
    """Identity of an alert across detection re-runs.

    ``run_threat_detection`` deletes and recreates a file's alerts on every
    pass, so row ids change each time. Rule name plus source IP is what
    actually stays stable, and it is what the rule engine already de-duplicates
    on internally.
    """
    return (alert.threat_name, alert.source_ip or "")


async def _replay(fixture_name: str, filename: str, content: bytes) -> None:
    """Feed one fixture through the pipeline line by line, pushing new alerts."""
    lines = [line for line in content.decode("utf-8").splitlines() if line.strip()]
    announced: set[tuple[str, str]] = set()
    total_new = 0

    async with AsyncSessionLocal() as db:
        log_file = LogFile(
            filename=f"{SIMULATION_PREFIX} {filename}",
            # Unique per run: file_path is a unique column, and a replay writes
            # no file of its own.
            file_path=f"simulated://{fixture_name}/{asyncio.get_running_loop().time():.6f}",
            mime_type="text/plain",
            file_size_bytes=len(content),
            log_type="text",
            status=LogFileStatus.PARSING,
        )
        db.add(log_file)
        await db.commit()

        await manager.broadcast(
            {
                "type": EVENT_SIMULATION,
                "state": "started",
                "fixture": fixture_name,
                "filename": log_file.filename,
                "total_lines": len(lines),
            }
        )

        try:
            for index, line in enumerate(lines, start=1):
                # Parse this single line on its own. line_number comes back as
                # 1 every time, so the real position is restored here.
                records = parse_log(f"{line}\n".encode(), filename)
                db.add_all(
                    ParsedLogEntry(
                        log_file_id=log_file.id,
                        line_number=index,
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
                await db.commit()

                # Re-run the unmodified rule engine over everything seen so
                # far, then push only the rules that have newly fired.
                await run_threat_detection(db, log_file.id)
                current = list(
                    (
                        await db.scalars(
                            select(Alert)
                            .where(Alert.log_file_id == log_file.id)
                            .order_by(Alert.id)
                        )
                    ).all()
                )
                for alert in current:
                    key = _alert_key(alert)
                    if key in announced:
                        continue
                    announced.add(key)
                    total_new += 1
                    await manager.broadcast(alert_event(alert))

                await manager.broadcast(
                    {
                        "type": EVENT_SIMULATION,
                        "state": "progress",
                        "line": index,
                        "total_lines": len(lines),
                        "alerts_so_far": total_new,
                    }
                )
                await asyncio.sleep(LINE_DELAY_SECONDS)

            log_file.alerts_count = len(announced)
            log_file.status = LogFileStatus.ANALYZED
            await db.commit()
        except Exception:
            logger.exception("Live simulation of %s failed", fixture_name)
            await db.rollback()
            log_file.status = LogFileStatus.FAILED
            await db.commit()
            await manager.broadcast(
                {"type": EVENT_SIMULATION, "state": "failed", "fixture": fixture_name}
            )
            return

    await manager.broadcast(
        {
            "type": EVENT_SIMULATION,
            "state": "finished",
            "fixture": fixture_name,
            "lines": len(lines),
            "alerts": total_new,
        }
    )
    logger.info(
        "Live simulation of %s finished: %d lines, %d alerts", fixture_name, len(lines), total_new
    )


async def run_simulation(fixture_name: str) -> None:
    """Replay one whitelisted fixture, holding the single-run lock throughout.

    Returns immediately if another replay is already in flight, so a background
    task started for a rejected request cannot pile up behind the first.
    """
    fixture = FIXTURES.get(fixture_name)
    if fixture is None:
        logger.warning("Refusing to simulate unknown fixture %r", fixture_name)
        return
    if _simulation_lock.locked():
        logger.info("Simulation already running; ignoring request for %r", fixture_name)
        return

    async with _simulation_lock:
        try:
            content = fixture.read_bytes()
        except OSError:
            logger.exception("Could not read simulation fixture %s", fixture)
            await manager.broadcast(
                {"type": EVENT_SIMULATION, "state": "failed", "fixture": fixture_name}
            )
            return
        await _replay(fixture_name, fixture.name, content)
