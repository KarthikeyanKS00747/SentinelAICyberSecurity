# SentinelAI Phase 3 Review Handoff

## Review objective

Review the Phase 3 backend threat-detection implementation for correctness, security, async SQLAlchemy usage, schema compatibility, and alignment with the stated acceptance criteria. Do not propose frontend work; Phase 4 has not started.

## Project context

SentinelAI is an educational SIEM dashboard built with FastAPI, async SQLAlchemy, SQLite, HTMX/Tailwind (future frontend), and local Ollama. Phase 1 foundation and Phase 2 secure upload/parsing are complete.

## Phase 3 changes

### New file

`utils/detector.py`

Defines:

```python
async def run_threat_detection(db: AsyncSession, log_file_id: int) -> int:
    ...
```

Rules implemented:

1. Malicious IP: compares parsed `source_ip` values with local `ThreatIntel.indicator` values and creates a critical alert with risk score 95.
2. Brute force: counts statuses containing `fail` or `denied`; creates a high alert at five or more attempts with risk score 85.
3. Port scan/high volume: uses distinct destination ports when available, otherwise total events; thresholds are 10 distinct ports or 50 events, with a medium alert and risk score 60.

`processed_threats` prevents duplicate alerts for the same rule and source. Malicious-IP matches are intentionally combined into one file-level alert so the acceptance sample returns two alerts rather than one alert per blacklisted IP.

All generated alerts are persisted with one `db.add_all()` and one `await db.commit()`.

### Updated `main.py`

- Seeds ThreatIntel on startup only when the table is empty:
  - `192.168.1.100` — Botnet — High
  - `10.0.0.50` — Malware — Critical
  - `203.0.113.42` — Brute Forcer — High
- Adds a SQLite startup migration for `log_files.alerts_count` when upgrading an existing database.

### Updated `routers/logs.py`

- Commits the uploaded `LogFile` and `ParsedLogEntry` records.
- Calls `run_threat_detection(db, log_file.id)`.
- Stores the generated count in `alerts_count`.
- Returns `alerts_generated` in the response.

### Updated `models.py`

Adds:

```python
alerts_count: Mapped[int] = mapped_column(Integer, default=0)
```

Existing model naming is retained:

- `ThreatIntel.indicator` corresponds to the requested IP address field.
- `ThreatIntel.threat_category` corresponds to category.
- `ThreatIntel.risk_level` uses `SeverityLevel`.
- `Alert.detected_at` corresponds to the requested alert timestamp.

## Acceptance test performed

The eight-line SSH attack sample was uploaded using:

```powershell
curl.exe -X POST http://127.0.0.1:8000/api/logs/upload `
  -F "file=@test_attack.log"
```

Observed response:

```json
{
  "id": 2,
  "filename": "test_attack.log",
  "entries_parsed": 8,
  "alerts_generated": 2,
  "status": "analyzed"
}
```

## Review checklist

Please inspect:

- Whether the detector correctly handles empty/null IPs and statuses.
- Whether alert deduplication semantics are appropriate, especially the aggregated malicious-IP alert.
- Whether committing the upload before detection creates any undesirable partial-failure behavior.
- Whether the SQLite `ALTER TABLE` migration is safe and compatible with the current startup lifecycle.
- Whether thresholds, severity enums, risk scores, and descriptions match the Phase 3 specification.
- Whether async SQLAlchemy queries and commits are used correctly.
- Whether rerunning detection on the same file could create duplicate alerts.
- Whether any security or error-handling issues remain.

## Scope boundary

Do not add HTML, HTMX, Tailwind, charts, Ollama explanation UI, PDF reporting, or other Phase 4/5 functionality during this review.

## Review refinements applied

The checklist recommendations were applied after review:

- Detection now deletes existing alerts for the file before re-analysis, making reruns idempotent.
- Malicious-IP deduplication uses the file-scoped key `MALICIOUS_IP_FILE_<id>`.
- Null/empty source IPs are excluded from grouping and null statuses are ignored safely.
- Detection failures are logged server-side and mark the log file as `FAILED` without exposing a traceback.
- The SQLite `alerts_count` migration retains the existing `PRAGMA` check and also handles a repeated/concurrent `ALTER TABLE` safely.

Post-refinement verification returned `entries_parsed: 8`, `alerts_generated: 2`, and `status: "analyzed"` for the attack sample.
