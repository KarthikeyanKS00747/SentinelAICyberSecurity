"""SentinelAI FastAPI application entry point (Phase 1 – 4)."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy import select, text
from sqlalchemy.exc import OperationalError

import models  # noqa: F401 - registers all ORM models with Base.metadata.
from config import settings
from database import AsyncSessionLocal, Base, engine
from models import ROLE_ADMIN, ROLE_ANALYST, AppSetting, SeverityLevel, ThreatIntel
from routers.abuse import router as abuse_router
from routers.alerts import router as alerts_router
from routers.anomalies import router as anomalies_router
from routers.attack_map import router as attack_map_router
from routers.audit import router as audit_router
from routers.auth import (
    AuthenticationRequired,
    AuthorizationRequired,
    authentication_required_handler,
    authorization_required_handler,
    router as auth_router,
)
from routers.correlation import router as correlation_router
from routers.dashboard import router as dashboard_router
from routers.geo import router as geo_router
from routers.health import router as health_router
from routers.live import router as live_router
from routers.logs import router as logs_router
from routers.mitre import router as mitre_router
from routers.reports import router as reports_router
from routers.response import router as response_router
from routers.settings import router as settings_router
from routers.users import router as users_router

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Create the SQLite schema before accepting requests."""
    settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
        columns = await connection.execute(text("PRAGMA table_info(log_files)"))
        if "alerts_count" not in {row[1] for row in columns.fetchall()}:
            try:
                await connection.execute(text("ALTER TABLE log_files ADD COLUMN alerts_count INTEGER DEFAULT 0"))
            except OperationalError:
                # A concurrent/repeated startup may have added it already.
                logger.info("alerts_count column already exists")
        # create_all() adds missing tables but never missing columns, so new
        # columns on existing tables need their own guarded ALTER.
        columns = await connection.execute(text("PRAGMA table_info(alerts)"))
        if "recommended_action" not in {row[1] for row in columns.fetchall()}:
            try:
                await connection.execute(text("ALTER TABLE alerts ADD COLUMN recommended_action VARCHAR(128)"))
            except OperationalError:
                logger.info("recommended_action column already exists")
        columns = await connection.execute(text("PRAGMA table_info(users)"))
        if "role" not in {row[1] for row in columns.fetchall()}:
            try:
                await connection.execute(
                    text(f"ALTER TABLE users ADD COLUMN role VARCHAR(16) DEFAULT '{ROLE_ANALYST}'")
                )
                # Accounts that predate RBAC were provisioned by hand through
                # seed_admin.py, so they are the operators. Defaulting them to
                # analyst would lock every existing install out of settings,
                # blocking and user management with no way back in. This runs
                # only in the branch that adds the column, so a later analyst
                # account is never promoted by a restart.
                promoted = await connection.execute(
                    text(f"UPDATE users SET role = '{ROLE_ADMIN}' WHERE role IS NULL OR role = '{ROLE_ANALYST}'")
                )
                logger.info(
                    "Added users.role and promoted %d pre-existing account(s) to admin",
                    promoted.rowcount,
                )
            except OperationalError:
                logger.info("role column already exists")
    async with AsyncSessionLocal() as db:
        existing = await db.scalar(select(ThreatIntel.id).limit(1))
        if existing is None:
            db.add_all(
                [
                    ThreatIntel(indicator="192.168.1.100", indicator_type="ip", threat_category="Botnet", risk_level=SeverityLevel.HIGH, source="SentinelAI seed"),
                    ThreatIntel(indicator="10.0.0.50", indicator_type="ip", threat_category="Malware", risk_level=SeverityLevel.CRITICAL, source="SentinelAI seed"),
                    ThreatIntel(indicator="203.0.113.42", indicator_type="ip", threat_category="Brute Forcer", risk_level=SeverityLevel.HIGH, source="SentinelAI seed"),
                ]
            )
            await db.commit()

        existing_setting = await db.scalar(select(AppSetting.id).limit(1))
        if existing_setting is None:
            db.add_all(
                [
                    AppSetting(key="detection.brute_force_threshold", value="5", value_type="int", description="Failed authentication attempts from one source IP before a Brute Force alert is raised."),
                    AppSetting(key="detection.port_scan_threshold", value="10", value_type="int", description="Distinct destination ports contacted by one source IP before a Port Scan alert is raised."),
                    AppSetting(key="detection.high_volume_threshold", value="50", value_type="int", description="Total log entries from one source IP before a High Volume alert is raised."),
                    AppSetting(key="detection.duplicate_cooldown_minutes", value="0", value_type="int", description="Reserved: minutes to suppress repeat alerts for the same rule and IP. Not enforced yet."),
                    AppSetting(key="ollama.explanation_timeout_seconds", value="120", value_type="int", description="Seconds to wait for a local Ollama explanation. Not wired to the request timeout yet."),
                ]
            )
            await db.commit()

        # Seeded per-key rather than in the block above, because that block
        # only fires on a completely empty settings table -- an existing
        # install would otherwise never receive these two rows.
        anomaly_defaults = [
            AppSetting(key="anomaly.contamination", value="0.1", value_type="float", description="Expected share of source IPs the Isolation Forest treats as outliers. Must be within (0, 0.5]."),
            AppSetting(key="anomaly.min_distinct_ips", value="5", value_type="int", description="Distinct source IPs a log file needs before ML anomaly detection runs on it at all."),
        ]
        existing_keys = set(
            (await db.scalars(select(AppSetting.key).where(AppSetting.key.startswith("anomaly.")))).all()
        )
        missing = [setting for setting in anomaly_defaults if setting.key not in existing_keys]
        if missing:
            db.add_all(missing)
            await db.commit()
    yield
    await engine.dispose()


app = FastAPI(
    title=settings.APP_NAME,
    version="0.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization", "X-CSRF-Token"],
)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SECRET_KEY,
    session_cookie="sentinelai_session",
    max_age=8 * 60 * 60,
    same_site="lax",
    https_only=False,  # local prototype is served over plain HTTP
)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "testserver"],
)


app.add_exception_handler(AuthenticationRequired, authentication_required_handler)
app.add_exception_handler(AuthorizationRequired, authorization_required_handler)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Log diagnostics locally without disclosing implementation details."""
    logger.exception("Unhandled error while processing %s", request.url.path, exc_info=exc)
    return JSONResponse(status_code=500, content={"detail": "Internal server error."})


# Phase 4: UI routers registered before the API routers so that
# GET / renders the dashboard instead of the health-check JSON.
app.include_router(auth_router)
app.include_router(dashboard_router)
app.include_router(alerts_router)
app.include_router(anomalies_router)
app.include_router(attack_map_router)
app.include_router(settings_router)
app.include_router(users_router)
app.include_router(audit_router)
# API routers
app.include_router(logs_router)
app.include_router(reports_router)
app.include_router(geo_router)
app.include_router(abuse_router)
app.include_router(response_router)
app.include_router(correlation_router)
app.include_router(mitre_router)
app.include_router(live_router)
app.include_router(health_router)
