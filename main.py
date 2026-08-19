"""SentinelAI FastAPI application entry point (Phase 1 – 4)."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import select, text
from sqlalchemy.exc import OperationalError

import models  # noqa: F401 - registers all ORM models with Base.metadata.
from config import settings
from database import AsyncSessionLocal, Base, engine
from models import SeverityLevel, ThreatIntel
from routers.alerts import router as alerts_router
from routers.dashboard import router as dashboard_router
from routers.health import router as health_router
from routers.logs import router as logs_router

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
    allow_headers=["Content-Type", "Authorization"],
)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "testserver"],
)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Log diagnostics locally without disclosing implementation details."""
    logger.exception("Unhandled error while processing %s", request.url.path, exc_info=exc)
    return JSONResponse(status_code=500, content={"detail": "Internal server error."})


# Phase 4: UI routers registered before the API routers so that
# GET / renders the dashboard instead of the health-check JSON.
app.include_router(dashboard_router)
app.include_router(alerts_router)
# API routers
app.include_router(logs_router)
app.include_router(health_router)
