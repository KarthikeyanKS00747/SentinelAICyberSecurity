"""SQLAlchemy ORM schema for SentinelAI's SIEM data."""

import enum
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


def utc_now() -> datetime:
    """Return the current timezone-aware UTC time."""
    return datetime.now(timezone.utc)


class SeverityLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, enum.Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"


class LogFileStatus(str, enum.Enum):
    PENDING = "pending"
    PARSING = "parsing"
    ANALYZED = "analyzed"
    FAILED = "failed"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    log_files: Mapped[list["LogFile"]] = relationship(back_populates="owner")


class LogFile(Base):
    __tablename__ = "log_files"

    id: Mapped[int] = mapped_column(primary_key=True)
    filename: Mapped[str] = mapped_column(String(255))
    file_path: Mapped[str] = mapped_column(String(512), unique=True)
    mime_type: Mapped[str] = mapped_column(String(127))
    file_size_bytes: Mapped[int] = mapped_column(Integer)
    log_type: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[LogFileStatus] = mapped_column(Enum(LogFileStatus), default=LogFileStatus.PENDING)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    analyzed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    alerts_count: Mapped[int] = mapped_column(Integer, default=0)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))

    owner: Mapped["User | None"] = relationship(back_populates="log_files")
    log_entries: Mapped[list["ParsedLogEntry"]] = relationship(
        back_populates="log_file", cascade="all, delete-orphan"
    )
    alerts: Mapped[list["Alert"]] = relationship(back_populates="log_file", cascade="all, delete-orphan")


class ParsedLogEntry(Base):
    __tablename__ = "parsed_log_entries"

    id: Mapped[int] = mapped_column(primary_key=True)
    log_file_id: Mapped[int] = mapped_column(ForeignKey("log_files.id"), index=True)
    line_number: Mapped[int | None] = mapped_column(Integer)
    timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    source_port: Mapped[int | None] = mapped_column(Integer)
    destination_port: Mapped[int | None] = mapped_column(Integer)
    username: Mapped[str | None] = mapped_column(String(128), index=True)
    event_type: Mapped[str | None] = mapped_column(String(128), index=True)
    status: Mapped[str | None] = mapped_column(String(64), index=True)
    message: Mapped[str | None] = mapped_column(Text)
    raw_line: Mapped[str] = mapped_column(Text)

    log_file: Mapped["LogFile"] = relationship(back_populates="log_entries")


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    log_file_id: Mapped[int] = mapped_column(ForeignKey("log_files.id"), index=True)
    threat_name: Mapped[str] = mapped_column(String(128))
    severity: Mapped[SeverityLevel] = mapped_column(Enum(SeverityLevel), index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    source_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    description: Mapped[str] = mapped_column(Text)
    status: Mapped[AlertStatus] = mapped_column(Enum(AlertStatus), default=AlertStatus.OPEN, index=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ai_explanation: Mapped[str | None] = mapped_column(Text)

    log_file: Mapped["LogFile"] = relationship(back_populates="alerts")


class AppSetting(Base):
    """Typed key-value store for runtime-tunable application settings."""

    __tablename__ = "app_settings"

    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    value: Mapped[str] = mapped_column(Text)
    value_type: Mapped[str] = mapped_column(String(16), default="string")
    description: Mapped[str | None] = mapped_column(String(255))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )


class GeoLocation(Base):
    """Cached IP geolocation, filled lazily the first time an IP is displayed.

    Deliberately separate from ThreatIntel: the detector treats every
    ``ThreatIntel`` row with ``indicator_type == "ip"`` as blacklisted, so
    caching benign IPs there would raise false Malicious IP alerts.
    """

    __tablename__ = "geo_locations"

    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(45), unique=True, index=True)
    country: Mapped[str | None] = mapped_column(String(64))
    country_code: Mapped[str | None] = mapped_column(String(2))
    region: Mapped[str | None] = mapped_column(String(64))
    city: Mapped[str | None] = mapped_column(String(64))
    isp: Mapped[str | None] = mapped_column(String(128))
    lat: Mapped[float | None] = mapped_column(Float)
    lon: Mapped[float | None] = mapped_column(Float)
    looked_up_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class AbuseCheck(Base):
    """Cached AbuseIPDB reputation for one IP.

    Separate from GeoLocation and ThreatIntel: abuse scores change over time
    (so rows expire), and ThreatIntel drives the detector's blocklist -- a
    cached lookup must never leak into it.
    """

    __tablename__ = "abuse_checks"

    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(45), unique=True, index=True)
    abuse_confidence_score: Mapped[int] = mapped_column(Integer, default=0)
    total_reports: Mapped[int] = mapped_column(Integer, default=0)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ThreatIntel(Base):
    __tablename__ = "threat_intel"

    id: Mapped[int] = mapped_column(primary_key=True)
    indicator: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    indicator_type: Mapped[str] = mapped_column(String(32), default="ip")
    threat_category: Mapped[str] = mapped_column(String(128))
    risk_level: Mapped[SeverityLevel] = mapped_column(Enum(SeverityLevel), default=SeverityLevel.HIGH)
    confidence: Mapped[float] = mapped_column(Float, default=0.8)
    recommended_action: Mapped[str | None] = mapped_column(String(255))
    source: Mapped[str | None] = mapped_column(String(128))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
