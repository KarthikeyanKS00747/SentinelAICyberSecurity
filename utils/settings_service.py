"""Typed read/write helpers for the AppSetting key-value store.

Settings are stored as strings alongside a ``value_type`` so callers get a
correctly typed value back. Kept out of the routers so the detector can read
thresholds without importing web code.
"""

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import AppSetting

logger = logging.getLogger(__name__)

TRUE_VALUES = {"true", "1", "yes", "on"}
FALSE_VALUES = {"false", "0", "no", "off"}
VALUE_TYPES = ("int", "float", "bool", "string")
NUMERIC_TYPES = ("int", "float")
# Narrow exemption: 0 is this setting's meaningful "disabled" state, not a
# broken value. Every other numeric setting must still be greater than zero.
ZERO_ALLOWED_KEYS = frozenset({"detection.duplicate_cooldown_minutes"})


def _to_bool(raw: str) -> bool:
    lowered = raw.strip().lower()
    if lowered in TRUE_VALUES:
        return True
    if lowered in FALSE_VALUES:
        return False
    raise ValueError("Enter a boolean value (true or false).")


def cast_value(raw: str, value_type: str) -> Any:
    """Convert a stored string into its declared type.

    Raises ``ValueError`` with a message suitable for showing to the user.
    """
    text = (raw or "").strip()
    if value_type == "int":
        try:
            return int(text)
        except ValueError:
            raise ValueError("Enter a whole number.") from None
    if value_type == "float":
        try:
            return float(text)
        except ValueError:
            raise ValueError("Enter a number.") from None
    if value_type == "bool":
        return _to_bool(text)
    if value_type == "string":
        return text
    raise ValueError(f"Unsupported value type {value_type!r}.")


def validate_numeric_range(typed: Any, value_type: str, key: str = "") -> None:
    """Reject non-positive numbers for int/float settings.

    A zero or negative threshold or timeout disables detection or explanations
    silently; failing the write loudly is better than shipping a dead rule.
    Keys in ``ZERO_ALLOWED_KEYS`` may be zero but still not negative. Applied
    on write only, so values already stored are still readable.
    """
    if value_type not in NUMERIC_TYPES:
        return
    if key in ZERO_ALLOWED_KEYS:
        if typed < 0:
            raise ValueError("Enter zero or a positive value.")
        return
    if typed <= 0:
        raise ValueError("Enter a value greater than zero.")


async def get_setting(db: AsyncSession, key: str, default: Any = None) -> Any:
    """Return one setting's typed value, or ``default`` when it is unusable.

    Never raises: a missing row or a corrupted value falls back to ``default``
    so a bad setting cannot take detection offline.
    """
    setting = await db.scalar(select(AppSetting).where(AppSetting.key == key))
    if setting is None:
        logger.warning("Setting %s is not configured; using default %r", key, default)
        return default
    try:
        return cast_value(setting.value, setting.value_type)
    except ValueError:
        logger.warning(
            "Setting %s holds %r which is not a valid %s; using default %r",
            key, setting.value, setting.value_type, default,
        )
        return default


async def update_setting(db: AsyncSession, key: str, value: str) -> AppSetting:
    """Validate and persist one setting.

    Raises ``LookupError`` for an unknown key and ``ValueError`` when the
    submitted value does not match the setting's declared type or, for
    numeric settings, is not greater than zero.
    """
    setting = await db.scalar(select(AppSetting).where(AppSetting.key == key))
    if setting is None:
        raise LookupError(key)

    # Both raise ValueError, which the router turns into a 422 with the message.
    typed = cast_value(value, setting.value_type)
    validate_numeric_range(typed, setting.value_type, setting.key)
    setting.value = str(typed).lower() if setting.value_type == "bool" else str(typed)
    await db.commit()
    await db.refresh(setting)
    logger.info("Setting %s updated to %r", key, setting.value)
    return setting
