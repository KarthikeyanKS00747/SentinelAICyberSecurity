"""Recording of admin-gated actions to the audit log.

The helper only stages the row; the calling route commits it. That is
deliberate: staging into the same session as the change itself means the
action and its audit record land in one transaction, so a failure cannot
leave a setting changed with nothing recorded against it.

The username is snapshotted onto the row rather than read back through the
relationship, so the history stays readable if the account is later renamed
or removed.
"""

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from models import AuditLog, User

logger = logging.getLogger(__name__)

# Action verbs. Kept as constants so the audit page and the routes cannot
# drift apart on spelling.
ACTION_SETTING_UPDATE = "setting.update"
ACTION_IP_BLOCK = "ip.block"
ACTION_IP_UNBLOCK = "ip.unblock"
ACTION_ROLE_CHANGE = "user.role_change"
ACTION_SIMULATION_START = "simulation.start"
ACTION_2FA_ENABLED = "2fa_enabled"
ACTION_2FA_DISABLED = "2fa_disabled"
ACTION_2FA_RESET = "2fa_reset"

# Human-readable labels and icons for the audit page.
ACTION_LABELS = {
    ACTION_SETTING_UPDATE: ("Setting changed", "fa-sliders", "text-blue-400"),
    ACTION_IP_BLOCK: ("IP blocked", "fa-ban", "text-red-400"),
    ACTION_IP_UNBLOCK: ("Block lifted", "fa-lock-open", "text-green-400"),
    ACTION_ROLE_CHANGE: ("Role changed", "fa-user-shield", "text-amber-400"),
    ACTION_SIMULATION_START: ("Simulation started", "fa-flask", "text-purple-400"),
    ACTION_2FA_ENABLED: ("2FA enabled", "fa-shield-halved", "text-green-400"),
    ACTION_2FA_DISABLED: ("2FA disabled", "fa-shield-halved", "text-amber-400"),
    ACTION_2FA_RESET: ("2FA reset by admin", "fa-key", "text-red-400"),
}

# Column widths in the model; over-long input is trimmed rather than raising,
# because refusing to record an action that already happened is worse than
# recording an abbreviated description of it.
TARGET_MAX = 255


def record_audit(
    db: AsyncSession,
    user: User | None,
    action: str,
    target: str | None = None,
    details: str | None = None,
) -> AuditLog:
    """Stage one audit row on ``db``. The caller must commit."""
    entry = AuditLog(
        user_id=user.id if user else None,
        username=user.username if user else None,
        action=action,
        target=(target or "")[:TARGET_MAX] or None,
        details=details,
    )
    db.add(entry)
    logger.info(
        "AUDIT %s by %s on %s: %s",
        action, user.username if user else "system", target, details,
    )
    return entry


def describe_action(action: str) -> tuple[str, str, str]:
    """Return (label, icon, colour) for one action, with a neutral fallback."""
    return ACTION_LABELS.get(action, (action, "fa-circle-info", "text-slate-400"))
