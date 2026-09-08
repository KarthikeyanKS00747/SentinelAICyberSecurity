"""TOTP secret handling and QR rendering for two-factor authentication.

Kept out of the routers so the login flow, the self-service 2FA page and the
admin reset action all share one definition of what a valid code is.

Scope note for a course project: this is TOTP only. There are no backup codes,
and a code stays valid for its whole time step -- a code observed in transit
could be replayed within that window by an attacker who also has the password.
Defeating that needs a per-user record of the last consumed time step, which is
a third column and beyond what this task asked for. The recovery path for a
lost authenticator is the admin reset documented in the README, not backup
codes.
"""

import base64
import io
import logging

import pyotp
import qrcode

logger = logging.getLogger(__name__)

# Shown in the authenticator app's account list.
TOTP_ISSUER = "SentinelAI"

# One step either side of now, i.e. codes stay usable for roughly 30 seconds
# before and after their own window. Covers ordinary phone/server clock drift
# without widening the guessing surface much.
VALID_WINDOW = 1

# Codes are always six digits; anything else is rejected before pyotp is asked,
# so a long or non-numeric submission cannot reach the comparison at all.
CODE_LENGTH = 6


def generate_secret() -> str:
    """Return a fresh base32 TOTP secret."""
    return pyotp.random_base32()


def provisioning_uri(secret: str, username: str) -> str:
    """Build the otpauth:// URI an authenticator app scans."""
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=TOTP_ISSUER)


def normalise_code(code: str | None) -> str:
    """Strip spaces and separators an authenticator app may display."""
    return "".join(ch for ch in (code or "") if ch.isdigit())


def verify_code(secret: str | None, code: str | None) -> bool:
    """Whether ``code`` is currently valid for ``secret``.

    Never raises and never logs the code or the secret: a malformed secret or
    a garbage submission is simply a failed check.
    """
    if not secret:
        return False
    digits = normalise_code(code)
    if len(digits) != CODE_LENGTH:
        return False
    try:
        return pyotp.TOTP(secret).verify(digits, valid_window=VALID_WINDOW)
    except Exception:  # noqa: BLE001 - an unusable secret is a failed check.
        logger.warning("TOTP verification failed for an unusable secret")
        return False


def qr_data_uri(secret: str, username: str) -> str:
    """Render the provisioning URI as a base64 PNG ``data:`` URI.

    Embedded in the page rather than served from its own endpoint so the
    secret never appears in a URL, a browser history entry, or an access log.
    """
    image = qrcode.make(provisioning_uri(secret, username))
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def format_secret_for_display(secret: str) -> str:
    """Group the secret in fours for manual entry when a camera is unavailable."""
    return " ".join(secret[index:index + 4] for index in range(0, len(secret), 4))
