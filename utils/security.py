"""Password hashing and session-bound CSRF helpers.

Kept out of the routers so both ``routers/auth.py`` and the ``utils.seed_admin``
command line can share one hashing configuration.
"""

import secrets

from passlib.context import CryptContext

# bcrypt truncates at 72 bytes; reject longer secrets rather than silently
# ignoring the tail of a passphrase.
MAX_PASSWORD_BYTES = 72
MIN_PASSWORD_LENGTH = 8
SESSION_CSRF_KEY = "csrf_token"
CSRF_HEADER_NAME = "X-CSRF-Token"
CSRF_FORM_FIELD = "csrf_token"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Return a bcrypt hash for ``password``."""
    validate_password_strength(password)
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Check ``password`` against a stored bcrypt hash."""
    try:
        return pwd_context.verify(password, password_hash)
    except ValueError:
        # Malformed or unsupported hash in the database.
        return False


def dummy_verify() -> None:
    """Burn the same time as a real verify when the username does not exist."""
    pwd_context.dummy_verify()


def validate_password_strength(password: str) -> None:
    """Raise ``ValueError`` when a password cannot be stored safely."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.")
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise ValueError(f"Password must be at most {MAX_PASSWORD_BYTES} bytes long.")


def issue_csrf_token(session) -> str:
    """Return this session's CSRF token, creating one on first use."""
    token = session.get(SESSION_CSRF_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[SESSION_CSRF_KEY] = token
    return token


def rotate_csrf_token(session) -> str:
    """Force a fresh token, e.g. right after a privilege change."""
    session[SESSION_CSRF_KEY] = secrets.token_urlsafe(32)
    return session[SESSION_CSRF_KEY]


def csrf_token_matches(session, submitted: str | None) -> bool:
    """Constant-time comparison of a submitted token against the session's."""
    expected = session.get(SESSION_CSRF_KEY)
    if not expected or not submitted:
        return False
    return secrets.compare_digest(str(expected), str(submitted))
