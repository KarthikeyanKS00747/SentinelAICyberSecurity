"""Self-service two-factor authentication - Phase 14.

Provides:
  GET  /settings/2fa       - Enrollment QR, or the enabled state with a
                             disable form.
  POST /api/2fa/enable     - Confirm a scanned secret with a live code.
  POST /api/2fa/disable    - Turn the second factor off, password required.

Every route here acts on the caller's *own* account only. There is no user id
in any path or form field, so one signed-in user cannot touch another's second
factor; the admin equivalent lives on the users page and is gated separately.
Not admin-gated: an analyst securing their own login is exactly the point.
"""

import logging

from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import User
from routers.auth import get_current_user, require_csrf
from utils.audit import ACTION_2FA_DISABLED, ACTION_2FA_ENABLED, record_audit
from utils.security import verify_password
from utils.totp import (
    format_secret_for_display,
    generate_secret,
    qr_data_uri,
    verify_code,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Two-Factor"])
templates = Jinja2Templates(directory="templates")

PAGE_PATH = "/settings/2fa"

# The secret being enrolled lives in the session until a live code proves the
# user actually scanned it. Keeping it out of the database until then means an
# abandoned enrollment leaves no row behind, and a stored secret always
# corresponds to a working authenticator.
PENDING_SECRET_KEY = "pending_totp_secret"


def _tpl(name: str, request: Request, status_code: int = 200, **ctx):
    """Compatibility wrapper for Starlette >=1.x TemplateResponse."""
    return templates.TemplateResponse(request=request, name=name, context=ctx, status_code=status_code)


def _enrollment_secret(request: Request) -> str:
    """The secret currently being enrolled, generating one on first view.

    Reused across reloads on purpose: regenerating per request would silently
    invalidate the QR code the user already scanned, and their first code
    would then fail for no visible reason.
    """
    secret = request.session.get(PENDING_SECRET_KEY)
    if not secret:
        secret = generate_secret()
        request.session[PENDING_SECRET_KEY] = secret
    return secret


def _render_page(
    request: Request,
    current_user: User,
    status_code: int = 200,
    error: str | None = None,
    notice: str | None = None,
) -> HTMLResponse:
    """Render the 2FA page in whichever state the account is in."""
    context: dict[str, object] = {
        "current_user": current_user,
        "error": error,
        "notice": notice,
        "enabled": current_user.totp_enabled,
    }
    if not current_user.totp_enabled:
        secret = _enrollment_secret(request)
        context["secret_display"] = format_secret_for_display(secret)
        context["qr_data_uri"] = qr_data_uri(secret, current_user.username)
    return _tpl("settings_2fa.html", request, status_code=status_code, **context)


# -- GET /settings/2fa -----------------------------------------------
@router.get(PAGE_PATH, response_class=HTMLResponse)
async def two_factor_page(
    request: Request,
    current_user: User = Depends(get_current_user),
) -> HTMLResponse:
    """Show enrollment or the enabled state for the signed-in user."""
    return _render_page(request, current_user)


# -- POST /api/2fa/enable --------------------------------------------
@router.post("/api/2fa/enable", response_class=HTMLResponse)
async def enable_two_factor(
    request: Request,
    code: str = Form(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _csrf: None = Depends(require_csrf),
) -> HTMLResponse:
    """Turn on 2FA, but only after a code proves the secret was scanned."""
    if current_user.totp_enabled:
        return _render_page(request, current_user, notice="Two-factor authentication is already on.")

    secret = request.session.get(PENDING_SECRET_KEY)
    if not secret:
        # Session lost the secret (expired cookie, different browser). Start
        # over rather than enabling something the user cannot generate codes for.
        return _render_page(
            request, current_user,
            status_code=status.HTTP_400_BAD_REQUEST,
            error="That enrollment expired. Scan the new QR code below and try again.",
        )

    if not verify_code(secret, code):
        logger.info("User #%d submitted an invalid 2FA enrollment code", current_user.id)
        return _render_page(
            request, current_user,
            status_code=status.HTTP_401_UNAUTHORIZED,
            error="That code is not valid. Make sure the app is showing the SentinelAI entry, then try again.",
        )

    current_user.totp_secret = secret
    current_user.totp_enabled = True
    record_audit(
        db, current_user, ACTION_2FA_ENABLED,
        target=f"user #{current_user.id} ({current_user.username})",
        details="two-factor authentication enabled by the account owner",
    )
    await db.commit()
    await db.refresh(current_user)
    request.session.pop(PENDING_SECRET_KEY, None)
    logger.info("User #%d enabled 2FA", current_user.id)

    return _render_page(
        request, current_user,
        notice="Two-factor authentication is on. You will be asked for a code at your next sign-in.",
    )


# -- POST /api/2fa/disable -------------------------------------------
@router.post("/api/2fa/disable", response_class=HTMLResponse)
async def disable_two_factor(
    request: Request,
    password: str = Form(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _csrf: None = Depends(require_csrf),
) -> HTMLResponse:
    """Turn off 2FA, requiring the account password rather than a bare click.

    A click alone would let anyone who walks up to an unlocked browser strip
    the second factor off the account, which is most of what it was protecting
    against.
    """
    if not current_user.totp_enabled:
        return _render_page(request, current_user, notice="Two-factor authentication is already off.")

    if not verify_password(password, current_user.password_hash):
        logger.warning("User #%d gave a wrong password when disabling 2FA", current_user.id)
        return _render_page(
            request, current_user,
            status_code=status.HTTP_401_UNAUTHORIZED,
            error="That password is not correct. Two-factor authentication is still on.",
        )

    current_user.totp_enabled = False
    # The secret is cleared too, so re-enrolling always issues a fresh one
    # rather than silently reviving a secret the user may have deleted from
    # their authenticator app.
    current_user.totp_secret = None
    record_audit(
        db, current_user, ACTION_2FA_DISABLED,
        target=f"user #{current_user.id} ({current_user.username})",
        details="two-factor authentication disabled by the account owner",
    )
    await db.commit()
    await db.refresh(current_user)
    request.session.pop(PENDING_SECRET_KEY, None)
    logger.info("User #%d disabled 2FA", current_user.id)

    return _render_page(
        request, current_user,
        notice="Two-factor authentication is off. Scan the new QR code below to turn it back on.",
    )
