"""Session authentication router - Phase 6.

Provides:
  GET  /login   - Standalone login page.
  POST /login   - Verify credentials, open a session, redirect to the dashboard.
  POST /logout  - Clear the session and return to the login page.

Also exposes ``get_current_user`` (the dependency every page and mutating
endpoint depends on) and ``require_csrf`` for state-changing POST routes.
"""

import logging
import time

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import ROLE_ADMIN, User
from utils.totp import verify_code
from utils.security import (
    CSRF_FORM_FIELD,
    CSRF_HEADER_NAME,
    csrf_token_matches,
    dummy_verify,
    issue_csrf_token,
    rotate_csrf_token,
    verify_password,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Auth"])
templates = Jinja2Templates(directory="templates")

LOGIN_PATH = "/login"
API_PREFIX = "/api/"
SESSION_USER_KEY = "user_id"
# Where a signed-in non-admin lands after being refused an admin-only page.
DENIED_REDIRECT = "/dashboard"

# -- Pending second factor -------------------------------------------
# Deliberately a DIFFERENT session key from SESSION_USER_KEY. get_current_user
# reads only SESSION_USER_KEY, so a session holding nothing but these keys is
# not authenticated for any route in the app: it can reach the code form and
# nothing else. Password success alone must never write SESSION_USER_KEY.
PENDING_2FA_USER_KEY = "pending_2fa_user_id"
PENDING_2FA_AT_KEY = "pending_2fa_started_at"
PENDING_2FA_TRIES_KEY = "pending_2fa_attempts"
PENDING_2FA_NEXT_KEY = "pending_2fa_next"
TWO_FACTOR_PATH = "/login/2fa"

# The window between entering a correct password and entering the code. Short
# enough that an unattended browser is not left one form away from a session.
PENDING_2FA_TTL_SECONDS = 5 * 60
# Wrong codes allowed before the pending state is discarded and the password
# has to be entered again.
PENDING_2FA_MAX_ATTEMPTS = 5


def _clear_pending_2fa(session) -> None:
    """Drop every pending-second-factor key from the session."""
    for key in (
        PENDING_2FA_USER_KEY,
        PENDING_2FA_AT_KEY,
        PENDING_2FA_TRIES_KEY,
        PENDING_2FA_NEXT_KEY,
    ):
        session.pop(key, None)


def _pending_2fa_user_id(session) -> int | None:
    """The user id awaiting a code, or None when there is no live pending state.

    An expired pending state is cleared here rather than merely ignored, so a
    stale entry cannot sit in the cookie until something else happens to
    overwrite it.
    """
    user_id = session.get(PENDING_2FA_USER_KEY)
    if user_id is None:
        return None
    started_at = session.get(PENDING_2FA_AT_KEY, 0)
    if time.time() - float(started_at or 0) > PENDING_2FA_TTL_SECONDS:
        logger.info("Pending 2FA state for user #%s expired", user_id)
        _clear_pending_2fa(session)
        return None
    return int(user_id)


def _tpl(name: str, request: Request, status_code: int = 200, **ctx):
    """Compatibility wrapper for Starlette >=1.x TemplateResponse."""
    return templates.TemplateResponse(request=request, name=name, context=ctx, status_code=status_code)


class AuthenticationRequired(Exception):
    """Raised by ``get_current_user`` when there is no usable session."""

    def __init__(self, next_url: str | None = None, is_htmx: bool = False) -> None:
        self.next_url = next_url
        self.is_htmx = is_htmx
        super().__init__("Authentication required")


async def authentication_required_handler(request: Request, exc: AuthenticationRequired) -> Response:
    """Turn a missing session into the right answer for the caller.

    htmx gets 204 + HX-Redirect, non-htmx /api/ callers get a JSON 401, and
    a plain browser navigation gets a 303 to the login page.
    """
    target = LOGIN_PATH
    if exc.next_url and _is_safe_next(exc.next_url) and exc.next_url != LOGIN_PATH:
        target = f"{LOGIN_PATH}?next={exc.next_url}"
    if exc.is_htmx:
        # htmx will not follow a redirect usefully inside a partial swap;
        # HX-Redirect makes the browser navigate to the login page instead.
        return Response(status_code=status.HTTP_204_NO_CONTENT, headers={"HX-Redirect": target})
    if request.url.path.startswith(API_PREFIX):
        # fetch/curl callers follow a 303 into the login page's HTML and read it
        # as success; a JSON 401 lets them see the failure. Checked after the
        # htmx branch so HTMX calls to /api/... still get HX-Redirect.
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Authentication required."},
        )
    return RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)


def _is_safe_next(candidate: str) -> bool:
    """Allow only same-site absolute paths, never an off-site redirect."""
    return candidate.startswith("/") and not candidate.startswith("//")


async def get_current_user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    """Load the signed-in user or bounce the request to the login page."""
    is_htmx = bool(request.headers.get("HX-Request"))
    next_url = request.url.path if request.method == "GET" else None

    user_id = request.session.get(SESSION_USER_KEY)
    if user_id is None:
        raise AuthenticationRequired(next_url, is_htmx)

    user = await db.get(User, user_id)
    if user is None or not user.is_active:
        # Deleted or deactivated between requests - drop the stale session.
        request.session.clear()
        raise AuthenticationRequired(next_url, is_htmx)

    request.state.current_user = user
    return user


class AuthorizationRequired(Exception):
    """Raised by ``require_admin`` when a signed-in user lacks the admin role.

    Distinct from :class:`AuthenticationRequired`: the caller *is* signed in,
    so bouncing them to the login page would be misleading. This is a 403, not
    a 401.
    """

    def __init__(self, is_htmx: bool = False) -> None:
        self.is_htmx = is_htmx
        super().__init__("Administrator access required")


async def authorization_required_handler(request: Request, exc: AuthorizationRequired) -> Response:
    """Turn a role failure into the right answer for the caller.

    The /api/ branch comes first here, the opposite of the authentication
    handler: every admin-gated mutation is an /api/ route driven by htmx, and
    answering those with HX-Redirect would navigate the whole page away from
    the analyst's work instead of just refusing the action. A JSON 403 leaves
    the page intact, and the existing toast layer already reports the failure.
    """
    if request.url.path.startswith(API_PREFIX):
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": "Administrator access required."},
        )
    if exc.is_htmx:
        return Response(status_code=status.HTTP_204_NO_CONTENT, headers={"HX-Redirect": DENIED_REDIRECT})
    return RedirectResponse(DENIED_REDIRECT, status_code=status.HTTP_303_SEE_OTHER)


async def require_admin(
    request: Request,
    current_user: User = Depends(get_current_user),
) -> User:
    """Allow only administrators through, and hand the route the user.

    Depends on ``get_current_user`` rather than re-reading the session, so an
    unauthenticated caller still gets the ordinary login redirect and only a
    signed-in non-admin sees the 403.
    """
    if current_user.role != ROLE_ADMIN:
        logger.warning(
            "User #%d (%s, role=%s) was refused admin action %s %s",
            current_user.id, current_user.username, current_user.role,
            request.method, request.url.path,
        )
        raise AuthorizationRequired(bool(request.headers.get("HX-Request")))
    return current_user


async def require_csrf(request: Request) -> None:
    """Reject state-changing requests that do not carry the session's token."""
    submitted = request.headers.get(CSRF_HEADER_NAME)
    if not submitted:
        try:
            form = await request.form()
        except Exception:  # noqa: BLE001 - a body we cannot parse carries no token.
            form = {}
        submitted = form.get(CSRF_FORM_FIELD)

    if not csrf_token_matches(request.session, submitted):
        logger.warning("Rejected %s %s: missing or invalid CSRF token", request.method, request.url.path)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing CSRF token.",
        )


# -- GET /login ------------------------------------------------------
@router.get(LOGIN_PATH, response_class=HTMLResponse)
async def login_page(request: Request, next: str | None = None) -> Response:
    """Render the login form, issuing a CSRF token for this session."""
    if request.session.get(SESSION_USER_KEY):
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    # Returning to the password form abandons any half-finished 2FA step.
    _clear_pending_2fa(request.session)
    return _tpl(
        "login.html",
        request,
        csrf_token=issue_csrf_token(request.session),
        next_url=next if next and _is_safe_next(next) else "",
        error=None,
    )


# -- POST /login -----------------------------------------------------
@router.post(LOGIN_PATH, response_class=HTMLResponse)
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(""),
    next: str = Form(""),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Validate credentials and open a session."""
    safe_next = next if next and _is_safe_next(next) else "/"

    def failure(message: str) -> Response:
        return _tpl(
            "login.html",
            request,
            status_code=status.HTTP_401_UNAUTHORIZED,
            csrf_token=issue_csrf_token(request.session),
            next_url=safe_next if safe_next != "/" else "",
            error=message,
        )

    if not csrf_token_matches(request.session, csrf_token):
        logger.warning("Rejected login for %r: missing or invalid CSRF token", username)
        return failure("Your session expired. Please try again.")

    user = await db.scalar(select(User).where(User.username == username.strip()))
    if user is None:
        dummy_verify()  # keep the response time the same for unknown usernames
        logger.info("Failed login for unknown username %r", username)
        return failure("Invalid username or password.")

    if not verify_password(password, user.password_hash) or not user.is_active:
        logger.info("Failed login for user #%d", user.id)
        return failure("Invalid username or password.")

    # New session identity on privilege change (session-fixation defence).
    request.session.clear()

    if user.totp_enabled:
        # Password was correct, but the login is NOT complete. Only the
        # pending keys are written -- SESSION_USER_KEY stays unset, so
        # get_current_user still treats this session as anonymous and every
        # protected route bounces it to the login page.
        request.session[PENDING_2FA_USER_KEY] = user.id
        request.session[PENDING_2FA_AT_KEY] = time.time()
        request.session[PENDING_2FA_TRIES_KEY] = 0
        request.session[PENDING_2FA_NEXT_KEY] = safe_next
        rotate_csrf_token(request.session)
        logger.info("User #%d (%s) passed password, awaiting 2FA code", user.id, user.username)
        return RedirectResponse(TWO_FACTOR_PATH, status_code=status.HTTP_303_SEE_OTHER)

    request.session[SESSION_USER_KEY] = user.id
    rotate_csrf_token(request.session)
    logger.info("User #%d (%s) signed in", user.id, user.username)

    return RedirectResponse(safe_next, status_code=status.HTTP_303_SEE_OTHER)


# -- GET /login/2fa --------------------------------------------------
@router.get(TWO_FACTOR_PATH, response_class=HTMLResponse)
async def two_factor_page(request: Request) -> Response:
    """Ask for the six-digit code, only while a pending state is live."""
    if request.session.get(SESSION_USER_KEY):
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    if _pending_2fa_user_id(request.session) is None:
        # No pending state (never started, already used, or expired): the only
        # way forward is the password step.
        return RedirectResponse(LOGIN_PATH, status_code=status.HTTP_303_SEE_OTHER)
    return _tpl(
        "login_2fa.html",
        request,
        csrf_token=issue_csrf_token(request.session),
        error=None,
    )


# -- POST /login/2fa -------------------------------------------------
@router.post(TWO_FACTOR_PATH, response_class=HTMLResponse)
async def two_factor_verify(
    request: Request,
    code: str = Form(...),
    csrf_token: str = Form(""),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Verify the code and only then open the real authenticated session."""
    def failure(message: str) -> Response:
        return _tpl(
            "login_2fa.html",
            request,
            status_code=status.HTTP_401_UNAUTHORIZED,
            csrf_token=issue_csrf_token(request.session),
            error=message,
        )

    if not csrf_token_matches(request.session, csrf_token):
        logger.warning("Rejected 2FA step: missing or invalid CSRF token")
        _clear_pending_2fa(request.session)
        return RedirectResponse(LOGIN_PATH, status_code=status.HTTP_303_SEE_OTHER)

    user_id = _pending_2fa_user_id(request.session)
    if user_id is None:
        return RedirectResponse(LOGIN_PATH, status_code=status.HTTP_303_SEE_OTHER)

    attempts = int(request.session.get(PENDING_2FA_TRIES_KEY, 0)) + 1
    request.session[PENDING_2FA_TRIES_KEY] = attempts

    user = await db.get(User, user_id)
    # Re-checked here, not just at the password step: the account could have
    # been deactivated, or its second factor reset by an admin, in between.
    if user is None or not user.is_active or not user.totp_enabled:
        logger.info("Pending 2FA for user #%s is no longer valid", user_id)
        _clear_pending_2fa(request.session)
        return RedirectResponse(LOGIN_PATH, status_code=status.HTTP_303_SEE_OTHER)

    if not verify_code(user.totp_secret, code):
        if attempts >= PENDING_2FA_MAX_ATTEMPTS:
            logger.warning(
                "User #%d exhausted %d 2FA attempts; discarding pending state",
                user.id, PENDING_2FA_MAX_ATTEMPTS,
            )
            _clear_pending_2fa(request.session)
            return RedirectResponse(LOGIN_PATH, status_code=status.HTTP_303_SEE_OTHER)
        logger.info("Invalid 2FA code for user #%d (attempt %d)", user.id, attempts)
        return failure("That code is not valid. Check your authenticator app and try again.")

    # Code accepted: promote the pending state into a real session. The next
    # target is read before the clear, since clearing drops it too.
    safe_next = request.session.get(PENDING_2FA_NEXT_KEY) or "/"
    if not _is_safe_next(safe_next):
        safe_next = "/"
    request.session.clear()
    request.session[SESSION_USER_KEY] = user.id
    rotate_csrf_token(request.session)
    logger.info("User #%d (%s) signed in with 2FA", user.id, user.username)
    return RedirectResponse(safe_next, status_code=status.HTTP_303_SEE_OTHER)


# -- POST /logout ----------------------------------------------------
@router.post("/logout")
async def logout(request: Request, csrf_token: str = Form("")) -> Response:
    """Clear the session and return to the login page."""
    if not csrf_token_matches(request.session, csrf_token):
        logger.warning("Rejected logout: missing or invalid CSRF token")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing CSRF token.",
        )

    user_id = request.session.get(SESSION_USER_KEY)
    request.session.clear()
    if user_id is not None:
        logger.info("User #%s signed out", user_id)
    return RedirectResponse(LOGIN_PATH, status_code=status.HTTP_303_SEE_OTHER)
