"""Session authentication router - Phase 6.

Provides:
  GET  /login   - Standalone login page.
  POST /login   - Verify credentials, open a session, redirect to the dashboard.
  POST /logout  - Clear the session and return to the login page.

Also exposes ``get_current_user`` (the dependency every page and mutating
endpoint depends on) and ``require_csrf`` for state-changing POST routes.
"""

import logging

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import User
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
    request.session[SESSION_USER_KEY] = user.id
    rotate_csrf_token(request.session)
    logger.info("User #%d (%s) signed in", user.id, user.username)

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
