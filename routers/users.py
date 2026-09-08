"""User management - admin only.

Provides:
  GET  /users               - Every account and its role.
  POST /api/users/{id}/role      - Change one account's role; returns the
                                   refreshed row as an HTML fragment.
  POST /api/users/{id}/reset-2fa - Clear a locked-out account's second factor.

Roles are the only thing editable here. Creating accounts and setting
passwords stay in ``utils/seed_admin.py``: SentinelAI has no self-service
sign-up, and adding password handling to a web route would widen the
authentication surface this layer is deliberately built on top of.
"""

import logging

from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import ROLE_ADMIN, ROLES, User
from routers.auth import require_admin, require_csrf
from utils.audit import ACTION_2FA_RESET, ACTION_ROLE_CHANGE, record_audit

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Users"])
templates = Jinja2Templates(directory="templates")


def _tpl(name: str, request: Request, status_code: int = 200, **ctx):
    """Compatibility wrapper for Starlette >=1.x TemplateResponse."""
    return templates.TemplateResponse(request=request, name=name, context=ctx, status_code=status_code)


async def _admin_count(db: AsyncSession) -> int:
    """How many active admins exist right now."""
    return (
        await db.scalar(
            select(func.count(User.id)).where(User.role == ROLE_ADMIN, User.is_active.is_(True))
        )
    ) or 0


# -- GET /users ------------------------------------------------------
@router.get("/users", response_class=HTMLResponse)
async def users_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> HTMLResponse:
    """List every account with its role and a control to change it."""
    users = list((await db.scalars(select(User).order_by(User.username))).all())
    return _tpl(
        "users.html",
        request,
        users=users,
        roles=ROLES,
        admin_count=await _admin_count(db),
        current_user=current_user,
    )


# -- POST /api/users/{user_id}/role ----------------------------------
@router.post("/api/users/{user_id}/role", response_class=HTMLResponse)
async def update_user_role(
    user_id: int,
    request: Request,
    role: str = Form(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
) -> HTMLResponse:
    """Change one account's role, refusing to remove the last administrator.

    The last-admin guard counts admins *other than* the target rather than
    trusting a total, so it holds whether an admin is demoting themselves or
    someone else. Without it the install would have no way back into settings,
    blocking or this page.
    """
    role = (role or "").strip().lower()
    if role not in ROLES:
        return _tpl(
            "partials/user_row.html", request,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            user=await db.get(User, user_id), roles=ROLES, current_user=current_user,
            error=f"Unknown role. Choose one of: {', '.join(ROLES)}.",
        )

    target = await db.get(User, user_id)
    if target is None:
        return HTMLResponse(
            content='<tr><td colspan="5" class="px-4 py-3 text-red-400 text-xs">User not found.</td></tr>',
            status_code=status.HTTP_404_NOT_FOUND,
        )

    if target.role == role:
        return _tpl("partials/user_row.html", request, user=target, roles=ROLES,
                    current_user=current_user, saved=True)

    if target.role == ROLE_ADMIN and role != ROLE_ADMIN:
        other_admins = (
            await db.scalar(
                select(func.count(User.id)).where(
                    User.role == ROLE_ADMIN, User.is_active.is_(True), User.id != target.id
                )
            )
        ) or 0
        if other_admins == 0:
            logger.warning(
                "User #%d tried to demote the last admin (#%d)", current_user.id, target.id
            )
            return _tpl(
                "partials/user_row.html", request,
                status_code=status.HTTP_409_CONFLICT,
                user=target, roles=ROLES, current_user=current_user,
                error="This is the last administrator. Promote another account first.",
            )

    previous = target.role
    target.role = role
    # Staged on the same session as the change, so the role edit and its audit
    # row commit together or not at all.
    record_audit(
        db, current_user, ACTION_ROLE_CHANGE,
        target=f"user #{target.id} ({target.username})",
        details=f"role {previous} -> {role}",
    )
    await db.commit()
    await db.refresh(target)

    return _tpl("partials/user_row.html", request, user=target, roles=ROLES,
                current_user=current_user, saved=True)


# -- POST /api/users/{user_id}/reset-2fa -----------------------------
@router.post("/api/users/{user_id}/reset-2fa", response_class=HTMLResponse)
async def reset_user_two_factor(
    user_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
) -> HTMLResponse:
    """Clear one account's second factor so a locked-out user can sign in again.

    This is the recovery path in place of backup codes (see the README). It
    only removes the second factor -- it never reveals a secret, sets a
    password, or signs anyone in, so an admin cannot use it to take over an
    account without the password holder noticing 2FA is off.
    """
    target = await db.get(User, user_id)
    if target is None:
        return HTMLResponse(
            content='<tr><td colspan="6" class="px-4 py-3 text-red-400 text-xs">User not found.</td></tr>',
            status_code=status.HTTP_404_NOT_FOUND,
        )

    if not target.totp_enabled and target.totp_secret is None:
        return _tpl("partials/user_row.html", request, user=target, roles=ROLES,
                    current_user=current_user,
                    error="That account does not have two-factor authentication set up.",
                    status_code=status.HTTP_409_CONFLICT)

    target.totp_enabled = False
    target.totp_secret = None
    record_audit(
        db, current_user, ACTION_2FA_RESET,
        target=f"user #{target.id} ({target.username})",
        details="second factor cleared by an administrator; the user must re-enroll",
    )
    await db.commit()
    await db.refresh(target)
    logger.warning("Admin #%d reset 2FA for user #%d (%s)",
                   current_user.id, target.id, target.username)

    return _tpl("partials/user_row.html", request, user=target, roles=ROLES,
                current_user=current_user, saved=True,
                notice="Two-factor authentication cleared. The user can sign in with their password and re-enroll.")
