"""Create or update the SentinelAI admin account.

SentinelAI has no self-service sign-up: the dashboard exposes every parsed log
line and alert, and the ``User`` model carries no roles to gate a public
registration form. Accounts are provisioned locally instead, the same way
``main.py`` seeds the ThreatIntel table.

Usage::

    python -m utils.seed_admin                      # prompts for the details
    SENTINEL_ADMIN_USERNAME=analyst \\
    SENTINEL_ADMIN_EMAIL=analyst@example.com \\
    SENTINEL_ADMIN_PASSWORD=... python -m utils.seed_admin

Re-running with an existing username resets that account's password and
re-asserts the admin role.

Recovering a user locked out by two-factor authentication
---------------------------------------------------------
SentinelAI has no backup codes. If someone loses their authenticator device:

1. Preferred -- another administrator signs in and presses **Reset 2FA** on
   the /users page. That clears ``totp_enabled`` and ``totp_secret`` and writes
   a ``2fa_reset`` entry to the audit log. The user then signs in with their
   password alone and re-enrols from /settings/2fa.

2. If *every* administrator is locked out, there is no one left to press that
   button, so fall back to the database directly. Stop the server first::

       sqlite3 sentinelai.db "UPDATE users SET totp_enabled = 0,
                              totp_secret = NULL WHERE username = 'admin';"

   This fallback leaves NO audit-log entry, because it bypasses the
   application entirely. Prefer route 1 whenever an admin can still sign in.

Note that re-running this script does *not* clear a second factor: it only
touches the password, email and role, so an operator resetting a forgotten
password cannot silently strip 2FA off an account as a side effect.
"""

import asyncio
import getpass
import os
import sys

from sqlalchemy import select

from database import AsyncSessionLocal, Base, engine
from models import ROLE_ADMIN, User
from utils.security import hash_password, validate_password_strength

ENV_USERNAME = "SENTINEL_ADMIN_USERNAME"
ENV_EMAIL = "SENTINEL_ADMIN_EMAIL"
ENV_PASSWORD = "SENTINEL_ADMIN_PASSWORD"


def _no_terminal(env_var: str) -> SystemExit:
    return SystemExit(
        f"{env_var} is not set and there is no terminal to prompt on. "
        f"Set {ENV_USERNAME}, {ENV_EMAIL} and {ENV_PASSWORD}, or run this from a terminal."
    )


def _prompt(label: str, env_var: str, default: str = "") -> str:
    """Read a value from the environment, falling back to an interactive prompt."""
    value = os.environ.get(env_var, "").strip()
    if value:
        return value
    if not sys.stdin.isatty():
        raise _no_terminal(env_var)
    suffix = f" [{default}]" if default else ""
    try:
        return input(f"{label}{suffix}: ").strip() or default
    except EOFError:
        raise _no_terminal(env_var) from None


def _prompt_password() -> str:
    """Read the password from the environment or ask for it twice."""
    password = os.environ.get(ENV_PASSWORD, "")
    if password:
        try:
            validate_password_strength(password)
        except ValueError as exc:
            raise SystemExit(f"{ENV_PASSWORD} rejected: {exc}") from None
        return password
    if not sys.stdin.isatty():
        raise _no_terminal(ENV_PASSWORD)
    while True:
        try:
            password = getpass.getpass("Password: ")
        except EOFError:
            raise _no_terminal(ENV_PASSWORD) from None
        try:
            validate_password_strength(password)
        except ValueError as exc:
            print(f"  {exc}")
            continue
        if password != getpass.getpass("Confirm password: "):
            print("  Passwords do not match.")
            continue
        return password


async def seed_admin(username: str, email: str, password: str) -> str:
    """Create the account as an administrator, or reset it if it exists."""
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        user = await db.scalar(select(User).where(User.username == username))
        if user is None:
            clash = await db.scalar(select(User).where(User.email == email))
            if clash is not None:
                raise SystemExit(f"Email {email!r} already belongs to user {clash.username!r}.")
            db.add(User(
                username=username, email=email, password_hash=hash_password(password),
                role=ROLE_ADMIN, is_active=True,
            ))
            action = "created"
        else:
            user.password_hash = hash_password(password)
            user.email = email
            user.is_active = True
            # This script provisions operators, so it always (re)asserts admin.
            # Demoting an admin is done from /users, never by a password reset
            # -- and a locked-out install is fixed by re-running this.
            user.role = ROLE_ADMIN
            action = "updated"
        await db.commit()
    await engine.dispose()
    return action


def main() -> None:
    username = _prompt("Username", ENV_USERNAME, "admin")
    email = _prompt("Email", ENV_EMAIL, f"{username}@sentinelai.local")
    password = _prompt_password()
    action = asyncio.run(seed_admin(username, email, password))
    print(f"Admin account {action}: {username} <{email}> (role: {ROLE_ADMIN})")
    print("Sign in at http://localhost:8000/login")
    print()
    print("Note: this does not change two-factor authentication. If this account is")
    print("locked out by a lost authenticator, another admin can clear it with")
    print("'Reset 2FA' on the /users page. If every admin is locked out, see the")
    print("direct-database fallback documented at the top of this file.")


if __name__ == "__main__":
    main()
