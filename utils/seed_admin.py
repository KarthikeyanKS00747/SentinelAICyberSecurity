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

Re-running with an existing username resets that account's password.
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


if __name__ == "__main__":
    main()
