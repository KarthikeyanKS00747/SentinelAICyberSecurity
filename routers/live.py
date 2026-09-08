"""Real-time alert push over WebSockets.

Provides:
  WS   /ws/alerts          - Authenticated live feed of newly created alerts.
  POST /api/live/simulate  - Demo-only replay of a bundled fixture log.
  GET  /api/live/status    - How many clients are connected, and whether a
                             replay is in flight.

Authentication reuses the same signed session cookie as every page: Starlette's
SessionMiddleware populates ``scope["session"]`` for WebSocket handshakes as
well as HTTP requests, so the check here mirrors ``get_current_user`` rather
than introducing a second mechanism. It is a separate function only because a
failed WebSocket handshake has to be refused with a close frame instead of the
HTTP redirect ``AuthenticationRequired`` produces.
"""

import asyncio
import logging

from fastapi import APIRouter, Depends, Form, HTTPException, Request, WebSocket, WebSocketDisconnect, status
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import User
from routers.auth import SESSION_USER_KEY, get_current_user, require_csrf
from utils.live_bus import EVENT_HELLO, manager
from utils.live_simulator import DEFAULT_FIXTURE, FIXTURES, is_running, run_simulation

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Live"])

# Application-level heartbeat. Browsers cannot send WebSocket ping frames from
# JavaScript, so the client sends this text and the server answers PONG; it
# keeps idle intermediaries from silently dropping the socket and gives the
# client positive proof the connection is still alive.
PING_MESSAGE = "ping"
PONG_MESSAGE = "pong"

# Close code for an unauthenticated or expired session (RFC 6455 policy
# violation). Sent before accepting, so the handshake itself fails.
WS_POLICY_VIOLATION = status.WS_1008_POLICY_VIOLATION

# The event loop only holds a weak reference to a bare create_task() result, so
# a running replay can be garbage-collected mid-flight without this.
_background_tasks: set[asyncio.Task] = set()


async def _session_user(websocket: WebSocket, db: AsyncSession) -> User | None:
    """Resolve the signed-in user for a handshake, or None to refuse it.

    Mirrors ``get_current_user``: same session key, same active-user check,
    so a deactivated account cannot hold a live socket open.
    """
    try:
        user_id = websocket.session.get(SESSION_USER_KEY)
    except (AssertionError, KeyError):
        # No SessionMiddleware in the stack; refuse rather than run unauthenticated.
        logger.warning("WebSocket handshake without a session scope")
        return None
    if user_id is None:
        return None
    user = await db.get(User, user_id)
    if user is None or not user.is_active:
        return None
    return user


# -- WS /ws/alerts ---------------------------------------------------
@router.websocket("/ws/alerts")
async def alerts_feed(websocket: WebSocket, db: AsyncSession = Depends(get_db)) -> None:
    """Push newly created alerts to one authenticated browser tab.

    The receive loop exists to notice the client going away and to answer
    heartbeats; the socket carries no client commands. All outbound traffic is
    produced by :mod:`utils.live_bus` broadcasts.
    """
    user = await _session_user(websocket, db)
    if user is None:
        await websocket.close(code=WS_POLICY_VIOLATION)
        return

    await manager.connect(websocket)
    try:
        await websocket.send_json(
            {
                "type": EVENT_HELLO,
                "username": user.username,
                "clients": manager.connection_count,
            }
        )
        while True:
            message = await websocket.receive_text()
            if message == PING_MESSAGE:
                await websocket.send_text(PONG_MESSAGE)
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001 - a broken socket is normal, not an error.
        logger.debug("Live socket ended unexpectedly", exc_info=True)
    finally:
        await manager.disconnect(websocket)


# -- POST /api/live/simulate -----------------------------------------
@router.post("/api/live/simulate")
async def simulate_live_log(
    request: Request,
    fixture: str = Form(DEFAULT_FIXTURE),
    current_user: User = Depends(get_current_user),
    _csrf: None = Depends(require_csrf),
) -> dict[str, object]:
    """Start a demo replay of a bundled fixture log in the background.

    Demo feature only: it replays a file that already ships with the repo so
    the live-push path can be shown working. It does not tail or watch anything
    and there is no real-time log source behind it.

    Returns as soon as the replay starts; alerts arrive over the WebSocket as
    each line is processed. There is no role system in SentinelAI, so this is
    open to any signed-in user, CSRF-protected like every other mutating route.
    """
    if fixture not in FIXTURES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown fixture. Choose one of: {', '.join(sorted(FIXTURES))}.",
        )
    if is_running():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A simulation is already running. Wait for it to finish.",
        )

    # Fire-and-forget: the replay outlives this request by design, so it gets
    # its own session inside run_simulation rather than borrowing the
    # request-scoped one, which closes when the response is returned.
    task = asyncio.create_task(run_simulation(fixture))
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)

    logger.info("User #%d started a live simulation of %r", current_user.id, fixture)
    return {
        "started": True,
        "fixture": fixture,
        "simulation": True,
        "detail": "Replaying a bundled fixture log. This is a demo, not live log tailing.",
    }


# -- GET /api/live/status --------------------------------------------
@router.get("/api/live/status")
async def live_status(current_user: User = Depends(get_current_user)) -> dict[str, object]:
    """Report live-feed state, for debugging and the demo write-up."""
    return {
        "connected_clients": manager.connection_count,
        "simulation_running": is_running(),
        "fixtures": sorted(FIXTURES),
    }
