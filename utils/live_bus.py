"""In-process fan-out of new alerts to connected WebSocket clients.

Deliberately a plain in-memory set rather than Redis or a pub/sub broker: this
prototype runs as a single Uvicorn process, so a shared object is both
sufficient and honest about the scale. The one consequence worth stating is
that it does not survive a restart and does not span workers -- run this under
more than one worker and each worker would only reach its own clients.

Nothing here may raise into a caller: a broadcast is a side effect of alert
creation, and a dead socket must never fail the detection run that triggered
it.
"""

import asyncio
import logging
from typing import Any

from starlette.websockets import WebSocket, WebSocketState

from models import Alert

logger = logging.getLogger(__name__)

# Message envelope types the client switches on.
EVENT_HELLO = "hello"
EVENT_ALERT = "alert"
EVENT_SIMULATION = "simulation"


def alert_event(alert: Alert) -> dict[str, Any]:
    """Build the wire payload for one newly created alert.

    Intentionally small -- the client uses it to render a row and a toast, not
    as a substitute for loading the alert. ``risk_score`` and ``status`` ride
    along with the four identifying fields so a pushed row looks exactly like
    a server-rendered one instead of showing empty cells.
    """
    return {
        "type": EVENT_ALERT,
        "id": alert.id,
        "severity": alert.severity.value,
        "threat_name": alert.threat_name,
        "source_ip": alert.source_ip,
        "risk_score": alert.risk_score,
        "status": alert.status.value,
    }


class ConnectionManager:
    """Tracks live WebSocket clients and fans messages out to all of them."""

    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()
        # Guards the set itself. Sends happen outside it, against a snapshot,
        # so one slow client cannot block another connecting or disconnecting.
        self._lock = asyncio.Lock()

    @property
    def connection_count(self) -> int:
        return len(self._connections)

    async def connect(self, websocket: WebSocket) -> None:
        """Accept the handshake and start tracking this client."""
        await websocket.accept()
        async with self._lock:
            self._connections.add(websocket)
        logger.info("Live client connected (%d active)", len(self._connections))

    async def disconnect(self, websocket: WebSocket) -> None:
        """Stop tracking a client. Safe to call more than once."""
        async with self._lock:
            self._connections.discard(websocket)
        logger.info("Live client disconnected (%d active)", len(self._connections))

    async def broadcast(self, message: dict[str, Any]) -> int:
        """Send one JSON message to every live client; return how many got it.

        Clients that fail or have already gone away are dropped rather than
        retried -- the browser reconnects on its own and re-reads current state
        from the page it loads.
        """
        async with self._lock:
            targets = list(self._connections)
        if not targets:
            return 0

        results = await asyncio.gather(
            *(self._send(websocket, message) for websocket in targets),
            return_exceptions=True,
        )
        stale = [
            websocket
            for websocket, result in zip(targets, results)
            if result is not True
        ]
        if stale:
            async with self._lock:
                for websocket in stale:
                    self._connections.discard(websocket)
            logger.info("Dropped %d unreachable live client(s)", len(stale))
        return len(targets) - len(stale)

    async def _send(self, websocket: WebSocket, message: dict[str, Any]) -> bool:
        """Send to one client, reporting failure instead of raising."""
        if websocket.client_state is not WebSocketState.CONNECTED:
            return False
        try:
            await websocket.send_json(message)
        except Exception:  # noqa: BLE001 - any send failure means "drop it".
            logger.debug("Live send failed; dropping client", exc_info=True)
            return False
        return True


# One manager per process, imported by both the WebSocket route and the
# detection flow that publishes to it.
manager = ConnectionManager()


async def broadcast_new_alerts(alerts: list[Alert]) -> int:
    """Publish freshly created alerts, swallowing any failure.

    Called from the upload/detection path, where the alerts are already
    committed: a push problem must not roll anything back or surface as an
    upload error.
    """
    delivered = 0
    try:
        for alert in alerts:
            delivered += await manager.broadcast(alert_event(alert))
    except Exception:  # noqa: BLE001 - broadcasting is strictly best-effort.
        logger.exception("Failed to broadcast %d new alert(s)", len(alerts))
    return delivered
