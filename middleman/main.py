"""FastAPI middleman for libbpf-exp frontend monitor.

Receives newline-delimited JSON events from the eBPF auditor over a UNIX
domain socket and broadcasts them to connected Vue frontend clients over
WebSocket.
"""

import asyncio
import errno
import json
import logging
import os
import select
import socket
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional, Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import uvicorn

SOCK_PATH = "/tmp/libbpf-exp.sock"
HOST = "0.0.0.0"
PORT = 8000
# Persisted event history so the frontend does not lose logs on page refresh
# or when the middleman itself restarts.
EVENTS_FILE = "/tmp/libbpf-exp-events.json"

# Persisted deny list so the frontend can show currently denied cgroups/inodes
# even after a middleman restart.
DENIED_FILE = "/tmp/libbpf-exp-denied.json"

# Default cgroup that the auditor polices; its cgroup.procs lists the PIDs
# currently inside the denied cgroup.
DEFAULT_CGROUP_PATH = "/sys/fs/cgroup/denied"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [middleman] %(message)s")
log = logging.getLogger("middleman")

# Set of active WebSocket connections
clients: Set[WebSocket] = set()
clients_lock = asyncio.Lock()

# Recent events buffer (last 100) for the /v1/models endpoint
recent_events: list = []
recent_events_lock = asyncio.Lock()
MAX_RECENT = 100

# Currently denied cgroup paths, tracked from /v1/command deny/allow
# commands and persisted to disk so the frontend can display them across
# middleman restarts.
#
# Paths are the user-facing concept. The server resolves each path to its
# inode internally (via os.stat / path_to_inode) and stores the resolved
# inode alongside the path for display only -- the user never types or sees
# a raw inode number. Inodes are the enforcement key inside the BPF maps
# (denied_cgroups / denied_inodes), but that is an implementation detail.
denied_cgroups: list = []  # list of {"path": str, "inode": Optional[int]}
denied_lock = asyncio.Lock()

# The active UNIX-socket connection from the eBPF auditor (client side).
# The middleman is the server; it accepts the auditor's connection and can
# send command JSON back down the same socket.
# Stored as a single-element list [conn_or_None] to avoid variable rebinding
# issues across threads.
auditor_conn: list = [None]
auditor_conn_lock = threading.Lock()


class CommandRequest(BaseModel):
    action: str  # deny_path | allow_path | set_audit_only
    path: Optional[str] = None
    enabled: Optional[bool] = None


class CgroupMoveRequest(BaseModel):
    pid: int
    cgroup_path: str


async def broadcast(message: str):
    """Send a message to all connected WebSocket clients."""
    async with clients_lock:
        dead = []
        for ws in clients:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            clients.discard(ws)

    # Store in recent events
    try:
        payload = json.loads(message)
    except json.JSONDecodeError:
        payload = {"raw": message}
    async with recent_events_lock:
        recent_events.insert(0, {
            "received_at": datetime.now(timezone.utc).isoformat(),
            "event": payload,
        })
        if len(recent_events) > MAX_RECENT:
            recent_events.pop()
        snapshot = list(recent_events)
    # Persist to disk so history survives a middleman restart.
    try:
        _persist_events(snapshot)
    except OSError as exc:
        log.error("failed to persist events to %s: %s", EVENTS_FILE, exc)


def _persist_events(events):
    """Atomically write the recent-events history to disk."""
    tmp = EVENTS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(events, f)
    os.replace(tmp, EVENTS_FILE)


def _persist_denied():
    """Atomically write the denied list to disk."""
    data = {
        "cgroups": denied_cgroups,
    }
    tmp = DENIED_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, DENIED_FILE)


def _load_denied():
    """Load the persisted deny list from disk, if any."""
    global denied_cgroups
    if not os.path.exists(DENIED_FILE):
        return
    try:
        with open(DENIED_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            if isinstance(data.get("cgroups"), list):
                denied_cgroups = data["cgroups"]
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("could not load persisted deny list: %s", exc)


def read_cgroup_procs(cgroup_path: str = DEFAULT_CGROUP_PATH):
    """Read the PIDs currently inside a cgroup's cgroup.procs file.

    Returns a list of int PIDs, or an empty list on any error (missing file,
    permissions, etc.). The caller decides how to surface errors.
    """
    cgroup_procs = f"{cgroup_path.rstrip('/')}/cgroup.procs"
    try:
        with open(cgroup_procs, "r", encoding="utf-8") as f:
            pids = []
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    pids.append(int(line))
                except ValueError:
                    continue
            return pids
    except (FileNotFoundError, PermissionError, OSError) as exc:
        log.warning("could not read cgroup.procs for %s: %s", cgroup_path, exc)
        return []


def path_to_inode(path: str):
    """Resolve a filesystem/cgroup path to its inode number.

    Returns (inode, error_message). On success error_message is None.
    """
    try:
        st = os.stat(path)
        return st.st_ino, None
    except FileNotFoundError:
        return None, f"path not found: {path}"
    except NotADirectoryError:
        return None, f"not a directory: {path}"
    except PermissionError:
        return None, f"permission denied: {path} (run middleman as root)"
    except OSError as exc:
        return None, str(exc)


def _log_broadcast_errors(future):
    """Log exceptions from broadcast() scheduled from the socket thread.

    ``run_coroutine_threadsafe`` never raises in the caller; errors happen
    inside the coroutine on the main loop and would otherwise be silent.
    """
    try:
        future.result()
    except Exception as exc:  # pragma: no cover - defensive logging
        log.error("broadcast to WebSocket clients failed: %s", exc)


def socket_reader_loop(main_loop):
    """Blocking loop: read JSON lines from the UNIX socket and broadcast.

    Runs in a background daemon thread. Each validated JSON line is handed
    to ``broadcast()`` on the main asyncio event loop (captured at startup
    in ``lifespan``). Keeping all WebSocket state on a single loop avoids
    asyncio lock/timer cross-loop errors and, crucially, lets the loop
    actually run the scheduled coroutines.
    """
    # Remove stale socket file if it exists.
    try:
        os.unlink(SOCK_PATH)
    except FileNotFoundError:
        pass
    except PermissionError as exc:
        # May not have permission if the stale socket is owned by another
        # process; try binding anyway — bind() will fail with EADDRINUSE if
        # the socket is truly still in use.
        log.warning("could not remove stale socket %s: %s; retrying bind", SOCK_PATH, exc)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(SOCK_PATH)
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            # Socket file still exists from a previous run; try once more to
            # remove it and rebind.
            try:
                os.unlink(SOCK_PATH)
                server.bind(SOCK_PATH)
            except OSError:
                log.error("could not bind to %s: %s", SOCK_PATH, exc)
                raise
        else:
            raise
    server.listen(1)
    server.settimeout(1.0)

    log.info("listening on %s", SOCK_PATH)

    while True:
        try:
            conn, _ = server.accept()
        except socket.timeout:
            continue
        except OSError:
            break

        conn.settimeout(5.0)
        log.info("auditor connection accepted from %s", conn.getpeername() if hasattr(conn, 'getpeername') else 'unknown')
        # Remember this connection so HTTP handlers can send commands
        # back to the auditor. Only one auditor is expected at a time.
        print(f"[MIDDLEMAN] about to set auditor_conn (conn={id(conn)})", flush=True)
        with auditor_conn_lock:
            auditor_conn[0] = conn
        print(f"[MIDDLEMAN] auditor_conn SET (conn={id(conn)})", flush=True)
        log.info("auditor_conn set; connected=%s", auditor_conn[0] is not None)
        buf = b""
        recv_errors = 0
        try:
            while True:
                try:
                    data = conn.recv(4096)
                except socket.timeout:
                    # No data within timeout; keep the connection alive.
                    recv_errors = 0
                    continue
                except (OSError, ConnectionError) as exc:
                    # Transient socket error; do not tear down the
                    # connection. Retry a few times before giving up.
                    recv_errors += 1
                    if recv_errors > 10:
                        log.info("auditor connection error: %s; giving up after %d retries", exc, recv_errors)
                        break
                    log.info("auditor connection error: %s; retrying (%d/10)", exc, recv_errors)
                    time.sleep(0.1)
                    continue
                if not data:
                    log.info("auditor connection closed by peer (empty recv)")
                    break
                recv_errors = 0
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    try:
                        text = line.decode("utf-8").strip()
                    except UnicodeDecodeError:
                        continue
                    if not text:
                        continue
                    # Validate JSON
                    try:
                        json.loads(text)
                    except json.JSONDecodeError:
                        continue
                    log.info("received event: %s", text[:120])
                    # Schedule the broadcast on the main event loop so it
                    # actually executes (that loop runs forever under uvicorn)
                    # and shares state with the WebSocket handlers.
                    try:
                        future = asyncio.run_coroutine_threadsafe(
                            broadcast(text), main_loop
                        )
                        future.add_done_callback(_log_broadcast_errors)
                    except RuntimeError as exc:
                        # Loop is shutting down; drop the event.
                        log.debug(
                            "broadcast not delivered (loop stopping): %s", exc
                        )
        except (OSError, ConnectionError) as exc:
            log.info("auditor connection error: %s", exc)
        finally:
            # Do NOT clear auditor_conn here. The connection may be
            # temporarily unhealthy but still usable; clearing it would
            # make the command handler report "auditor not connected"
            # even though a new auditor connection might arrive shortly.
            # auditor_conn is overwritten when a new connection is
            # accepted via server.accept(). Dead-socket writes are caught
            # by the sendall error handler in the command handler.
            try:
                conn.close()
            except OSError:
                pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load persisted history so logs survive a middleman restart.
    if os.path.exists(EVENTS_FILE):
        try:
            with open(EVENTS_FILE, "r", encoding="utf-8") as f:
                loaded = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            loaded = []
            log.warning("could not load persisted events: %s", exc)
        if isinstance(loaded, list):
            loaded = loaded[:MAX_RECENT]
            async with recent_events_lock:
                recent_events[:] = loaded
            log.info("loaded %d persisted events", len(recent_events))

    # Load persisted deny list so the frontend can show currently denied
    # cgroups/inodes across restarts.
    _load_denied()
    log.info("loaded deny list: %d cgroups", len(denied_cgroups))

    # Capture the running (uvicorn) event loop. The UNIX socket reader runs
    # in a background thread, but every broadcast is scheduled on this loop
    # so WebSocket clients, the client set, and the recent-events buffer
    # all live on a single asyncio loop.
    main_loop = asyncio.get_running_loop()
    t = threading.Thread(target=socket_reader_loop, args=(main_loop,), daemon=True)
    t.start()
    yield


# Create the app ONCE with lifespan
app = FastAPI(title="libbpf-exp Middleman", lifespan=lifespan)

# CORS for regular HTTP endpoints
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    # Accept the connection regardless of origin (WebSocket CORS is handled
    # manually here because CORSMiddleware does not cover WebSocket upgrades).
    origin = websocket.headers.get("origin", "unknown")
    log.info("WebSocket connection attempt from origin: %s", origin)
    await websocket.accept()
    async with clients_lock:
        clients.add(websocket)
    # Backfill recent history so a new or refreshing client sees past events
    # immediately instead of an empty table.
    async with recent_events_lock:
        history = [entry["event"] for entry in list(recent_events)]
    for entry in history:
        try:
            await websocket.send_text(json.dumps(entry))
        except Exception:
            break
    log.info("WebSocket client connected (total: %d, backfilled %d events)", len(clients), len(history))
    try:
        while True:
            # Keep connection alive; ignore incoming messages
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        async with clients_lock:
            clients.discard(websocket)
        log.info("WebSocket client disconnected (total: %d)", len(clients))


@app.get("/")
async def root():
    return {"status": "ok", "clients": len(clients)}


@app.get("/test")
async def test_page():
    """Simple HTML page to test WebSocket connectivity directly."""
    return HTMLResponse(content="""
    <!DOCTYPE html>
    <html>
    <head><title>WebSocket Test</title></head>
    <body>
        <h2>WebSocket Test</h2>
        <div id="status">Connecting...</div>
        <div id="messages"></div>
        <script>
            const status = document.getElementById('status');
            const messages = document.getElementById('messages');
            const ws = new WebSocket('ws://' + window.location.host + '/ws');
            ws.onopen = () => {
                status.textContent = 'CONNECTED';
                status.style.color = 'green';
            };
            ws.onmessage = (event) => {
                const div = document.createElement('div');
                div.textContent = event.data;
                messages.prepend(div);
            };
            ws.onclose = () => {
                status.textContent = 'DISCONNECTED';
                status.style.color = 'red';
            };
            ws.onerror = (err) => {
                status.textContent = 'ERROR: ' + err;
                status.style.color = 'red';
            };
        </script>
    </body>
    </html>
    """, media_type="text/html")


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/v1/models")
async def models():
    """Return information about connected clients and recent events."""
    async with clients_lock:
        client_count = len(clients)
    async with recent_events_lock:
        events_copy = list(recent_events[:10])
    return {
        "status": "ok",
        "connected_clients": client_count,
        "recent_events": events_copy,
    }


@app.post("/v1/command")
async def command(req: CommandRequest):
    """Send a deny/allow/audit-only command to the eBPF auditor.

    The command is forwarded as a JSON line over the UNIX socket to the
    auditor, which applies it to the police BPF maps (denied_inodes,
    denied_cgroups, police_config) and emits a CMD_ACK event back.

    The middleman also tracks the deny/allow state locally so the frontend
    can display currently denied cgroups/inodes via GET /v1/denied.
    """
    payload = req.model_dump(exclude_none=True)
    text = json.dumps(payload)

    print(f"[MIDDLEMAN] command handler: about to read auditor_conn", flush=True)
    with auditor_conn_lock:
        conn = auditor_conn[0]
        print(f"[MIDDLEMAN] command handler: read auditor_conn = {'set' if conn else 'None'} (id={id(conn) if conn else 'N/A'})", flush=True)

    print(f"[MIDDLEMAN] command handler: auditor_conn is {'set' if conn else 'None'} (conn={id(conn) if conn else 'N/A'})", flush=True)

    if conn is None:
        return {"status": "error", "message": "auditor not connected"}

    # Verify the connection is still alive before sending.
    # select.poll() is not available on Windows; use select.select() instead.
    try:
        r, w, x = select.select([conn], [], [conn], 0)
        if x:
            return {"status": "error", "message": "auditor connection is dead"}
    except (OSError, TypeError):
        # OSError: socket error; TypeError: conn has no fileno() (e.g.,
        # MagicMock in tests). In both cases assume the connection is alive
        # and let sendall() report any real failure.
        pass

    try:
        conn.sendall((text + "\n").encode("utf-8"))
    except (OSError, BrokenPipeError, ConnectionError) as exc:
        return {"status": "error", "message": str(exc)}

    # Update the local deny list so the frontend can show currently denied
    # cgroup paths. The server resolves the path to its inode internally
    # (mirroring what the auditor's path_to_id() does in userspace C) and
    # stores the resolved inode for display only. The auditor receives the
    # raw path and performs its own stat() conversion before updating the
    # BPF denied_cgroups map.
    action = req.action
    if action == "deny_path" and req.path:
        inode, _ = path_to_inode(req.path)
        entry = {"path": req.path}
        if inode is not None:
            entry["inode"] = inode
        async with denied_lock:
            if entry not in denied_cgroups:
                denied_cgroups.append(entry)
            _persist_denied()
    elif action == "allow_path" and req.path:
        async with denied_lock:
            # Remove any entry matching this path (with or without inode).
            denied_cgroups[:] = [e for e in denied_cgroups if e.get("path") != req.path]
            _persist_denied()
    elif action in ("deny_inode", "allow_inode"):
        # Raw inode commands are not exposed over the HTTP API. Users work
        # with paths; the server resolves them to inodes internally.
        return {"status": "error", "message": "use deny_path/allow_path instead of raw inodes"}

    # Broadcast the command to WebSocket clients so the frontend can show it.
    await broadcast(json.dumps({
        "type": "CMD_SENT",
        "action": req.action,
        "payload": payload,
    }))
    return {"status": "ok", "sent": text}


@app.post("/v1/cgroup/move")
async def cgroup_move(req: CgroupMoveRequest):
    """Move a process into a cgroup by writing its PID to cgroup.procs.

    Requires root privileges and that the target cgroup directory exists.
    """
    cgroup_procs = f"{req.cgroup_path.rstrip('/')}/cgroup.procs"

    try:
        pid = int(req.pid)
        if pid <= 0:
            return {"status": "error", "message": "PID must be a positive integer"}

        # cgroup v2 (especially under WSL2) can transiently return EBUSY
        # when writing to cgroup.procs. Retry a few times before giving up.
        last_exc = None
        for attempt in range(5):
            try:
                with open(cgroup_procs, "w") as f:
                    f.write(str(pid))
                last_exc = None
                break
            except OSError as exc:
                last_exc = exc
                if exc.errno != errno.EBUSY or attempt == 4:
                    raise
                time.sleep(0.5 * (attempt + 1))
        if last_exc is not None:
            raise last_exc

    except (ValueError, TypeError):
        return {"status": "error", "message": "Invalid PID"}
    except FileNotFoundError:
        return {"status": "error", "message": f"Cgroup not found: {req.cgroup_path}"}
    except PermissionError:
        return {"status": "error", "message": "Permission denied (run middleman as root)"}
    except OSError as exc:
        return {"status": "error", "message": str(exc)}

    # Broadcast the move to WebSocket clients so the frontend can show it.
    await broadcast(json.dumps({
        "type": "CGROUP_MOVE",
        "pid": pid,
        "cgroup_path": req.cgroup_path,
    }))
    return {"status": "ok", "pid": pid, "cgroup_path": req.cgroup_path}


@app.get("/v1/cgroup/procs")
async def cgroup_procs(cgroup_path: str = DEFAULT_CGROUP_PATH):
    """Return the PIDs currently inside a cgroup's cgroup.procs file.

    Defaults to the denied cgroup (/sys/fs/cgroup/denied). Requires the
    middleman to run with sufficient privileges to read cgroup.procs.
    """
    pids = read_cgroup_procs(cgroup_path)
    return {
        "status": "ok",
        "cgroup_path": cgroup_path,
        "pids": pids,
        "count": len(pids),
    }


@app.post("/v1/cgroup/remove")
async def cgroup_remove(req: CgroupMoveRequest):
    """Remove a process from a cgroup by writing its PID to the parent
    cgroup's cgroup.procs file.

    In cgroup v2, writing a PID to a cgroup's cgroup.procs moves the process
    into that cgroup. To remove a process from the denied cgroup we write its
    PID to the parent cgroup's cgroup.procs, which preserves every other PID
    currently listed in the denied cgroup.
    """
    cgroup_path = req.cgroup_path.rstrip('/')
    parent = os.path.dirname(cgroup_path) or "/sys/fs/cgroup"
    target_procs = f"{parent}/cgroup.procs"

    try:
        pid = int(req.pid)
        if pid <= 0:
            return {"status": "error", "message": "PID must be a positive integer"}

        # cgroup v2 (especially under WSL2) can transiently return EBUSY
        # when writing to cgroup.procs. Retry aggressively before giving up.
        last_exc = None
        for attempt in range(10):
            try:
                with open(target_procs, "w") as f:
                    f.write(str(pid))
                last_exc = None
                break
            except OSError as exc:
                last_exc = exc
                if exc.errno != errno.EBUSY or attempt == 9:
                    raise
                time.sleep(1.0 * (attempt + 1))
        if last_exc is not None:
            raise last_exc

    except (ValueError, TypeError):
        return {"status": "error", "message": "Invalid PID"}
    except FileNotFoundError:
        return {"status": "error", "message": f"Parent cgroup not found: {parent}"}
    except PermissionError:
        return {"status": "error", "message": "Permission denied (run middleman as root)"}
    except OSError as exc:
        return {"status": "error", "message": str(exc)}

    # Broadcast the removal so the frontend can refresh the list.
    await broadcast(json.dumps({
        "type": "CGROUP_REMOVE",
        "pid": pid,
        "cgroup_path": cgroup_path,
        "to": parent,
    }))
    return {"status": "ok", "pid": pid, "from": cgroup_path, "to": parent}


@app.get("/v1/denied")
async def denied():
    """Return the currently denied cgroup paths.

    The list is maintained by the middleman from /v1/command deny/allow
    requests and persisted to disk, so it survives middleman restarts.
    Each entry is {"path": str, "inode": Optional[int]} where the inode is
    resolved server-side for display only -- the user never types it.
    """
    async with denied_lock:
        return {
            "status": "ok",
            "cgroups": list(denied_cgroups),
        }


@app.get("/v1/debug/auditor_conn")
async def debug_auditor_conn():
    """Debug endpoint to check auditor connection state."""
    with auditor_conn_lock:
        connected = auditor_conn[0] is not None
    return {"status": "ok", "auditor_connected": connected}


if __name__ == "__main__":
    uvicorn.run(app, host=HOST, port=PORT)
