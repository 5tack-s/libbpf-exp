import asyncio
import sys
sys.path.insert(0, '/root/libbpf-exp/middleman')

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
import uvicorn
import socket
import os
import threading

SOCK_PATH = "/tmp/libbpf-exp-test.sock"
clients = set()
clients_lock = asyncio.Lock()

async def broadcast(message: str):
    async with clients_lock:
        dead = []
        for ws in clients:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            clients.discard(ws)


def _log_broadcast_errors(future):
    try:
        future.result()
    except Exception as exc:  # pragma: no cover - defensive logging
        print(f"[test] broadcast to WebSocket clients failed: {exc}", flush=True)

app = FastAPI()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    clients.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        clients.discard(websocket)

@app.get("/")
async def root():
    return {"status": "ok", "clients": len(clients)}

def socket_reader_loop(main_loop):
    try:
        os.unlink(SOCK_PATH)
    except FileNotFoundError:
        pass
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCK_PATH)
    server.listen(1)
    server.settimeout(1.0)
    print(f"[test] listening on {SOCK_PATH}", flush=True)
    while True:
        try:
            conn, _ = server.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        conn.settimeout(5.0)
        buf = b""
        try:
            while True:
                try:
                    data = conn.recv(4096)
                except socket.timeout:
                    continue
                if not data:
                    break
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    try:
                        text = line.decode("utf-8").strip()
                    except UnicodeDecodeError:
                        continue
                    if not text:
                        continue
                    import json
                    try:
                        json.loads(text)
                    except json.JSONDecodeError:
                        continue
                    try:
                        future = asyncio.run_coroutine_threadsafe(
                            broadcast(text), main_loop
                        )
                        future.add_done_callback(_log_broadcast_errors)
                    except RuntimeError as exc:
                        print(f"[test] broadcast not delivered: {exc}", flush=True)
        except (OSError, ConnectionError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

@app.on_event("startup")
async def startup():
    main_loop = asyncio.get_running_loop()
    t = threading.Thread(target=socket_reader_loop, args=(main_loop,), daemon=True)
    t.start()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
