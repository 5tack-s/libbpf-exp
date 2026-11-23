"""End-to-end HTTP/WebSocket tests for the libbpf-exp FastAPI middleman.

These tests use FastAPI's TestClient, so they do not require a running
server, root privileges, cgroup v2, or a loaded eBPF auditor. The
``mock_auditor_conn`` fixture captures commands forwarded to the auditor,
allowing the deny/allow command path to be verified end-to-end.

Run with:

    pytest tests/
"""

import json
import os

import pytest
from fastapi.testclient import TestClient

import main  # noqa: F401  (conftest already imports it; re-import for clarity)


# ---------------------------------------------------------------------------
# Health / info endpoints
# ---------------------------------------------------------------------------

def test_health(client: TestClient):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_root(client: TestClient):
    resp = client.get("/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert "clients" in body


def test_openapi(client: TestClient):
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    data = resp.json()
    assert "paths" in data
    paths = data["paths"]
    # The command and cgroup-move endpoints should be documented.
    assert "/v1/command" in paths
    assert "/v1/cgroup/move" in paths


def test_models(client: TestClient):
    resp = client.get("/v1/models")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert "connected_clients" in body
    assert "recent_events" in body


# ---------------------------------------------------------------------------
# Command endpoint (deny / allow inode or path)
# ---------------------------------------------------------------------------

def test_command_deny_path(client: TestClient, mock_auditor_conn):
    """Denying a cgroup path is the primary way to deny a cgroup from the
    web frontend. The server resolves the path to its inode internally and
    forwards deny_path to the auditor, which stats the path and keys the
    BPF denied_cgroups map on st_ino."""
    path = "/sys/fs/cgroup/untrusted"
    resp = client.post(
        "/v1/command",
        json={"action": "deny_path", "path": path},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    mock_auditor_conn.sendall.assert_called_once()
    sent = json.loads(mock_auditor_conn.sendall.call_args[0][0])
    assert sent == {"action": "deny_path", "path": path}


def test_command_allow_path(client: TestClient, mock_auditor_conn):
    path = "/sys/fs/cgroup/untrusted"
    resp = client.post(
        "/v1/command",
        json={"action": "allow_path", "path": path},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    mock_auditor_conn.sendall.assert_called_once()
    sent = json.loads(mock_auditor_conn.sendall.call_args[0][0])
    assert sent == {"action": "allow_path", "path": path}


def test_command_no_auditor(client: TestClient):
    """Without a connected auditor the command endpoint must return an
    error instead of crashing."""
    resp = client.post(
        "/v1/command",
        json={"action": "deny_path", "path": "/sys/fs/cgroup/denied"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "error"
    assert "auditor not connected" in body["message"]


def test_command_rejects_raw_inode(client: TestClient, mock_auditor_conn):
    """Raw inode commands (deny_inode/allow_inode) are not exposed over the
    HTTP API. Users work with paths; the server resolves them internally."""
    resp = client.post(
        "/v1/command",
        json={"action": "deny_inode", "inode": 12345},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "error"
    assert "deny_path/allow_path" in body["message"]


def test_command_missing_action(client: TestClient, mock_auditor_conn):
    resp = client.post("/v1/command", json={"path": "/sys/fs/cgroup/denied"})
    assert resp.status_code == 422  # FastAPI validation error


# ---------------------------------------------------------------------------
# Cgroup move endpoint (move a process into the denied cgroup)
# ---------------------------------------------------------------------------

def test_cgroup_move_success(client: TestClient, tmp_path):
    """Moving a PID into a cgroup writes the PID to cgroup.procs."""
    cg_dir = tmp_path / "cgroup"
    cg_dir.mkdir()
    (cg_dir / "cgroup.procs").write_text("")

    resp = client.post(
        "/v1/cgroup/move",
        json={"pid": 1234, "cgroup_path": str(cg_dir)},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["pid"] == 1234
    assert body["cgroup_path"] == str(cg_dir)

    # Verify the PID was actually written.
    contents = (cg_dir / "cgroup.procs").read_text().strip()
    assert contents == "1234"


def test_cgroup_move_invalid_pid(client: TestClient):
    resp = client.post(
        "/v1/cgroup/move",
        json={"pid": -5, "cgroup_path": "/tmp"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "error"
    assert "positive integer" in body["message"]


def test_cgroup_move_nonexistent_cgroup(client: TestClient):
    resp = client.post(
        "/v1/cgroup/move",
        json={"pid": 1, "cgroup_path": "/tmp/does-not-exist-cgroup-xyz"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "error"
    assert "not found" in body["message"]


def test_cgroup_move_missing_fields(client: TestClient):
    resp = client.post("/v1/cgroup/move", json={"pid": 1})
    assert resp.status_code == 422  # cgroup_path is required


# ---------------------------------------------------------------------------
# Denied list endpoint
# ---------------------------------------------------------------------------

def test_denied_empty(client: TestClient):
    """With no denies applied, the endpoint returns an empty cgroups list."""
    resp = client.get("/v1/denied")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["cgroups"] == []


def test_denied_tracked_from_command(client: TestClient, mock_auditor_conn):
    """Deny commands sent via /v1/command should appear in /v1/denied."""
    client.post("/v1/command", json={"action": "deny_path", "path": "/sys/fs/cgroup/untrusted"})

    resp = client.get("/v1/denied")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert {"path": "/sys/fs/cgroup/untrusted"} in body["cgroups"]


def test_denied_allow_removes(client: TestClient, mock_auditor_conn):
    """Allowing a path should remove it from the denied list."""
    client.post("/v1/command", json={"action": "deny_path", "path": "/sys/fs/cgroup/untrusted"})
    client.post("/v1/command", json={"action": "allow_path", "path": "/sys/fs/cgroup/untrusted"})

    resp = client.get("/v1/denied")
    assert resp.status_code == 200
    body = resp.json()
    assert body["cgroups"] == []


def test_denied_openapi(client: TestClient):
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    assert "/v1/denied" in resp.json()["paths"]


# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------

def test_websocket_connect(client: TestClient):
    """Verifies the WebSocket upgrade is accepted. No inbound message is
    expected (the endpoint waits for client messages after backfill)."""
    with client.websocket_connect("/ws") as ws:
        # Just confirming the connection was accepted is enough;
        # receive_text() would block since the server waits for client input.
        pass


def test_websocket_backfills_history(temp_events_file, monkeypatch):
    """A newly connected WebSocket client receives previously persisted
    events from the events file (loaded at startup via lifespan)."""
    persisted = [
        {
            "received_at": "2026-01-01T00:00:00+00:00",
            "event": {
                "ts_ms": 1731500000000,
                "type": "POLICE",
                "pid": 999,
                "comm": "testproc",
                "cgid": 5678,
                "inode": 5678,
                "cmd": 5,
                "reason": "cgroup",
            },
        }
    ]
    with open(temp_events_file, "w") as f:
        json.dump(persisted, f)

    # Point the app at the temp file and start a fresh client so lifespan
    # loads the persisted events on startup.
    main.EVENTS_FILE = temp_events_file
    main.clients = set()
    main.recent_events = []
    with TestClient(main.app) as test_client:
        with test_client.websocket_connect("/ws") as ws:
            data = ws.receive_text()
            payload = json.loads(data)
            assert payload["type"] == "POLICE"
            assert payload["pid"] == 999
            assert payload["comm"] == "testproc"


# ---------------------------------------------------------------------------
# Test page
# ---------------------------------------------------------------------------

def test_test_page(client: TestClient):
    resp = client.get("/test")
    assert resp.status_code == 200
    assert "WebSocket" in resp.text
    assert "/ws" in resp.text
