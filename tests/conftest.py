"""Pytest fixtures for libbpf-exp middleman tests.

Provides a FastAPI TestClient backed by a temporary events file and an
optional mock auditor UNIX-socket connection, so the HTTP API and WebSocket
can be tested without a running kernel, root privileges, or a live eBPF
auditor.
"""

import json
import os
import sys
import tempfile
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

# Ensure the middleman package is importable.
MIDDLEMAN_DIR = os.path.join(os.path.dirname(__file__), "..", "middleman")
sys.path.insert(0, os.path.abspath(MIDDLEMAN_DIR))

import main  # noqa: E402  (import after sys.path insert)


@pytest.fixture
def temp_events_file():
    """Path to a writable temp events file; removed after the test."""
    fd, path = tempfile.mkstemp(suffix="-libbpf-exp-events.json")
    os.close(fd)
    yield path
    try:
        os.unlink(path)
    except OSError:
        pass


@pytest.fixture
def temp_denied_file():
    """Path to a writable temp denied file; removed after the test."""
    fd, path = tempfile.mkstemp(suffix="-libbpf-exp-denied.json")
    os.close(fd)
    yield path
    try:
        os.unlink(path)
    except OSError:
        pass


@pytest.fixture
def client(temp_events_file, temp_denied_file, monkeypatch):
    """FastAPI TestClient with isolated state.

    - Points EVENTS_FILE and DENIED_FILE at temp files so tests don't clobber
      /tmp/libbpf-exp-events.json or /tmp/libbpf-exp-denied.json.
    - Clears connected clients, recent events, and denied lists between tests.
    - No auditor is connected by default (command tests should use
      the ``mock_auditor_conn`` fixture).
    """
    main.EVENTS_FILE = temp_events_file
    main.DENIED_FILE = temp_denied_file
    main.clients = set()
    main.recent_events = []
    main.denied_cgroups = []
    main.auditor_conn = [None]

    with TestClient(main.app) as test_client:
        yield test_client


@pytest.fixture
def mock_auditor_conn(monkeypatch):
    """A mock auditor connection that captures every command sent over the
    UNIX socket. Yields the mock so tests can assert what was sent."""
    mock = MagicMock(spec=["sendall", "close"])
    main.auditor_conn = [mock]
    yield mock
    main.auditor_conn = [None]
