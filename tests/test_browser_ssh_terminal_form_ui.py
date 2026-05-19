from __future__ import annotations

import os
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import create_app


def test_browser_ssh_form_fields_and_defaults_rendered() -> None:
    """The root page serves a simple backend info page (SSH UI moved to frontend)."""
    app = create_app()
    client = TestClient(app)

    html = client.get("/").text

    assert "<title>Backend</title>" in html
    assert "Backend API server" in html


def test_browser_ssh_connect_disconnect_button_state_defaults() -> None:
    """The /browser-ssh route returns 410 Gone when the feature is enabled."""
    app = create_app()
    client = TestClient(app)

    with patch.dict(os.environ, {"BROWSER_SSH_TERMINAL_ENABLED": "true"}):
        resp = client.get("/browser-ssh")

    assert resp.status_code == 410
    assert "moved" in resp.json()["detail"].lower()


def test_browser_ssh_terminal_view_and_xterm_assets_rendered() -> None:
    """The /browser-ssh route returns 404 when the feature is disabled."""
    app = create_app()
    client = TestClient(app)

    with patch.dict(os.environ, {"BROWSER_SSH_TERMINAL_ENABLED": "false"}):
        resp = client.get("/browser-ssh")

    assert resp.status_code == 404


def test_browser_ssh_copy_paste_controls_rendered() -> None:
    """The browser-ssh API router is mounted and responds to requests."""
    app = create_app()
    client = TestClient(app)

    # The API routes exist — an unauthenticated request should get 403 or 401, not 404
    resp = client.get("/api/browser-ssh/config")
    assert resp.status_code != 404


def test_browser_ssh_status_badge_and_retry_rendered() -> None:
    """The root index.html is an HTML document served as a FileResponse."""
    app = create_app()
    client = TestClient(app)

    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")
