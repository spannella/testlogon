from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app
from app.routers import browser_ssh_terminal


class DeterministicEchoBridge:
    def __init__(self) -> None:
        self.closed = False
        self._output: list[str] = []

    def connect(self) -> None:
        self._output.append("connected\r\n")

    def poll_output(self) -> str:
        if not self._output:
            return ""
        return self._output.pop(0)

    def send_input(self, data: str) -> None:
        normalized = data.replace("\r\n", "\n")
        if normalized.strip() == "echo smoke":
            self._output.append("smoke\r\n")
        else:
            self._output.append(normalized)

    def resize(self, cols: int, rows: int) -> None:
        self._output.append(f"resize:{cols}x{rows}\r\n")

    def close(self) -> None:
        self.closed = True


def _allow_terminal_ws_access(monkeypatch) -> None:
    async def _allow(_websocket):
        return {"user_sub": "e2e-user", "role": "admin"}, None

    monkeypatch.setattr(browser_ssh_terminal, "_authorize_terminal_access", _allow)


def test_browser_ssh_e2e_connect_command_resize_disconnect(monkeypatch) -> None:
    _allow_terminal_ws_access(monkeypatch)
    bridge = DeterministicEchoBridge()
    monkeypatch.setattr(browser_ssh_terminal, "_create_ssh_bridge", lambda *_: bridge)

    app = create_app()
    client = TestClient(app)

    with client.websocket_connect("/api/browser-ssh/ws") as ws:
        ready = ws.receive_json()
        assert ready["type"] == "status"
        assert ready["payload"]["phase"] == "ready"

        ws.send_json(
            {
                "type": "connect",
                "payload": {
                    "host": "fixture.internal",
                    "port": 22,
                    "username": "alice",
                    "authType": "password",
                    "password": "secret",
                },
            }
        )
        connected = ws.receive_json()
        assert connected["type"] == "status"
        assert connected["payload"]["phase"] == "connected"

        ws.send_json({"type": "input", "payload": {"data": "echo smoke\n"}})
        first_output = ws.receive_json()
        assert first_output["type"] == "output"
        output = ws.receive_json()
        assert output["type"] == "output"
        assert "smoke" in output["payload"]["data"]

        ws.send_json({"type": "resize", "payload": {"cols": 132, "rows": 40}})
        resized = ws.receive_json()
        assert resized["type"] == "status"
        assert resized["payload"]["phase"] == "resized"

    assert bridge.closed is True
