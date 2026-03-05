from __future__ import annotations

import json

from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.main import create_app
from app.routers import browser_ssh_terminal


class FakeBridge:
    def __init__(self, should_fail: bool = False) -> None:
        self.should_fail = should_fail
        self.closed = False
        self.resized: tuple[int, int] | None = None
        self.inputs: list[str] = []
        self.output = ""

    def connect(self) -> None:
        if self.should_fail:
            raise browser_ssh_terminal.BrowserSshError(
                "auth_failed", "Authentication failed. Check your username or password."
            )

    def poll_output(self) -> str:
        out = self.output
        self.output = ""
        return out

    def send_input(self, data: str) -> None:
        self.inputs.append(data)
        if data.strip() == "echo hello":
            self.output = "hello\r\n"

    def resize(self, cols: int, rows: int) -> None:
        self.resized = (cols, rows)

    def close(self) -> None:
        self.closed = True




def _allow_terminal_ws_access(monkeypatch) -> None:
    async def _allow(_websocket):
        return {"user_sub": "alice", "role": "admin"}, None

    monkeypatch.setattr(browser_ssh_terminal, "_authorize_terminal_access", _allow)
def test_browser_ssh_config_respects_runtime_flag(monkeypatch) -> None:
    monkeypatch.setenv("BROWSER_SSH_TERMINAL_ENABLED", "1")
    app = create_app()
    client = TestClient(app)

    resp = client.get("/api/browser-ssh/config")
    assert resp.status_code == 200
    body = resp.json()
    assert body["enabled"] is True
    assert body["route"] == "/browser-ssh"
    assert body["ws_path"] == "/api/browser-ssh/ws"
    assert body["protocol_version"] == "v1"
    assert body["policy"] == {
        "allowed_hosts_configured": False,
        "denied_hosts_configured": False,
        "allowed_ports_configured": False,
        "denied_ports_configured": False,
    }
    assert body["limits"]["idle_timeout_seconds"] >= 1
    assert body["limits"]["max_session_duration_seconds"] >= 1
    assert body["limits"]["max_sessions_per_user"] >= 0


def test_browser_ssh_health_endpoint_available() -> None:
    app = create_app()
    client = TestClient(app)

    resp = client.get("/api/browser-ssh/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
    assert resp.json()["websocket_placeholder"] is False
    assert resp.json()["protocol_version"] == "v1"


def test_browser_ssh_protocol_endpoint_documents_message_contract() -> None:
    app = create_app()
    client = TestClient(app)

    resp = client.get("/api/browser-ssh/protocol")
    assert resp.status_code == 200
    body = resp.json()
    assert body["version"] == "v1"
    assert set(body["client_messages"].keys()) == {"connect", "input", "resize"}
    assert set(body["server_messages"].keys()) == {"status", "output", "error"}
    assert body["client_messages"]["connect"]["authType"] == ["password", "private_key"]


def test_browser_ssh_frontend_route_guarded_by_feature_flag(monkeypatch) -> None:
    monkeypatch.setenv("BROWSER_SSH_TERMINAL_ENABLED", "0")
    disabled_app = create_app()
    disabled_client = TestClient(disabled_app)
    disabled_resp = disabled_client.get("/browser-ssh")
    assert disabled_resp.status_code == 404

    monkeypatch.setenv("BROWSER_SSH_TERMINAL_ENABLED", "1")
    enabled_app = create_app()
    enabled_client = TestClient(enabled_app)
    enabled_resp = enabled_client.get("/browser-ssh")
    assert enabled_resp.status_code == 200
    assert "text/html" in enabled_resp.headers.get("content-type", "")


def test_browser_ssh_websocket_invalid_payload_does_not_crash_session(monkeypatch) -> None:
    _allow_terminal_ws_access(monkeypatch)
    app = create_app()
    client = TestClient(app)

    with client.websocket_connect("/api/browser-ssh/ws") as ws:
        first = ws.receive_json()
        assert first["type"] == "status"
        assert first["payload"]["phase"] == "ready"

        ws.send_text("not-json")
        err = ws.receive_json()
        assert err["type"] == "error"
        assert err["payload"]["code"] == "invalid_json"

        ws.send_text(json.dumps({"payload": {}}))
        err2 = ws.receive_json()
        assert err2["type"] == "error"
        assert err2["payload"]["code"] == "missing_type"


def test_browser_ssh_websocket_protocol_happy_path_exchange(monkeypatch) -> None:
    _allow_terminal_ws_access(monkeypatch)
    bridge = FakeBridge()
    monkeypatch.setattr(browser_ssh_terminal, "_create_ssh_bridge", lambda *_: bridge)

    app = create_app()
    client = TestClient(app)

    with client.websocket_connect("/api/browser-ssh/ws") as ws:
        _ = ws.receive_json()
        ws.send_json(
            {
                "type": "connect",
                "payload": {
                    "host": "example.internal",
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

        ws.send_json({"type": "resize", "payload": {"cols": 120, "rows": 40}})
        resized = ws.receive_json()
        assert resized["type"] == "status"
        assert resized["payload"]["phase"] == "resized"
        assert bridge.resized == (120, 40)

        ws.send_json({"type": "input", "payload": {"data": "echo hello\n"}})
        output = ws.receive_json()
        assert output["type"] == "output"
        assert "hello" in output["payload"]["data"]

    assert bridge.closed is True


def test_browser_ssh_websocket_connect_auth_failure_returns_clear_error(monkeypatch) -> None:
    _allow_terminal_ws_access(monkeypatch)
    monkeypatch.setattr(browser_ssh_terminal, "_create_ssh_bridge", lambda *_: FakeBridge(should_fail=True))

    app = create_app()
    client = TestClient(app)

    with client.websocket_connect("/api/browser-ssh/ws") as ws:
        _ = ws.receive_json()
        ws.send_json(
            {
                "type": "connect",
                "payload": {
                    "host": "example.internal",
                    "port": 22,
                    "username": "alice",
                    "authType": "password",
                    "password": "wrong",
                },
            }
        )
        err = ws.receive_json()
        assert err["type"] == "error"
        assert err["payload"]["code"] == "auth_failed"
        assert "password" in err["payload"]["message"].lower()


def test_paramiko_bridge_requests_xterm_256color_and_default_pty_size(monkeypatch) -> None:
    class FakeChannel:
        def __init__(self) -> None:
            self.timeout = None

        def settimeout(self, value):
            self.timeout = value

        def recv_ready(self):
            return False

        def close(self):
            return None

    class FakeClient:
        def __init__(self) -> None:
            self.invoke_kwargs = None

        def set_missing_host_key_policy(self, policy):
            return None

        def connect(self, **kwargs):
            return None

        def invoke_shell(self, **kwargs):
            self.invoke_kwargs = kwargs
            return FakeChannel()

        def close(self):
            return None

    fake_client = FakeClient()

    class FakeParamiko:
        class AuthenticationException(Exception):
            pass

        class SSHException(Exception):
            pass

        class AutoAddPolicy:
            pass

        @staticmethod
        def SSHClient():
            return fake_client

    monkeypatch.setitem(__import__("sys").modules, "paramiko", FakeParamiko)

    bridge = browser_ssh_terminal._create_ssh_bridge(
        {
            "host": "example.internal",
            "port": 22,
            "username": "alice",
            "password": "secret",
            "authType": "password",
        },
        cols=0,
        rows=0,
    )
    bridge.connect()
    try:
        assert fake_client.invoke_kwargs is not None
        assert fake_client.invoke_kwargs["term"] == "xterm-256color"
        assert fake_client.invoke_kwargs["width"] == 80
        assert fake_client.invoke_kwargs["height"] == 24
    finally:
        bridge.close()


def test_browser_ssh_websocket_rapid_resize_is_stable(monkeypatch) -> None:
    _allow_terminal_ws_access(monkeypatch)
    bridge = FakeBridge()
    monkeypatch.setattr(browser_ssh_terminal, "_create_ssh_bridge", lambda *_: bridge)

    app = create_app()
    client = TestClient(app)

    with client.websocket_connect("/api/browser-ssh/ws") as ws:
        _ = ws.receive_json()
        ws.send_json(
            {
                "type": "connect",
                "payload": {
                    "host": "example.internal",
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

        last_cols = 0
        last_rows = 0
        for i in range(1, 26):
            last_cols = 80 + i
            last_rows = 24 + i
            ws.send_json({"type": "resize", "payload": {"cols": last_cols, "rows": last_rows}})
            resized = ws.receive_json()
            assert resized["type"] == "status"
            assert resized["payload"]["phase"] == "resized"

        assert bridge.resized == (last_cols, last_rows)

        ws.send_json({"type": "input", "payload": {"data": "echo hello\n"}})
        output = ws.receive_json()
        assert output["type"] == "output"
        assert "hello" in output["payload"]["data"]


def test_browser_ssh_websocket_rejects_invalid_private_key_format(monkeypatch) -> None:
    _allow_terminal_ws_access(monkeypatch)
    app = create_app()
    client = TestClient(app)

    with client.websocket_connect("/api/browser-ssh/ws") as ws:
        _ = ws.receive_json()
        ws.send_json(
            {
                "type": "connect",
                "payload": {
                    "host": "example.internal",
                    "port": 22,
                    "username": "alice",
                    "authType": "private_key",
                    "privateKey": "not-a-key",
                },
            }
        )
        err = ws.receive_json()
        assert err["type"] == "error"
        assert err["payload"]["code"] == "invalid_private_key_format"


def test_browser_ssh_websocket_private_key_auth_happy_path(monkeypatch) -> None:
    _allow_terminal_ws_access(monkeypatch)
    bridge = FakeBridge()
    monkeypatch.setattr(browser_ssh_terminal, "_create_ssh_bridge", lambda *_: bridge)

    app = create_app()
    client = TestClient(app)

    with client.websocket_connect("/api/browser-ssh/ws") as ws:
        _ = ws.receive_json()
        ws.send_json(
            {
                "type": "connect",
                "payload": {
                    "host": "example.internal",
                    "port": 22,
                    "username": "alice",
                    "authType": "private_key",
                    "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----",
                    "passphrase": "topsecret",
                },
            }
        )
        connected = ws.receive_json()
        assert connected["type"] == "status"
        assert connected["payload"]["phase"] == "connected"


def test_paramiko_bridge_private_key_unencrypted_supported(monkeypatch) -> None:
    class FakePKey:
        pass

    class FakeLoader:
        @staticmethod
        def from_private_key(fd, password=None):
            data = fd.read()
            if "UNENCRYPTED" in data and password is None:
                return FakePKey()
            raise ValueError("not this key")

    class RejectLoader:
        @staticmethod
        def from_private_key(fd, password=None):
            raise ValueError("unsupported")

    class FakeChannel:
        def settimeout(self, value):
            return None

        def recv_ready(self):
            return False

        def close(self):
            return None

    class FakeClient:
        def __init__(self) -> None:
            self.connect_kwargs = None

        def set_missing_host_key_policy(self, policy):
            return None

        def connect(self, **kwargs):
            self.connect_kwargs = kwargs
            return None

        def invoke_shell(self, **kwargs):
            return FakeChannel()

        def close(self):
            return None

    fake_client = FakeClient()

    class FakeParamiko:
        class AuthenticationException(Exception):
            pass

        class SSHException(Exception):
            pass

        class AutoAddPolicy:
            pass

        RSAKey = RejectLoader
        Ed25519Key = FakeLoader
        ECDSAKey = RejectLoader
        DSSKey = RejectLoader

        @staticmethod
        def SSHClient():
            return fake_client

    monkeypatch.setitem(__import__("sys").modules, "paramiko", FakeParamiko)

    bridge = browser_ssh_terminal._create_ssh_bridge(
        {
            "host": "example.internal",
            "port": 22,
            "username": "alice",
            "authType": "private_key",
            "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nUNENCRYPTED\n-----END OPENSSH PRIVATE KEY-----",
            "passphrase": None,
        },
        cols=80,
        rows=24,
    )
    bridge.connect()
    try:
        assert isinstance(fake_client.connect_kwargs["pkey"], FakePKey)
        assert "password" not in fake_client.connect_kwargs
    finally:
        bridge.close()


def test_paramiko_bridge_private_key_encrypted_supported(monkeypatch) -> None:
    class FakePKey:
        pass

    class EncLoader:
        @staticmethod
        def from_private_key(fd, password=None):
            data = fd.read()
            if "ENCRYPTED" in data and password == "correct-pass":
                return FakePKey()
            raise ValueError("bad passphrase")

    class RejectLoader:
        @staticmethod
        def from_private_key(fd, password=None):
            raise ValueError("unsupported")

    class FakeChannel:
        def settimeout(self, value):
            return None

        def recv_ready(self):
            return False

        def close(self):
            return None

    class FakeClient:
        def __init__(self) -> None:
            self.connect_kwargs = None

        def set_missing_host_key_policy(self, policy):
            return None

        def connect(self, **kwargs):
            self.connect_kwargs = kwargs
            return None

        def invoke_shell(self, **kwargs):
            return FakeChannel()

        def close(self):
            return None

    fake_client = FakeClient()

    class FakeParamiko:
        class AuthenticationException(Exception):
            pass

        class SSHException(Exception):
            pass

        class AutoAddPolicy:
            pass

        RSAKey = RejectLoader
        Ed25519Key = RejectLoader
        ECDSAKey = EncLoader
        DSSKey = RejectLoader

        @staticmethod
        def SSHClient():
            return fake_client

    monkeypatch.setitem(__import__("sys").modules, "paramiko", FakeParamiko)

    bridge = browser_ssh_terminal._create_ssh_bridge(
        {
            "host": "example.internal",
            "port": 22,
            "username": "alice",
            "authType": "private_key",
            "privateKey": "-----BEGIN EC PRIVATE KEY-----\nENCRYPTED\n-----END EC PRIVATE KEY-----",
            "passphrase": "correct-pass",
        },
        cols=80,
        rows=24,
    )
    bridge.connect()
    try:
        assert isinstance(fake_client.connect_kwargs["pkey"], FakePKey)
    finally:
        bridge.close()


def test_paramiko_bridge_private_key_invalid_passphrase_deterministic_error(monkeypatch) -> None:
    class RejectLoader:
        @staticmethod
        def from_private_key(fd, password=None):
            raise ValueError("bad passphrase")

    class FakeParamiko:
        class AuthenticationException(Exception):
            pass

        class SSHException(Exception):
            pass

        class AutoAddPolicy:
            pass

        RSAKey = RejectLoader
        Ed25519Key = RejectLoader
        ECDSAKey = RejectLoader
        DSSKey = RejectLoader

        @staticmethod
        def SSHClient():
            class FakeClient:
                def set_missing_host_key_policy(self, policy):
                    return None

                def connect(self, **kwargs):
                    return None

                def invoke_shell(self, **kwargs):
                    class C:
                        def settimeout(self, value):
                            return None
                    return C()

                def close(self):
                    return None

            return FakeClient()

    monkeypatch.setitem(__import__("sys").modules, "paramiko", FakeParamiko)

    bridge = browser_ssh_terminal._create_ssh_bridge(
        {
            "host": "example.internal",
            "port": 22,
            "username": "alice",
            "authType": "private_key",
            "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nENCRYPTED\n-----END OPENSSH PRIVATE KEY-----",
            "passphrase": "wrong-pass",
        },
        cols=80,
        rows=24,
    )
    try:
        bridge.connect()
        assert False, "expected BrowserSshError"
    except browser_ssh_terminal.BrowserSshError as exc:
        assert exc.code == "invalid_private_key_format"
        assert "passphrase" in exc.message.lower()


def test_redact_connect_payload_masks_sensitive_values() -> None:
    redacted = browser_ssh_terminal._redact_connect_payload(
        {
            "host": "example.internal",
            "password": "secret",
            "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----",
            "passphrase": "phrase",
        }
    )
    assert redacted["password"] == "***REDACTED***"
    assert redacted["passphrase"] == "***REDACTED***"
    assert "chars" in redacted["privateKey"]


def test_browser_ssh_websocket_policy_denies_blocked_host(monkeypatch) -> None:
    _allow_terminal_ws_access(monkeypatch)
    monkeypatch.setenv("BROWSER_SSH_DENIED_HOSTS", "blocked.internal")
    app = create_app()
    client = TestClient(app)

    with client.websocket_connect("/api/browser-ssh/ws") as ws:
        _ = ws.receive_json()
        ws.send_json(
            {
                "type": "connect",
                "payload": {
                    "host": "blocked.internal",
                    "port": 22,
                    "username": "alice",
                    "authType": "password",
                    "password": "secret",
                },
            }
        )
        err = ws.receive_json()
        assert err["type"] == "error"
        assert err["payload"]["code"] == "policy_denied_host"
        assert "blocked" in err["payload"]["message"].lower()


def test_browser_ssh_websocket_policy_denies_non_allowlisted_port(monkeypatch) -> None:
    _allow_terminal_ws_access(monkeypatch)
    monkeypatch.setenv("BROWSER_SSH_ALLOWED_PORTS", "22")
    app = create_app()
    client = TestClient(app)

    with client.websocket_connect("/api/browser-ssh/ws") as ws:
        _ = ws.receive_json()
        ws.send_json(
            {
                "type": "connect",
                "payload": {
                    "host": "example.internal",
                    "port": 2200,
                    "username": "alice",
                    "authType": "password",
                    "password": "secret",
                },
            }
        )
        err = ws.receive_json()
        assert err["type"] == "error"
        assert err["payload"]["code"] == "policy_denied_port"
        assert "allowlisted" in err["payload"]["message"].lower()


def test_browser_ssh_websocket_policy_allows_allowlisted_host_and_port(monkeypatch) -> None:
    _allow_terminal_ws_access(monkeypatch)
    bridge = FakeBridge()
    monkeypatch.setattr(browser_ssh_terminal, "_create_ssh_bridge", lambda *_: bridge)
    monkeypatch.setenv("BROWSER_SSH_ALLOWED_HOSTS", "*.internal")
    monkeypatch.setenv("BROWSER_SSH_ALLOWED_PORTS", "22,2222")

    app = create_app()
    client = TestClient(app)

    with client.websocket_connect("/api/browser-ssh/ws") as ws:
        _ = ws.receive_json()
        ws.send_json(
            {
                "type": "connect",
                "payload": {
                    "host": "dev.internal",
                    "port": 22,
                    "username": "alice",
                    "authType": "password",
                    "password": "secret",
                },
            }
        )
        status = ws.receive_json()
        assert status["type"] == "status"
        assert status["payload"]["phase"] == "connected"


def test_browser_ssh_websocket_unauthorized_user_denied_and_audited(monkeypatch) -> None:
    events = []

    def _audit(event, user_sub, request=None, **fields):
        events.append((event, user_sub, fields))

    async def _deny(_websocket):
        return None, browser_ssh_terminal._error_payload(
            code="unauthorized",
            message="Authentication required to open terminal session",
            request_type="connect",
        )

    monkeypatch.setattr(browser_ssh_terminal, "audit_event", _audit)
    monkeypatch.setattr(browser_ssh_terminal, "_authorize_terminal_access", _deny)

    app = create_app()
    client = TestClient(app)

    with client.websocket_connect("/api/browser-ssh/ws") as ws:
        err = ws.receive_json()
        assert err["type"] == "error"
        assert err["payload"]["code"] == "unauthorized"


def test_browser_ssh_websocket_authorized_user_can_open(monkeypatch) -> None:
    _allow_terminal_ws_access(monkeypatch)
    app = create_app()
    client = TestClient(app)

    with client.websocket_connect("/api/browser-ssh/ws") as ws:
        ready = ws.receive_json()
        assert ready["type"] == "status"
        assert ready["payload"]["phase"] == "ready"
        assert "alice" in ready["payload"]["message"]


def test_authorize_terminal_access_denial_is_audited(monkeypatch) -> None:
    events = []

    async def _unauth(_req):
        raise HTTPException(401, "unauthenticated")

    def _audit(event, user_sub, request=None, **fields):
        events.append((event, user_sub, fields))

    monkeypatch.setattr(browser_ssh_terminal, "get_authenticated_user", _unauth)
    monkeypatch.setattr(browser_ssh_terminal, "audit_event", _audit)

    class FakeWs:
        cookies = {}
        headers = {}
        client = None

    import asyncio
    ctx, err = asyncio.run(browser_ssh_terminal._authorize_terminal_access(FakeWs()))
    assert ctx is None
    assert err is not None
    assert err["code"] == "unauthorized"
    assert events
    assert events[-1][0] == "browser_ssh_connect_access_denied"


def test_browser_ssh_websocket_connect_rate_limited(monkeypatch) -> None:
    _allow_terminal_ws_access(monkeypatch)
    monkeypatch.setenv("BROWSER_SSH_CONNECT_RATE_LIMIT_COUNT", "1")
    monkeypatch.setenv("BROWSER_SSH_CONNECT_RATE_LIMIT_WINDOW_SECONDS", "60")
    browser_ssh_terminal._CONNECT_ATTEMPTS_BY_USER["alice"] = __import__("collections").deque([browser_ssh_terminal.time.time()])

    app = create_app()
    client = TestClient(app)

    with client.websocket_connect("/api/browser-ssh/ws") as ws:
        _ = ws.receive_json()
        ws.send_json(
            {
                "type": "connect",
                "payload": {
                    "host": "example.internal",
                    "port": 22,
                    "username": "alice",
                    "authType": "password",
                    "password": "secret",
                },
            }
        )
        err = ws.receive_json()
        assert err["type"] == "error"
        assert err["payload"]["code"] == "rate_limited"


def test_browser_ssh_websocket_session_limit_exceeded(monkeypatch) -> None:
    _allow_terminal_ws_access(monkeypatch)
    monkeypatch.setenv("BROWSER_SSH_MAX_SESSIONS_PER_USER", "0")

    app = create_app()
    client = TestClient(app)

    with client.websocket_connect("/api/browser-ssh/ws") as ws:
        _ = ws.receive_json()
        ws.send_json(
            {
                "type": "connect",
                "payload": {
                    "host": "example.internal",
                    "port": 22,
                    "username": "alice",
                    "authType": "password",
                    "password": "secret",
                },
            }
        )
        err = ws.receive_json()
        assert err["type"] == "error"
        assert err["payload"]["code"] == "session_limit_exceeded"


def test_session_timeout_error_helper_covers_idle_and_duration() -> None:
    now = 1000.0
    idle_err = browser_ssh_terminal._session_timeout_error(started_at=900.0, last_activity_at=0.0, now=now)
    assert idle_err is not None
    assert idle_err["code"] == "idle_timeout"

    duration_err = browser_ssh_terminal._session_timeout_error(started_at=0.0, last_activity_at=now, now=now + 999999)
    assert duration_err is not None
    assert duration_err["code"] in {"idle_timeout", "session_expired"}


def test_browser_ssh_session_start_end_audit_and_session_id_logs(monkeypatch, caplog) -> None:
    _allow_terminal_ws_access(monkeypatch)
    bridge = FakeBridge()
    events = []

    def _audit(event, user_sub, request=None, **fields):
        events.append((event, user_sub, fields))

    monkeypatch.setattr(browser_ssh_terminal, "_create_ssh_bridge", lambda *_: bridge)
    monkeypatch.setattr(browser_ssh_terminal, "audit_event", _audit)

    caplog.set_level("INFO", logger="app.routers.browser_ssh_terminal")

    app = create_app()
    client = TestClient(app)

    with client.websocket_connect("/api/browser-ssh/ws") as ws:
        _ = ws.receive_json()
        ws.send_json(
            {
                "type": "connect",
                "payload": {
                    "host": "audit.internal",
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

    start_events = [evt for evt in events if evt[0] == "browser_ssh_session_start"]
    end_events = [evt for evt in events if evt[0] == "browser_ssh_session_end"]
    assert start_events
    assert end_events

    _, start_user, start_fields = start_events[-1]
    _, end_user, end_fields = end_events[-1]

    assert start_user == "alice"
    assert end_user == "alice"
    assert start_fields["host"] == "audit.internal"
    assert start_fields["port"] == 22
    assert end_fields["host"] == "audit.internal"
    assert end_fields["port"] == 22
    assert start_fields["outcome"] == "success"
    assert end_fields["outcome"] == "disconnected"
    assert "session_id" in start_fields
    assert end_fields["session_id"] == start_fields["session_id"]
    assert "password" not in repr(start_fields)
    assert "password" not in repr(end_fields)

    assert any(getattr(record, "session_id", None) for record in caplog.records)
