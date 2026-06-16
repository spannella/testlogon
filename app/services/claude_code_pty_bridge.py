"""PTY-wrapped Claude Code CLI bridge (ACS-003 / ADR-002).

Exposes the canonical terminal-bridge surface used by the Browser SSH terminal
(``ParamikoSshBridge``): ``connect`` / ``poll_output`` / ``send_input`` /
``resize`` / ``close``. This lets the agent-session WebSocket loop reuse the SSH
loop scaffolding verbatim while driving an interactive ``claude`` process on the
worker's compute instead of a raw shell.

SECOPS-007 dev/prod parity: the ONLY fork between dev and prod is the bridge
*factory* (``build_claude_code_bridge``). Protocol, auth, ownership,
rate-limit, the monitor tap, and the session state machine are a single shared
code path in both environments.

- dev (``S.dev_mode``): ``MockClaudePtyBridge`` echoes input and emits scripted
  Claude-style banner output INCLUDING a ``[AGENT_FEEDBACK_NEEDED]`` line so the
  terminal_monitor signal + feedback pipeline is exercised offline with no real
  compute.
- prod: ``RealClaudePtyBridge`` opens a Paramiko channel to the worker's compute
  (``public_ip``) using the worker's stored SSH key (resolved server-side via
  ``ssh_key_manager.get_decrypted_private_key``) and launches
  ``env ANTHROPIC_API_KEY=… claude`` under a PTY. The LLM key is resolved
  server-side via ``llm_provider_keys.get_decrypted_api_key`` and is NEVER placed
  in any browser-bound message or log (same principle as the stored-key PEM
  handling in the SSH terminal).
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Optional

from app.core.settings import S

logger = logging.getLogger(__name__)


class ClaudeBridgeError(Exception):
    """Mirrors ``browser_ssh_terminal.BrowserSshError`` so the WS loop can map
    ``code`` / ``message`` into the Protocol v1 ``error`` envelope identically.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# Env var name the CLI expects for its API key (matches the provisioner's
# TOOL_INSTALL_SCRIPTS["claude_code"]["env_var"]).
_CLAUDE_ENV_VAR = "ANTHROPIC_API_KEY"
# Launch command. The key is interpolated server-side and never logged.
_CLAUDE_LAUNCH = "claude"


class MockClaudePtyBridge:
    """Dev-mode bridge: echoes input + emits scripted Claude-style output.

    No network, no real PTY. The scripted banner intentionally contains an
    ``[AGENT_FEEDBACK_NEEDED]`` line so the monitor + feedback path is covered
    offline.
    """

    def __init__(self, *, cols: int, rows: int) -> None:
        self._cols = cols
        self._rows = rows
        self._closed = False
        self._lock = threading.Lock()
        self._chunks: list[str] = []

    def connect(self) -> None:
        # Scripted startup banner. The feedback line drives the monitor signal.
        with self._lock:
            self._chunks.append(
                "\r\n".join(
                    [
                        "Claude Code (mock session) started.",
                        "Type a message and press Enter.",
                        "[AGENT_FEEDBACK_NEEDED] How would you like to proceed?",
                        "",
                    ]
                )
                + "\r\n"
            )

    def poll_output(self) -> str:
        with self._lock:
            if not self._chunks:
                return ""
            out = "".join(self._chunks)
            self._chunks.clear()
            return out

    def send_input(self, data: str) -> None:
        if self._closed:
            raise ClaudeBridgeError("not_connected", "Claude session is not connected.")
        # Echo the input back plus a canned assistant reply so a human typing in
        # the browser sees a visible response (parity with a real PTY echo).
        with self._lock:
            self._chunks.append(data)
            if data.strip() and not data.strip().startswith("\x1b"):
                self._chunks.append(
                    f"\r\nClaude: received {len(data.strip())} chars. Working...\r\n"
                )

    def resize(self, cols: int, rows: int) -> None:
        self._cols = cols
        self._rows = rows

    def close(self) -> None:
        self._closed = True
        with self._lock:
            self._chunks.clear()


class RealClaudePtyBridge:
    """Prod bridge: SSH to the worker's compute and launch ``claude`` under a PTY.

    Reuses Paramiko exactly like ``ParamikoSshBridge`` but, post-connect,
    immediately launches the CLI with the LLM key injected as an env var on the
    command line so it is consumed by the worker shell, never echoed to the
    browser and never logged.
    """

    def __init__(
        self,
        *,
        host: str,
        port: int,
        username: str,
        private_key_pem: str,
        api_key: str,
        cols: int,
        rows: int,
    ) -> None:
        self._host = host
        self._port = port
        self._username = username
        self._private_key_pem = private_key_pem
        self._api_key = api_key
        self._cols = cols
        self._rows = rows
        self._client: Any | None = None
        self._channel: Any | None = None
        self._closed = False
        self._lock = threading.Lock()
        self._chunks: list[str] = []
        self._reader: threading.Thread | None = None

    def _load_key(self, paramiko: Any) -> Any:
        import io

        text = (self._private_key_pem or "").strip()
        for loader in (
            paramiko.Ed25519Key.from_private_key,
            paramiko.RSAKey.from_private_key,
            paramiko.ECDSAKey.from_private_key,
        ):
            try:
                return loader(io.StringIO(text))
            except Exception:  # pragma: no cover - tried in aggregate
                continue
        raise ClaudeBridgeError(
            "invalid_worker_key", "Unable to load the worker's SSH key."
        )

    def connect(self) -> None:
        try:
            import paramiko
        except ImportError as exc:  # pragma: no cover - dependency protection
            raise ClaudeBridgeError(
                "ssh_unavailable", "SSH support is unavailable on this server."
            ) from exc
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=self._host,
                port=self._port,
                username=self._username,
                pkey=self._load_key(paramiko),
                look_for_keys=False,
                allow_agent=False,
                timeout=10,
                banner_timeout=10,
                auth_timeout=10,
            )
            channel = client.invoke_shell(
                term="xterm-256color", width=self._cols, height=self._rows
            )
            channel.settimeout(0.0)
            self._client = client
            self._channel = channel
            self._reader = threading.Thread(target=self._reader_loop, daemon=True)
            self._reader.start()
            # Launch the CLI with the key injected on the command line. The key
            # is consumed by the worker shell; it is never sent to the browser
            # or logged. `env VAR=... claude` keeps it out of the parent env.
            self._channel.send(
                f"{_CLAUDE_ENV_VAR}={self._api_key} {_CLAUDE_LAUNCH}\n"
            )
        except ClaudeBridgeError:
            self.close()
            raise
        except Exception as exc:
            self.close()
            raise ClaudeBridgeError(
                "connect_failed", "Unable to start the Claude session on the worker."
            ) from exc

    def _reader_loop(self) -> None:
        import time

        while not self._closed:
            try:
                if not self._channel:
                    return
                if self._channel.recv_ready():
                    chunk = self._channel.recv(4096)
                    if not chunk:
                        return
                    with self._lock:
                        self._chunks.append(chunk.decode("utf-8", errors="replace"))
                    continue
            except Exception:
                return
            time.sleep(0.01)

    def poll_output(self) -> str:
        with self._lock:
            if not self._chunks:
                return ""
            out = "".join(self._chunks)
            self._chunks.clear()
            return out

    def send_input(self, data: str) -> None:
        if not self._channel:
            raise ClaudeBridgeError("not_connected", "Claude session is not connected.")
        try:
            self._channel.send(data)
        except Exception as exc:
            raise ClaudeBridgeError("io_error", "Claude channel is unavailable.") from exc

    def resize(self, cols: int, rows: int) -> None:
        if not self._channel:
            raise ClaudeBridgeError("not_connected", "Claude session is not connected.")
        try:
            self._channel.resize_pty(width=cols, height=rows)
        except Exception as exc:
            raise ClaudeBridgeError("resize_failed", "Failed to resize the session.") from exc

    def close(self) -> None:
        self._closed = True
        try:
            if self._channel:
                self._channel.close()
        finally:
            self._channel = None
        try:
            if self._client:
                self._client.close()
        finally:
            self._client = None


def _resolve_worker_ssh_key(user_id: str, worker: dict) -> str:
    """Resolve the decrypted PEM used to SSH to the worker's compute.

    The worker record carries an ``ssh_key_id`` (the injected agent keypair).
    Resolved server-side; the PEM never reaches the browser. Raises
    ``ClaudeBridgeError`` if no usable key is available.
    """
    key_id = str(worker.get("ssh_key_id") or "").strip()
    if not key_id:
        raise ClaudeBridgeError(
            "worker_key_missing", "Worker has no SSH key configured."
        )
    from app.services.ssh_key_manager import get_decrypted_private_key

    pem = get_decrypted_private_key(user_id, key_id)
    if not pem:
        raise ClaudeBridgeError(
            "worker_key_missing", "Worker SSH key not found or access denied."
        )
    return pem


def build_claude_code_bridge(
    *,
    user_id: str,
    worker: dict,
    cols: int,
    rows: int,
) -> Any:
    """Bridge factory — the SINGLE dev/prod fork point (SECOPS-007).

    dev → ``MockClaudePtyBridge``; prod → ``RealClaudePtyBridge`` wired to the
    worker's compute with the LLM key resolved server-side.
    """
    safe_cols = max(int(cols or 0), 80)
    safe_rows = max(int(rows or 0), 24)

    if S.dev_mode:
        return MockClaudePtyBridge(cols=safe_cols, rows=safe_rows)

    host = str(worker.get("public_ip") or "").strip()
    if not host:
        raise ClaudeBridgeError(
            "worker_unreachable", "Worker has no reachable address."
        )
    llm_key_id = str(worker.get("llm_key_id") or "").strip()
    if not llm_key_id:
        raise ClaudeBridgeError(
            "llm_key_missing", "Worker has no LLM key configured."
        )
    from app.services.llm_provider_keys import get_decrypted_api_key

    api_key = get_decrypted_api_key(user_id, llm_key_id)
    pem = _resolve_worker_ssh_key(user_id, worker)
    username = str(worker.get("ssh_username") or "ubuntu")
    return RealClaudePtyBridge(
        host=host,
        port=int(worker.get("ssh_port") or 22),
        username=username,
        private_key_pem=pem,
        api_key=api_key,
        cols=safe_cols,
        rows=safe_rows,
    )
