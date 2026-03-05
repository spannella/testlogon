from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app


def test_browser_ssh_form_fields_and_defaults_rendered() -> None:
    app = create_app()
    client = TestClient(app)

    html = client.get("/").text

    assert 'id="browserSshHost"' in html
    assert 'id="browserSshPort"' in html
    assert 'value="22"' in html
    assert 'id="browserSshUsername"' in html
    assert 'id="browserSshAuthType"' in html
    assert '<option value="password" selected>Password</option>' in html
    assert '<option value="private_key">Private key</option>' in html
    assert 'id="browserSshPasswordRow"' in html
    assert 'id="browserSshPassword"' in html
    assert 'id="browserSshPrivateKey"' in html
    assert 'id="browserSshPrivateKeyFile"' in html
    assert 'id="browserSshPassphrase"' in html


def test_browser_ssh_connect_disconnect_button_state_defaults() -> None:
    app = create_app()
    client = TestClient(app)

    html = client.get("/").text

    assert 'id="browserSshConnectBtn" disabled' in html
    assert 'id="browserSshDisconnectBtn" class="hidden"' in html


def test_browser_ssh_terminal_view_and_xterm_assets_rendered() -> None:
    app = create_app()
    client = TestClient(app)

    html = client.get("/").text

    assert 'id="browserSshTerminalViewport"' in html
    assert 'id="browserSshTerminal"' in html
    assert 'id="browserSshSize"' in html
    assert 'cdn.jsdelivr.net/npm/xterm@5.5.0/css/xterm.min.css' in html
    assert 'cdn.jsdelivr.net/npm/xterm@5.5.0/lib/xterm.min.js' in html
    assert 'cdn.jsdelivr.net/npm/@xterm/addon-fit@0.10.0/lib/addon-fit.min.js' in html


def test_browser_ssh_copy_paste_controls_rendered() -> None:
    app = create_app()
    client = TestClient(app)

    html = client.get("/").text

    assert "id=\"browserSshCopyBtn\"" in html
    assert "id=\"browserSshPasteBtn\"" in html
    assert "id=\"browserSshContextMenu\"" in html
    assert "id=\"browserSshContextCopy\"" in html
    assert "id=\"browserSshContextPaste\"" in html


def test_browser_ssh_status_badge_and_retry_rendered() -> None:
    app = create_app()
    client = TestClient(app)

    html = client.get("/").text

    assert "id=\"browserSshStateBadge\"" in html
    assert ">disconnected<" in html
    assert "id=\"browserSshRetryBtn\"" in html
    assert "id=\"browserSshRetryBtn\" type=\"button\" class=\"hidden\"" in html
    assert ">Reconnect<" in html
    assert "id=\"browserSshReuseCreds\"" in html
