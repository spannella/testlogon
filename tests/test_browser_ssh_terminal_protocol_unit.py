from __future__ import annotations

from app.routers import browser_ssh_terminal


VALID_KEY = """-----BEGIN OPENSSH PRIVATE KEY-----
ZmFrZSBrZXk=
-----END OPENSSH PRIVATE KEY-----"""


def test_validate_connect_payload_accepts_password_auth() -> None:
    ok, normalized, err = browser_ssh_terminal._validate_connect_payload(
        {
            "host": "example.internal",
            "port": 22,
            "username": "alice",
            "authType": "password",
            "password": "secret",
        }
    )

    assert ok is True
    assert err is None
    assert normalized is not None
    assert normalized["authType"] == "password"


def test_validate_connect_payload_accepts_private_key_auth() -> None:
    ok, normalized, err = browser_ssh_terminal._validate_connect_payload(
        {
            "host": "example.internal",
            "port": 22,
            "username": "alice",
            "authType": "private_key",
            "privateKey": VALID_KEY,
            "passphrase": "optional-passphrase",
        }
    )

    assert ok is True
    assert err is None
    assert normalized is not None
    assert normalized["authType"] == "private_key"


def test_validate_connect_payload_rejects_invalid_auth_variants() -> None:
    ok, normalized, err = browser_ssh_terminal._validate_connect_payload(
        {
            "host": "example.internal",
            "port": 22,
            "username": "alice",
            "authType": "token",
        }
    )

    assert ok is False
    assert normalized is None
    assert err is not None
    assert err["code"] == "invalid_auth_type"


def test_validate_connect_payload_rejects_unsupported_private_key_format() -> None:
    ok, normalized, err = browser_ssh_terminal._validate_connect_payload(
        {
            "host": "example.internal",
            "port": 22,
            "username": "alice",
            "authType": "private_key",
            "privateKey": "not-a-private-key",
        }
    )

    assert ok is False
    assert normalized is None
    assert err is not None
    assert err["code"] == "invalid_private_key_format"
