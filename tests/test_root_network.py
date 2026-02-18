from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.auth.root_network import enforce_root_network_gate
from app.core.settings import S


def _req(*, direct_ip: str | None, xff: str | None = None):
    headers = {}
    if xff is not None:
        headers["x-forwarded-for"] = xff
    client = None if direct_ip is None else SimpleNamespace(host=direct_ip)
    return SimpleNamespace(headers=headers, client=client)


def test_root_network_allows_allowlisted_ip() -> None:
    object.__setattr__(S, "root_login_allowed_ips", "203.0.113.0/24")
    object.__setattr__(S, "root_login_local_only", False)
    object.__setattr__(S, "trusted_proxy_cidrs", "")
    assert enforce_root_network_gate(_req(direct_ip="203.0.113.10")) == "203.0.113.10"


def test_root_network_denies_non_allowlisted_ip() -> None:
    object.__setattr__(S, "root_login_allowed_ips", "203.0.113.0/24")
    object.__setattr__(S, "root_login_local_only", False)
    object.__setattr__(S, "trusted_proxy_cidrs", "")
    with pytest.raises(HTTPException) as exc:
        enforce_root_network_gate(_req(direct_ip="198.51.100.20"))
    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "root_network_restricted"
    assert exc.value.detail["reason"] == "untrusted_source"


def test_root_network_allows_local_mode() -> None:
    object.__setattr__(S, "root_login_allowed_ips", "")
    object.__setattr__(S, "root_login_local_only", True)
    object.__setattr__(S, "trusted_proxy_cidrs", "")
    assert enforce_root_network_gate(_req(direct_ip="127.0.0.1")) == "127.0.0.1"


def test_root_network_trusted_proxy_uses_xff() -> None:
    object.__setattr__(S, "root_login_allowed_ips", "203.0.113.0/24")
    object.__setattr__(S, "root_login_local_only", False)
    object.__setattr__(S, "trusted_proxy_cidrs", "10.0.0.0/8")
    out = enforce_root_network_gate(_req(direct_ip="10.1.2.3", xff="203.0.113.25, 10.1.2.3"))
    assert out == "203.0.113.25"


def test_root_network_ignores_spoofed_xff_when_proxy_untrusted() -> None:
    object.__setattr__(S, "root_login_allowed_ips", "203.0.113.0/24")
    object.__setattr__(S, "root_login_local_only", False)
    object.__setattr__(S, "trusted_proxy_cidrs", "10.0.0.0/8")
    with pytest.raises(HTTPException) as exc:
        enforce_root_network_gate(_req(direct_ip="198.51.100.5", xff="203.0.113.25"))
    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "root_network_restricted"
    assert exc.value.detail["reason"] == "untrusted_source"
    assert exc.value.detail["source"] == "direct_untrusted_proxy"


def test_root_network_unknown_source_gets_deterministic_reason() -> None:
    object.__setattr__(S, "root_login_allowed_ips", "203.0.113.0/24")
    object.__setattr__(S, "root_login_local_only", False)
    object.__setattr__(S, "trusted_proxy_cidrs", "")
    with pytest.raises(HTTPException) as exc:
        enforce_root_network_gate(_req(direct_ip=None))
    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "root_network_restricted"
    assert exc.value.detail["reason"] == "unknown_source"
