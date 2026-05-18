from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module():
    path = Path("scripts/check_webrtc_turn_readiness.py")
    spec = importlib.util.spec_from_file_location("check_webrtc_turn_readiness", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_parse_turn_urls_extracts_scheme_host_port_transport():
    mod = _load_module()
    endpoints = mod.parse_turn_urls(
        "turn:turn.example.com:3478?transport=udp,turns:turn.example.com:5349?transport=tcp"
    )
    assert len(endpoints) == 2
    assert endpoints[0].scheme == "turn"
    assert endpoints[0].host == "turn.example.com"
    assert endpoints[0].port == 3478
    assert endpoints[0].transport == "udp"
    assert endpoints[1].scheme == "turns"
    assert endpoints[1].transport == "tcp"


def test_parse_turn_urls_ignores_stun_urls():
    mod = _load_module()
    endpoints = mod.parse_turn_urls("stun:stun.example.com:3478,stuns:stun.example.com:5349")
    assert endpoints == []


def test_run_readiness_checks_returns_success_with_mocked_connectivity(monkeypatch):
    mod = _load_module()
    monkeypatch.setenv("MESSAGING_WEBRTC_TURN_SECRET", "supersecret")
    monkeypatch.setenv("MESSAGING_WEBRTC_TURN_TTL_SECONDS", "600")
    monkeypatch.setattr(mod.socket, "getaddrinfo", lambda *_args, **_kwargs: [object()])
    monkeypatch.setattr(mod, "_tcp_connect", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(mod, "_tls_connect", lambda *_args, **_kwargs: True)

    code = mod.run_readiness_checks("turn:turn.example.com:3478?transport=tcp,turns:turn.example.com:5349?transport=tcp")
    assert code == 0


def test_run_readiness_checks_fails_on_missing_secret(monkeypatch):
    mod = _load_module()
    monkeypatch.delenv("MESSAGING_WEBRTC_TURN_SECRET", raising=False)
    monkeypatch.setenv("MESSAGING_WEBRTC_TURN_TTL_SECONDS", "600")

    code = mod.run_readiness_checks("turn:turn.example.com:3478?transport=tcp")
    assert code == 2


def test_run_readiness_checks_fails_on_invalid_ttl(monkeypatch):
    mod = _load_module()
    monkeypatch.setenv("MESSAGING_WEBRTC_TURN_SECRET", "supersecret")
    monkeypatch.setenv("MESSAGING_WEBRTC_TURN_TTL_SECONDS", "99999")

    code = mod.run_readiness_checks("turn:turn.example.com:3478?transport=tcp")
    assert code == 2


def test_run_readiness_checks_skips_when_turn_disabled(monkeypatch):
    mod = _load_module()
    monkeypatch.setenv("MESSAGING_WEBRTC_TURN_ENABLED", "false")
    monkeypatch.delenv("MESSAGING_WEBRTC_TURN_SECRET", raising=False)
    monkeypatch.delenv("MESSAGING_WEBRTC_TURN_TTL_SECONDS", raising=False)

    code = mod.run_readiness_checks("")
    assert code == 0


def test_run_readiness_checks_fails_when_only_stun_urls_provided(monkeypatch):
    mod = _load_module()
    monkeypatch.setenv("MESSAGING_WEBRTC_TURN_ENABLED", "true")
    monkeypatch.setenv("MESSAGING_WEBRTC_TURN_SECRET", "supersecret")
    monkeypatch.setenv("MESSAGING_WEBRTC_TURN_TTL_SECONDS", "600")

    code = mod.run_readiness_checks("stun:stun.example.com:3478")
    assert code == 2
