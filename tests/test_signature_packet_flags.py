from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.core import settings as settings_module
from app.services import signature_packet_flags as flags
from app.services import signature_packet_store as store
from app.services.signature_packet_domain import SignatureSignerStatus


def test_signature_pdf_defaults_are_safe() -> None:
    assert settings_module.S.signature_pdf_enabled is False
    assert settings_module.S.signature_packet_expiration_hours == 168
    assert settings_module.S.signature_packet_max_signers == 10
    assert settings_module.S.signature_packet_max_fields == 200
    assert settings_module.S.signature_packet_renderer_timeout_seconds == 60


def test_require_signature_pdf_enabled_raises_when_disabled(monkeypatch) -> None:
    monkeypatch.setattr(flags, "S", SimpleNamespace(signature_pdf_enabled=False))
    with pytest.raises(flags.SignaturePdfDisabledError):
        flags.require_signature_pdf_enabled()


def test_signature_store_queries_are_flag_gated(monkeypatch) -> None:
    monkeypatch.setattr(
        store,
        "require_signature_pdf_enabled",
        lambda: (_ for _ in ()).throw(RuntimeError("disabled")),
    )

    with pytest.raises(RuntimeError):
        store.list_packets_by_sender("owner-1")
    with pytest.raises(RuntimeError):
        store.list_packets_for_signer("signer-1", SignatureSignerStatus.PENDING)
    with pytest.raises(RuntimeError):
        store.load_packet_aggregate("pkt-1")
