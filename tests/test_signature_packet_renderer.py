from __future__ import annotations

import base64

from app.services import signature_packet_renderer as renderer


def test_render_completed_packet_generates_ready_artifact(monkeypatch) -> None:
    events = []

    monkeypatch.setattr(renderer, "get_packet", lambda _packet_id: {"packet_id": "sp_1", "status": "completed", "owner_user_id": "user-1", "source_path": "/f.pdf"})
    monkeypatch.setattr(renderer, "get_packet_artifact", lambda _packet_id: None)
    monkeypatch.setattr(renderer, "download_file", lambda _owner, _path: {"content": b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF"})
    monkeypatch.setattr(renderer, "list_packet_fields", lambda _packet_id: [{"field_id": "sf_1", "page": 1, "field_type": "signature", "value": "[drawn]", "capture_mode": "drawn", "render_payload": {"kind": "drawn_path", "strokes": [[0.1, 0.2], [0.2, 0.3]]}, "filled_at": "2026-01-01T00:00:00+00:00"}])
    monkeypatch.setattr(
        renderer,
        "list_packet_signers",
        lambda _packet_id: [
            {"signer_id": "user-9", "completed_at": "2026-01-01T03:00:00+00:00", "completed_ip": "203.0.113.19"},
            {"signer_id": "user-2", "completed_at": "2026-01-01T01:00:00+00:00", "completed_ip": "203.0.113.10"},
        ],
    )
    monkeypatch.setattr(renderer, "list_packet_events", lambda _packet_id: [{"event_type": "packet_sent", "created_at": "2026-01-01T00:10:00+00:00"}])
    monkeypatch.setattr(renderer, "record_signature_packet_render_job", lambda **_kwargs: None)
    monkeypatch.setattr(renderer, "record_signature_packet_render_latency", lambda **_kwargs: None)
    monkeypatch.setattr(renderer, "append_packet_event", lambda **kwargs: events.append(kwargs))

    stored = {}

    def _put(packet_id: str, artifact):
        stored.update({"packet_id": packet_id, **artifact})
        return stored

    monkeypatch.setattr(renderer, "put_packet_artifact", _put)

    out = renderer.render_completed_packet("sp_1")

    assert out["status"] == "ready"
    assert stored["status"] == "ready"
    assert stored["content_type"] == "application/pdf"
    assert stored["hash_algorithm"] == "sha256"
    assert stored["immutable"] is True
    assert base64.b64decode(stored["final_pdf_base64"]).startswith(b"%PDF")
    assert stored["audit_appendix"]["first_sent_at"] == "2026-01-01T00:10:00+00:00"
    assert [s["signer_id"] for s in stored["audit_appendix"]["signer_timeline"]] == ["user-2", "user-9"]
    assert stored["audit_appendix"]["signer_timeline"][0]["source_ip"] == "203.0.113.10"
    assert events[-1]["event_type"] == "packet_finalized"


def test_render_completed_packet_failure_is_retryable_and_observable(monkeypatch) -> None:
    events = []
    monkeypatch.setattr(renderer, "get_packet", lambda _packet_id: {"packet_id": "sp_1", "status": "completed", "owner_user_id": "user-1", "source_path": "/f.pdf"})
    monkeypatch.setattr(renderer, "get_packet_artifact", lambda _packet_id: {"packet_id": "sp_1", "retry_count": 1})
    monkeypatch.setattr(renderer, "download_file", lambda _owner, _path: {"content": b"%PDF-1.4\n%%EOF"})
    monkeypatch.setattr(renderer, "list_packet_fields", lambda _packet_id: [])
    monkeypatch.setattr(renderer, "list_packet_signers", lambda _packet_id: [])
    monkeypatch.setattr(renderer, "list_packet_events", lambda _packet_id: [])
    monkeypatch.setattr(renderer, "record_signature_packet_render_job", lambda **_kwargs: None)
    monkeypatch.setattr(renderer, "record_signature_packet_render_latency", lambda **_kwargs: None)
    monkeypatch.setattr(renderer, "append_packet_event", lambda **kwargs: events.append(kwargs))

    stored = {}

    def _put(packet_id: str, artifact):
        stored.update({"packet_id": packet_id, **artifact})
        return stored

    monkeypatch.setattr(renderer, "put_packet_artifact", _put)

    out = renderer.render_completed_packet("sp_1", renderer=lambda _src, _fields: (_ for _ in ()).throw(renderer.SignaturePacketRenderError("transient_render_error", retryable=True)))

    assert out["status"] == "retry_pending"
    assert stored["retry_count"] == 2
    assert stored["status"] == "retry_pending"
    assert events[-1]["event_type"] == "packet_finalize_failed"


def test_process_completed_packet_finalization_jobs_summarizes(monkeypatch) -> None:
    monkeypatch.setattr(renderer, "list_completed_packets", lambda limit: [{"packet_id": "sp_1"}, {"packet_id": "sp_2"}, {"packet_id": "sp_3"}])

    statuses = iter([{"status": "ready"}, {"status": "retry_pending"}, {"status": "failed"}])
    monkeypatch.setattr(renderer, "render_completed_packet", lambda _packet_id: next(statuses))

    out = renderer.process_completed_packet_finalization_jobs(limit=10)

    assert out == {"processed": 3, "succeeded": 1, "retry_pending": 1, "failed": 1}
