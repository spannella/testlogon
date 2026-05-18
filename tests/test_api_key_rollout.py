from __future__ import annotations

from types import SimpleNamespace

from app.services import api_key_rollout as svc


def test_rollout_shadow_phase_disables_enforcement(monkeypatch) -> None:
    monkeypatch.setattr(
        svc,
        "S",
        SimpleNamespace(
            api_key_filemanager=True,
            api_key_filemanager_phase="shadow",
            api_key_filemanager_canary_percent=0,
            api_key_filemanager_canary_subjects="",
        ),
    )
    out = svc.evaluate_api_key_rollout("filemanager", {"api_key_id": "k1"})
    assert out["phase"] == "shadow"
    assert out["enforce"] is False
    assert out["shadow"] is True


def test_rollout_canary_phase_uses_allowlist(monkeypatch) -> None:
    monkeypatch.setattr(
        svc,
        "S",
        SimpleNamespace(
            api_key_filemanager=True,
            api_key_filemanager_phase="canary",
            api_key_filemanager_canary_percent=0,
            api_key_filemanager_canary_subjects="k1,k2",
        ),
    )
    out = svc.evaluate_api_key_rollout("filemanager", {"api_key_id": "k1"})
    assert out["phase"] == "canary"
    assert out["enforce"] is True


def test_rollout_flag_disabled_is_immediate_rollback(monkeypatch) -> None:
    monkeypatch.setattr(
        svc,
        "S",
        SimpleNamespace(
            api_key_newsfeed=False,
            api_key_newsfeed_phase="ga",
            api_key_newsfeed_canary_percent=100,
            api_key_newsfeed_canary_subjects="*",
        ),
    )
    out = svc.evaluate_api_key_rollout("newsfeed", {"api_key_id": "k1"})
    assert out["phase"] == "off"
    assert out["enforce"] is False


def test_validate_rollout_settings_rejects_invalid_phase(monkeypatch) -> None:
    monkeypatch.setattr(
        svc,
        "S",
        SimpleNamespace(
            api_key_filemanager=True,
            api_key_filemanager_phase="bad",
            api_key_filemanager_canary_percent=0,
            api_key_newsfeed=True,
            api_key_newsfeed_phase="ga",
            api_key_newsfeed_canary_percent=0,
            api_key_tickets=True,
            api_key_tickets_phase="ga",
            api_key_tickets_canary_percent=0,
            api_key_shopping=True,
            api_key_shopping_phase="ga",
            api_key_shopping_canary_percent=0,
            api_key_messager=True,
            api_key_messager_phase="ga",
            api_key_messager_canary_percent=0,
        ),
    )
    try:
        svc.validate_api_key_rollout_settings()
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "api_key_filemanager_phase" in str(exc)


def test_validate_rollout_settings_rejects_out_of_range_percent(monkeypatch) -> None:
    monkeypatch.setattr(
        svc,
        "S",
        SimpleNamespace(
            api_key_filemanager=True,
            api_key_filemanager_phase="ga",
            api_key_filemanager_canary_percent=101,
            api_key_newsfeed=True,
            api_key_newsfeed_phase="ga",
            api_key_newsfeed_canary_percent=0,
            api_key_tickets=True,
            api_key_tickets_phase="ga",
            api_key_tickets_canary_percent=0,
            api_key_shopping=True,
            api_key_shopping_phase="ga",
            api_key_shopping_canary_percent=0,
            api_key_messager=True,
            api_key_messager_phase="ga",
            api_key_messager_canary_percent=0,
        ),
    )
    try:
        svc.validate_api_key_rollout_settings()
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "api_key_filemanager_canary_percent" in str(exc)


def test_get_api_key_rollout_state_exposes_effective_modes(monkeypatch) -> None:
    monkeypatch.setattr(
        svc,
        "S",
        SimpleNamespace(
            api_key_filemanager=True,
            api_key_filemanager_phase="canary",
            api_key_filemanager_canary_percent=25,
            api_key_filemanager_canary_subjects="k1,k2",
            api_key_newsfeed=False,
            api_key_newsfeed_phase="ga",
            api_key_newsfeed_canary_percent=0,
            api_key_newsfeed_canary_subjects="",
            api_key_tickets=True,
            api_key_tickets_phase="shadow",
            api_key_tickets_canary_percent=0,
            api_key_tickets_canary_subjects="",
            api_key_shopping=True,
            api_key_shopping_phase="ga",
            api_key_shopping_canary_percent=100,
            api_key_shopping_canary_subjects="",
            api_key_messager=True,
            api_key_messager_phase="off",
            api_key_messager_canary_percent=0,
            api_key_messager_canary_subjects="",
            api_key_dual_credential_mode="reject",
        ),
    )
    state = svc.get_api_key_rollout_state()
    assert state["dual_credential_mode"] == "reject"
    assert state["products"]["filemanager"]["phase_effective"] == "canary"
    assert state["products"]["filemanager"]["canary_subject_count"] == 2
    assert "canary_subjects_raw" not in state["products"]["filemanager"]
    assert state["products"]["newsfeed"]["enabled"] is False

    verbose_state = svc.get_api_key_rollout_state(include_subjects=True)
    assert verbose_state["products"]["filemanager"]["canary_subjects_raw"] == "k1,k2"


def test_validate_rollout_settings_rejects_invalid_dual_credential_mode(monkeypatch) -> None:
    monkeypatch.setattr(
        svc,
        "S",
        SimpleNamespace(
            api_key_filemanager=True,
            api_key_filemanager_phase="ga",
            api_key_filemanager_canary_percent=0,
            api_key_newsfeed=True,
            api_key_newsfeed_phase="ga",
            api_key_newsfeed_canary_percent=0,
            api_key_tickets=True,
            api_key_tickets_phase="ga",
            api_key_tickets_canary_percent=0,
            api_key_shopping=True,
            api_key_shopping_phase="ga",
            api_key_shopping_canary_percent=0,
            api_key_messager=True,
            api_key_messager_phase="ga",
            api_key_messager_canary_percent=0,
            api_key_dual_credential_mode="surprise",
        ),
    )
    try:
        svc.validate_api_key_rollout_settings()
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "api_key_dual_credential_mode" in str(exc)


def test_validate_rollout_settings_rejects_negative_registry_drift_threshold(monkeypatch) -> None:
    monkeypatch.setattr(
        svc,
        "S",
        SimpleNamespace(
            api_key_filemanager=True,
            api_key_filemanager_phase="ga",
            api_key_filemanager_canary_percent=0,
            api_key_newsfeed=True,
            api_key_newsfeed_phase="ga",
            api_key_newsfeed_canary_percent=0,
            api_key_tickets=True,
            api_key_tickets_phase="ga",
            api_key_tickets_canary_percent=0,
            api_key_shopping=True,
            api_key_shopping_phase="ga",
            api_key_shopping_canary_percent=0,
            api_key_messager=True,
            api_key_messager_phase="ga",
            api_key_messager_canary_percent=0,
            api_key_dual_credential_mode="prefer_api_key",
            api_key_registry_drift_warn_threshold=-1,
        ),
    )
    try:
        svc.validate_api_key_rollout_settings()
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "api_key_registry_drift_warn_threshold" in str(exc)
