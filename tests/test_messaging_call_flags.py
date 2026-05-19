from types import SimpleNamespace

from app.services import messaging_call_flags as flags


class _Settings(SimpleNamespace):
    messaging_webrtc_direct_call_enabled: bool = False
    messaging_webrtc_direct_call_kill_switch: bool = False
    messaging_webrtc_direct_call_mode: str = "enabled"
    messaging_webrtc_direct_call_enabled_tenant_ids: str = ""
    messaging_webrtc_direct_call_internal_tenant_ids: str = "internal"
    messaging_webrtc_direct_call_enabled_cohorts: str = ""


def _with_settings(monkeypatch, **kwargs):
    s = _Settings(**kwargs)
    monkeypatch.setattr(flags, "S", s)
    return s


def test_disabled_when_global_flag_off(monkeypatch):
    _with_settings(monkeypatch, messaging_webrtc_direct_call_enabled=False)
    assert flags.is_webrtc_direct_call_enabled_for(user_id="u1") is False


def test_disabled_when_kill_switch_on(monkeypatch):
    _with_settings(
        monkeypatch,
        messaging_webrtc_direct_call_enabled=True,
        messaging_webrtc_direct_call_kill_switch=True,
    )
    assert flags.is_webrtc_direct_call_enabled_for(user_id="u1") is False


def test_enabled_mode_allows_calls(monkeypatch):
    _with_settings(monkeypatch, messaging_webrtc_direct_call_enabled=True, messaging_webrtc_direct_call_mode="enabled")
    assert flags.is_webrtc_direct_call_enabled_for(user_id="u1") is True


def test_internal_mode_requires_internal_tenant(monkeypatch):
    _with_settings(
        monkeypatch,
        messaging_webrtc_direct_call_enabled=True,
        messaging_webrtc_direct_call_mode="internal",
        messaging_webrtc_direct_call_internal_tenant_ids="internal-a,internal-b",
    )
    assert flags.is_webrtc_direct_call_enabled_for(user_id="u1", tenant_id="internal-a") is True
    assert flags.is_webrtc_direct_call_enabled_for(user_id="u1", tenant_id="external") is False


def test_selective_mode_tenant_or_cohort_allowlist(monkeypatch):
    _with_settings(
        monkeypatch,
        messaging_webrtc_direct_call_enabled=True,
        messaging_webrtc_direct_call_mode="selective",
        messaging_webrtc_direct_call_enabled_tenant_ids="tenant-a",
        messaging_webrtc_direct_call_enabled_cohorts="beta,staff",
    )
    assert flags.is_webrtc_direct_call_enabled_for(user_id="u1", tenant_id="tenant-a", cohort="none") is True
    assert flags.is_webrtc_direct_call_enabled_for(user_id="u1", tenant_id="tenant-z", cohort="beta") is True
    assert flags.is_webrtc_direct_call_enabled_for(user_id="u1", tenant_id="tenant-z", cohort="none") is False


def test_selective_mode_uses_resolver_when_tenant_missing(monkeypatch):
    _with_settings(
        monkeypatch,
        messaging_webrtc_direct_call_enabled=True,
        messaging_webrtc_direct_call_mode="tenant",
        messaging_webrtc_direct_call_enabled_tenant_ids="tenant-a",
    )

    assert (
        flags.is_webrtc_direct_call_enabled_for(
            user_id="u1",
            tenant_resolver=lambda _uid: "tenant-a",
        )
        is True
    )


def test_snapshot_shape(monkeypatch):
    _with_settings(
        monkeypatch,
        messaging_webrtc_direct_call_enabled=True,
        messaging_webrtc_direct_call_mode="selective",
        messaging_webrtc_direct_call_enabled_tenant_ids="b,a",
        messaging_webrtc_direct_call_internal_tenant_ids="int-2,int-1",
        messaging_webrtc_direct_call_enabled_cohorts="Beta,alpha",
    )
    snapshot = flags.get_webrtc_direct_call_flag_snapshot()
    assert snapshot["enabled"] is True
    assert snapshot["mode"] == "selective"
    assert snapshot["enabled_tenant_ids"] == ["a", "b"]
    assert snapshot["internal_tenant_ids"] == ["int-1", "int-2"]
    assert snapshot["enabled_cohorts"] == ["alpha", "beta"]
