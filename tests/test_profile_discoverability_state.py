from app.services.profile_discoverability import (
    DISCOVERABILITY_FIELD,
    DiscoverabilityState,
    normalize_discoverability_state,
    resolve_discoverability_state,
)


def test_normalize_discoverability_state_accepts_valid_states() -> None:
    assert normalize_discoverability_state("active") == DiscoverabilityState.ACTIVE
    assert normalize_discoverability_state("hidden") == DiscoverabilityState.HIDDEN
    assert normalize_discoverability_state("deactivated") == DiscoverabilityState.DEACTIVATED
    assert normalize_discoverability_state("deleted") == DiscoverabilityState.DELETED


def test_normalize_discoverability_state_falls_back_for_missing_and_malformed() -> None:
    assert normalize_discoverability_state(None) == DiscoverabilityState.ACTIVE
    assert normalize_discoverability_state("") == DiscoverabilityState.ACTIVE
    assert normalize_discoverability_state("UNKNOWN") == DiscoverabilityState.ACTIVE


def test_resolve_discoverability_state_uses_discoverability_field_when_present() -> None:
    assert resolve_discoverability_state({DISCOVERABILITY_FIELD: "hidden", "status": "active"}) == DiscoverabilityState.HIDDEN


def test_resolve_discoverability_state_uses_legacy_status_when_field_missing() -> None:
    assert resolve_discoverability_state({"status": "deactivated"}) == DiscoverabilityState.DEACTIVATED
    assert resolve_discoverability_state({"status": "deleted"}) == DiscoverabilityState.DELETED


def test_resolve_discoverability_state_defaults_for_legacy_missing_or_malformed() -> None:
    assert resolve_discoverability_state({}) == DiscoverabilityState.ACTIVE
    assert resolve_discoverability_state({"status": "suspension_requested"}) == DiscoverabilityState.ACTIVE
    assert resolve_discoverability_state({DISCOVERABILITY_FIELD: "garbage"}) == DiscoverabilityState.ACTIVE
