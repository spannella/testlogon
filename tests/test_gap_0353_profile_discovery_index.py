"""GAP-0353 (SOC-003 §4.6): apply_profile_update must (re)populate the discovery
search index after a successful save, non-fatally.

Hermetic / offline: no AWS, no real DynamoDB. We stub get_profile/save_profile so
the profile write does no I/O, and spy on the lazily-imported
app.services.discovery.index_user_for_discovery.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import app.services.profile as profile


def _stub_storage():
    """Patch out the DDB-backed read/write so apply_profile_update is offline.

    Returns the patch context managers' targets pre-configured:
      - get_profile -> empty profile (so any provided field counts as a change)
      - save_profile -> no-op
    """
    return (
        patch.object(profile, "get_profile", return_value=profile.empty_profile()),
        patch.object(profile, "save_profile", return_value=None),
    )


def test_discovery_field_change_triggers_reindex():
    spy = MagicMock(return_value=3)
    get_p, save_p = _stub_storage()
    with get_p, save_p, patch(
        "app.services.discovery.index_user_for_discovery", spy
    ):
        result = profile.apply_profile_update(
            "user-123", {"display_name": "New Name"}, replace=False
        )

    assert result["display_name"] == "New Name"
    spy.assert_called_once_with("user-123")


def test_reindex_failure_is_non_fatal():
    """If index_user_for_discovery raises, the profile update still succeeds."""
    spy = MagicMock(side_effect=RuntimeError("discovery index down"))
    get_p, save_p = _stub_storage()
    with get_p, save_p, patch(
        "app.services.discovery.index_user_for_discovery", spy
    ):
        # Must NOT raise.
        result = profile.apply_profile_update(
            "user-123", {"display_name": "Another Name"}, replace=False
        )

    assert result["display_name"] == "Another Name"
    spy.assert_called_once_with("user-123")


def test_non_discovery_field_only_change_skips_reindex():
    """Changing only a non-discovery field (e.g. locale) does NOT reindex."""
    spy = MagicMock(return_value=0)
    # Start from a profile where display_name etc. already match, so only locale
    # changes. get_profile returns a baseline with a locale of None.
    baseline = profile.empty_profile()
    with patch.object(profile, "get_profile", return_value=baseline), patch.object(
        profile, "save_profile", return_value=None
    ), patch("app.services.discovery.index_user_for_discovery", spy):
        result = profile.apply_profile_update(
            "user-123", {"locale": "en"}, replace=False
        )

    assert result["locale"] == "en"
    spy.assert_not_called()


def test_no_change_skips_reindex():
    """An update that changes nothing does not reindex."""
    spy = MagicMock(return_value=0)
    baseline = profile.empty_profile()
    baseline["display_name"] = "Same"
    with patch.object(profile, "get_profile", return_value=baseline), patch.object(
        profile, "save_profile", return_value=None
    ), patch("app.services.discovery.index_user_for_discovery", spy):
        result = profile.apply_profile_update(
            "user-123", {"display_name": "Same"}, replace=False
        )

    assert result["display_name"] == "Same"
    spy.assert_not_called()


def test_discovery_fields_match_index_reads():
    """Guard: DISCOVERY_FIELDS only lists real profile fields."""
    assert profile.DISCOVERY_FIELDS <= set(profile.PROFILE_FIELDS)
    # The fields the discovery indexer actually reads from the profile.
    assert profile.DISCOVERY_FIELDS == {
        "display_name",
        "description",
        "title",
        "profile_photo_url",
    }
