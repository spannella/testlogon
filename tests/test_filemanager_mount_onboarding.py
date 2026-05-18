from unittest.mock import Mock, patch

from fastapi import HTTPException

from app.services import filemanager_mount_onboarding as svc


def test_clear_onboarding_sessions_for_mount_deletes_matching_rows() -> None:
    sessions = Mock()
    sessions.query.return_value = {
        "Items": [
            {"entity_type": "filemgr_mount_onboarding", "mount_id": "m1", "session_id": "filemgr_mount_onboard#a"},
            {"entity_type": "filemgr_mount_onboarding", "mount_id": "m2", "session_id": "filemgr_mount_onboard#b"},
            {"entity_type": "other", "mount_id": "m1", "session_id": "x"},
        ]
    }
    with patch.object(svc, "T", Mock(sessions=sessions)):
        deleted = svc.clear_onboarding_sessions_for_mount(user_sub="u1", mount_id="m1")

    assert deleted == 1
    sessions.delete_item.assert_called_once_with(Key={"user_sub": "u1", "session_id": "filemgr_mount_onboard#a"})


def test_get_onboarding_session_rejects_expired_session() -> None:
    sessions = Mock()
    sessions.get_item.return_value = {
        "Item": {
            "entity_type": "filemgr_mount_onboarding",
            "session_id": "filemgr_mount_onboard#expired",
            "expires_at": "2000-01-01T00:00:00+00:00",
        }
    }
    with patch.object(svc, "T", Mock(sessions=sessions)):
        try:
            svc.get_onboarding_session(user_sub="u1", onboarding_session_id="filemgr_mount_onboard#expired")
            assert False, "expected HTTPException"
        except HTTPException as exc:
            assert exc.status_code == 410


def test_get_onboarding_session_accepts_future_session() -> None:
    sessions = Mock()
    sessions.get_item.return_value = {
        "Item": {
            "entity_type": "filemgr_mount_onboarding",
            "session_id": "filemgr_mount_onboard#ok",
            "expires_at": "2999-01-01T00:00:00+00:00",
            "mount_id": "m1",
        }
    }
    with patch.object(svc, "T", Mock(sessions=sessions)):
        out = svc.get_onboarding_session(user_sub="u1", onboarding_session_id="filemgr_mount_onboard#ok")
    assert out["mount_id"] == "m1"


def test_clear_onboarding_sessions_for_mount_paginates() -> None:
    sessions = Mock()
    sessions.query.side_effect = [
        {
            "Items": [
                {"entity_type": "filemgr_mount_onboarding", "mount_id": "m1", "session_id": "filemgr_mount_onboard#a"},
            ],
            "LastEvaluatedKey": {"user_sub": "u1", "session_id": "cursor#1"},
        },
        {
            "Items": [
                {"entity_type": "filemgr_mount_onboarding", "mount_id": "m1", "session_id": "filemgr_mount_onboard#b"},
            ]
        },
    ]
    with patch.object(svc, "T", Mock(sessions=sessions)):
        deleted = svc.clear_onboarding_sessions_for_mount(user_sub="u1", mount_id="m1")

    assert deleted == 2
    assert sessions.query.call_count == 2
