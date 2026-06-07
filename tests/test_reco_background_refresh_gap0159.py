"""GAP-0159: background recommendation refresh job registration.

Offline regression tests (in-memory, no real AWS). These verify that:

1. ``refresh_all_users`` iterates over every signal user and refreshes each,
   tolerating per-user errors.
2. ``start_reco_refresh_task`` schedules the background loop when enabled and
   is a no-op when recommendations are disabled.
3. The startup handler is wired into the FastAPI app at module import time.

Settings ``S`` is frozen, so we mutate it via ``object.__setattr__``.
"""

from unittest.mock import patch

import app.services.recommendations as reco


def test_refresh_all_users_calls_per_user_refresh():
    """refresh_all_users must iterate all signal users and refresh each."""
    with (
        patch.object(reco, "_list_all_signal_users", return_value=["user_a", "user_b"]),
        patch.object(reco, "refresh_user_recommendations") as mock_refresh,
    ):
        result = reco.refresh_all_users()

    assert mock_refresh.call_count == 2
    mock_refresh.assert_any_call("user_a")
    mock_refresh.assert_any_call("user_b")
    assert result["users_processed"] == 2
    assert result["errors"] == 0


def test_refresh_all_users_tolerates_per_user_errors():
    """A failure for one user must not abort the whole batch."""
    with (
        patch.object(reco, "_list_all_signal_users", return_value=["ok", "bad"]),
        patch.object(
            reco,
            "refresh_user_recommendations",
            side_effect=[None, RuntimeError("DDB timeout")],
        ),
    ):
        result = reco.refresh_all_users()

    assert result["users_processed"] == 1
    assert result["errors"] == 1


def test_start_reco_refresh_task_schedules_loop_when_enabled():
    """start_reco_refresh_task schedules the background loop when enabled."""
    orig = reco.S.recommendations_enabled
    object.__setattr__(reco.S, "recommendations_enabled", True)
    try:
        with patch.object(reco.asyncio, "ensure_future") as mock_ensure:
            reco.start_reco_refresh_task()
        assert mock_ensure.call_count == 1
    finally:
        object.__setattr__(reco.S, "recommendations_enabled", orig)


def test_start_reco_refresh_task_noop_when_disabled():
    """start_reco_refresh_task is a no-op when recommendations are disabled."""
    orig = reco.S.recommendations_enabled
    object.__setattr__(reco.S, "recommendations_enabled", False)
    try:
        with patch.object(reco.asyncio, "ensure_future") as mock_ensure:
            reco.start_reco_refresh_task()
        mock_ensure.assert_not_called()
    finally:
        object.__setattr__(reco.S, "recommendations_enabled", orig)


def test_reco_refresh_startup_handler_registered():
    """The reco refresh startup handler must be registered on the app."""
    from app.main import create_app

    app = create_app()
    handler_names = [
        getattr(h, "__name__", repr(h)) for h in app.router.on_startup
    ]
    assert "start_reco_refresh_task" in handler_names, (
        "Recommendation refresh startup handler not found in app.on_startup"
    )
