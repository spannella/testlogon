"""Regression tests for GAP-0163 and GAP-0164 (poll vote endpoint).

Both gaps live in ``vote_on_poll`` in ``app/routers/newsfeed.py``:

GAP-0164 (access gate)
    The handler validated only that the post existed and was a poll, never that
    the caller could *view* the post. A non-follower / non-subscriber could vote
    on a ``visibility="followers"`` poll. Fails-before: returns 200 for a gated
    voter. Passes-after: raises 403.

GAP-0163 (real-time SSE)
    The handler cast the vote and returned counts but never published a
    ``poll:vote`` SSE event, so live vote tallies never updated. Fails-before:
    ``sse_hub.publish`` is never scheduled. Passes-after: a ``poll:vote`` event
    is published to the post author.

Fully offline: ``ddb_get_item`` and the polls-service helpers are monkeypatched
to in-memory fakes, ``can_view_post`` is stubbed per-test, and ``sse_hub`` is
replaced with a recorder. No real AWS / DynamoDB access occurs.
"""
from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException

from app.routers import newsfeed as nf

ALICE = "alice@test.local"
BOB = "bob@test.local"

POLL = {
    "user_id": ALICE,
    "post_type": "poll",
    "visibility": "followers",
    "poll_total_votes": 1,
    "poll_data": {
        "questions": [
            {
                "question_id": "q1",
                "choice_mode": "single",
                "options": [{"option_id": "opt_a"}],
            }
        ]
    },
}


def _patch_common(monkeypatch):
    """Stub DDB + polls service so the handler runs offline."""
    monkeypatch.setattr(nf, "ddb_get_item", lambda key: dict(POLL))

    import app.services.newsfeed_polls as polls

    monkeypatch.setattr(
        polls, "cast_vote", lambda **kwargs: {"opt_a": 1}
    )
    monkeypatch.setattr(
        polls, "get_user_vote_for_question", lambda *a, **k: "opt_a"
    )
    monkeypatch.setattr(
        polls, "get_user_multi_votes", lambda *a, **k: set()
    )


class _RecordingHub:
    def __init__(self):
        self.published: list[tuple[str, dict]] = []

    async def publish(self, user_id, event):
        self.published.append((user_id, dict(event)))
        return 1


# ── GAP-0164: access gate ────────────────────────────────────────────────────


def test_non_follower_cannot_vote_on_gated_poll(monkeypatch):
    """Bob (no access) must get 403 on Alice's followers-only poll.

    FAILS-BEFORE: handler returns 200 (no can_view_post guard).
    PASSES-AFTER: handler raises 403.
    """
    _patch_common(monkeypatch)
    monkeypatch.setattr(nf, "can_view_post", lambda viewer, post: False)

    with pytest.raises(HTTPException) as exc:
        nf.vote_on_poll(
            post_id="p1",
            body=nf.VoteIn(question_id="q1", option_id="opt_a"),
            user_id=BOB,
        )
    assert exc.value.status_code == 403


def test_access_check_runs_before_poll_type_check(monkeypatch):
    """Access denial must take precedence over the 'not a poll' 400 so the
    endpoint is not an enumeration oracle."""
    non_poll = dict(POLL)
    non_poll["post_type"] = "text"
    monkeypatch.setattr(nf, "ddb_get_item", lambda key: dict(non_poll))
    monkeypatch.setattr(nf, "can_view_post", lambda viewer, post: False)

    with pytest.raises(HTTPException) as exc:
        nf.vote_on_poll(
            post_id="p1",
            body=nf.VoteIn(question_id="q1", option_id="opt_a"),
            user_id=BOB,
        )
    assert exc.value.status_code == 403


def test_owner_can_vote_on_own_poll(monkeypatch):
    """The post owner bypasses the gate and votes successfully."""
    _patch_common(monkeypatch)
    # can_view_post must NOT be needed for the owner; make it raise if called.
    monkeypatch.setattr(
        nf, "can_view_post", lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not be called for owner"))
    )

    result = nf.vote_on_poll(
        post_id="p1",
        body=nf.VoteIn(question_id="q1", option_id="opt_a"),
        user_id=ALICE,
    )
    assert result["ok"] is True
    assert result["vote_counts"] == {"opt_a": 1}


def test_follower_with_access_can_vote(monkeypatch):
    """A viewer with access (can_view_post True) votes successfully."""
    _patch_common(monkeypatch)
    monkeypatch.setattr(nf, "can_view_post", lambda viewer, post: True)

    result = nf.vote_on_poll(
        post_id="p1",
        body=nf.VoteIn(question_id="q1", option_id="opt_a"),
        user_id=BOB,
    )
    assert result["ok"] is True


# ── GAP-0163: real-time SSE event ────────────────────────────────────────────


def test_vote_publishes_poll_vote_sse_event(monkeypatch):
    """A successful vote must publish a poll:vote SSE event to the post author.

    FAILS-BEFORE: sse_hub.publish is never scheduled.
    PASSES-AFTER: a poll:vote event is published to the author.

    Run inside a running event loop so the handler's
    ``asyncio.get_running_loop()`` succeeds and ``create_task`` fires.
    """
    _patch_common(monkeypatch)
    monkeypatch.setattr(nf, "can_view_post", lambda viewer, post: True)
    hub = _RecordingHub()
    monkeypatch.setattr(nf, "sse_hub", hub)

    async def run():
        result = nf.vote_on_poll(
            post_id="p1",
            body=nf.VoteIn(question_id="q1", option_id="opt_a"),
            user_id=BOB,
        )
        # Let the scheduled publish task run.
        await asyncio.sleep(0)
        return result

    result = asyncio.run(run())
    assert result["ok"] is True

    poll_events = [ev for (uid, ev) in hub.published if ev.get("type") == "poll:vote"]
    assert len(poll_events) == 1, f"expected one poll:vote event, got {hub.published}"

    target_user = hub.published[0][0]
    assert target_user == ALICE, "SSE event must be published to the post author"

    ev = poll_events[0]
    assert ev["post_id"] == "p1"
    assert ev["question_id"] == "q1"
    assert ev["option_id"] == "opt_a"
    assert ev["voter_sub"] == BOB
    assert ev["vote_counts"] == {"opt_a": 1}
