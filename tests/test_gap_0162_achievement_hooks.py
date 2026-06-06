"""Regression test for GAP-0162.

ENGAGE-001 shipped ``advance_progress`` / ``update_streak`` but no newsfeed
action handler ever called them, so achievements could never auto-unlock through
normal user behaviour. This test confirms the newsfeed router action handlers
now invoke ``advance_progress`` with the expected metric key.

Fails-before: handlers never called ``advance_progress`` → recorder list empty.
Passes-after: each handler records exactly the expected metric advance.

Fully offline: the newsfeed module's DynamoDB helpers are replaced with an
in-memory fake, ``advance_progress`` / ``update_streak`` are monkeypatched to
recorders, and the feature flag is forced on via ``object.__setattr__`` (the
``S`` settings object is frozen). No real AWS / DynamoDB access occurs.
"""
from __future__ import annotations

import pytest

from app.core.settings import S
from app.routers import newsfeed as nf
from app.services import achievement_progress as ach


@pytest.fixture
def hook_recorder(monkeypatch):
    """Patch achievement service + newsfeed DDB helpers; return the recorder."""
    advanced: list[tuple[str, str]] = []
    streaks: list[tuple[str, str]] = []

    monkeypatch.setattr(
        ach, "advance_progress",
        lambda user_sub, metric_key, delta=1: advanced.append((user_sub, metric_key)) or [],
    )
    monkeypatch.setattr(
        ach, "update_streak",
        lambda user_sub, metric_key: streaks.append((user_sub, metric_key)) or 0,
    )

    # Force flag on so the (mocked) service functions would run in prod parity;
    # S is frozen, so use object.__setattr__. Restored after the test to avoid
    # leaking the flag into other tests sharing the process-global settings.
    _prev_flag = getattr(S, "achievements_enabled", False)
    object.__setattr__(S, "achievements_enabled", True)

    # In-memory single-table fake for the newsfeed DDB helpers.
    store: dict[tuple, dict] = {}

    def fake_get(key):
        return store.get((key["pk"], key["sk"]))

    def fake_put(item):
        store[(item["pk"], item["sk"])] = dict(item)

    def fake_update(*, key, update_expr, expr_vals, **kwargs):
        item = store.setdefault((key["pk"], key["sk"]), dict(key))
        if ":r" in expr_vals:
            item["reactions"] = expr_vals[":r"]
        if ":one" in expr_vals:
            item["comment_count"] = int(item.get("comment_count", 0)) + 1
        return item

    monkeypatch.setattr(nf, "ddb_get_item", fake_get)
    monkeypatch.setattr(nf, "ddb_put_item", fake_put)
    monkeypatch.setattr(nf, "ddb_update_item", fake_update)
    monkeypatch.setattr(nf, "ddb_query", lambda **kw: {"Items": []})
    monkeypatch.setattr(nf, "put_notification", lambda **kw: None)

    try:
        yield store, advanced, streaks
    finally:
        object.__setattr__(S, "achievements_enabled", _prev_flag)


def test_add_reaction_advances_reaction_count(hook_recorder):
    store, advanced, _streaks = hook_recorder
    store[(nf.pk_post("p1"), nf.sk_post())] = {
        "pk": nf.pk_post("p1"), "sk": nf.sk_post(),
        "post_id": "p1", "user_id": "author",
    }

    nf.add_reaction("p1", nf.ReactionRequest(emoji="\U0001F44D"), "reactor")

    assert ("reactor", "reaction_count") in advanced, (
        f"add_reaction must call advance_progress(reaction_count); got {advanced}"
    )


def test_create_comment_advances_comment_count(hook_recorder, monkeypatch):
    store, advanced, _streaks = hook_recorder
    store[(nf.pk_post("p2"), nf.sk_post())] = {
        "pk": nf.pk_post("p2"), "sk": nf.sk_post(),
        "post_id": "p2", "user_id": "author",
    }
    # can_view_post / locked checks: author commenting on own post bypasses both.
    nf.create_comment(
        "p2",
        nf.CreateCommentRequest(kind="text", body="hi"),
        "author",
    )

    assert ("author", "comment_count") in advanced, (
        f"create_comment must call advance_progress(comment_count); got {advanced}"
    )
