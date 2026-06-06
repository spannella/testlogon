"""Regression test for GAP-0165 (ENGAGE-003 Live Q&A).

When an authenticated user submits a question to the Live Q&A queue, the
submitter's *real profile display name* must be attached to the question — not
the raw ``user_sub`` (a UUID-style string). ``require_ui_session`` does not put
``display_name`` into the session ctx, so the router handler must resolve it
from the profile table before calling ``live_qa.submit_question``.

Fails-before: the handler used ``ctx.get("display_name") or ctx["user_sub"]``;
``display_name`` is never in ctx, so the raw sub was always passed.
Passes-after: the handler fetches the profile row and passes its
``display_name``, falling back to the sub only when no display name exists.

Fully offline: the profile table is replaced with an in-memory fake and the
``live_qa.submit_question`` service is monkeypatched to record its kwargs, so no
real AWS / DynamoDB access occurs.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.core.settings import S
from app.models import LiveQaQuestionSubmitIn
from app.routers import live_qa as live_qa_router


@dataclass
class _FakeProfileTable:
    items: dict[str, dict] = field(default_factory=dict)

    def get_item(self, *, Key):
        item = self.items.get(str(Key["user_sub"]))
        return {"Item": dict(item)} if item else {}


def _patch(monkeypatch, request, *, profile_item: dict | None):
    # Live Q&A must be enabled so the handler does not 404 early.
    object.__setattr__(S, "live_qa_enabled", True)

    table = _FakeProfileTable()
    if profile_item is not None:
        table.items[profile_item["user_sub"]] = profile_item

    # The router does `from app.core.tables import T as _T` *inside* the handler,
    # so patch the attribute on the tables module's singleton. ``T`` is a frozen
    # dataclass, so use object.__setattr__ and restore it on teardown.
    from app.core import tables as tables_module

    original_profile = tables_module.T.profile
    object.__setattr__(tables_module.T, "profile", table)
    request.addfinalizer(
        lambda: object.__setattr__(tables_module.T, "profile", original_profile)
    )

    captured: dict = {}

    def _fake_submit(**kwargs):
        captured.update(kwargs)
        return {"ok": True, **kwargs}

    monkeypatch.setattr(live_qa_router.live_qa, "submit_question", _fake_submit)
    return captured


def test_submit_question_uses_profile_display_name(monkeypatch, request):
    user_sub = "auth0|abc123-uuid-style-sub"
    captured = _patch(
        monkeypatch,
        request,
        profile_item={"user_sub": user_sub, "display_name": "Ada Lovelace"},
    )

    live_qa_router.submit_question(
        session_id="sess1",
        body=LiveQaQuestionSubmitIn(text="What is your favourite algorithm?"),
        ctx={"user_sub": user_sub},
    )

    # FAILS-BEFORE: display_name == user_sub (raw sub) instead of the profile name.
    assert captured["display_name"] == "Ada Lovelace"
    assert captured["user_id"] == user_sub
    assert captured["session_id"] == "sess1"


def test_submit_question_falls_back_to_user_sub_without_profile(monkeypatch, request):
    user_sub = "auth0|no-profile-sub"
    captured = _patch(monkeypatch, request, profile_item=None)

    live_qa_router.submit_question(
        session_id="sess2",
        body=LiveQaQuestionSubmitIn(text="Any question"),
        ctx={"user_sub": user_sub},
    )

    # No profile row -> graceful fallback to the sub.
    assert captured["display_name"] == user_sub
