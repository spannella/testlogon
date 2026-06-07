"""GAP-0358 regression test.

Reposting ANOTHER user's post must notify the original author via
``put_notification`` (notif_type="post_shared"). Reposting your OWN post
(self-repost) must NOT notify (the self-repost guard raises before any write).

Offline / hermetic: no AWS. All DDB helpers and notification sinks in the
``app.routers.newsfeed`` namespace are patched to in-memory spies/stubs.
"""
import importlib

import pytest

nf = importlib.import_module("app.routers.newsfeed")


class _Spy:
    def __init__(self):
        self.calls = []

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        return "ntf_stub"


def _make_post(author_id, post_id="p1"):
    return {
        "pk": nf.pk_post(post_id),
        "sk": nf.sk_post(),
        "Entity": "Post",
        "post_id": post_id,
        "user_id": author_id,
        "status": "published",
        "locked": False,
    }


def _install_stubs(monkeypatch, *, post):
    """Wire create_repost's DDB collaborators to in-memory stubs."""
    put_spy = _Spy()
    alert_spy = _Spy()

    # The post lookup returns our post; the "already reposted" lookup returns None.
    def fake_ddb_get_item(key):
        if key.get("sk") == nf.sk_post():
            return post
        return None

    monkeypatch.setattr(nf, "ddb_get_item", fake_ddb_get_item)
    monkeypatch.setattr(nf, "ddb_put_item", lambda item: None)
    monkeypatch.setattr(
        nf,
        "ddb_update_item",
        lambda **kw: {"repost_count": 1},
    )

    class _FakeTbl:
        def put_item(self, **kw):
            return None

    monkeypatch.setattr(nf, "tbl", _FakeTbl())
    monkeypatch.setattr(nf, "_post_fadt_display_name", lambda uid: "Tester")
    monkeypatch.setattr(nf, "put_notification", put_spy)
    monkeypatch.setattr(nf, "emit_social_alert", alert_spy)
    # Avoid importing/fanning out to real follower service.
    import app.services.newsfeed_fanout as fanout
    monkeypatch.setattr(fanout, "_get_all_follower_ids", lambda uid: [])
    # Block check (step 4) does a real DDB lookup — stub it out.
    import app.services.blocking as blocking
    monkeypatch.setattr(blocking, "is_any_block", lambda a, b: False)
    return put_spy, alert_spy


def test_repost_other_user_notifies_author(monkeypatch):
    author_id = "u_author"
    reposter_id = "u_reposter"
    post = _make_post(author_id)
    put_spy, alert_spy = _install_stubs(monkeypatch, post=post)

    result = nf.create_repost("p1", nf.RepostRequest(quote=None), reposter_id)

    assert result["ok"] is True
    repost_id = result["repost_id"]

    # put_notification fired to the original author with the documented shape.
    assert len(put_spy.calls) == 1, "expected exactly one put_notification"
    call = put_spy.calls[0]
    assert call["recipient_user_id"] == author_id
    assert call["notif_type"] == "post_shared"
    payload = call["payload"]
    assert payload["post_id"] == "p1"
    assert payload["repost_id"] == repost_id
    assert payload["from_user_id"] == reposter_id

    # Social alert parity (GAP-0355): also fired, to the author, type post_shared.
    assert len(alert_spy.calls) == 1
    a = alert_spy.calls[0]
    assert a["recipient_user_id"] == author_id
    assert a["alert_type"] == "post_shared"
    assert a["actor_user_id"] == reposter_id


def test_self_repost_does_not_notify(monkeypatch):
    me = "u_self"
    post = _make_post(me)
    put_spy, alert_spy = _install_stubs(monkeypatch, post=post)

    with pytest.raises(nf.HTTPException) as exc:
        nf.create_repost("p1", nf.RepostRequest(quote=None), me)

    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == "self_repost"
    # No notification of any kind for a self-repost.
    assert put_spy.calls == []
    assert alert_spy.calls == []
