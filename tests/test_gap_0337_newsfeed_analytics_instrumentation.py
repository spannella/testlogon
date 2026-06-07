"""GAP-0337: newsfeed router analytics instrumentation.

The analytics pipeline (GAP-0334 recording service + GAP-0335 rollup engine) had
NO data source — no router emitted analytics events. This test asserts that the
newsfeed router now calls the `record_*` functions from
`app.services.analytics_events` at its key engagement/revenue points.

Strategy (offline / hermetic — no AWS):
  * Patch the `record_engagement_event` / `record_revenue_event` symbols IN THE
    `newsfeed` module namespace (they're imported there) with spies.
  * Drive `tip_post` (revenue) and `like_post` (engagement) handler coroutines
    /functions directly with stubbed DDB stores, asserting the right record_*
    call fires on the success path with the right creator/amount.
  * For the remaining instrumentation points (create_post, create_comment,
    unlock_post) assert the import + presence of the matching record_* call via
    source assertion.

fails-before/passes-after: before the fix there were no record_* calls in
newsfeed.py, so the spies are never invoked and the source assertions miss.
"""
from __future__ import annotations

import inspect
from unittest import mock

import app.routers.newsfeed as nf


# ---------------------------------------------------------------------------
# Import / wiring assertions
# ---------------------------------------------------------------------------

def test_record_functions_imported_into_newsfeed_namespace():
    # Imported at module top so handlers can call them.
    assert hasattr(nf, "record_engagement_event")
    assert hasattr(nf, "record_revenue_event")
    from app.services import analytics_events as ae
    assert nf.record_engagement_event is ae.record_engagement_event
    assert nf.record_revenue_event is ae.record_revenue_event


def _source_of(fn) -> str:
    return inspect.getsource(fn)


def test_create_post_has_engagement_call():
    src = _source_of(nf.create_post)
    assert "record_engagement_event(" in src


def test_create_comment_has_engagement_call():
    src = _source_of(nf.create_comment)
    assert "record_engagement_event(" in src


def test_unlock_post_has_revenue_call():
    src = _source_of(nf.unlock_post)
    assert "record_revenue_event(" in src
    assert 'revenue_type="unlock"' in src


# ---------------------------------------------------------------------------
# like_post — engagement end-to-end (direct call, stubbed stores)
# ---------------------------------------------------------------------------

def test_like_post_records_engagement_event():
    post = {"pk": "POST#p1", "sk": "POST", "user_id": "creator_alice"}

    with mock.patch.object(nf, "ddb_get_item", return_value=post), \
         mock.patch.object(nf, "ddb_update_item", return_value=None), \
         mock.patch.object(nf, "tbl") as tbl, \
         mock.patch.object(nf, "record_engagement_event") as spy_eng:
        tbl.put_item.return_value = None
        out = nf.like_post(post_id="p1", user_id="actor_bob")

    assert out == {"ok": True}
    spy_eng.assert_called_once()
    kwargs = spy_eng.call_args.kwargs
    assert kwargs.get("creator_id") == "creator_alice"
    assert kwargs.get("actor_id") == "actor_bob"
    assert kwargs.get("content_id") == "p1"
    assert kwargs.get("action") == "reaction"


def test_like_post_analytics_failure_does_not_break_like():
    post = {"pk": "POST#p1", "sk": "POST", "user_id": "creator_alice"}

    with mock.patch.object(nf, "ddb_get_item", return_value=post), \
         mock.patch.object(nf, "ddb_update_item", return_value=None), \
         mock.patch.object(nf, "tbl") as tbl, \
         mock.patch.object(nf, "record_engagement_event", side_effect=RuntimeError("boom")):
        tbl.put_item.return_value = None
        # Must NOT raise — analytics is best-effort.
        out = nf.like_post(post_id="p1", user_id="actor_bob")

    assert out == {"ok": True}


# ---------------------------------------------------------------------------
# tip_post — revenue end-to-end (direct call, stubbed stores + payments)
# ---------------------------------------------------------------------------

class _FakeReq:
    amount_cents = 500
    currency = "usd"
    payment_method_id = None


def _tip_patches():
    """Patches shared by the tip_post drives (stub all DDB-touching side paths)."""
    import app.services.tip_ledger as tl
    import app.services.license_revenue as lr
    return [
        mock.patch.object(tl, "write_tip_ledger", return_value=None),
        mock.patch.object(lr, "process_revenue_split", return_value=None),
    ]


def _drive_tip_post():
    post = {"pk": "POST#p9", "sk": "POST", "user_id": "creator_carol"}
    fake_payments = mock.MagicMock()
    fake_payments.create_payment_intent.return_value = {"payment_intent_id": "pi_1"}
    fake_payments.confirm_payment_intent.return_value = {"status": "succeeded"}

    extra = _tip_patches()
    for p in extra:
        p.start()
    try:
        with mock.patch.object(nf, "ddb_get_item", return_value=post), \
             mock.patch.object(nf, "ddb_update_item", return_value={"tip_total_cents": 500}), \
             mock.patch.object(nf, "payments", fake_payments), \
             mock.patch.object(nf, "put_notification", return_value="n1"), \
                 mock.patch.object(nf, "record_revenue_event") as spy_rev:
            out = nf.tip_post(post_id="p9", req=_FakeReq(), user_id="tipper_dave")
    finally:
        for p in extra:
            p.stop()
    return out, spy_rev


def test_tip_post_records_revenue_event():
    out, spy_rev = _drive_tip_post()
    assert out["ok"] is True
    spy_rev.assert_called_once()
    kwargs = spy_rev.call_args.kwargs
    assert kwargs.get("creator_id") == "creator_carol"
    assert kwargs.get("revenue_type") == "tip"
    assert kwargs.get("amount_cents") == 500
    assert kwargs.get("subscriber_id") == "tipper_dave"
    assert kwargs.get("content_id") == "p9"


def test_tip_post_analytics_failure_does_not_break_tip():
    post = {"pk": "POST#p9", "sk": "POST", "user_id": "creator_carol"}
    fake_payments = mock.MagicMock()
    fake_payments.create_payment_intent.return_value = {"payment_intent_id": "pi_1"}
    fake_payments.confirm_payment_intent.return_value = {"status": "succeeded"}

    extra = _tip_patches()
    for p in extra:
        p.start()
    try:
        with mock.patch.object(nf, "ddb_get_item", return_value=post), \
             mock.patch.object(nf, "ddb_update_item", return_value={"tip_total_cents": 500}), \
             mock.patch.object(nf, "payments", fake_payments), \
             mock.patch.object(nf, "put_notification", return_value="n1"), \
                 mock.patch.object(nf, "record_revenue_event", side_effect=RuntimeError("boom")):
            out = nf.tip_post(post_id="p9", req=_FakeReq(), user_id="tipper_dave")
    finally:
        for p in extra:
            p.stop()

    assert out["ok"] is True
