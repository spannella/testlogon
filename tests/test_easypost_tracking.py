"""Unit tests for the EasyPost shipment-tracking integration (ECOM D5).

Proves WITHOUT a live EasyPost key:
  * the EasyPost Tracker.status -> internal status map (all vocab);
  * the EasyPost ``tracker.updated`` webhook parser against a REAL EasyPost
    sample payload shape (result.status + tracking_details[]);
  * the webhook HMAC signature verify;
  * ingest_webhook routes an EasyPost payload -> advance -> fires the buyer
    out_for_delivery / delivered push (idempotently);
  * create_on_ship WOULD call EasyPost when a key is set (mocked), and is an
    exact no-op (simulate/internal behaviour UNCHANGED) when the key is absent.
"""
from __future__ import annotations

import hashlib
import hmac

import pytest

from app.services import easypost_client as ep
from app.services import shipment_tracking as st


# --------------------------------------------------------------------------- #
# 1. status map
# --------------------------------------------------------------------------- #
def test_easypost_status_map_all_vocab():
    assert ep.map_status("pre_transit") == "label_created"
    assert ep.map_status("unknown") == "label_created"
    assert ep.map_status("in_transit") == "in_transit"
    assert ep.map_status("available_for_pickup") == "in_transit"
    assert ep.map_status("out_for_delivery") == "out_for_delivery"
    assert ep.map_status("delivered") == "delivered"
    for s in ("return_to_sender", "failure", "error", "cancelled"):
        assert ep.map_status(s) == "exception", s
    assert ep.map_status("DELIVERED") == "delivered"   # case-insensitive
    assert ep.map_status("bogus_status") == ""          # unmapped -> no-op
    assert ep.map_status("") == ""


def test_normalize_status_agrees_with_easypost_map():
    """The webhook generic path (normalize_status) must agree with the EasyPost
    vocab so both ingest paths yield the same internal status."""
    for raw, exp in [
        ("pre_transit", "label_created"), ("unknown", "label_created"),
        ("in_transit", "in_transit"), ("available_for_pickup", "in_transit"),
        ("out_for_delivery", "out_for_delivery"), ("delivered", "delivered"),
        ("return_to_sender", "exception"), ("failure", "exception"),
        ("error", "exception"), ("cancelled", "exception"),
    ]:
        assert st.normalize_status(raw) == exp, raw


# --------------------------------------------------------------------------- #
# 2. webhook parser (REAL EasyPost tracker.updated payload shape)
# --------------------------------------------------------------------------- #
def _easypost_event(status, code="EZ1000000001", tid="trk_easypostSAMPLE01"):
    """A realistic EasyPost `tracker.updated` Event envelope (per EasyPost docs:
    an Event with object=='Event', description=='tracker.updated', and a
    `result` Tracker carrying `status` + `tracking_details[]`)."""
    return {
        "id": "evt_1f2e3d4c",
        "object": "Event",
        "description": "tracker.updated",
        "mode": "test",
        "previous_attributes": {"status": "pre_transit"},
        "created_at": "2023-06-01T00:00:00Z",
        "updated_at": "2023-06-02T08:00:00Z",
        "pending_urls": [],
        "completed_urls": [],
        "result": {
            "id": tid,
            "object": "Tracker",
            "mode": "test",
            "tracking_code": code,
            "status": status,
            "status_detail": status,
            "signed_by": None,
            "carrier": "USPS",
            "est_delivery_date": "2023-06-03T00:00:00Z",
            "shipment_id": None,
            "tracking_details": [
                {
                    "object": "TrackingDetail",
                    "message": "Shipping Label Created, USPS Awaiting Item",
                    "description": None,
                    "status": "pre_transit",
                    "status_detail": "status_update",
                    "datetime": "2023-06-01T00:00:00Z",
                    "source": "USPS",
                    "tracking_location": {
                        "object": "TrackingLocation",
                        "city": None, "state": None, "country": None, "zip": None,
                    },
                },
                {
                    "object": "TrackingDetail",
                    "message": "Arrived at USPS Regional Facility",
                    "description": None,
                    "status": status,
                    "status_detail": status,
                    "datetime": "2023-06-02T08:00:00Z",
                    "source": "USPS",
                    "tracking_location": {
                        "object": "TrackingLocation",
                        "city": "SAN FRANCISCO", "state": "CA", "country": "US",
                        "zip": "94105",
                    },
                },
            ],
            "carrier_detail": None,
            "public_url": "https://track.easypost.com/djE6dHJrX2Vhc3lwb3N0",
        },
    }


@pytest.mark.parametrize("raw,internal", [
    ("in_transit", "in_transit"),
    ("out_for_delivery", "out_for_delivery"),
    ("delivered", "delivered"),
])
def test_parse_webhook_maps_and_extracts(raw, internal):
    payload = _easypost_event(raw)
    assert ep.is_easypost_payload(payload) is True
    parsed = ep.parse_webhook(payload)
    assert parsed["ok"] is True
    assert parsed["provider"] == "easypost"
    assert parsed["status"] == internal
    assert parsed["raw_status"] == raw
    assert parsed["tracking_number"] == "EZ1000000001"
    assert parsed["easypost_tracker_id"] == "trk_easypostSAMPLE01"
    assert parsed["source"] == "easypost"
    # the tracking_detail matching the current status supplies the location
    assert parsed["location"] == "SAN FRANCISCO, CA, 94105"
    assert "USPS Regional Facility" in parsed["description"]


def test_parse_webhook_unmapped_status():
    parsed = ep.parse_webhook(_easypost_event("something_weird"))
    assert parsed["ok"] is False
    assert parsed["reason"] == "unmapped_status"


def test_is_easypost_payload_rejects_generic():
    assert ep.is_easypost_payload({"status": "delivered", "tracking_number": "X"}) is False
    assert ep.is_easypost_payload({}) is False


# --------------------------------------------------------------------------- #
# 3. webhook HMAC signature verify
# --------------------------------------------------------------------------- #
def test_verify_signature(monkeypatch):
    body = b'{"description":"tracker.updated"}'
    secret = "whsec_test_easypost"
    monkeypatch.setattr(ep, "webhook_secret", lambda: secret)
    good = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    assert ep.verify_signature(body, {"X-Hmac-Signature": good}) is True
    # EasyPost's prefixed form
    assert ep.verify_signature(body, {"X-Hmac-Signature": "hmac-sha256-hex=" + good}) is True
    assert ep.verify_signature(body, {"X-Hmac-Signature": "deadbeef"}) is False
    assert ep.verify_signature(body, {}) is False  # missing -> reject when configured


def test_verify_signature_open_when_unconfigured(monkeypatch):
    monkeypatch.setattr(ep, "webhook_secret", lambda: "")
    assert ep.verify_signature(b"anything", {}) is True  # dev seam open


# --------------------------------------------------------------------------- #
# fake DDB table so the advance/push wiring runs without DynamoDB
# --------------------------------------------------------------------------- #
class _CondFail(Exception):
    def __init__(self):
        self.response = {"Error": {"Code": "ConditionalCheckFailedException"}}


class FakeTable:
    def __init__(self, item=None):
        self.item = item
        self.puts = []

    def get_item(self, Key):
        if self.item and self.item.get("ship_group_id") == Key.get("ship_group_id"):
            return {"Item": dict(self.item)}
        return {}

    def query(self, **kw):
        return {"Items": [dict(self.item)] if self.item else []}

    def put_item(self, Item, **kw):
        self.puts.append(Item)
        self.item = Item

    def update_item(self, Key, UpdateExpression="", ExpressionAttributeValues=None,
                    ExpressionAttributeNames=None, ConditionExpression=None, **kw):
        v = ExpressionAttributeValues or {}
        if "ADD notified_statuses" in UpdateExpression:
            s = self.item.setdefault("notified_statuses", set())
            if ConditionExpression and v[":one"] in s:
                raise _CondFail()
            self.item["notified_statuses"] = s | v[":s"]
            return {}
        if UpdateExpression.startswith("SET"):
            self.item["status"] = v[":s"]
            self.item["updated_at"] = v[":u"]
            self.item["events"] = (self.item.get("events") or []) + v[":ev"]
            return {}
        return {}


@pytest.fixture
def fake_rec():
    return {
        "ship_group_id": "sg_test_1",
        "tracking_number": "EZ1000000001",
        "tracking_number_norm": "EZ1000000001",
        "carrier": "USPS",
        "status": "in_transit",
        "buyer_id": "buyer_1",
        "order_id": "order_1",
        "summary": "Blue Widget",
        "events": [],
        "easypost_tracker_id": "trk_easypostSAMPLE01",
        "created_at": 1000,
        "updated_at": 1000,
    }


# --------------------------------------------------------------------------- #
# 4. ingest_webhook routes an EasyPost payload -> advance -> push
# --------------------------------------------------------------------------- #
def test_ingest_easypost_webhook_fires_delivery_pushes(monkeypatch, fake_rec):
    fake = FakeTable(fake_rec)
    monkeypatch.setattr(st, "_table", lambda: fake)
    pushes = []
    monkeypatch.setattr(st, "_notify_buyer",
                        lambda rec, event, title: pushes.append((event, rec.get("status"))))

    # out_for_delivery -> advances + fires order_out_for_delivery
    res = st.ingest_webhook(_easypost_event("out_for_delivery"))
    assert res["ok"] is True and res["provider"] == "easypost"
    assert res["status"] == "out_for_delivery"
    assert ("order_out_for_delivery", "out_for_delivery") in pushes

    # delivered -> advances + fires order_delivered
    res = st.ingest_webhook(_easypost_event("delivered"))
    assert res["status"] == "delivered"
    assert ("order_delivered", "delivered") in pushes

    # replay delivered -> idempotent: NO second delivered push
    before = list(pushes)
    st.ingest_webhook(_easypost_event("delivered"))
    assert pushes == before, "delivered push must fire at most once"


def test_ingest_generic_webhook_still_works(monkeypatch, fake_rec):
    """No-key / non-EasyPost flat payload path is unchanged."""
    fake = FakeTable(dict(fake_rec, status="label_created"))
    monkeypatch.setattr(st, "_table", lambda: fake)
    pushes = []
    monkeypatch.setattr(st, "_notify_buyer",
                        lambda rec, event, title: pushes.append(event))
    res = st.ingest_webhook({"tracking_number": "EZ1000000001", "status": "out_for_delivery"})
    assert res["ok"] is True
    assert res.get("provider") is None  # generic path
    assert "order_out_for_delivery" in pushes


# --------------------------------------------------------------------------- #
# 5. create_on_ship: keyed -> calls EasyPost; no-key -> unchanged
# --------------------------------------------------------------------------- #
def test_create_on_ship_calls_easypost_when_keyed(monkeypatch):
    fake = FakeTable()
    monkeypatch.setattr(st, "_table", lambda: fake)
    calls = {}

    def fake_create_tracker(tracking_code, carrier=None, **kw):
        calls["tracking_code"] = tracking_code
        calls["carrier"] = carrier
        return {"ok": True, "id": "trk_LIVE99", "status": "pre_transit", "carrier": "USPS"}

    monkeypatch.setattr(ep, "is_enabled", lambda: True)
    monkeypatch.setattr(ep, "create_tracker", fake_create_tracker)

    sg = {"ship_group_id": "sg_key_1", "tracking_number": "1Z999AA10123456784",
          "buyer_id": "b1", "order_id": "o1", "line_items": [{"name": "Widget"}]}
    rec = st.create_on_ship(sg)
    assert rec is not None
    assert calls["tracking_code"] == "1Z999AA10123456784"
    assert calls["carrier"] == "UPS"            # detect_carrier(1Z...) -> UPS
    assert rec["easypost_tracker_id"] == "trk_LIVE99"
    assert rec["tracking_provider"] == "easypost"
    assert fake.puts and fake.puts[0]["easypost_tracker_id"] == "trk_LIVE99"


def test_create_on_ship_no_key_is_unchanged(monkeypatch):
    fake = FakeTable()
    monkeypatch.setattr(st, "_table", lambda: fake)
    monkeypatch.setattr(ep, "is_enabled", lambda: False)

    def _boom(*a, **k):
        raise AssertionError("EasyPost must NOT be called without a key")
    monkeypatch.setattr(ep, "create_tracker", _boom)

    sg = {"ship_group_id": "sg_nokey_1", "tracking_number": "1Z999AA10123456784",
          "buyer_id": "b1", "order_id": "o1", "line_items": [{"name": "Widget"}]}
    rec = st.create_on_ship(sg)
    assert rec is not None
    assert "easypost_tracker_id" not in rec
    assert "tracking_provider" not in rec
    assert rec["status"] == "label_created"     # internal/simulate baseline
    assert fake.puts and fake.puts[0]["status"] == "label_created"
