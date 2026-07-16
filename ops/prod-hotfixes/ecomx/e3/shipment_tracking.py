"""ECOM D4 - shipment tracking subsystem (keyed to a seller ship-group).

Detects the carrier from the tracking-number FORMAT, holds a tracking record
(carrier + tracking_number + status + event history), and drives the buyer
"out for delivery" / "delivered" pushes idempotently (each status once).

Ingestion SEAMS for a real USPS/UPS/FedEx/DHL or aggregator (EasyPost/Shippo/
AfterShip) feed later:
  * ingest_webhook(payload)  - a carrier/aggregator POSTs a status update
  * poll_tracking(number)    - a poller stub (query-by-tracking#)
  * simulate_step(sg_id)     - a DEMO driver advancing label_created ->
                               in_transit -> out_for_delivery -> delivered

Storage: table ``shipment_tracking`` - PK ``ship_group_id``; GSI
``GSI_TRACKING`` (partition ``tracking_number_norm``) for webhook/poller
lookup by tracking number.
"""
from __future__ import annotations

import logging
import re
import time
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.tables import T

logger = logging.getLogger(__name__)

# -- carriers -----------------------------------------------------------------
CARRIER_USPS = "USPS"
CARRIER_UPS = "UPS"
CARRIER_FEDEX = "FedEx"
CARRIER_DHL = "DHL"
CARRIER_UNKNOWN = "unknown"

# Public per-carrier tracking-page URL templates ({tracking_number} placeholder)
CARRIER_TRACKING_URLS: Dict[str, str] = {
    CARRIER_USPS: "https://tools.usps.com/go/TrackConfirmAction?tLabels={tracking_number}",
    CARRIER_UPS: "https://www.ups.com/track?loc=en_US&tracknum={tracking_number}",
    CARRIER_FEDEX: "https://www.fedex.com/fedextrack/?trknbr={tracking_number}",
    CARRIER_DHL: "https://www.dhl.com/us-en/home/tracking.html?tracking-id={tracking_number}",
}


def _norm(tracking_number: str) -> str:
    return re.sub(r"[\s-]+", "", str(tracking_number or "")).upper()


def detect_carrier(tracking_number: str) -> str:
    """Best-effort carrier detection from the tracking-number FORMAT.

    UPS   : 1Z + 16 alphanumerics (18 chars).
    USPS  : 20-22 digits beginning 9 (9400/9205/9407/9270/92..), or the
            2-letter + 9-digit + 'US' international form (e.g. EA123456785US).
    FedEx : 12, 15 or 20 digits.
    DHL   : 10 or 11 digits.
    """
    tn = _norm(tracking_number)
    if not tn:
        return CARRIER_UNKNOWN
    if re.fullmatch(r"1Z[0-9A-Z]{16}", tn):
        return CARRIER_UPS
    if re.fullmatch(r"9\d{19,21}", tn):
        return CARRIER_USPS
    if re.fullmatch(r"[A-Z]{2}\d{9}US", tn):
        return CARRIER_USPS
    if re.fullmatch(r"\d{12}|\d{15}|\d{20}", tn):
        return CARRIER_FEDEX
    if re.fullmatch(r"\d{10,11}", tn):
        return CARRIER_DHL
    return CARRIER_UNKNOWN


def tracking_url(carrier: str, tracking_number: str) -> str:
    tmpl = CARRIER_TRACKING_URLS.get(str(carrier or ""))
    if not tmpl:
        tmpl = CARRIER_TRACKING_URLS.get(detect_carrier(tracking_number))
    if not tmpl or not tracking_number:
        return ""
    return tmpl.format(tracking_number=_norm(tracking_number))


# -- status model -------------------------------------------------------------
STATUS_LABEL_CREATED = "label_created"
STATUS_IN_TRANSIT = "in_transit"
STATUS_OUT_FOR_DELIVERY = "out_for_delivery"
STATUS_DELIVERED = "delivered"
STATUS_EXCEPTION = "exception"

VALID_STATUSES = {
    STATUS_LABEL_CREATED, STATUS_IN_TRANSIT, STATUS_OUT_FOR_DELIVERY,
    STATUS_DELIVERED, STATUS_EXCEPTION,
}

# forward progression used by the SIMULATE driver
PROGRESSION = [
    STATUS_LABEL_CREATED, STATUS_IN_TRANSIT, STATUS_OUT_FOR_DELIVERY, STATUS_DELIVERED,
]

# ECOMX-32: monotonic status RANK. advance() refuses to REGRESS a shipment to a
# lower-ranked status (an out-of-order/replayed carrier event can't un-deliver a
# package). EXCEPTION is off-ladder (rank -1) and may be set from any non-final
# state.
STATUS_RANK = {
    STATUS_LABEL_CREATED: 0,
    STATUS_IN_TRANSIT: 1,
    STATUS_OUT_FOR_DELIVERY: 2,
    STATUS_DELIVERED: 3,
    STATUS_EXCEPTION: -1,
}


def _rank(status):
    return STATUS_RANK.get(str(status or ""), -1)

# buyer alert events (registered default-ON in alerts.DEFAULT_PUSH_EVENT_TYPES)
_STATUS_ALERTS = {
    STATUS_OUT_FOR_DELIVERY: ("order_out_for_delivery", "Your order is out for delivery"),
    STATUS_DELIVERED: ("order_delivered", "Your order was delivered"),
}

# external carrier/aggregator status vocab -> internal status
_EXTERNAL_STATUS_MAP = {
    "pre_transit": STATUS_LABEL_CREATED, "label_created": STATUS_LABEL_CREATED,
    "labelcreated": STATUS_LABEL_CREATED, "info_received": STATUS_LABEL_CREATED,
    "manifest": STATUS_LABEL_CREATED, "created": STATUS_LABEL_CREATED,
    "in_transit": STATUS_IN_TRANSIT, "intransit": STATUS_IN_TRANSIT,
    "transit": STATUS_IN_TRANSIT, "accepted": STATUS_IN_TRANSIT,
    "arrived": STATUS_IN_TRANSIT, "departed": STATUS_IN_TRANSIT,
    "available_for_pickup": STATUS_IN_TRANSIT,  # EasyPost
    "out_for_delivery": STATUS_OUT_FOR_DELIVERY, "outfordelivery": STATUS_OUT_FOR_DELIVERY,
    "delivery": STATUS_OUT_FOR_DELIVERY,
    "delivered": STATUS_DELIVERED,
    "exception": STATUS_EXCEPTION, "failure": STATUS_EXCEPTION,
    "returned": STATUS_EXCEPTION, "return_to_sender": STATUS_EXCEPTION,
    "error": STATUS_EXCEPTION, "cancelled": STATUS_EXCEPTION,  # EasyPost
    "canceled": STATUS_EXCEPTION, "unknown": STATUS_LABEL_CREATED,  # EasyPost
}


def normalize_status(raw: str) -> str:
    s = re.sub(r"[\s-]+", "_", str(raw or "").strip().lower())
    if s in VALID_STATUSES:
        return s
    return _EXTERNAL_STATUS_MAP.get(s, _EXTERNAL_STATUS_MAP.get(s.replace("_", ""), ""))


def _now() -> int:
    return int(time.time())


def _table():
    return T.shipment_tracking


def get_tracking(ship_group_id: str) -> Optional[Dict[str, Any]]:
    resp = _table().get_item(Key={"ship_group_id": ship_group_id})
    return resp.get("Item")


def get_by_tracking_number(tracking_number: str) -> Optional[Dict[str, Any]]:
    tn = _norm(tracking_number)
    if not tn:
        return None
    resp = _table().query(
        IndexName="GSI_TRACKING",
        KeyConditionExpression=Key("tracking_number_norm").eq(tn),
        Limit=1,
    )
    items = resp.get("Items", [])
    return items[0] if items else None


def to_public(rec: Dict[str, Any]) -> Dict[str, Any]:
    if not rec:
        return {}
    carrier = str(rec.get("carrier") or "")
    tn = str(rec.get("tracking_number") or "")
    return {
        "ship_group_id": rec.get("ship_group_id"),
        "order_id": rec.get("order_id"),
        "carrier": carrier,
        "tracking_number": tn,
        "tracking_url": tracking_url(carrier, tn),
        "status": rec.get("status"),
        "events": sorted(rec.get("events", []) or [], key=lambda e: int(e.get("ts", 0) or 0)),
        "created_at": int(rec.get("created_at", 0) or 0),
        "updated_at": int(rec.get("updated_at", 0) or 0),
    }


def create_on_ship(sg_row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Called when a seller ship-group transitions to SHIPPED. Creates the
    tracking record (carrier detected from the #), status=label_created + an
    initial event. Idempotent (one record per ship-group)."""
    sg_id = str(sg_row.get("ship_group_id") or "")
    if not sg_id:
        return None
    tn = str(sg_row.get("tracking_number") or "").strip()
    carrier = detect_carrier(tn) if tn else CARRIER_UNKNOWN
    if carrier == CARRIER_UNKNOWN and sg_row.get("carrier"):
        carrier = str(sg_row.get("carrier"))
    now = _now()
    lines = sg_row.get("line_items", []) or []
    first = (lines[0].get("name") if lines else "") or "your order"
    summary = first if len(lines) <= 1 else f"{first} +{len(lines) - 1} more"
    rec = {
        "ship_group_id": sg_id,
        "tracking_number": tn,
        "tracking_number_norm": _norm(tn) or sg_id,
        "carrier": carrier,
        "status": STATUS_LABEL_CREATED,
        "buyer_id": str(sg_row.get("buyer_id") or ""),
        "order_id": str(sg_row.get("order_id") or ""),
        "seller_id": str(sg_row.get("seller_id") or ""),
        "summary": summary,
        "events": [{"ts": now, "status": STATUS_LABEL_CREATED, "source": "seller_ship",
                    "description": "Shipping label created"}],
        "created_at": now,
        "updated_at": now,
    }
    # EasyPost seam (config-gated on EASYPOST_API_KEY). When the key is present
    # AND we have a tracking#, create a REAL EasyPost Tracker and store its id so
    # tracker.updated webhooks / poll_tracking can advance status. Best-effort:
    # never block the ship on an EasyPost failure. When the key is absent this is
    # a no-op and behaviour is UNCHANGED (internal/simulate driver).
    if tn:
        try:
            from app.services import easypost_client as _ep
            if _ep.is_enabled():
                tr = _ep.create_tracker(tracking_code=tn, carrier=carrier)
                if tr and tr.get("id"):
                    rec["easypost_tracker_id"] = str(tr["id"])
                    rec["tracking_provider"] = "easypost"
                    # seed the real carrier EasyPost resolved, if any
                    if tr.get("carrier"):
                        rec["carrier_easypost"] = str(tr["carrier"])
                    mapped = _ep.map_status(tr.get("status") or "")
                    if mapped and mapped != STATUS_LABEL_CREATED and mapped in VALID_STATUSES:
                        rec["status"] = mapped
                        rec["events"].append({"ts": now, "status": mapped,
                                              "source": "easypost", "description": "EasyPost tracker created"})
                else:
                    logger.warning("EasyPost create_tracker returned no id for sg %s: %s",
                                   sg_id, (tr or {}).get("reason") or (tr or {}).get("error"))
        except Exception:
            logger.exception("EasyPost create_tracker failed for sg %s (continuing)", sg_id)
    try:
        _table().put_item(Item=rec, ConditionExpression="attribute_not_exists(ship_group_id)")
    except Exception as exc:
        code = ""
        try:
            code = exc.response["Error"]["Code"]  # type: ignore[attr-defined]
        except Exception:
            pass
        if code == "ConditionalCheckFailedException":
            return get_tracking(sg_id)  # already created (idempotent)
        logger.exception("create_on_ship failed for %s", sg_id)
        return None
    return rec


class _TransientNotifyError(Exception):
    """A non-ConditionalCheckFailed DDB error while claiming the notify slot.
    Distinguished from a genuine dedupe so the caller can RETRY rather than
    silently drop the buyer delivery push (ECOMX-32)."""


def _claim_notify(ship_group_id: str, status_key: str) -> bool:
    """Atomically mark a status as notified exactly once. Returns True the first
    time (caller pushes), False on a genuine REPLAY (already notified).

    ECOMX-32: a ConditionalCheckFailed is a real dedupe (return False). ANY OTHER
    error is transient (network/throttle/500) and is RAISED as
    _TransientNotifyError so advance() can retry instead of dropping the push."""
    try:
        _table().update_item(
            Key={"ship_group_id": ship_group_id},
            UpdateExpression="ADD notified_statuses :s",
            ExpressionAttributeValues={":s": set([status_key]), ":one": status_key},
            ConditionExpression="attribute_not_exists(notified_statuses) OR NOT contains(notified_statuses, :one)",
        )
        return True
    except Exception as exc:
        code = ""
        try:
            code = exc.response["Error"]["Code"]  # type: ignore[attr-defined]
        except Exception:
            pass
        if code == "ConditionalCheckFailedException":
            return False  # genuine dedupe: someone already claimed+pushed
        logger.warning("claim_notify transient error for %s/%s: %s",
                       ship_group_id, status_key, exc)
        raise _TransientNotifyError(str(exc)) from exc


def _claim_notify_with_retry(ship_group_id: str, status_key: str, attempts: int = 3) -> bool:
    """_claim_notify + bounded retry on transient errors. On a genuine dedupe or
    exhausted retries returns False (no push); True means THIS caller won the
    slot and must push exactly once."""
    for i in range(max(1, attempts)):
        try:
            return _claim_notify(ship_group_id, status_key)
        except _TransientNotifyError:
            if i == attempts - 1:
                logger.error("claim_notify exhausted retries for %s/%s (push dropped)",
                             ship_group_id, status_key)
                return False
            time.sleep(0.1 * (i + 1))
    return False


def _notify_buyer(rec: Dict[str, Any], event: str, title: str) -> None:
    buyer = str(rec.get("buyer_id") or "")
    if not buyer:
        return
    sg_id = str(rec.get("ship_group_id") or "")
    order_id = str(rec.get("order_id") or "")
    carrier = str(rec.get("carrier") or "")
    tn = str(rec.get("tracking_number") or "")
    summary = str(rec.get("summary") or "your order")
    if event == "order_out_for_delivery":
        body = f"{summary} is out for delivery today. Tap to track."
    else:
        body = f"{summary} was delivered. Tap to view."
    action_url = f"/orders?order={order_id}&ship_group={sg_id}&track=1"
    alert_id = ""
    try:
        from app.services.alerts import write_alert
        res = write_alert(
            buyer, event=event, outcome="success", title=title,
            details={
                "alert_type": event, "ship_group_id": sg_id, "order_id": order_id,
                "carrier": carrier, "tracking_number": tn, "status": rec.get("status"),
                "summary": summary,
            },
            action_url=action_url, source_type="order_shipment", source_id=sg_id,
        )
        alert_id = (res or {}).get("alert_id", "") if isinstance(res, dict) else ""
    except Exception:
        logger.exception("write_alert(%s) failed for buyer %s sg %s", event, buyer, sg_id)
    try:
        from app.services.push import send_push_for_alert
        send_push_for_alert(buyer, event, title, body, alert_id or sg_id, action_url=action_url)
    except Exception:
        logger.exception("buyer %s push failed for %s sg %s", event, buyer, sg_id)


def advance(*, ship_group_id: Optional[str] = None, tracking_number: Optional[str] = None,
            status: str, location: Optional[str] = None, description: Optional[str] = None,
            source: str = "system") -> Optional[Dict[str, Any]]:
    """Advance a tracking record to a new status, append an event, and fire the
    buyer delivery pushes idempotently (each status pushes at most once)."""
    rec = None
    if ship_group_id:
        rec = get_tracking(ship_group_id)
    if not rec and tracking_number:
        rec = get_by_tracking_number(tracking_number)
    if not rec:
        return None
    sg_id = str(rec.get("ship_group_id"))
    new_status = normalize_status(status)
    if new_status not in VALID_STATUSES:
        logger.warning("advance: unmapped status %r for %s", status, sg_id)
        return rec
    cur_status = str(rec.get("status") or STATUS_LABEL_CREATED)
    # ECOMX-32: monotonic guard. Never REGRESS the ladder (a replayed/out-of-order
    # event can't un-deliver). A same-status replay is a no-op. EXCEPTION (rank
    # -1) is allowed as a terminal off-ladder signal EXCEPT once DELIVERED, which
    # is final and cannot be overwritten.
    if new_status == cur_status:
        return rec
    if new_status == STATUS_EXCEPTION:
        if cur_status == STATUS_DELIVERED:
            return rec
    elif _rank(new_status) <= _rank(cur_status):
        logger.info("advance: refusing regress %s -> %s for %s",
                    cur_status, new_status, sg_id)
        return rec
    now = _now()
    event: Dict[str, Any] = {"ts": now, "status": new_status, "source": source}
    if location:
        event["location"] = str(location)
    if description:
        event["description"] = str(description)
    try:
        _table().update_item(
            Key={"ship_group_id": sg_id},
            UpdateExpression="SET #st = :s, updated_at = :u, events = list_append(if_not_exists(events, :e), :ev)",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":s": new_status, ":u": now, ":e": [], ":ev": [event], ":cur": cur_status},
            # ECOMX-32: CAS so a concurrent writer that already moved the record
            # forward wins; we don't clobber a further-along status.
            ConditionExpression="attribute_not_exists(#st) OR #st = :cur",
        )
    except Exception as exc:
        code = ""
        try:
            code = exc.response["Error"]["Code"]  # type: ignore[attr-defined]
        except Exception:
            pass
        if code == "ConditionalCheckFailedException":
            # a concurrent advance moved it first; re-read + return that truth.
            logger.info("advance CAS lost for %s (%s); another writer won", sg_id, new_status)
            return get_tracking(sg_id) or rec
        raise
    rec["status"] = new_status
    alert = _STATUS_ALERTS.get(new_status)
    if alert and _claim_notify_with_retry(sg_id, new_status):
        _notify_buyer(rec, alert[0], alert[1])
    # ECOMX-21/23: bridge the tracking edge back to the order header so a
    # delivered/out-for-delivery tracking event advances the aggregate (all
    # groups delivered => header completed). Best-effort; the tracking write
    # already committed above regardless.
    order_id = str(rec.get("order_id") or "")
    if order_id and new_status in (STATUS_OUT_FOR_DELIVERY, STATUS_DELIVERED):
        try:
            from app.services import order_fulfillment_bridge as _bridge
            _bridge.reconcile_order(order_id, actor="system:tracking",
                                    reason=f"tracking {sg_id} -> {new_status}")
        except Exception:
            logger.exception("order aggregate reconcile failed on tracking %s", sg_id)
    return get_tracking(sg_id) or rec


def simulate_step(ship_group_id: str) -> Optional[Dict[str, Any]]:
    """DEMO driver: advance to the NEXT status in the forward progression
    (label_created -> in_transit -> out_for_delivery -> delivered). No-op once
    delivered."""
    rec = get_tracking(ship_group_id)
    if not rec:
        return None
    cur = str(rec.get("status") or STATUS_LABEL_CREATED)
    try:
        idx = PROGRESSION.index(cur)
    except ValueError:
        idx = 0
    if idx >= len(PROGRESSION) - 1:
        return rec  # already delivered (terminal)
    nxt = PROGRESSION[idx + 1]
    descr = {
        STATUS_IN_TRANSIT: "Package in transit",
        STATUS_OUT_FOR_DELIVERY: "Out for delivery",
        STATUS_DELIVERED: "Delivered",
    }.get(nxt, nxt)
    return advance(ship_group_id=ship_group_id, status=nxt, source="simulate", description=descr)


def simulate_to_delivered(ship_group_id: str, max_steps: int = 6) -> Optional[Dict[str, Any]]:
    for _ in range(max_steps):
        rec = get_tracking(ship_group_id)
        if not rec or str(rec.get("status")) == STATUS_DELIVERED:
            break
        simulate_step(ship_group_id)
    return get_tracking(ship_group_id)


def ingest_webhook(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Real-feed INGESTION SEAM: a carrier/aggregator (USPS/UPS/FedEx/DHL or
    EasyPost/Shippo/AfterShip) POSTs a status update. Resolves the record by
    ship_group_id or tracking_number, maps the external status, and advances.

    Handles the EasyPost ``tracker.updated`` Event shape (``result.status`` +
    ``result.tracking_details[]``) as well as the flat generic shape
    (``status``/``event`` + ``tracking_number``/``ship_group_id``)."""
    sg_id = str(payload.get("ship_group_id") or "").strip()
    tn = str(payload.get("tracking_number") or "").strip()
    location = payload.get("location")
    description = payload.get("description")
    source = str(payload.get("source") or "webhook")

    # EasyPost Event envelope -> normalize via the EasyPost parser.
    try:
        from app.services import easypost_client as _ep
        if _ep.is_easypost_payload(payload):
            parsed = _ep.parse_webhook(payload)
            if not parsed.get("ok"):
                return {"ok": False, "reason": parsed.get("reason") or "unmapped_status",
                        "raw_status": parsed.get("raw_status", "")}
            mapped = parsed["status"]
            tn = tn or str(parsed.get("tracking_number") or "").strip()
            location = location or parsed.get("location")
            description = description or parsed.get("description")
            source = "easypost"
            rec = None
            if sg_id:
                rec = get_tracking(sg_id)
            # EasyPost tracking_code == our stored tracking_number (GSI_TRACKING).
            if not rec and tn:
                rec = get_by_tracking_number(tn)
            if not rec:
                return {"ok": False, "reason": "tracking_not_found",
                        "easypost_tracker_id": parsed.get("easypost_tracker_id", "")}
            updated = advance(ship_group_id=str(rec["ship_group_id"]), status=mapped,
                              location=location, description=description, source=source)
            return {"ok": True, "provider": "easypost",
                    "ship_group_id": str(rec["ship_group_id"]),
                    "status": (updated or {}).get("status")}
    except Exception:
        logger.exception("EasyPost webhook parse failed; falling back to generic")

    # Generic flat shape.
    raw_status = payload.get("status") or payload.get("event") or ""
    mapped = normalize_status(raw_status)
    if not mapped:
        return {"ok": False, "reason": "unmapped_status", "raw_status": str(raw_status)}
    rec = None
    if sg_id:
        rec = get_tracking(sg_id)
    if not rec and tn:
        rec = get_by_tracking_number(tn)
    if not rec:
        return {"ok": False, "reason": "tracking_not_found"}
    updated = advance(
        ship_group_id=str(rec["ship_group_id"]), status=mapped,
        location=location, description=description, source=source,
    )
    return {"ok": True, "ship_group_id": str(rec["ship_group_id"]),
            "status": (updated or {}).get("status")}


def poll_tracking(tracking_number: str) -> Dict[str, Any]:
    """Poller SEAM: query-by-tracking#. When EasyPost is configured AND the
    record carries an easypost_tracker_id, GET the live EasyPost Tracker and
    feed its status through advance() (webhook fallback). Without a key it
    returns the current stored record so the poll contract stays exercisable."""
    rec = get_by_tracking_number(tracking_number)
    if not rec:
        return {"ok": False, "reason": "tracking_not_found", "tracking_number": tracking_number}
    poller = "stub"  # real carrier/aggregator query drop-in point
    tracker_id = str(rec.get("easypost_tracker_id") or "")
    if tracker_id:
        try:
            from app.services import easypost_client as _ep
            if _ep.is_enabled():
                tr = _ep.get_tracker(tracker_id)
                if tr and tr.get("ok") is not False and tr.get("status"):
                    mapped = _ep.map_status(tr.get("status") or "")
                    if mapped and mapped != str(rec.get("status")):
                        details = tr.get("tracking_details") or []
                        last = details[-1] if details and isinstance(details[-1], dict) else {}
                        loc = last.get("tracking_location") or {}
                        location = ", ".join(p for p in [str(loc.get("city") or ""),
                                             str(loc.get("state") or "")] if p) if isinstance(loc, dict) else None
                        advance(ship_group_id=str(rec["ship_group_id"]), status=mapped,
                                location=location or None,
                                description=str(last.get("message") or "") or None,
                                source="easypost_poll")
                        rec = get_tracking(str(rec["ship_group_id"])) or rec
                    poller = "easypost"
        except Exception:
            logger.exception("EasyPost poll_tracking failed for %s", tracking_number)
    pub = to_public(rec)
    pub["ok"] = True
    pub["poller"] = poller
    return pub


# -- ECOMX-30: real-carrier sync driver --------------------------------------
# Terminal statuses no longer worth advancing/polling.
_TERMINAL_STATUSES = {STATUS_DELIVERED, STATUS_EXCEPTION}


def list_active(limit: int = 200) -> List[Dict[str, Any]]:
    """Scan the tracking table for shipments still in flight (status not
    terminal). Bounded by ``limit``. Used by the background progression runner
    and the admin run-now endpoint."""
    out: List[Dict[str, Any]] = []
    scan_kwargs: Dict[str, Any] = {}
    last_key = None
    while True:
        if last_key:
            scan_kwargs["ExclusiveStartKey"] = last_key
        resp = _table().scan(**scan_kwargs)
        for it in resp.get("Items", []):
            if str(it.get("status") or STATUS_LABEL_CREATED) in _TERMINAL_STATUSES:
                continue
            out.append(it)
            if len(out) >= limit:
                return out
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return out


def _advance_one_forward(rec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Advance a single in-flight shipment by ONE honest step.

    * EasyPost-backed (has easypost_tracker_id + key configured): poll the REAL
      tracker and apply its status (poll_tracking already does this).
    * Otherwise (prod-mock / no key): drive the mock progression forward one
      status. This is the honest "mock-that-progresses" driver — like the payout
      runner — so a shipped order reaches delivered WITHOUT an admin clicking
      simulate.
    """
    sg_id = str(rec.get("ship_group_id") or "")
    if not sg_id:
        return None
    tracker_id = str(rec.get("easypost_tracker_id") or "")
    if tracker_id:
        try:
            from app.services import easypost_client as _ep
            if _ep.is_enabled():
                tn = str(rec.get("tracking_number") or "")
                res = poll_tracking(tn) if tn else None
                return get_tracking(sg_id) or rec
        except Exception:
            logger.exception("easypost poll in runner failed for %s", sg_id)
    # internal mock progression: advance one step along the ladder.
    return simulate_step(sg_id)


def run_progression_once(limit: int = 200) -> Dict[str, Any]:
    """Advance every in-flight shipment by one honest step. Returns a summary.
    Idempotent per call; terminal shipments are skipped. Safe to run on a timer
    OR via the admin run-now endpoint."""
    active = list_active(limit=limit)
    advanced = 0
    delivered = 0
    for rec in active:
        sg_id = str(rec.get("ship_group_id") or "")
        before = str(rec.get("status") or "")
        try:
            updated = _advance_one_forward(rec)
        except Exception:
            logger.exception("progression step failed for %s", sg_id)
            continue
        after = str((updated or {}).get("status") or before)
        if after != before:
            advanced += 1
            if after == STATUS_DELIVERED:
                delivered += 1
    return {"checked": len(active), "advanced": advanced, "delivered": delivered}
