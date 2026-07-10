"""EasyPost integration client for the shipment-tracking subsystem.

SEAM-READY / CONFIG-GATED on ``EASYPOST_API_KEY``:

  * When the key is PRESENT the real EasyPost REST API is called
    (create a Tracker on ship, GET a Tracker when polling) and EasyPost
    ``tracker.updated`` webhooks drive status advancement.
  * When the key is ABSENT (default today) every network entrypoint is a
    graceful no-op -- ``is_enabled()`` is False and the caller keeps the
    existing internal / simulate behaviour UNCHANGED.

Only ``is_enabled`` / ``create_tracker`` / ``get_tracker`` / ``verify_signature``
touch the network or settings; the PURE helpers ``map_status`` and
``parse_webhook`` depend on nothing but the stdlib so the status-map and the
EasyPost payload parser are unit-testable without a live key.

EasyPost API: https://api.easypost.com/v2  (HTTP Basic auth, API key as the
username, empty password).  Tracker object docs define the status vocab
(pre_transit / in_transit / out_for_delivery / delivered /
available_for_pickup / return_to_sender / failure / unknown / error /
cancelled) and the ``tracking_details[]`` event array.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import unicodedata
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_API_BASE = "https://api.easypost.com/v2"

# -- internal status constants (mirror app.services.shipment_tracking) --------
_LABEL_CREATED = "label_created"
_IN_TRANSIT = "in_transit"
_OUT_FOR_DELIVERY = "out_for_delivery"
_DELIVERED = "delivered"
_EXCEPTION = "exception"

# EasyPost Tracker.status -> internal shipment_tracking status.
EASYPOST_STATUS_MAP: Dict[str, str] = {
    "pre_transit": _LABEL_CREATED,
    "unknown": _LABEL_CREATED,
    "in_transit": _IN_TRANSIT,
    "available_for_pickup": _IN_TRANSIT,
    "out_for_delivery": _OUT_FOR_DELIVERY,
    "delivered": _DELIVERED,
    "return_to_sender": _EXCEPTION,
    "failure": _EXCEPTION,
    "error": _EXCEPTION,
    "cancelled": _EXCEPTION,
}

# internal carrier -> EasyPost carrier string (best-effort; when unknown the
# carrier is omitted from create_tracker and EasyPost auto-detects it).
_EASYPOST_CARRIER = {
    "USPS": "USPS",
    "UPS": "UPS",
    "FedEx": "FedEx",
    "DHL": "DHLExpress",
}


# -- config gate --------------------------------------------------------------
def _settings() -> Any:
    from app.core.settings import S  # lazy so the pure helpers need no settings
    return S


def api_key() -> str:
    return str(getattr(_settings(), "easypost_api_key", "") or "")


def webhook_secret() -> str:
    return str(getattr(_settings(), "easypost_webhook_secret", "") or "")


def api_base() -> str:
    return str(getattr(_settings(), "easypost_api_base", "") or "").rstrip("/") or DEFAULT_API_BASE


def is_enabled() -> bool:
    """True only when EASYPOST_API_KEY is configured. Callers fall back to the
    internal / simulate behaviour when this is False."""
    return bool(api_key())


def easypost_carrier(internal_carrier: str) -> Optional[str]:
    return _EASYPOST_CARRIER.get(str(internal_carrier or ""))


# -- pure status map ----------------------------------------------------------
def map_status(raw: str) -> str:
    """Map an EasyPost Tracker status to the internal status. Returns "" for an
    unrecognised value (caller treats it as no-op)."""
    return EASYPOST_STATUS_MAP.get(str(raw or "").strip().lower(), "")


# -- pure webhook parser ------------------------------------------------------
def is_easypost_payload(payload: Dict[str, Any]) -> bool:
    """Detect the EasyPost Event envelope (``object`` == "Event" carrying a
    ``result`` Tracker, or a ``tracker.*`` description)."""
    if not isinstance(payload, dict):
        return False
    desc = str(payload.get("description") or "")
    result = payload.get("result")
    if str(payload.get("object") or "") == "Event" and isinstance(result, dict):
        return True
    if desc.startswith("tracker") and isinstance(result, dict):
        return True
    # a bare Tracker object POSTed directly
    if str(payload.get("object") or "") == "Tracker" and payload.get("tracking_code"):
        return True
    return False


def parse_webhook(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Parse an EasyPost ``tracker.updated`` webhook (or a bare Tracker) into the
    normalized fields ingest_webhook consumes.

    Handles the real EasyPost shape: ``result.status`` +
    ``result.tracking_details[]`` (latest detail supplies location/description).
    Returns ``{ok, tracking_number, status(internal), raw_status,
    easypost_tracker_id, location, description, source, event}``.
    """
    if not isinstance(payload, dict):
        return {"ok": False, "reason": "not_easypost"}
    event = str(payload.get("description") or "")
    tracker = payload.get("result")
    if not isinstance(tracker, dict):
        # a bare Tracker object was POSTed
        tracker = payload if str(payload.get("object") or "") == "Tracker" else {}
    if not isinstance(tracker, dict) or not tracker:
        return {"ok": False, "reason": "no_tracker"}

    raw_status = str(tracker.get("status") or "")
    internal = map_status(raw_status)
    tracking_code = str(tracker.get("tracking_code") or "")
    tracker_id = str(tracker.get("id") or "")

    location = ""
    description = ""
    details = tracker.get("tracking_details")
    if isinstance(details, list) and details:
        last = details[-1] if isinstance(details[-1], dict) else {}
        # prefer the detail whose status matches the tracker's current status
        for d in reversed(details):
            if isinstance(d, dict) and str(d.get("status") or "").lower() == raw_status.lower():
                last = d
                break
        description = str(last.get("message") or last.get("status_detail") or "")
        loc = last.get("tracking_location")
        if isinstance(loc, dict):
            parts = [str(loc.get("city") or ""), str(loc.get("state") or ""),
                     str(loc.get("zip") or "")]
            location = ", ".join(p for p in parts if p)

    return {
        "ok": bool(internal),
        "reason": "" if internal else "unmapped_status",
        "provider": "easypost",
        "event": event,
        "tracking_number": tracking_code,
        "easypost_tracker_id": tracker_id,
        "raw_status": raw_status,
        "status": internal,
        "location": location,
        "description": description,
        "source": "easypost",
    }


# -- webhook signature --------------------------------------------------------
def verify_signature(raw_body: bytes, headers: Dict[str, str]) -> bool:
    """Verify an EasyPost webhook HMAC signature when EASYPOST_WEBHOOK_SECRET is
    configured. EasyPost signs the raw request body with HMAC-SHA256 (hex) and
    sends it in ``X-Hmac-Signature`` as ``hmac-sha256-hex=<digest>``.

    Returns True when no secret is configured (open seam, dev) OR the signature
    matches; False on mismatch/missing signature. NFC-normalizes the secret per
    EasyPost's documented guidance for unicode secrets.
    """
    secret = webhook_secret()
    if not secret:
        return True  # not configured -> seam is open (dev)
    provided = ""
    for k, v in (headers or {}).items():
        if str(k).lower() == "x-hmac-signature":
            provided = str(v or "")
            break
    if not provided:
        return False
    provided = provided.split("=", 1)[1] if provided.lower().startswith("hmac-sha256-hex=") else provided
    key = unicodedata.normalize("NFKD", secret).encode("utf-8")
    body = raw_body if isinstance(raw_body, (bytes, bytearray)) else str(raw_body or "").encode("utf-8")
    expected = hmac.new(key, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, provided.strip().lower())


# -- HTTP (only reached when a key is set) ------------------------------------
def _auth_header() -> str:
    token = base64.b64encode(f"{api_key()}:".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def _http(method: str, path: str, body: Optional[Dict[str, Any]] = None,
          timeout: float = 15.0) -> Dict[str, Any]:
    url = f"{api_base()}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", _auth_header())
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8")
        except Exception:
            pass
        logger.warning("EasyPost %s %s failed: HTTP %s %s", method, path, exc.code, detail[:400])
        return {"ok": False, "status_code": exc.code, "error": detail}
    except Exception as exc:  # network / timeout
        logger.warning("EasyPost %s %s errored: %s", method, path, exc)
        return {"ok": False, "error": str(exc)}
    try:
        parsed = json.loads(payload) if payload else {}
    except Exception:
        parsed = {}
    parsed.setdefault("ok", True)
    return parsed


def create_tracker(tracking_code: str, carrier: Optional[str] = None,
                   timeout: float = 15.0) -> Dict[str, Any]:
    """POST /v2/trackers -> create a real EasyPost Tracker. ``carrier`` is the
    internal carrier name (mapped to EasyPost's, omitted when unknown so
    EasyPost auto-detects). Returns the Tracker dict (with ``id``/``status``) or
    ``{ok: False, ...}`` on failure. Never raises."""
    if not is_enabled():
        return {"ok": False, "reason": "easypost_disabled"}
    tc = str(tracking_code or "").strip()
    if not tc:
        return {"ok": False, "reason": "no_tracking_code"}
    tracker: Dict[str, Any] = {"tracking_code": tc}
    ep_carrier = easypost_carrier(carrier or "")
    if ep_carrier:
        tracker["carrier"] = ep_carrier
    return _http("POST", "/trackers", {"tracker": tracker}, timeout=timeout)


def get_tracker(tracker_id: str, timeout: float = 15.0) -> Dict[str, Any]:
    """GET /v2/trackers/{id} -> retrieve a Tracker (poll fallback). Never raises."""
    if not is_enabled():
        return {"ok": False, "reason": "easypost_disabled"}
    tid = str(tracker_id or "").strip()
    if not tid:
        return {"ok": False, "reason": "no_tracker_id"}
    return _http("GET", f"/trackers/{tid}", None, timeout=timeout)
