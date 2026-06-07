from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Request

from app.core.settings import S
from app.models import PushRegisterReq, PushRevokeReq, PushSubscribeReq, PushUnsubscribeReq
from app.services.alerts import audit_event
from app.services.push import (
    list_push_devices,
    revoke_push_device,
    send_push_for_alert,
    upsert_push_device,
)
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui", tags=["push"])


def _web_push_subscription_json(endpoint: str, p256dh: str, auth: str) -> str:
    """Serialize a web-push subscription in the exact shape ``web_push_send``
    (``app/services/push.py:166``) deserializes: ``{"endpoint":..., "keys":{"p256dh":..., "auth":...}}``.

    ``sort_keys=True`` makes the blob canonical so that the same subscription
    always yields the same ``push_device_id`` (used to compute the SK on
    subscribe and to remove it on unsubscribe).
    """
    return json.dumps(
        {"endpoint": endpoint, "keys": {"p256dh": p256dh, "auth": auth}},
        sort_keys=True,
        separators=(",", ":"),
    )


@router.get("/push/vapid-key")
async def ui_get_vapid_key():
    """Return the VAPID public key for push subscription.

    The VAPID public key is safe to expose publicly -- it is used by
    the browser to authenticate the application server when subscribing
    to push notifications.
    """
    if not S.vapid_public_key:
        raise HTTPException(404, "VAPID not configured")
    return {"vapid_public_key": S.vapid_public_key}


@router.get("/push/devices")
async def ui_list_push_devices(ctx=Depends(require_ui_session)):
    return {"devices": list_push_devices(ctx["user_sub"])}


@router.post("/push/register")
async def ui_register_push(req: Request, body: PushRegisterReq, ctx=Depends(require_ui_session)):
    if not S.push_enabled:
        raise HTTPException(400, "Push disabled")
    token = (body.token or "").strip()
    if len(token) < 20:
        raise HTTPException(400, "Bad token")
    platform = (body.platform or "").strip()[:32]
    it = upsert_push_device(ctx["user_sub"], token, platform)
    audit_event("push_device_register", ctx["user_sub"], req, outcome="success", platform=platform)
    return it


@router.post("/push/subscribe")
async def ui_subscribe_push(req: Request, body: PushSubscribeReq, ctx=Depends(require_ui_session)):
    """Register a proper VAPID web-push subscription.

    Accepts ``{endpoint, keys_p256dh, keys_auth}`` and stores it as a parseable
    web-push subscription JSON blob (``token``) so the delivery path
    (``web_push_send`` / ``send_push_for_alert``) can ``json.loads`` it and read
    ``subscription["endpoint"]`` + ``subscription["keys"]["p256dh"]`` /
    ``["auth"]`` for VAPID delivery. Stored with ``platform="web"``.
    """
    if not S.push_enabled:
        raise HTTPException(400, "Push disabled")
    endpoint = (body.endpoint or "").strip()
    p256dh = (body.keys_p256dh or "").strip()
    auth = (body.keys_auth or "").strip()
    if not (endpoint and p256dh and auth):
        raise HTTPException(400, "Bad subscription")
    # NOTE: ``upsert_push_device`` derives the device_id (SK) from sha256(token)
    # and stores the token verbatim. ``web_push_send``/``send_push_for_alert``
    # then ``json.loads(token)`` directly (push.py:166/285), so the token MUST
    # be the bare subscription JSON (no SK prefix) to remain deserializable.
    token = _web_push_subscription_json(endpoint, p256dh, auth)
    it = upsert_push_device(ctx["user_sub"], token, "web")
    audit_event("push_web_subscribe", ctx["user_sub"], req, outcome="success", platform="web")
    return it


@router.delete("/push/subscribe")
async def ui_unsubscribe_push(req: Request, body: PushUnsubscribeReq, ctx=Depends(require_ui_session)):
    """Unsubscribe a web-push subscription by its endpoint.

    Rebuilds the stored device key from the endpoint by scanning the user's
    web devices for a matching endpoint, then revokes it.
    """
    endpoint = (body.endpoint or "").strip()
    if not endpoint:
        raise HTTPException(400, "Bad subscription")
    from boto3.dynamodb.conditions import Key  # local import: mirror service-layer usage
    from app.core.tables import T

    removed = False
    try:
        r = T.push_devices.query(KeyConditionExpression=Key("user_sub").eq(ctx["user_sub"]), Limit=200)
        for item in r.get("Items", []):
            if item.get("platform") != "web":
                continue
            tok = item.get("token", "")
            try:
                sub = json.loads(tok)
            except (json.JSONDecodeError, TypeError):
                continue
            if sub.get("endpoint") == endpoint:
                revoke_push_device(ctx["user_sub"], item.get("device_id"))
                removed = True
    except Exception:
        pass
    audit_event("push_web_unsubscribe", ctx["user_sub"], req, outcome="success", platform="web")
    return {"ok": True, "removed": removed}


@router.post("/push/revoke")
async def ui_revoke_push(req: Request, body: PushRevokeReq, ctx=Depends(require_ui_session)):
    revoke_push_device(ctx["user_sub"], body.device_id)
    audit_event("push_device_revoke", ctx["user_sub"], req, outcome="success", device_id=body.device_id)
    return {"ok": True}


@router.post("/push/test")
async def ui_push_test(req: Request, ctx=Depends(require_ui_session)):
    send_push_for_alert(ctx["user_sub"], "security_event", "Test notification", "This is a test push.", "test")
    audit_event("push_test", ctx["user_sub"], req, outcome="success")
    return {"ok": True}
