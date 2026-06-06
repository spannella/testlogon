from __future__ import annotations

import importlib.util
import json
import hashlib
import logging
import sys
import threading
import time
import uuid
from collections import OrderedDict
from typing import Any, Callable, Dict, Iterable, List, Optional
from urllib.parse import urljoin

if "stripe" in sys.modules:
    stripe = sys.modules["stripe"]  # type: ignore
elif importlib.util.find_spec("stripe") is not None:
    import stripe  # type: ignore
else:  # pragma: no cover
    stripe = None  # type: ignore
from botocore.exceptions import ClientError
from fastapi import APIRouter, Depends, HTTPException, Request

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.policy import require_admin_scope, require_role_value
from app.auth.roles import AdminScope, Role, admin_profile_has_scope, normalize_role
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.models import (
    AddCardReq,
    AddChargeReq,
    BillingCheckoutReq,
    PaymentIncidentEvidenceUploadReq,
    PaymentIncidentSubmitResponseReq,
    StripePaymentMethodOut,
    PayBalanceReq,
    SetAutopayReq,
    SetDefaultReq,
    SetPriorityReq,
    StripeChargeReq,
    StripeRefundReq,
    StripePaymentMethodOut,
    VerifyMicrodepositsReq,
    WalletDepositReq,
    WalletWithdrawReq,
)
from app.services.sessions import require_ui_session
from app.services.alerts import audit_event
from app.services.billing_shared import (
    apply_balance_delta,
    apply_wallet_delta,
    compute_due,
    ddb_del,
    ddb_get,
    ddb_put,
    ddb_query_pk,
    ddb_update,
    ensure_balance_row,
    get_wallet_balance,
    new_ledger_entry,
    settle_or_reverse_ledger,
    user_pk,
    WALLET_SK,
)
from app.services.profile import get_profile
from app.services.purchase_history import mark_completed, mark_reverted, record_billing_transaction
from app.services.billing_dunning import (
    bump_dunning_after_payment_method_update,
    schedule_autopay_disabled_notice,
    schedule_dunning,
)
from app.services.ttl import with_ttl
from app.services.payment_provider_health import is_provider_enabled
from app.services import fraud_detection as fd
from app.services.payment_incident_providers import (
    DEFAULT_PROVIDER_REGISTRY,
    resolve_provider_adapter,
)
from app.services.payment_incident_stripe_adapter import StripePaymentIncidentAdapter
from app.services.payment_incident_paypal_adapter import PayPalPaymentIncidentAdapter
from app.services.payment_incident_ccbill_adapter import CCBillPaymentIncidentAdapter
from app.services.payment_incident_transitions import PaymentIncidentTransitionService, PaymentIncidentTransitionError
from app.services.payment_incidents_domain import PaymentIncidentType
from app.services.payment_incidents_store import DynamoPaymentIncidentRepository
from app.services.payment_incident_ticket_sync import ensure_incident_ticket_link, evaluate_ticket_trigger, sync_ticket_from_incident
from app.services.payment_failure_alerts import dispatch_auto_payment_failure_alert, clear_auto_payment_failure_alerts
from app.services.payment_incident_metrics import (
    record_incident_created,
    record_retry_attempt,
    record_webhook_outcome,
    record_webhook_replay_event,
    set_webhook_replay_cache_entries,
)

router = APIRouter(tags=["billing"])
logger = logging.getLogger(__name__)


def _require_provider_enabled(provider: str) -> None:
    """GAP-0206 / FIN-014: gate the charge path on the admin provider toggle.

    Raises 503 when an operator has explicitly disabled ``provider`` via the
    payment-provider-health admin toggle. Defaults to enabled when no CONFIG
    row exists, so dev/prod behaviour is identical (SECOPS-007).
    """
    if not is_provider_enabled(provider):
        logger.info(
            "payment_provider_disabled_rejected", extra={"provider": provider}
        )
        raise HTTPException(
            status_code=503,
            detail=f"Payment provider '{provider}' is currently disabled. "
            "Please try again later or contact support.",
        )


def _fraud_gate(
    user_id: str,
    amount_cents: int,
    entry_type: str,
    tx_id: str = "",
    req: Optional[Request] = None,
    *,
    enforce_block: bool = True,
) -> None:
    """GAP-0207 / FIN-015: run fraud evaluation + freeze check on the charge path.

    Always runs the synchronous freeze check (a single DDB read). Then runs
    ``evaluate_transaction`` which short-circuits to ``allow`` when fraud
    detection is disabled. A ``block`` action raises 403 (when ``enforce_block``);
    a ``flag`` action is logged and allowed through (review queue).
    """
    if fd.is_frozen(user_id):
        logger.warning("fraud_gate_frozen", extra={"user_id": user_id})
        raise HTTPException(
            status_code=403,
            detail="Account is frozen. Contact support.",
        )

    ip = req.client.host if req is not None and req.client else None
    result = fd.evaluate_transaction(
        user_id=user_id,
        amount_cents=int(amount_cents),
        entry_type=entry_type,
        tx_id=tx_id,
        ip_address=ip,
    )
    action = result.get("action", "allow")
    if action == "block":
        logger.warning(
            "fraud_gate_blocked",
            extra={
                "user_id": user_id,
                "amount_cents": int(amount_cents),
                "triggered_rules": result.get("triggered_rules"),
                "risk_score": result.get("risk_score"),
            },
        )
        if enforce_block:
            raise HTTPException(
                status_code=403,
                detail="Transaction blocked by fraud prevention. Contact support.",
            )
    elif action == "flag":
        logger.info(
            "fraud_gate_flagged",
            extra={
                "user_id": user_id,
                "amount_cents": int(amount_cents),
                "triggered_rules": result.get("triggered_rules"),
                "risk_score": result.get("risk_score"),
            },
        )


_PAYMENT_INCIDENT_WEBHOOK_REPLAY_CACHE: "OrderedDict[str, float]" = OrderedDict()
_PAYMENT_INCIDENT_WEBHOOK_REPLAY_LOCK = threading.Lock()


DEFAULT_PROVIDER_REGISTRY.register(StripePaymentIncidentAdapter())
DEFAULT_PROVIDER_REGISTRY.register(PayPalPaymentIncidentAdapter())
DEFAULT_PROVIDER_REGISTRY.register(CCBillPaymentIncidentAdapter())


require_billing_support_admin = require_admin_scope("billing_support")


_PAYMENT_INCIDENT_WEBHOOK_ERROR_RESPONSES: dict[int, dict[str, Any]] = {
    400: {
        "description": "Webhook verification or payload parsing rejected",
        "content": {
            "application/json": {
                "examples": {
                    "invalid_signature": {
                        "summary": "Invalid signature",
                        "value": {"detail": {"code": "invalid_signature", "message": "bad sig"}},
                    },
                    "invalid_payload": {
                        "summary": "Payload parse failed",
                        "value": {"detail": {"code": "invalid_payload", "message": "webhook payload could not be parsed"}},
                    },
                    "signature_too_large": {
                        "summary": "Signature header exceeds configured limit",
                        "value": {"detail": {"code": "signature_too_large", "message": "webhook signature exceeds configured size limit"}},
                    },
                    "signature_missing": {
                        "summary": "Required signature header is missing",
                        "value": {"detail": {"code": "signature_missing", "message": "webhook signature is required"}},
                    },
                    "verification_error": {
                        "summary": "Verification subsystem error",
                        "value": {"detail": {"code": "verification_error", "message": "webhook verification failed"}},
                    },
                    "too_many_events": {
                        "summary": "Parsed event batch exceeds configured limit",
                        "value": {"detail": {"code": "too_many_events", "message": "webhook contains too many events"}},
                    },
                }
            }
        },
    },
    409: {
        "description": "Replay detected or invalid transition",
        "content": {
            "application/json": {
                "examples": {
                    "replay_detected": {
                        "summary": "Duplicate webhook delivery",
                        "value": {"detail": {"code": "replay_detected", "message": "duplicate webhook delivery rejected"}},
                    },
                    "invalid_transition": {
                        "summary": "Transition conflict",
                        "value": {"detail": {"code": "invalid_transition", "message": "invalid incident transition"}},
                    },
                }
            }
        },
    },
    413: {
        "description": "Webhook payload too large",
        "content": {
            "application/json": {
                "example": {"detail": {"code": "payload_too_large", "message": "webhook payload exceeds configured size limit"}}
            }
        },
    },
    415: {
        "description": "Unsupported webhook content type",
        "content": {
            "application/json": {
                "example": {"detail": {"code": "unsupported_media_type", "message": "webhook content type is not supported"}}
            }
        },
    },
    404: {
        "description": "Incident not found while applying transition",
        "content": {
            "application/json": {
                "example": {"detail": {"code": "missing_incident", "message": "incident not found"}}
            }
        },
    },
}


def _rollout_provider_set(raw: str, *, default_all: bool = False) -> set[str]:
    vals = {p.strip().lower() for p in str(raw or "").split(",") if p.strip()}
    if vals:
        return vals
    if default_all:
        return {"stripe", "paypal", "ccbill"}
    return set()


def _payment_incident_rollout_mode(provider: str) -> str:
    normalized = str(provider or "").strip().lower()
    if not getattr(S, "payment_incidents_rollout_enabled", True):
        return "disabled"
    rollout_providers = _rollout_provider_set(getattr(S, "payment_incidents_rollout_providers", ""), default_all=True)
    if normalized not in rollout_providers:
        return "disabled"
    shadow_all = bool(getattr(S, "payment_incidents_shadow_mode", False))
    shadow_providers = _rollout_provider_set(getattr(S, "payment_incidents_shadow_providers", ""))
    if shadow_all or normalized in shadow_providers:
        return "shadow"
    return "live"


def _audit_shadow_validation(*, provider: str, events: list[Any], req: Request) -> None:
    limit = max(1, int(getattr(S, "payment_incidents_shadow_audit_sample_limit", 25)))
    sample = []
    for event in events[:limit]:
        sample.append(
            {
                "provider_event_id": getattr(event, "provider_event_id", ""),
                "incident_id": getattr(event, "incident_id", ""),
                "incident_type": getattr(event, "incident_type", ""),
                "target_status": getattr(event, "target_status", ""),
            }
        )
    audit_event(
        "payment_incident_rollout_shadow_validated",
        "system",
        req,
        outcome="success",
        provider=provider,
        event_count=len(events),
        sampled_events=sample,
    )


def _payment_incident_webhook_max_body_bytes() -> int:
    raw = int(getattr(S, "payment_incidents_webhook_max_body_bytes", 262144) or 262144)
    return max(1024, raw)


def _payment_incident_webhook_max_signature_bytes() -> int:
    raw = int(getattr(S, "payment_incidents_webhook_max_signature_bytes", 2048) or 2048)
    return max(64, raw)


def _payment_incident_webhook_max_events() -> int:
    raw = int(getattr(S, "payment_incidents_webhook_max_events", 200) or 200)
    return max(1, raw)


def _payment_incident_webhook_allowed_content_types() -> set[str]:
    raw = str(getattr(S, "payment_incidents_webhook_allowed_content_types", "application/json") or "")
    vals = {v.strip().lower() for v in raw.split(",") if v.strip()}
    return vals or {"application/json"}


def _enforce_payment_incident_webhook_content_type(*, provider: str, req: Request) -> None:
    content_type = (req.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
    if not content_type:
        return
    if content_type in _payment_incident_webhook_allowed_content_types():
        return
    record_webhook_outcome(provider=provider, outcome="rejected", reason="unsupported_media_type")
    raise HTTPException(
        status_code=415,
        detail={"code": "unsupported_media_type", "message": "webhook content type is not supported"},
    )


def _enforce_payment_incident_webhook_size_from_headers(*, provider: str, req: Request) -> None:
    max_bytes = _payment_incident_webhook_max_body_bytes()
    header_value = req.headers.get("content-length")
    if not header_value:
        return
    try:
        content_length = int(header_value)
    except (TypeError, ValueError):
        return
    if content_length <= max_bytes:
        return
    record_webhook_outcome(provider=provider, outcome="rejected", reason="payload_too_large")
    raise HTTPException(
        status_code=413,
        detail={"code": "payload_too_large", "message": "webhook payload exceeds configured size limit"},
    )


def _enforce_payment_incident_webhook_size_from_body(*, provider: str, payload: bytes) -> None:
    if len(payload) <= _payment_incident_webhook_max_body_bytes():
        return
    record_webhook_outcome(provider=provider, outcome="rejected", reason="payload_too_large")
    raise HTTPException(
        status_code=413,
        detail={"code": "payload_too_large", "message": "webhook payload exceeds configured size limit"},
    )


def _enforce_payment_incident_webhook_signature_size(*, provider: str, signature: str | None) -> None:
    sig = signature or ""
    if len(sig.encode("utf-8")) <= _payment_incident_webhook_max_signature_bytes():
        return
    record_webhook_outcome(provider=provider, outcome="rejected", reason="signature_too_large")
    raise HTTPException(
        status_code=400,
        detail={"code": "signature_too_large", "message": "webhook signature exceeds configured size limit"},
    )


def _enforce_payment_incident_webhook_signature_present(*, provider: str, signature: str | None) -> None:
    if not bool(getattr(S, "payment_incidents_webhook_require_signature", True)):
        return
    if signature and str(signature).strip():
        return
    record_webhook_outcome(provider=provider, outcome="rejected", reason="signature_missing")
    raise HTTPException(
        status_code=400,
        detail={"code": "signature_missing", "message": "webhook signature is required"},
    )


def _enforce_payment_incident_webhook_event_count(*, provider: str, events: list[Any]) -> None:
    if len(events) <= _payment_incident_webhook_max_events():
        return
    record_webhook_outcome(provider=provider, outcome="rejected", reason="too_many_events")
    raise HTTPException(
        status_code=400,
        detail={"code": "too_many_events", "message": "webhook contains too many events"},
    )


def _verify_payment_incident_webhook(*, provider: str, adapter: Any, signature: str | None, payload: bytes, headers: dict[str, str]) -> Any:
    try:
        return adapter.verify_webhook(signature=signature, body=payload, headers=headers)
    except Exception as exc:
        logger.warning("payment incident webhook verification error", extra={"provider": provider, "error": str(exc)})
        record_webhook_outcome(provider=provider, outcome="rejected", reason="verification_error")
        raise HTTPException(
            status_code=400,
            detail={"code": "verification_error", "message": "webhook verification failed"},
        ) from exc


def _parse_payment_incident_webhook_events(*, provider: str, adapter: Any, payload: bytes, headers: dict[str, str]) -> list[Any]:
    try:
        return adapter.parse_webhook_events(body=payload, headers=headers)
    except Exception as exc:
        logger.warning("payment incident webhook parse error", extra={"provider": provider, "error": str(exc)})
        record_webhook_outcome(provider=provider, outcome="rejected", reason="invalid_payload")
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_payload", "message": "webhook payload could not be parsed"},
        ) from exc


def _payment_incident_webhook_replay_ttl_seconds() -> int:
    return max(0, int(getattr(S, "payment_incidents_webhook_replay_ttl_seconds", 300) or 0))


def _payment_incident_webhook_replay_cache_size() -> int:
    return max(1, int(getattr(S, "payment_incidents_webhook_replay_cache_size", 5000) or 5000))


def _payment_incident_webhook_replay_key(*, provider: str, signature: str | None, payload: bytes) -> str | None:
    ttl_seconds = _payment_incident_webhook_replay_ttl_seconds()
    if ttl_seconds <= 0:
        return None
    sig = (signature or "").strip()
    if not sig:
        return None

    digest = hashlib.sha256()
    digest.update(provider.encode("utf-8"))
    digest.update(b"|")
    digest.update(sig.encode("utf-8"))
    digest.update(b"|")
    digest.update(payload)
    return digest.hexdigest()


def _prune_payment_incident_webhook_replay_cache(*, now: float) -> None:
    while _PAYMENT_INCIDENT_WEBHOOK_REPLAY_CACHE:
        first_key = next(iter(_PAYMENT_INCIDENT_WEBHOOK_REPLAY_CACHE))
        if _PAYMENT_INCIDENT_WEBHOOK_REPLAY_CACHE[first_key] > now:
            break
        _PAYMENT_INCIDENT_WEBHOOK_REPLAY_CACHE.popitem(last=False)


def _reject_payment_incident_webhook_replay(*, provider: str, signature: str | None, payload: bytes) -> str | None:
    cache_key = _payment_incident_webhook_replay_key(provider=provider, signature=signature, payload=payload)
    if not cache_key:
        record_webhook_replay_event(provider=provider, event="skipped")
        return None
    now = time.time()

    with _PAYMENT_INCIDENT_WEBHOOK_REPLAY_LOCK:
        _prune_payment_incident_webhook_replay_cache(now=now)
        set_webhook_replay_cache_entries(entries=len(_PAYMENT_INCIDENT_WEBHOOK_REPLAY_CACHE))

        existing_expiry = _PAYMENT_INCIDENT_WEBHOOK_REPLAY_CACHE.get(cache_key)
        if existing_expiry and existing_expiry > now:
            record_webhook_replay_event(provider=provider, event="rejected")
            record_webhook_outcome(provider=provider, outcome="rejected", reason="replay_detected")
            raise HTTPException(
                status_code=409,
                detail={"code": "replay_detected", "message": "duplicate webhook delivery rejected"},
            )
    record_webhook_replay_event(provider=provider, event="checked")
    return cache_key


def _mark_payment_incident_webhook_replay(*, provider: str, cache_key: str | None) -> None:
    if not cache_key:
        return
    now = time.time()
    expires_at = now + _payment_incident_webhook_replay_ttl_seconds()
    with _PAYMENT_INCIDENT_WEBHOOK_REPLAY_LOCK:
        _prune_payment_incident_webhook_replay_cache(now=now)
        _PAYMENT_INCIDENT_WEBHOOK_REPLAY_CACHE[cache_key] = expires_at
        _PAYMENT_INCIDENT_WEBHOOK_REPLAY_CACHE.move_to_end(cache_key)
        max_size = _payment_incident_webhook_replay_cache_size()
        while len(_PAYMENT_INCIDENT_WEBHOOK_REPLAY_CACHE) > max_size:
            _PAYMENT_INCIDENT_WEBHOOK_REPLAY_CACHE.popitem(last=False)
        set_webhook_replay_cache_entries(entries=len(_PAYMENT_INCIDENT_WEBHOOK_REPLAY_CACHE))
    record_webhook_replay_event(provider=provider, event="marked")


async def require_billing_admin_operator(user: AuthenticatedUser = Depends(get_authenticated_user), request: Request = None) -> AuthenticatedUser:
    if bool(getattr(S, "admin_scope_enforce_billing_support", True)):
        return await require_billing_support_admin(request=request, user=user)
    require_role_value(normalize_role(user.role).value, {Role.ADMIN, Role.ROOT})
    return user


def _resolve_actor_from_context(ctx: Dict[str, Any], actor: AuthenticatedUser | Any) -> AuthenticatedUser:
    if isinstance(actor, AuthenticatedUser):
        return actor
    role = normalize_role((ctx or {}).get("role"))
    return AuthenticatedUser(sub=str((ctx or {}).get("user_sub") or ""), role=role)


def _require_billing_support_actor(actor: AuthenticatedUser) -> None:
    if not bool(getattr(S, "admin_scope_enforce_billing_support", True)):
        require_role_value(normalize_role(actor.role).value, {Role.ADMIN, Role.ROOT})
        return
    role = normalize_role(actor.role)
    if role is Role.ROOT:
        return
    if role is Role.ADMIN:
        if admin_profile_has_scope(actor.admin_profile, AdminScope.BILLING_SUPPORT):
            return
        raise HTTPException(
            status_code=403,
            detail={
                "code": "role_required_scope",
                "required_scope": AdminScope.BILLING_SUPPORT.value,
                "actual_role": role.value,
                "actual_admin_profile": actor.admin_profile.to_dict(),
            },
        )
    require_role_value(role.value, {Role.ADMIN, Role.ROOT})


def _billing_read_user_sub(ctx: Dict[str, Any], target_user_sub: Optional[str], actor: AuthenticatedUser | Any = None) -> str:
    requested = (target_user_sub or "").strip()
    resolved_actor = _resolve_actor_from_context(ctx, actor)
    if requested and requested != ctx["user_sub"]:
        _require_billing_support_actor(resolved_actor)
        return requested
    return ctx["user_sub"]


def _billing_write_user_context(ctx: Dict[str, Any], target_user_sub: Optional[str], actor: AuthenticatedUser | Any = None) -> tuple[str, Dict[str, Any]]:
    requested = (target_user_sub or "").strip()
    resolved_actor = _resolve_actor_from_context(ctx, actor)
    actor_sub = str(ctx.get("actor_sub") or resolved_actor.sub or ctx["user_sub"])
    effective_sub = ctx["user_sub"]
    tags: Dict[str, Any] = {}
    if requested and requested != ctx["user_sub"]:
        _require_billing_support_actor(resolved_actor)
        effective_sub = requested
        tags = {
            "viewed_as_admin": True,
            "viewed-as-admin": True,
            "actor_sub": actor_sub,
            "effective_sub": effective_sub,
        }
    return effective_sub, tags


def _incident_owned_by_user(incident: Dict[str, Any], user_sub: str) -> bool:
    account_id = str(incident.get("account_id") or "")
    customer_id = str(incident.get("customer_id") or "")
    return account_id == user_sub or customer_id == user_sub


def _resolve_customer_issue_or_404(repo: DynamoPaymentIncidentRepository, *, incident_id: str, user_sub: str) -> Dict[str, Any]:
    incident = repo.get_incident(incident_id)
    if not incident or not _incident_owned_by_user(incident, user_sub):
        raise HTTPException(status_code=404, detail={"code": "payment_issue_not_found", "message": "payment issue not found"})
    return incident


def dual_route(methods: str | Iterable[str], path: str, **kwargs: Any) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    if isinstance(methods, str):
        methods = [methods]
    else:
        methods = list(methods)

    def decorator(func):
        router.add_api_route(f"/api{path}", func, methods=methods, **kwargs)
        router.add_api_route(f"/ui{path}", func, methods=methods, **kwargs)
        return func

    return decorator


def ensure_stripe_configured() -> None:
    if not stripe:
        raise HTTPException(501, "Stripe SDK not installed")
    if not S.stripe_secret_key:
        raise HTTPException(501, "Stripe is not configured")
    stripe.api_key = S.stripe_secret_key
    if S.stripe_api_base:
        stripe.api_base = S.stripe_api_base


def build_return_url(req: Request, fallback_query: str) -> str:
    if fallback_query.startswith("/"):
        return urljoin(str(req.base_url), fallback_query.lstrip("/"))
    return urljoin(str(req.base_url), fallback_query)


def get_or_create_customer(user_id: str) -> str:
    pk = user_pk(user_id)
    try:
        profile = get_profile(user_id)
    except Exception:
        profile = {}
    customer_payload = {}
    if profile.get("display_name"):
        customer_payload["name"] = profile["display_name"]
    if profile.get("displayed_email"):
        customer_payload["email"] = profile["displayed_email"]
    prof = ddb_get(T.billing, pk, "PROFILE")
    if prof and prof.get("stripe_customer_id"):
        if customer_payload:
            try:
                stripe.Customer.modify(prof["stripe_customer_id"], **customer_payload)
            except Exception as exc:
                logger.warning(
                    "Stripe customer update failed",
                    extra={"user_id": user_id, "stripe_customer_id": prof.get("stripe_customer_id")},
                    exc_info=exc,
                )
        return prof["stripe_customer_id"]

    cust = stripe.Customer.create(metadata={"app_user_id": user_id}, **customer_payload)
    ddb_put(T.billing, {"pk": pk, "sk": "PROFILE", "stripe_customer_id": cust["id"], "created_at": now_ts()})
    return cust["id"]


def user_id_from_customer(customer_id: str) -> Optional[str]:
    try:
        cust = stripe.Customer.retrieve(customer_id)
        return cust.get("metadata", {}).get("app_user_id")
    except Exception:
        return None


def pay_sk(payment_intent_id: str) -> str:
    return f"PAY#{payment_intent_id}"


def put_payment_record(
    user_id: str,
    pi: Dict[str, Any],
    ledger_sk_value: str,
    payment_method_type: str,
    purchase_txn_id: Optional[str] = None,
) -> None:
    pk = user_pk(user_id)
    item = {
        "pk": pk,
        "sk": pay_sk(pi["id"]),
        "payment_intent_id": pi["id"],
        "status": pi.get("status"),
        "amount_cents": int(pi.get("amount", 0)),
        "currency": pi.get("currency", "usd"),
        "customer_id": pi.get("customer"),
        "payment_method_id": pi.get("payment_method"),
        "payment_method_type": payment_method_type,
        "ledger_sk": ledger_sk_value,
        "created_at": now_ts(),
        "updated_at": now_ts(),
    }
    if purchase_txn_id:
        item["purchase_txn_id"] = purchase_txn_id
    ddb_put(T.billing, item)


def update_payment_status(
    user_id: str,
    pi_id: str,
    status: str,
    charge_id: Optional[str] = None,
    last_error: Optional[Dict[str, Any]] = None,
) -> None:
    pk = user_pk(user_id)
    names = {"#st": "status", "#u": "updated_at"}
    values: Dict[str, Any] = {":st": status, ":u": now_ts()}
    sets = ["#st = :st", "#u = :u"]

    if charge_id is not None:
        names["#ch"] = "charge_id"
        values[":ch"] = charge_id
        sets.append("#ch = :ch")

    if last_error is not None:
        names["#le"] = "last_error"
        values[":le"] = last_error
        sets.append("#le = :le")

    ddb_update(T.billing, pk, pay_sk(pi_id), "SET " + ", ".join(sets), values, names=names)


def _sync_purchase_history_status(
    *,
    user_id: str,
    purchase_txn_id: Optional[str],
    status: str,
    charge_id: Optional[str],
    last_error: Optional[Dict[str, Any]] = None,
) -> None:
    if not purchase_txn_id:
        return
    try:
        if status == "succeeded":
            mark_completed(user_id, purchase_txn_id, charge_id, "Stripe payment succeeded")
        elif status in ("canceled", "payment_failed", "requires_payment_method"):
            reason = last_error.get("message") if last_error else status
            mark_reverted(user_id, purchase_txn_id, reason)
    except HTTPException:
        return


def pm_sk(payment_method_id: str) -> str:
    return f"PM#{payment_method_id}"


def list_payment_methods_ddb(user_id: str) -> List[Dict[str, Any]]:
    items = ddb_query_pk(T.billing, user_pk(user_id))
    return [it for it in items if it["sk"].startswith("PM#")]


def list_payment_records_ddb(user_id: str) -> List[Dict[str, Any]]:
    items = ddb_query_pk(T.billing, user_pk(user_id))
    return [it for it in items if it["sk"].startswith("PAY#")]


def current_default_pm(user_id: str) -> Optional[str]:
    billing = ddb_get(T.billing, user_pk(user_id), "BILLING") or {}
    return billing.get("default_payment_method_id")


def set_default_pm(user_id: str, pm_id: Optional[str]) -> None:
    pk = user_pk(user_id)
    if not ddb_get(T.billing, pk, "BILLING"):
        ddb_put(T.billing, {"pk": pk, "sk": "BILLING", "autopay_enabled": False, "currency": "usd", "default_payment_method_id": pm_id})
    else:
        ddb_update(T.billing, pk, "BILLING", "SET default_payment_method_id = :pm", {":pm": pm_id})


def mark_event_processed(event_id: str) -> bool:
    try:
        ddb_put(
            T.billing,
            with_ttl(
                {"pk": "STRIPE_EVENT", "sk": event_id, "ts": now_ts()},
                ttl_epoch=now_ts() + 60 * 60 * 24 * 7,
            ),
            condition_expression="attribute_not_exists(pk)",
        )
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False
        raise


@dual_route("GET", "/billing/config")
def billing_config() -> Dict[str, str]:
    if not S.stripe_publishable_key:
        raise HTTPException(500, "Missing STRIPE_PUBLISHABLE_KEY")
    return {
        "publishable_key": S.stripe_publishable_key,
        "currency": S.stripe_default_currency,
    }


@dual_route("GET", "/billing/settings")
def get_settings(ctx=Depends(require_ui_session), actor: AuthenticatedUser = Depends(get_authenticated_user), user_sub: Optional[str] = None) -> Dict[str, Any]:
    user_id = _billing_read_user_sub(ctx, user_sub, actor)
    pk = user_pk(user_id)
    settings = ddb_get(T.billing, pk, "BILLING") or {"autopay_enabled": False, "currency": "usd", "default_payment_method_id": None}
    return settings


@dual_route("POST", "/billing/autopay")
def set_autopay(body: SetAutopayReq, req: Request = None, ctx=Depends(require_ui_session), actor: AuthenticatedUser = Depends(get_authenticated_user), user_sub: Optional[str] = None) -> Dict[str, bool]:
    user_id, admin_tags = _billing_write_user_context(ctx, user_sub, actor)
    pk = user_pk(user_id)
    if not ddb_get(T.billing, pk, "BILLING"):
        ddb_put(T.billing, {"pk": pk, "sk": "BILLING", "autopay_enabled": False, "currency": "usd", "default_payment_method_id": None})
    ddb_update(T.billing, pk, "BILLING", "SET autopay_enabled = :e", {":e": bool(body.enabled)})
    audit_event("billing_autopay_set", user_id, req, outcome="success", enabled=bool(body.enabled), **admin_tags)
    if not body.enabled:
        schedule_autopay_disabled_notice(user_id, "stripe")
    return {"ok": True}


@dual_route("GET", "/billing/balance")
def get_balance(ctx=Depends(require_ui_session), actor: AuthenticatedUser = Depends(get_authenticated_user), user_sub: Optional[str] = None) -> Dict[str, Any]:
    user_id = _billing_read_user_sub(ctx, user_sub, actor)
    pk = user_pk(user_id)
    ensure_balance_row(T.billing, pk, S.stripe_default_currency or "usd")
    bal = ddb_get(T.billing, pk, "BALANCE") or {}
    due = compute_due(bal)
    return {
        "currency": bal.get("currency", "usd"),
        "owed_pending_cents": int(bal.get("owed_pending_cents", 0)),
        "owed_settled_cents": int(bal.get("owed_settled_cents", 0)),
        "payments_pending_cents": int(bal.get("payments_pending_cents", 0)),
        "payments_settled_cents": int(bal.get("payments_settled_cents", 0)),
        **due,
        "updated_at": bal.get("updated_at"),
    }


@dual_route("POST", "/billing/setup-intent/card")
def create_card_setup_intent(ctx=Depends(require_ui_session)) -> Dict[str, str]:
    ensure_stripe_configured()
    user_id = ctx["user_sub"]
    customer_id = get_or_create_customer(user_id)
    si = stripe.SetupIntent.create(
        customer=customer_id,
        payment_method_types=["card"],
        usage="off_session",
    )
    return {"client_secret": si["client_secret"]}


@dual_route("POST", "/billing/setup-intent/us-bank")
def create_us_bank_setup_intent(ctx=Depends(require_ui_session)) -> Dict[str, str]:
    ensure_stripe_configured()
    user_id = ctx["user_sub"]
    customer_id = get_or_create_customer(user_id)
    si = stripe.SetupIntent.create(
        customer=customer_id,
        payment_method_types=["us_bank_account"],
        usage="off_session",
    )
    return {"client_secret": si["client_secret"]}


@dual_route("POST", "/billing/payment-methods/card")
def add_card(body: AddCardReq, req: Request = None, ctx=Depends(require_ui_session)) -> Dict[str, Any]:
    ensure_stripe_configured()
    user_id = ctx["user_sub"]
    customer_id = get_or_create_customer(user_id)

    pm_data: Dict[str, Any] = {
        "type": "card",
        "card": {
            "number": body.card_number.replace(" ", "").replace("-", ""),
            "exp_month": body.exp_month,
            "exp_year": body.exp_year,
            "cvc": body.cvc,
        },
    }
    if body.cardholder_name:
        pm_data["billing_details"] = {"name": body.cardholder_name}

    try:
        pm = stripe.PaymentMethod.create(**pm_data)
    except Exception as exc:
        logger.warning("add_card PaymentMethod.create failed", extra={"user_id": user_id}, exc_info=exc)
        raise HTTPException(400, f"Card declined or invalid: {exc}") from exc

    pm_id = pm["id"]

    try:
        stripe.PaymentMethod.attach(pm_id, customer=customer_id)
    except Exception as exc:
        logger.warning("add_card PaymentMethod.attach failed", extra={"user_id": user_id, "pm_id": pm_id}, exc_info=exc)
        raise HTTPException(400, f"Failed to attach card: {exc}") from exc

    pm_type = pm.get("type", "card")
    card = pm.get("card", {}) or {}
    brand = card.get("brand")
    last4 = card.get("last4")
    exp_month = card.get("exp_month")
    exp_year = card.get("exp_year")
    label = f"{brand} ****{last4}" if brand and last4 else None

    pk = user_pk(user_id)
    existing = list_payment_methods_ddb(user_id)
    next_priority = 0 if not existing else (max(int(x.get("priority", 0)) for x in existing) + 1)

    ddb_put(T.billing, {
        "pk": pk,
        "sk": pm_sk(pm_id),
        "payment_method_id": pm_id,
        "provider": "stripe",
        "provider_method_id": pm_id,
        "method_type": pm_type,
        "label": label,
        "brand": brand,
        "last4": last4,
        "exp_month": exp_month,
        "exp_year": exp_year,
        "priority": next_priority,
        "created_at": now_ts(),
    })

    if not current_default_pm(user_id):
        set_default_pm(user_id, pm_id)
        try:
            stripe.Customer.modify(customer_id, invoice_settings={"default_payment_method": pm_id})
        except Exception:
            pass

    bump_dunning_after_payment_method_update(user_id, "stripe")
    audit_event("billing_add_card", user_id, req, outcome="success", payment_method_id=pm_id)
    return {
        "payment_method_id": pm_id,
        "method_type": pm_type,
        "brand": brand,
        "last4": last4,
        "exp_month": exp_month,
        "exp_year": exp_year,
        "label": label,
    }


@dual_route("POST", "/billing/us-bank/verify-microdeposits")
def verify_microdeposits(body: VerifyMicrodepositsReq, ctx=Depends(require_ui_session)) -> Dict[str, str]:
    ensure_stripe_configured()
    if not body.amounts and not body.descriptor_code:
        raise HTTPException(400, "Provide amounts or descriptor_code")
    si = stripe.SetupIntent.verify_microdeposits(
        body.setup_intent_id,
        amounts=body.amounts,
        descriptor_code=body.descriptor_code,
    )
    return {"status": si["status"]}


@dual_route("GET", "/billing/payment-methods", response_model=List[StripePaymentMethodOut])
def list_payment_methods(ctx=Depends(require_ui_session)) -> List[StripePaymentMethodOut]:
    user_id = ctx["user_sub"]
    default_pm = current_default_pm(user_id)
    pms = list_payment_methods_ddb(user_id)

    out: List[StripePaymentMethodOut] = []
    for it in pms:
        out.append(StripePaymentMethodOut(
            payment_method_id=it["payment_method_id"],
            method_type=it.get("method_type", "unknown"),
            label=it.get("label"),
            brand=it.get("brand"),
            last4=it.get("last4"),
            exp_month=it.get("exp_month"),
            exp_year=it.get("exp_year"),
            priority=int(it.get("priority", 0)),
            provider=it.get("provider") or "stripe",
            provider_method_id=it.get("provider_method_id") or it.get("payment_method_id"),
            is_default=it.get("payment_method_id") == default_pm,
        ))
    out.sort(key=lambda x: x.priority)
    return out


@dual_route("POST", "/billing/payment-methods/priority")
def set_priority(body: SetPriorityReq, req: Request = None, ctx=Depends(require_ui_session), actor: AuthenticatedUser = Depends(get_authenticated_user), user_sub: Optional[str] = None) -> Dict[str, bool]:
    user_id, admin_tags = _billing_write_user_context(ctx, user_sub, actor)
    pk = user_pk(user_id)
    sk = pm_sk(body.payment_method_id)
    if not ddb_get(T.billing, pk, sk):
        raise HTTPException(404, "Payment method not found")
    ddb_update(T.billing, pk, sk, "SET priority = :p", {":p": int(body.priority)})
    audit_event("billing_payment_method_priority", user_id, req, outcome="success", payment_method_id=body.payment_method_id, priority=int(body.priority), **admin_tags)
    return {"ok": True}


@dual_route("POST", "/billing/payment-methods/default")
def set_default(body: SetDefaultReq, req: Request = None, ctx=Depends(require_ui_session), actor: AuthenticatedUser = Depends(get_authenticated_user), user_sub: Optional[str] = None) -> Dict[str, bool]:
    ensure_stripe_configured()
    user_id, admin_tags = _billing_write_user_context(ctx, user_sub, actor)
    pk = user_pk(user_id)
    if not ddb_get(T.billing, pk, pm_sk(body.payment_method_id)):
        raise HTTPException(404, "Payment method not found")

    customer_id = get_or_create_customer(user_id)
    set_default_pm(user_id, body.payment_method_id)
    stripe.Customer.modify(customer_id, invoice_settings={"default_payment_method": body.payment_method_id})
    audit_event("billing_payment_method_default", user_id, req, outcome="success", payment_method_id=body.payment_method_id, **admin_tags)
    bump_dunning_after_payment_method_update(user_id, "stripe")
    return {"ok": True}


@dual_route("DELETE", "/billing/payment-methods/{payment_method_id}")
def remove_payment_method(payment_method_id: str, req: Request = None, ctx=Depends(require_ui_session), actor: AuthenticatedUser = Depends(get_authenticated_user), user_sub: Optional[str] = None) -> Dict[str, bool]:
    ensure_stripe_configured()
    user_id, admin_tags = _billing_write_user_context(ctx, user_sub, actor)
    pk = user_pk(user_id)
    sk = pm_sk(payment_method_id)
    if not ddb_get(T.billing, pk, sk):
        raise HTTPException(404, "Payment method not found")

    try:
        stripe.PaymentMethod.detach(payment_method_id)
    except Exception:
        pass

    ddb_del(T.billing, pk, sk)

    if current_default_pm(user_id) == payment_method_id:
        remaining = list_payment_methods_ddb(user_id)
        remaining.sort(key=lambda x: int(x.get("priority", 0)))
        new_default = remaining[0]["payment_method_id"] if remaining else None
        set_default_pm(user_id, new_default)

        customer_id = get_or_create_customer(user_id)
        stripe.Customer.modify(customer_id, invoice_settings={"default_payment_method": new_default})
        audit_event(
            "billing_payment_method_removed",
            user_id,
            req,
            outcome="success",
            payment_method_id=payment_method_id,
            new_default_payment_method_id=new_default,
            **admin_tags,
        )
    else:
        audit_event("billing_payment_method_removed", user_id, req, outcome="success", payment_method_id=payment_method_id, **admin_tags)
    return {"ok": True}


@dual_route("POST", "/billing/pay-balance")
def pay_balance(body: PayBalanceReq, req: Request = None, ctx=Depends(require_ui_session), actor: AuthenticatedUser = Depends(get_authenticated_user), user_sub: Optional[str] = None) -> Dict[str, str]:
    ensure_stripe_configured()
    _require_provider_enabled("stripe")  # GAP-0206
    user_id, admin_tags = _billing_write_user_context(ctx, user_sub, actor)
    pk = user_pk(user_id)

    ensure_balance_row(T.billing, pk, S.stripe_default_currency or "usd")
    bal = ddb_get(T.billing, pk, "BALANCE") or {}
    due = compute_due(bal)["due_settled_cents"]
    if due <= 0:
        return {"status": "no_settled_balance_due"}

    amount = due if body.amount_cents is None else min(int(body.amount_cents), due)
    if amount <= 0:
        return {"status": "no_settled_balance_due"}

    _fraud_gate(user_id, amount, "credit", req=req)  # GAP-0207

    billing = ddb_get(T.billing, pk, "BILLING") or {"currency": "usd", "default_payment_method_id": None}
    default_pm = billing.get("default_payment_method_id")
    if not default_pm:
        raise HTTPException(400, "No default payment method set")

    customer_id = get_or_create_customer(user_id)
    idem = body.idempotency_key or f"paybalance:{user_id}:{amount}:{int(now_ts()/30)}"
    try:
        pi = stripe.PaymentIntent.create(
            amount=amount,
            currency=billing.get("currency", "usd"),
            customer=customer_id,
            payment_method=default_pm,
            off_session=True,
            confirm=True,
            description=f"Pay settled balance for {user_id}",
            metadata={"app_user_id": user_id, "purpose": "pay_balance"},
            idempotency_key=idem,
        )
    except stripe.error.CardError as exc:
        audit_event(
            "billing_pay_balance",
            user_id,
            req,
            outcome="failure",
            amount_cents=amount,
            currency=billing.get("currency", "usd"),
            reason=str(exc),
            **admin_tags,
        )
        return {"status": "failed", "reason": str(exc)}

    pm_type = "unknown"
    try:
        pm_obj = stripe.PaymentMethod.retrieve(default_pm)
        pm_type = pm_obj.get("type", "unknown")
    except Exception:
        pass

    led_sk, led_item = new_ledger_entry(
        key_name="pk",
        key_value=pk,
        entry_type="credit",
        amount_cents=amount,
        state="pending" if pi.get("status") in ("processing", "requires_action") else ("settled" if pi.get("status") == "succeeded" else "pending"),
        reason="payment",
        meta={"idempotency_key": idem},
        extra={"stripe_payment_intent_id": pi["id"], "provider": "stripe"},
    )
    ddb_put(T.billing, led_item)

    if pi.get("status") == "succeeded":
        apply_balance_delta(T.billing, pk, {"payments_settled_cents": amount}, currency=billing.get("currency", "usd"))
        settle_or_reverse_ledger(T.billing, "pk", pk, led_sk, "settled")
    else:
        apply_balance_delta(T.billing, pk, {"payments_pending_cents": amount}, currency=billing.get("currency", "usd"))

    purchase_txn_id = record_billing_transaction(
        user_sub=user_id,
        amount_cents=amount,
        currency=billing.get("currency", "usd"),
        description=f"Pay settled balance for {user_id}",
        status="COMPLETED" if pi.get("status") == "succeeded" else "PENDING",
        external_ref=pi["id"],
        metadata={"purpose": "pay_balance", "payment_intent_id": pi["id"], "ledger_sk": led_sk},
    )

    put_payment_record(user_id, pi, led_sk, payment_method_type=pm_type, purchase_txn_id=purchase_txn_id)
    audit_event(
        "billing_pay_balance",
        user_id,
        req,
        outcome="success",
        amount_cents=amount,
        currency=billing.get("currency", "usd"),
        payment_intent_id=pi.get("id"),
        status=pi.get("status"),
        ledger_sk=led_sk,
        purchase_txn_id=purchase_txn_id,
        **admin_tags,
    )
    return {"status": pi.get("status"), "payment_intent_id": pi["id"]}


@dual_route("POST", "/billing/charge-once")
def charge_once(body: StripeChargeReq, req: Request = None, ctx=Depends(require_ui_session), actor: AuthenticatedUser = Depends(get_authenticated_user), user_sub: Optional[str] = None) -> Dict[str, Any]:
    ensure_stripe_configured()
    _require_provider_enabled("stripe")  # GAP-0206
    user_id, admin_tags = _billing_write_user_context(ctx, user_sub, actor)
    _fraud_gate(user_id, int(body.amount_cents), "credit", req=req)  # GAP-0207
    pk = user_pk(user_id)

    ensure_balance_row(T.billing, pk, S.stripe_default_currency or "usd")
    billing = ddb_get(T.billing, pk, "BILLING") or {"currency": "usd", "default_payment_method_id": None}
    payment_method_id = body.payment_method_id or billing.get("default_payment_method_id")
    if not payment_method_id:
        raise HTTPException(400, "No payment method provided")

    customer_id = get_or_create_customer(user_id)
    idem = body.idempotency_key or f"chargeonce:{user_id}:{body.amount_cents}:{int(now_ts()/30)}"
    description = body.description or f"One-time charge for {user_id}"

    try:
        pi = stripe.PaymentIntent.create(
            amount=int(body.amount_cents),
            currency=billing.get("currency", "usd"),
            customer=customer_id,
            payment_method=payment_method_id,
            off_session=True,
            confirm=True,
            description=description,
            metadata={"app_user_id": user_id, "purpose": "charge_once"},
            idempotency_key=idem,
        )
    except stripe.error.CardError as exc:
        audit_event(
            "billing_charge_once",
            user_id,
            req,
            outcome="failure",
            amount_cents=int(body.amount_cents),
            currency=billing.get("currency", "usd"),
            reason=str(exc),
            **admin_tags,
        )
        return {"status": "failed", "reason": str(exc)}

    pm_type = "unknown"
    try:
        pm_obj = stripe.PaymentMethod.retrieve(payment_method_id)
        pm_type = pm_obj.get("type", "unknown")
    except Exception:
        pass

    state = "pending"
    if pi.get("status") == "succeeded":
        state = "settled"
    elif pi.get("status") not in ("processing", "requires_action"):
        state = "pending"

    led_sk, led_item = new_ledger_entry(
        key_name="pk",
        key_value=pk,
        entry_type="credit",
        amount_cents=int(body.amount_cents),
        state=state,
        reason="charge_once",
        meta={"idempotency_key": idem, "payment_method_id": payment_method_id},
        extra={"stripe_payment_intent_id": pi["id"], "provider": "stripe"},
    )
    ddb_put(T.billing, led_item)

    if pi.get("status") == "succeeded":
        apply_balance_delta(T.billing, pk, {"payments_settled_cents": int(body.amount_cents)}, currency=billing.get("currency", "usd"))
        settle_or_reverse_ledger(T.billing, "pk", pk, led_sk, "settled")
    else:
        apply_balance_delta(T.billing, pk, {"payments_pending_cents": int(body.amount_cents)}, currency=billing.get("currency", "usd"))

    purchase_txn_id = record_billing_transaction(
        user_sub=user_id,
        amount_cents=int(body.amount_cents),
        currency=billing.get("currency", "usd"),
        description=description,
        status="COMPLETED" if pi.get("status") == "succeeded" else "PENDING",
        external_ref=pi["id"],
        metadata={"purpose": "charge_once", "payment_intent_id": pi["id"], "ledger_sk": led_sk},
    )

    put_payment_record(user_id, pi, led_sk, payment_method_type=pm_type, purchase_txn_id=purchase_txn_id)
    audit_event(
        "billing_charge_once",
        user_id,
        req,
        outcome="success",
        amount_cents=int(body.amount_cents),
        currency=billing.get("currency", "usd"),
        payment_intent_id=pi.get("id"),
        status=pi.get("status"),
        ledger_sk=led_sk,
        purchase_txn_id=purchase_txn_id,
        **admin_tags,
    )
    return {"status": pi.get("status"), "payment_intent_id": pi["id"]}


@dual_route("POST", "/billing/refund")
def refund_payment(body: StripeRefundReq, req: Request = None, ctx=Depends(require_ui_session), actor: AuthenticatedUser = Depends(get_authenticated_user), user_sub: Optional[str] = None) -> Dict[str, Any]:
    ensure_stripe_configured()
    user_id, admin_tags = _billing_write_user_context(ctx, user_sub, actor)
    pk = user_pk(user_id)

    pay = ddb_get(T.billing, pk, pay_sk(body.payment_intent_id))
    if not pay:
        raise HTTPException(404, "Payment record not found")

    amount = int(body.amount_cents or pay.get("amount_cents", 0))
    if amount <= 0:
        raise HTTPException(400, "amount_cents must be greater than zero")

    refund = stripe.Refund.create(
        payment_intent=body.payment_intent_id,
        amount=amount,
        reason=body.reason,
    )

    led_sk_value, led_item = new_ledger_entry(
        key_name="pk",
        key_value=pk,
        entry_type="adjustment",
        amount_cents=amount,
        state="settled",
        reason="refund",
        meta={"reason": body.reason},
        extra={"stripe_payment_intent_id": body.payment_intent_id, "stripe_refund_id": refund.get("id"), "provider": "stripe"},
    )
    ddb_put(T.billing, led_item)

    if pay.get("status") in ("processing", "requires_action"):
        apply_balance_delta(T.billing, pk, {"payments_pending_cents": -amount}, currency=pay.get("currency", "usd"))
    else:
        apply_balance_delta(T.billing, pk, {"payments_settled_cents": -amount}, currency=pay.get("currency", "usd"))

    if pay.get("ledger_sk"):
        settle_or_reverse_ledger(T.billing, "pk", pk, pay["ledger_sk"], "reversed")

    update_payment_status(user_id, body.payment_intent_id, "refunded", charge_id=refund.get("charge"))

    purchase_txn_id = pay.get("purchase_txn_id")
    if purchase_txn_id:
        mark_reverted(user_id, purchase_txn_id, body.reason or "refund")

    audit_event(
        "billing_refund",
        user_id,
        req,
        outcome="success",
        provider="stripe",
        payment_intent_id=body.payment_intent_id,
        refund_id=refund.get("id"),
        amount_cents=amount,
        reason=body.reason,
        **admin_tags,
    )
    return {"ok": True, "refund_id": refund.get("id"), "payment_intent_id": body.payment_intent_id}


@dual_route("POST", "/billing/checkout_session")
def create_checkout_session(body: BillingCheckoutReq, req: Request = None, ctx=Depends(require_ui_session), actor: AuthenticatedUser = Depends(get_authenticated_user), user_sub: Optional[str] = None) -> Dict[str, str]:
    ensure_stripe_configured()
    _require_provider_enabled("stripe")  # GAP-0206
    target_user_sub, admin_tags = _billing_write_user_context(ctx, user_sub, actor)
    if body.amount_cents <= 0:
        raise HTTPException(400, "amount_cents must be greater than zero")
    # GAP-0207: redirect/async flow — freeze still blocks, but a fraud "block"
    # is observe-only here since the real charge settles later via webhook.
    _fraud_gate(target_user_sub, int(body.amount_cents), "credit", req=req, enforce_block=False)
    currency = (body.currency or S.stripe_default_currency or "usd").lower()
    description = body.description or "Security Control Panel charge"

    success_url = S.stripe_success_url or build_return_url(req, "?stripe=success")
    cancel_url = S.stripe_cancel_url or build_return_url(req, "?stripe=cancel")

    session = stripe.checkout.Session.create(
        mode="payment",
        success_url=success_url,
        cancel_url=cancel_url,
        client_reference_id=target_user_sub,
        line_items=[
            {
                "quantity": 1,
                "price_data": {
                    "currency": currency,
                    "unit_amount": body.amount_cents,
                    "product_data": {"name": description},
                },
            }
        ],
        metadata={"user_sub": target_user_sub},
    )
    audit_event(
        "billing_checkout_session",
        target_user_sub,
        req,
        outcome="success",
        amount_cents=body.amount_cents,
        currency=currency,
        session_id=session.id,
        **admin_tags,
    )
    return {"session_id": session.id, "url": session.url}


@router.post("/api/stripe/webhook")
async def stripe_webhook(req: Request) -> Dict[str, Any]:
    ensure_stripe_configured()
    if not S.stripe_webhook_secret:
        raise HTTPException(501, "Stripe webhook secret not configured")

    payload = await req.body()
    sig = req.headers.get("stripe-signature")

    try:
        event = stripe.Webhook.construct_event(payload=payload, sig_header=sig, secret=S.stripe_webhook_secret)
    except Exception as exc:
        raise HTTPException(400, f"Webhook error: {exc}") from exc

    if not mark_event_processed(event["id"]):
        return {"received": True, "deduped": True}

    event_type = event["type"]

    if event_type == "setup_intent.succeeded":
        si = event["data"]["object"]
        customer_id = si.get("customer")
        pm_id = si.get("payment_method")
        if not customer_id or not pm_id:
            return {"received": True}

        user_id = user_id_from_customer(customer_id)
        if not user_id:
            return {"received": True}

        try:
            stripe.PaymentMethod.attach(pm_id, customer=customer_id)
        except Exception as exc:
            logger.warning(
                "Stripe payment method attach failed",
                extra={"user_id": user_id, "payment_method_id": pm_id, "customer_id": customer_id},
                exc_info=exc,
            )

        pm = stripe.PaymentMethod.retrieve(pm_id)
        pm_type = pm.get("type", "unknown")

        brand = last4 = None
        exp_month = exp_year = None
        label = None

        if pm_type == "card":
            card = pm.get("card", {}) or {}
            brand = card.get("brand")
            last4 = card.get("last4")
            exp_month = card.get("exp_month")
            exp_year = card.get("exp_year")
            label = f"{brand} ****{last4}"
        elif pm_type == "us_bank_account":
            uba = pm.get("us_bank_account", {}) or {}
            last4 = uba.get("last4")
            bank_name = uba.get("bank_name")
            label = f"{bank_name or 'Bank'} ****{last4}"

        pk = user_pk(user_id)
        existing = list_payment_methods_ddb(user_id)
        next_priority = 0 if not existing else (max(int(x.get("priority", 0)) for x in existing) + 1)

        ddb_put(T.billing, {
            "pk": pk,
            "sk": pm_sk(pm_id),
            "payment_method_id": pm_id,
            "provider": "stripe",
            "provider_method_id": pm_id,
            "method_type": pm_type,
            "label": label,
            "brand": brand,
            "last4": last4,
            "exp_month": exp_month,
            "exp_year": exp_year,
            "priority": next_priority,
            "created_at": now_ts(),
        })
        bump_dunning_after_payment_method_update(user_id, "stripe")

        if not current_default_pm(user_id):
            set_default_pm(user_id, pm_id)
            stripe.Customer.modify(customer_id, invoice_settings={"default_payment_method": pm_id})
            bump_dunning_after_payment_method_update(user_id, "stripe")

    elif event_type.startswith("payment_intent."):
        pi = event["data"]["object"]
        pi_id = pi["id"]
        status = pi.get("status")

        user_id = None
        md = pi.get("metadata", {}) or {}
        if md.get("app_user_id"):
            user_id = md["app_user_id"]
        elif pi.get("customer"):
            user_id = user_id_from_customer(pi["customer"])

        if not user_id:
            return {"received": True}

        pk = user_pk(user_id)
        pay = ddb_get(T.billing, pk, pay_sk(pi_id))
        if not pay:
            return {"received": True}

        amount = int(pay.get("amount_cents", 0))
        led_sk_value = pay.get("ledger_sk")
        purchase_txn_id = pay.get("purchase_txn_id")

        charge_id = None
        try:
            charges = (pi.get("charges") or {}).get("data") or []
            if charges:
                charge_id = charges[0].get("id")
        except Exception:
            pass

        if status == "processing":
            update_payment_status(user_id, pi_id, "processing", charge_id=charge_id)

        elif status == "succeeded":
            update_payment_status(user_id, pi_id, "succeeded", charge_id=charge_id)
            _sync_purchase_history_status(
                user_id=user_id,
                purchase_txn_id=purchase_txn_id,
                status="succeeded",
                charge_id=charge_id,
            )
            if pay.get("status") in ("processing", "requires_action"):
                apply_balance_delta(T.billing, pk, {"payments_pending_cents": -amount, "payments_settled_cents": amount}, currency=pay.get("currency", "usd"))
            if led_sk_value:
                settle_or_reverse_ledger(T.billing, "pk", pk, led_sk_value, "settled")
            audit_event(
                "billing_payment_intent_update",
                user_id,
                None,
                outcome="success",
                payment_intent_id=pi_id,
                status=status,
                charge_id=charge_id,
                amount_cents=amount,
                purchase_txn_id=purchase_txn_id,
            )

        elif status in ("requires_payment_method", "canceled"):
            update_payment_status(user_id, pi_id, status, charge_id=charge_id, last_error=pi.get("last_payment_error"))
            _sync_purchase_history_status(
                user_id=user_id,
                purchase_txn_id=purchase_txn_id,
                status=status,
                charge_id=charge_id,
                last_error=pi.get("last_payment_error"),
            )
            if pay.get("status") in ("processing", "requires_action"):
                apply_balance_delta(T.billing, pk, {"payments_pending_cents": -amount}, currency=pay.get("currency", "usd"))
            elif pay.get("status") == "succeeded":
                apply_balance_delta(T.billing, pk, {"payments_settled_cents": -amount}, currency=pay.get("currency", "usd"))
            if led_sk_value:
                settle_or_reverse_ledger(T.billing, "pk", pk, led_sk_value, "reversed")
            audit_event(
                "billing_payment_intent_update",
                user_id,
                None,
                outcome="failure",
                payment_intent_id=pi_id,
                status=status,
                charge_id=charge_id,
                amount_cents=amount,
                purchase_txn_id=purchase_txn_id,
                reason=(pi.get("last_payment_error") or {}).get("message"),
            )
            schedule_dunning(
                user_id=user_id,
                provider="stripe",
                amount_cents=amount,
                reason=status,
                payment_ref=pi_id,
            )

        elif status == "payment_failed":
            update_payment_status(user_id, pi_id, "payment_failed", charge_id=charge_id, last_error=pi.get("last_payment_error"))
            _sync_purchase_history_status(
                user_id=user_id,
                purchase_txn_id=purchase_txn_id,
                status="payment_failed",
                charge_id=charge_id,
                last_error=pi.get("last_payment_error"),
            )
            if pay.get("status") in ("processing", "requires_action"):
                apply_balance_delta(T.billing, pk, {"payments_pending_cents": -amount}, currency=pay.get("currency", "usd"))
            elif pay.get("status") == "succeeded":
                apply_balance_delta(T.billing, pk, {"payments_settled_cents": -amount}, currency=pay.get("currency", "usd"))
            if led_sk_value:
                settle_or_reverse_ledger(T.billing, "pk", pk, led_sk_value, "reversed")
            audit_event(
                "billing_payment_intent_update",
                user_id,
                None,
                outcome="failure",
                payment_intent_id=pi_id,
                status=status,
                charge_id=charge_id,
                amount_cents=amount,
                purchase_txn_id=purchase_txn_id,
                reason=(pi.get("last_payment_error") or {}).get("message"),
            )
            schedule_dunning(
                user_id=user_id,
                provider="stripe",
                amount_cents=amount,
                reason=status,
                payment_ref=pi_id,
            )

        else:
            update_payment_status(user_id, pi_id, status, charge_id=charge_id)

    elif event_type.startswith("charge.dispute."):
        dispute = event["data"]["object"]
        charge_id = dispute.get("charge")
        amount = int(dispute.get("amount", 0))
        currency = dispute.get("currency", "usd")

        pi_id = None
        user_id = None
        try:
            ch = stripe.Charge.retrieve(charge_id)
            pi_id = ch.get("payment_intent")
            customer_id = ch.get("customer")
            if customer_id:
                user_id = user_id_from_customer(customer_id)
            if not user_id and pi_id:
                pi = stripe.PaymentIntent.retrieve(pi_id)
                user_id = (pi.get("metadata") or {}).get("app_user_id") or user_id
        except Exception:
            pass

        if not user_id:
            return {"received": True}

        pk = user_pk(user_id)
        ensure_balance_row(T.billing, pk, S.stripe_default_currency or "usd")

        if event_type == "charge.dispute.created":
            # GAP-0208 (FIN-015): record the chargeback for fraud-detection risk
            # scoring so the chargeback_threshold auto-flag fires on real Stripe
            # events, not only on manual admin POSTs. A failure here must never
            # cause a non-2xx response (Stripe would retry and double-count).
            try:
                fd.record_chargeback(
                    user_id=user_id,
                    amount_cents=amount,
                    tx_id=pi_id or charge_id or "",
                )
                audit_event(
                    "billing_chargeback_recorded_from_webhook",
                    user_id,
                    None,
                    outcome="info",
                    charge_id=charge_id,
                    payment_intent_id=pi_id,
                    amount_cents=amount,
                    currency=currency,
                    dispute_id=dispute.get("id"),
                )
            except Exception:
                logger.exception(
                    "record_chargeback_failed",
                    extra={"user_id": user_id, "charge_id": charge_id},
                )

        elif event_type == "charge.dispute.funds_withdrawn":
            pay = ddb_get(T.billing, pk, pay_sk(pi_id)) if pi_id else None
            led_sk_value, led_item = new_ledger_entry(
                key_name="pk",
                key_value=pk,
                entry_type="adjustment",
                amount_cents=amount,
                state="settled",
                reason="dispute_funds_withdrawn",
                meta={"currency": currency, "dispute_id": dispute.get("id")},
                extra={"stripe_charge_id": charge_id, "stripe_payment_intent_id": pi_id, "provider": "stripe"},
            )
            ddb_put(T.billing, led_item)
            apply_balance_delta(T.billing, pk, {"owed_settled_cents": amount}, currency=currency)
            if pay and pay.get("ledger_sk"):
                settle_or_reverse_ledger(T.billing, "pk", pk, pay["ledger_sk"], "reversed")
            if pay and pay.get("purchase_txn_id"):
                mark_reverted(user_id, pay["purchase_txn_id"], "chargeback")
            audit_event(
                "billing_dispute_funds_withdrawn",
                user_id,
                None,
                outcome="info",
                charge_id=charge_id,
                payment_intent_id=pi_id,
                amount_cents=amount,
                currency=currency,
                dispute_id=dispute.get("id"),
            )

        elif event_type == "charge.dispute.funds_reinstated":
            led_sk_value, led_item = new_ledger_entry(
                key_name="pk",
                key_value=pk,
                entry_type="adjustment",
                amount_cents=amount,
                state="settled",
                reason="dispute_funds_reinstated",
                meta={"currency": currency, "dispute_id": dispute.get("id")},
                extra={"stripe_charge_id": charge_id, "stripe_payment_intent_id": pi_id, "provider": "stripe"},
            )
            ddb_put(T.billing, led_item)
            apply_balance_delta(T.billing, pk, {"owed_settled_cents": -amount}, currency=currency)
            audit_event(
                "billing_dispute_funds_reinstated",
                user_id,
                None,
                outcome="info",
                charge_id=charge_id,
                payment_intent_id=pi_id,
                amount_cents=amount,
                currency=currency,
                dispute_id=dispute.get("id"),
            )

    return {"received": True}


def _incident_type_from_str(value: str) -> PaymentIncidentType:
    normalized = str(value or "").strip().lower()
    if normalized == "dispute":
        return PaymentIncidentType.DISPUTE
    if normalized == "chargeback":
        return PaymentIncidentType.CHARGEBACK
    if normalized == "payment_failure":
        return PaymentIncidentType.PAYMENT_FAILURE
    raise ValueError(f"unsupported incident_type '{value}'")


@router.post("/api/billing/webhooks/stripe", responses={**_PAYMENT_INCIDENT_WEBHOOK_ERROR_RESPONSES, 501: {"description": "Stripe webhook secret is not configured"}})
async def stripe_payment_incidents_webhook(req: Request) -> Dict[str, Any]:
    ensure_stripe_configured()
    if not S.stripe_webhook_secret:
        raise HTTPException(501, "Stripe webhook secret not configured")

    _enforce_payment_incident_webhook_content_type(provider="stripe", req=req)
    _enforce_payment_incident_webhook_size_from_headers(provider="stripe", req=req)
    payload = await req.body()
    _enforce_payment_incident_webhook_size_from_body(provider="stripe", payload=payload)
    sig = req.headers.get("stripe-signature")
    _enforce_payment_incident_webhook_signature_present(provider="stripe", signature=sig)
    _enforce_payment_incident_webhook_signature_size(provider="stripe", signature=sig)
    headers = dict(req.headers)

    adapter = resolve_provider_adapter("stripe")
    verification = _verify_payment_incident_webhook(
        provider="stripe",
        adapter=adapter,
        signature=sig,
        payload=payload,
        headers=headers,
    )
    if not verification.valid:
        record_webhook_outcome(provider="stripe", outcome="rejected", reason=verification.code)
        raise HTTPException(status_code=400, detail={"code": verification.code, "message": verification.message})

    events = _parse_payment_incident_webhook_events(provider="stripe", adapter=adapter, payload=payload, headers=headers)
    _enforce_payment_incident_webhook_event_count(provider="stripe", events=events)
    if not events:
        record_webhook_outcome(provider="stripe", outcome="ignored", reason="empty_events")
        return {"received": True, "processed": 0, "deduped": 0, "ignored": True}
    rollout_mode = _payment_incident_rollout_mode("stripe")
    if rollout_mode == "disabled":
        record_webhook_outcome(provider="stripe", outcome="ignored", reason="rollout_disabled")
        return {"received": True, "processed": 0, "deduped": 0, "ignored": True, "reason": "rollout_disabled"}
    if rollout_mode == "shadow":
        record_webhook_outcome(provider="stripe", outcome="ignored", reason="shadow_mode")
        _audit_shadow_validation(provider="stripe", events=events, req=req)
        return {"received": True, "processed": 0, "deduped": 0, "ignored": True, "shadow_validated": len(events)}
    replay_cache_key = _reject_payment_incident_webhook_replay(provider="stripe", signature=sig, payload=payload)

    repo = DynamoPaymentIncidentRepository()
    transition_service = PaymentIncidentTransitionService(repository=repo)

    processed = 0
    deduped = 0

    for event in events:
        if not event.incident_id:
            continue

        existing = repo.list_incidents_by_case(provider="stripe", case_id=event.incident_id, limit=1)
        if existing:
            incident = existing[0]
        else:
            incident = repo.put_incident(
                {
                    "incident_id": f"pinc_{uuid.uuid4().hex[:20]}",
                    "provider": "stripe",
                    "provider_incident_id": event.incident_id,
                    "incident_type": event.incident_type,
                    "payment_reference": event.payload.get("payment_reference") or event.incident_id,
                    "account_id": event.payload.get("account_id", "unknown"),
                    "customer_id": event.payload.get("customer_id", "unknown"),
                    "subscription_id": event.payload.get("subscription_id"),
                    "order_id": event.payload.get("order_id"),
                    "amount": event.payload.get("amount", "0"),
                    "currency": event.payload.get("currency", "usd"),
                    "status": event.target_status,
                    "requires_customer_action": bool(event.payload.get("requires_customer_action", False)),
                    "customer_action_type": event.payload.get("customer_action_type"),
                    "response_due_at": event.payload.get("response_due_at"),
                    "raw_payload_ref": f"stripe_event:{event.provider_event_id}",
                }
            )
            record_incident_created(incident=incident)

        try:
            result = transition_service.apply_provider_transition(
                incident_id=incident["incident_id"],
                incident_type=_incident_type_from_str(event.incident_type),
                target_status=event.target_status,
                provider="stripe",
                provider_event_id=event.provider_event_id,
                source_event_type=event.payload.get("source_event_type", "stripe.webhook"),
                payload=event.payload,
            )
        except PaymentIncidentTransitionError as exc:
            record_webhook_outcome(provider="stripe", outcome="failed", reason=exc.code)
            if exc.code == "invalid_transition":
                raise HTTPException(status_code=409, detail={"code": exc.code, "message": exc.message}) from exc
            raise HTTPException(status_code=404, detail={"code": exc.code, "message": exc.message}) from exc

        if result.duplicate:
            deduped += 1
            record_webhook_outcome(provider="stripe", outcome="deduped", reason="idempotency")
        else:
            processed += 1
            record_webhook_outcome(provider="stripe", outcome="processed", reason="ok")
            trigger = evaluate_ticket_trigger(result.incident)
            if trigger:
                ensure_incident_ticket_link(repo, incident=result.incident, trigger=trigger)
            sync_ticket_from_incident(repo, incident=result.incident)
            dispatch_auto_payment_failure_alert(repo, incident=result.incident)
            clear_auto_payment_failure_alerts(repo, incident=result.incident)

    if processed > 0 or deduped > 0:
        _mark_payment_incident_webhook_replay(provider="stripe", cache_key=replay_cache_key)
    return {"received": True, "processed": processed, "deduped": deduped}


@router.post("/api/billing/webhooks/paypal", responses=_PAYMENT_INCIDENT_WEBHOOK_ERROR_RESPONSES)
async def paypal_payment_incidents_webhook(req: Request) -> Dict[str, Any]:
    _enforce_payment_incident_webhook_content_type(provider="paypal", req=req)
    _enforce_payment_incident_webhook_size_from_headers(provider="paypal", req=req)
    payload = await req.body()
    _enforce_payment_incident_webhook_size_from_body(provider="paypal", payload=payload)
    sig = req.headers.get("paypal-transmission-sig")
    _enforce_payment_incident_webhook_signature_present(provider="paypal", signature=sig)
    _enforce_payment_incident_webhook_signature_size(provider="paypal", signature=sig)
    headers = dict(req.headers)
    adapter = resolve_provider_adapter("paypal")

    verification = _verify_payment_incident_webhook(
        provider="paypal",
        adapter=adapter,
        signature=sig,
        payload=payload,
        headers=headers,
    )
    if not verification.valid:
        record_webhook_outcome(provider="paypal", outcome="rejected", reason=verification.code)
        raise HTTPException(status_code=400, detail={"code": verification.code, "message": verification.message})

    events = _parse_payment_incident_webhook_events(provider="paypal", adapter=adapter, payload=payload, headers=headers)
    _enforce_payment_incident_webhook_event_count(provider="paypal", events=events)
    if not events:
        record_webhook_outcome(provider="paypal", outcome="ignored", reason="empty_events")
        return {"received": True, "processed": 0, "deduped": 0, "ignored": True}
    rollout_mode = _payment_incident_rollout_mode("paypal")
    if rollout_mode == "disabled":
        record_webhook_outcome(provider="paypal", outcome="ignored", reason="rollout_disabled")
        return {"received": True, "processed": 0, "deduped": 0, "ignored": True, "reason": "rollout_disabled"}
    if rollout_mode == "shadow":
        record_webhook_outcome(provider="paypal", outcome="ignored", reason="shadow_mode")
        _audit_shadow_validation(provider="paypal", events=events, req=req)
        return {"received": True, "processed": 0, "deduped": 0, "ignored": True, "shadow_validated": len(events)}
    replay_cache_key = _reject_payment_incident_webhook_replay(provider="paypal", signature=sig, payload=payload)

    repo = DynamoPaymentIncidentRepository()
    transition_service = PaymentIncidentTransitionService(repository=repo)

    processed = 0
    deduped = 0

    for event in events:
        if not event.incident_id:
            continue

        existing = repo.list_incidents_by_case(provider="paypal", case_id=event.incident_id, limit=1)
        if existing:
            incident = existing[0]
        else:
            incident = repo.put_incident(
                {
                    "incident_id": f"pinc_{uuid.uuid4().hex[:20]}",
                    "provider": "paypal",
                    "provider_incident_id": event.incident_id,
                    "incident_type": event.incident_type,
                    "payment_reference": event.payload.get("payment_reference") or event.incident_id,
                    "account_id": event.payload.get("account_id", "unknown"),
                    "customer_id": event.payload.get("customer_id", "unknown"),
                    "subscription_id": event.payload.get("subscription_id"),
                    "order_id": event.payload.get("order_id"),
                    "amount": event.payload.get("amount", "0"),
                    "currency": event.payload.get("currency", "usd"),
                    "status": event.target_status,
                    "requires_customer_action": bool(event.payload.get("requires_customer_action", False)),
                    "customer_action_type": event.payload.get("customer_action_type"),
                    "response_due_at": event.payload.get("response_due_at"),
                    "raw_payload_ref": f"paypal_event:{event.provider_event_id}",
                }
            )
            record_incident_created(incident=incident)

        try:
            result = transition_service.apply_provider_transition(
                incident_id=incident["incident_id"],
                incident_type=_incident_type_from_str(event.incident_type),
                target_status=event.target_status,
                provider="paypal",
                provider_event_id=event.provider_event_id,
                source_event_type=event.payload.get("source_event_type", "paypal.webhook"),
                payload=event.payload,
            )
        except PaymentIncidentTransitionError as exc:
            record_webhook_outcome(provider="paypal", outcome="failed", reason=exc.code)
            if exc.code == "invalid_transition":
                raise HTTPException(status_code=409, detail={"code": exc.code, "message": exc.message}) from exc
            raise HTTPException(status_code=404, detail={"code": exc.code, "message": exc.message}) from exc

        if result.duplicate:
            deduped += 1
            record_webhook_outcome(provider="paypal", outcome="deduped", reason="idempotency")
        else:
            processed += 1
            record_webhook_outcome(provider="paypal", outcome="processed", reason="ok")
            trigger = evaluate_ticket_trigger(result.incident)
            if trigger:
                ensure_incident_ticket_link(repo, incident=result.incident, trigger=trigger)
            sync_ticket_from_incident(repo, incident=result.incident)
            dispatch_auto_payment_failure_alert(repo, incident=result.incident)
            clear_auto_payment_failure_alerts(repo, incident=result.incident)

    if processed > 0 or deduped > 0:
        _mark_payment_incident_webhook_replay(provider="paypal", cache_key=replay_cache_key)
    return {"received": True, "processed": processed, "deduped": deduped}


@router.post("/api/billing/webhooks/ccbill", responses=_PAYMENT_INCIDENT_WEBHOOK_ERROR_RESPONSES)
async def ccbill_payment_incidents_webhook(req: Request) -> Dict[str, Any]:
    _enforce_payment_incident_webhook_content_type(provider="ccbill", req=req)
    _enforce_payment_incident_webhook_size_from_headers(provider="ccbill", req=req)
    payload = await req.body()
    _enforce_payment_incident_webhook_size_from_body(provider="ccbill", payload=payload)
    sig = req.headers.get((S.ccbill_webhook_signature_header or "x-ccbill-signature"))
    _enforce_payment_incident_webhook_signature_present(provider="ccbill", signature=sig)
    _enforce_payment_incident_webhook_signature_size(provider="ccbill", signature=sig)
    headers = dict(req.headers)
    adapter = resolve_provider_adapter("ccbill")

    verification = _verify_payment_incident_webhook(
        provider="ccbill",
        adapter=adapter,
        signature=sig,
        payload=payload,
        headers=headers,
    )
    if not verification.valid:
        record_webhook_outcome(provider="ccbill", outcome="rejected", reason=verification.code)
        raise HTTPException(status_code=400, detail={"code": verification.code, "message": verification.message})

    events = _parse_payment_incident_webhook_events(provider="ccbill", adapter=adapter, payload=payload, headers=headers)
    _enforce_payment_incident_webhook_event_count(provider="ccbill", events=events)
    if not events:
        record_webhook_outcome(provider="ccbill", outcome="ignored", reason="empty_events")
        return {"received": True, "processed": 0, "deduped": 0, "ignored": True}
    rollout_mode = _payment_incident_rollout_mode("ccbill")
    if rollout_mode == "disabled":
        record_webhook_outcome(provider="ccbill", outcome="ignored", reason="rollout_disabled")
        return {"received": True, "processed": 0, "deduped": 0, "ignored": True, "reason": "rollout_disabled"}
    if rollout_mode == "shadow":
        record_webhook_outcome(provider="ccbill", outcome="ignored", reason="shadow_mode")
        _audit_shadow_validation(provider="ccbill", events=events, req=req)
        return {"received": True, "processed": 0, "deduped": 0, "ignored": True, "shadow_validated": len(events)}
    replay_cache_key = _reject_payment_incident_webhook_replay(provider="ccbill", signature=sig, payload=payload)

    repo = DynamoPaymentIncidentRepository()
    transition_service = PaymentIncidentTransitionService(repository=repo)

    processed = 0
    deduped = 0

    for event in events:
        if not event.incident_id:
            continue

        existing = repo.list_incidents_by_case(provider="ccbill", case_id=event.incident_id, limit=1)
        if existing:
            incident = existing[0]
        else:
            incident = repo.put_incident(
                {
                    "incident_id": f"pinc_{uuid.uuid4().hex[:20]}",
                    "provider": "ccbill",
                    "provider_incident_id": event.incident_id,
                    "incident_type": event.incident_type,
                    "payment_reference": event.payload.get("payment_reference") or event.incident_id,
                    "account_id": event.payload.get("account_id", "unknown"),
                    "customer_id": event.payload.get("customer_id", "unknown"),
                    "subscription_id": event.payload.get("subscription_id"),
                    "order_id": event.payload.get("order_id"),
                    "amount": event.payload.get("amount", "0"),
                    "currency": event.payload.get("currency", "usd"),
                    "status": event.target_status,
                    "requires_customer_action": bool(event.payload.get("requires_customer_action", False)),
                    "customer_action_type": event.payload.get("customer_action_type"),
                    "response_due_at": event.payload.get("response_due_at"),
                    "raw_payload_ref": f"ccbill_event:{event.provider_event_id}",
                }
            )
            record_incident_created(incident=incident)

        try:
            result = transition_service.apply_provider_transition(
                incident_id=incident["incident_id"],
                incident_type=_incident_type_from_str(event.incident_type),
                target_status=event.target_status,
                provider="ccbill",
                provider_event_id=event.provider_event_id,
                source_event_type=event.payload.get("source_event_type", "ccbill.webhook"),
                payload=event.payload,
            )
        except PaymentIncidentTransitionError as exc:
            record_webhook_outcome(provider="ccbill", outcome="failed", reason=exc.code)
            if exc.code == "invalid_transition":
                raise HTTPException(status_code=409, detail={"code": exc.code, "message": exc.message}) from exc
            raise HTTPException(status_code=404, detail={"code": exc.code, "message": exc.message}) from exc

        if result.duplicate:
            deduped += 1
            record_webhook_outcome(provider="ccbill", outcome="deduped", reason="idempotency")
        else:
            processed += 1
            record_webhook_outcome(provider="ccbill", outcome="processed", reason="ok")
            trigger = evaluate_ticket_trigger(result.incident)
            if trigger:
                ensure_incident_ticket_link(repo, incident=result.incident, trigger=trigger)
            sync_ticket_from_incident(repo, incident=result.incident)
            dispatch_auto_payment_failure_alert(repo, incident=result.incident)
            clear_auto_payment_failure_alerts(repo, incident=result.incident)

    if processed > 0 or deduped > 0:
        _mark_payment_incident_webhook_replay(provider="ccbill", cache_key=replay_cache_key)
    return {"received": True, "processed": processed, "deduped": deduped}


@router.get("/api/admin/payment-incidents")
def admin_list_payment_incidents(
    provider: Optional[str] = None,
    incident_type: Optional[str] = None,
    status: Optional[str] = None,
    customer_id: Optional[str] = None,
    due_before_ts: Optional[int] = None,
    min_amount: Optional[float] = None,
    max_amount: Optional[float] = None,
    limit: int = 100,
    actor: AuthenticatedUser = Depends(require_billing_admin_operator),
) -> Dict[str, Any]:
    _require_billing_support_actor(actor)
    repo = DynamoPaymentIncidentRepository()
    items = repo.list_incidents(
        provider=provider,
        incident_type=incident_type,
        status=status,
        customer_id=customer_id,
        due_before_ts=due_before_ts,
        min_amount=min_amount,
        max_amount=max_amount,
        limit=max(1, min(limit, 250)),
    )
    return {"items": items, "count": len(items)}


@dual_route("GET", "/billing/payment-issues")
def list_payment_issues(
    ctx=Depends(require_ui_session),
    actor: AuthenticatedUser = Depends(get_authenticated_user),
    user_sub: Optional[str] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    user_id = _billing_read_user_sub(ctx, user_sub, actor)
    repo = DynamoPaymentIncidentRepository()
    issues = repo.list_incidents(incident_type=PaymentIncidentType.PAYMENT_FAILURE.value, limit=max(1, min(limit, 250)))
    owned = [it for it in issues if _incident_owned_by_user(it, user_id)]
    out = []
    for item in owned:
        out.append(
            {
                **item,
                "retry_attempts": repo.list_retry_attempts(incident_id=str(item.get("incident_id")), limit=10),
            }
        )
    return {"items": out, "count": len(out)}


def _run_payment_issue_retry(
    *,
    repo: DynamoPaymentIncidentRepository,
    incident: Dict[str, Any],
    user_sub: str,
    action: str,
    payment_method_id: str | None = None,
    request: Request | None = None,
    audit_name: str = "payment_issue_retry",
    metadata: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    provider = str(incident.get("provider") or "")
    adapter = resolve_provider_adapter(provider)
    attempt_id = str(uuid.uuid4())
    payment_reference = str(incident.get("payment_reference") or incident.get("provider_incident_id") or incident.get("incident_id") or "")
    retry_result = adapter.retry_payment(payment_reference=payment_reference, metadata={"action": action, **(metadata or {})})
    attempt = repo.put_retry_attempt(
        incident_id=str(incident.get("incident_id")),
        attempt_id=attempt_id,
        attempt={
            "action": action,
            "requested_by": user_sub,
            "payment_method_id": payment_method_id,
            "provider": provider,
            "payment_reference": payment_reference,
            "ok": retry_result.ok,
            "code": retry_result.code,
            "message": retry_result.message,
            "payload": retry_result.payload,
        },
    )
    record_retry_attempt(incident=incident, action=action, ok=retry_result.ok, code=retry_result.code)

    if str(incident.get("incident_type") or "") == PaymentIncidentType.PAYMENT_FAILURE.value:
        transition_service = PaymentIncidentTransitionService(repo)
        try:
            if str(incident.get("status") or "") != "retry_pending":
                transition_service.apply_provider_transition(
                    incident_id=str(incident["incident_id"]),
                    incident_type=PaymentIncidentType.PAYMENT_FAILURE,
                    target_status="retry_pending",
                    provider=provider,
                    provider_event_id=f"retry_pending:{attempt_id}",
                    source_event_type=f"customer.{action}",
                    payload={"attempt_id": attempt_id},
                )
            transition_service.apply_provider_transition(
                incident_id=str(incident["incident_id"]),
                incident_type=PaymentIncidentType.PAYMENT_FAILURE,
                target_status="retry_succeeded" if retry_result.ok else "customer_action_required",
                provider=provider,
                provider_event_id=f"retry_result:{attempt_id}",
                source_event_type=f"customer.{action}",
                payload={"attempt_id": attempt_id, "retry_code": retry_result.code},
            )
        except Exception:
            repo.update_incident_status(
                incident_id=str(incident["incident_id"]),
                status="retry_succeeded" if retry_result.ok else "customer_action_required",
                status_reason=retry_result.code,
            )
    updated_incident = repo.get_incident(str(incident.get("incident_id")))
    if updated_incident:
        trigger = evaluate_ticket_trigger(updated_incident)
        if trigger:
            ensure_incident_ticket_link(repo, incident=updated_incident, trigger=trigger)
        sync_ticket_from_incident(repo, incident=updated_incident)
        dispatch_auto_payment_failure_alert(repo, incident=updated_incident)
        clear_auto_payment_failure_alerts(repo, incident=updated_incident)

    audit_event(
        audit_name,
        user_sub,
        request,
        outcome="success" if retry_result.ok else "failure",
        incident_id=incident.get("incident_id"),
        attempt_id=attempt_id,
        action=action,
        provider=provider,
        code=retry_result.code,
        payment_method_id=payment_method_id,
    )
    return {"ok": retry_result.ok, "code": retry_result.code, "message": retry_result.message, "attempt": attempt}


@dual_route("POST", "/billing/payment-issues/{incident_id}/confirm-and-retry")
def confirm_and_retry_payment_issue(
    incident_id: str,
    req: Request = None,
    ctx=Depends(require_ui_session),
    actor: AuthenticatedUser = Depends(get_authenticated_user),
    user_sub: Optional[str] = None,
) -> Dict[str, Any]:
    user_id = _billing_read_user_sub(ctx, user_sub, actor)
    repo = DynamoPaymentIncidentRepository()
    incident = _resolve_customer_issue_or_404(repo, incident_id=incident_id, user_sub=user_id)
    return _run_payment_issue_retry(
        repo=repo,
        incident=incident,
        user_sub=user_id,
        action="confirm_and_retry",
        request=req,
        audit_name="payment_issue_confirm_and_retry",
    )


@dual_route("POST", "/billing/payment-issues/{incident_id}/retry-automatic-payment")
def retry_automatic_payment_issue(
    incident_id: str,
    req: Request = None,
    ctx=Depends(require_ui_session),
    actor: AuthenticatedUser = Depends(get_authenticated_user),
    user_sub: Optional[str] = None,
) -> Dict[str, Any]:
    user_id = _billing_read_user_sub(ctx, user_sub, actor)
    repo = DynamoPaymentIncidentRepository()
    incident = _resolve_customer_issue_or_404(repo, incident_id=incident_id, user_sub=user_id)
    return _run_payment_issue_retry(
        repo=repo,
        incident=incident,
        user_sub=user_id,
        action="retry_automatic_payment",
        request=req,
        audit_name="payment_issue_retry_automatic_payment",
        metadata={"retry_mode": "autopay"},
    )


@dual_route("POST", "/billing/payment-methods/{payment_method_id}/set-default-and-retry")
def set_default_and_retry_payment_issue(
    payment_method_id: str,
    incident_id: str,
    req: Request = None,
    ctx=Depends(require_ui_session),
    actor: AuthenticatedUser = Depends(get_authenticated_user),
    user_sub: Optional[str] = None,
) -> Dict[str, Any]:
    ensure_stripe_configured()
    user_id = _billing_read_user_sub(ctx, user_sub, actor)
    pk = user_pk(user_id)
    if not ddb_get(T.billing, pk, pm_sk(payment_method_id)):
        raise HTTPException(status_code=404, detail={"code": "payment_method_not_found", "message": "payment method not found"})
    set_default_pm(user_id, payment_method_id)
    customer_id = get_or_create_customer(user_id)
    stripe.Customer.modify(customer_id, invoice_settings={"default_payment_method": payment_method_id})
    repo = DynamoPaymentIncidentRepository()
    incident = _resolve_customer_issue_or_404(repo, incident_id=incident_id, user_sub=user_id)
    return _run_payment_issue_retry(
        repo=repo,
        incident=incident,
        user_sub=user_id,
        action="set_default_and_retry",
        payment_method_id=payment_method_id,
        request=req,
        audit_name="payment_issue_set_default_and_retry",
        metadata={"retry_mode": "autopay", "default_payment_method_id": payment_method_id},
    )


@router.get("/api/admin/payment-incidents/{incident_id}")
def admin_get_payment_incident(
    incident_id: str,
    actor: AuthenticatedUser = Depends(require_billing_admin_operator),
) -> Dict[str, Any]:
    _require_billing_support_actor(actor)
    repo = DynamoPaymentIncidentRepository()
    item = repo.get_incident(incident_id)
    if not item:
        raise HTTPException(status_code=404, detail={"code": "payment_incident_not_found", "message": "payment incident not found"})
    return {
        **item,
        "events": repo.list_incident_events(incident_id=incident_id, limit=200),
        "evidence_versions": repo.list_dispute_evidence(incident_id=incident_id, limit=50),
        "ticket_link": repo.get_ticket_link(incident_id=incident_id),
    }


@router.post("/api/admin/payment-incidents/{incident_id}/evidence")
def admin_upload_payment_incident_evidence(
    incident_id: str,
    body: PaymentIncidentEvidenceUploadReq,
    req: Request,
    actor: AuthenticatedUser = Depends(require_billing_admin_operator),
) -> Dict[str, Any]:
    _require_billing_support_actor(actor)
    repo = DynamoPaymentIncidentRepository()
    incident = repo.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail={"code": "payment_incident_not_found", "message": "payment incident not found"})
    if str(incident.get("incident_type") or "") != PaymentIncidentType.DISPUTE.value:
        raise HTTPException(status_code=400, detail={"code": "payment_incident_not_dispute", "message": "incident does not support dispute evidence"})

    existing_versions = repo.list_dispute_evidence(incident_id=incident_id, limit=200)
    max_version = 0
    for row in existing_versions:
        try:
            max_version = max(max_version, int(str(row.get("version") or "0")))
        except Exception:
            continue
    next_version = max_version + 1
    evidence_payload = {
        "summary": body.summary,
        "evidence_items": body.evidence_items,
        "file_refs": body.file_refs,
        "uploaded_by": actor.sub,
    }
    saved = repo.put_dispute_evidence(incident_id=incident_id, version=next_version, evidence=evidence_payload)
    event = repo.append_incident_event(
        incident_id=incident_id,
        event_id=str(uuid.uuid4()),
        event_type="evidence_uploaded",
        payload={"version": next_version, "summary": body.summary, "uploaded_by": actor.sub, "file_ref_count": len(body.file_refs)},
    )
    audit_event(
        "payment_incident_evidence_uploaded",
        actor.sub,
        req,
        outcome="success",
        incident_id=incident_id,
        version=next_version,
        summary=body.summary,
        file_ref_count=len(body.file_refs),
    )
    return {"incident_id": incident_id, "version": next_version, "evidence": saved, "event": event}


@router.post("/api/admin/payment-incidents/{incident_id}/submit-response")
def admin_submit_payment_incident_response(
    incident_id: str,
    body: PaymentIncidentSubmitResponseReq,
    req: Request,
    actor: AuthenticatedUser = Depends(require_billing_admin_operator),
) -> Dict[str, Any]:
    _require_billing_support_actor(actor)
    repo = DynamoPaymentIncidentRepository()
    incident = repo.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail={"code": "payment_incident_not_found", "message": "payment incident not found"})
    if str(incident.get("incident_type") or "") != PaymentIncidentType.DISPUTE.value:
        raise HTTPException(status_code=400, detail={"code": "payment_incident_not_dispute", "message": "incident does not support dispute response"})

    provider = str(incident.get("provider") or "")
    adapter = resolve_provider_adapter(provider)
    evidence_versions = repo.list_dispute_evidence(incident_id=incident_id, limit=50)
    latest_evidence = evidence_versions[0] if evidence_versions else None
    provider_result = adapter.submit_dispute_response(
        provider_incident_id=str(incident.get("provider_incident_id") or incident_id),
        evidence={
            "response_summary": body.response_summary,
            "rationale": body.rationale,
            "evidence_version": latest_evidence.get("version") if latest_evidence else None,
            "evidence_payload": latest_evidence.get("payload") if latest_evidence else {},
        },
    )

    transition_service = PaymentIncidentTransitionService(repo)
    provider_event_id = f"admin_response:{uuid.uuid4()}"
    transition_result = transition_service.apply_provider_transition(
        incident_id=incident_id,
        incident_type=_incident_type_from_str(str(incident.get("incident_type") or "")),
        target_status="response_submitted",
        provider=provider,
        provider_event_id=provider_event_id,
        source_event_type=body.event_type,
        payload={
            "submitted_by": actor.sub,
            "response_summary": body.response_summary,
            "rationale": body.rationale,
            "provider_payload": provider_result.payload,
            "provider_message": provider_result.message,
        },
    )

    response_event = repo.append_incident_event(
        incident_id=incident_id,
        event_id=str(uuid.uuid4()),
        event_type="provider_response_submitted",
        payload={
            "submitted_by": actor.sub,
            "response_summary": body.response_summary,
            "rationale": body.rationale,
            "provider_code": provider_result.code,
        },
    )
    audit_event(
        "payment_incident_response_submitted",
        actor.sub,
        req,
        outcome="success",
        incident_id=incident_id,
        response_summary=body.response_summary,
        rationale=body.rationale,
        provider_code=provider_result.code,
    )
    return {
        "ok": provider_result.ok,
        "incident": transition_result.incident,
        "provider_code": provider_result.code,
        "event": response_event,
    }


@dual_route("POST", "/billing/_dev/add-charge")
def dev_add_charge(body: AddChargeReq, req: Request = None, ctx=Depends(require_ui_session), actor: AuthenticatedUser = Depends(require_billing_admin_operator), user_sub: Optional[str] = None) -> Dict[str, Any]:
    user_id, admin_tags = _billing_write_user_context(ctx, user_sub, actor)
    pk = user_pk(user_id)
    ensure_balance_row(T.billing, pk, S.stripe_default_currency or "usd")

    led_sk_value, led_item = new_ledger_entry(
        key_name="pk",
        key_value=pk,
        entry_type="debit",
        amount_cents=int(body.amount_cents),
        state=body.state,
        reason=body.reason,
    )
    ddb_put(T.billing, led_item)

    if body.state == "pending":
        apply_balance_delta(T.billing, pk, {"owed_pending_cents": int(body.amount_cents)}, currency=S.stripe_default_currency or "usd")
    else:
        apply_balance_delta(T.billing, pk, {"owed_settled_cents": int(body.amount_cents)}, currency=S.stripe_default_currency or "usd")

    audit_event(
        "billing_dev_add_charge",
        user_id,
        req,
        outcome="success",
        amount_cents=int(body.amount_cents),
        state=body.state,
        reason=body.reason,
        ledger_sk=led_sk_value,
        **admin_tags,
    )

    return {"ok": True, "ledger_sk": led_sk_value}


@dual_route("GET", "/billing/ledger")
def list_ledger(ctx=Depends(require_ui_session), actor: AuthenticatedUser = Depends(get_authenticated_user), limit: int = 50, user_sub: Optional[str] = None) -> Dict[str, Any]:
    user_id = _billing_read_user_sub(ctx, user_sub, actor)
    items = ddb_query_pk(T.billing, user_pk(user_id))
    led = [it for it in items if it["sk"].startswith("LEDGER#")]
    led.sort(key=lambda x: x.get("ts", 0), reverse=True)
    return {"items": led[: max(1, min(limit, 200))]}


@dual_route("GET", "/billing/payments")
def list_payments(ctx=Depends(require_ui_session), actor: AuthenticatedUser = Depends(get_authenticated_user), limit: int = 50, user_sub: Optional[str] = None) -> Dict[str, Any]:
    user_id = _billing_read_user_sub(ctx, user_sub, actor)
    pays = list_payment_records_ddb(user_id)
    pays.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    return {"items": pays[: max(1, min(limit, 200))]}


@dual_route("GET", "/billing/subscriptions")
def list_subscriptions(ctx=Depends(require_ui_session), actor: AuthenticatedUser = Depends(get_authenticated_user), limit: int = 50, user_sub: Optional[str] = None) -> Dict[str, Any]:
    if S.dev_mode:
        return {"items": []}
    ensure_stripe_configured()
    user_id = _billing_read_user_sub(ctx, user_sub, actor)
    customer_id = get_or_create_customer(user_id)
    capped_limit = max(1, min(limit, 200))
    resp = stripe.Subscription.list(customer=customer_id, limit=capped_limit)
    if isinstance(resp, dict):
        items = resp.get("data", [])
    else:
        items = getattr(resp, "data", []) or []
    return {"items": items}


# ─── Wallet endpoints ─────────────────────────────────────────────────────────

@dual_route("GET", "/billing/wallet")
def get_wallet_endpoint(ctx=Depends(require_ui_session), actor: AuthenticatedUser = Depends(get_authenticated_user), user_sub: Optional[str] = None) -> Dict[str, Any]:
    user_id = _billing_read_user_sub(ctx, user_sub, actor)
    return get_wallet_balance(T.billing, user_pk(user_id))


@dual_route("POST", "/billing/wallet/deposit")
def wallet_deposit(body: WalletDepositReq, req: Request = None, ctx=Depends(require_ui_session), actor: AuthenticatedUser = Depends(get_authenticated_user), user_sub: Optional[str] = None) -> Dict[str, Any]:
    ensure_stripe_configured()
    _require_provider_enabled("stripe")  # GAP-0206
    user_id, admin_tags = _billing_write_user_context(ctx, user_sub, actor)
    _fraud_gate(user_id, int(body.amount_cents), "credit", req=req)  # GAP-0207
    pk = user_pk(user_id)

    billing = ddb_get(T.billing, pk, "BILLING") or {"currency": "usd", "default_payment_method_id": None}
    payment_method_id = body.payment_method_id or billing.get("default_payment_method_id")
    if not payment_method_id:
        raise HTTPException(400, "No payment method provided")

    currency = billing.get("currency", "usd")
    customer_id = get_or_create_customer(user_id)
    idem = body.idempotency_key or f"wallet_deposit:{user_id}:{body.amount_cents}:{int(now_ts()/30)}"

    try:
        pi = stripe.PaymentIntent.create(
            amount=int(body.amount_cents),
            currency=currency,
            customer=customer_id,
            payment_method=payment_method_id,
            off_session=True,
            confirm=True,
            metadata={"app_user_id": user_id, "purpose": "wallet_deposit"},
            idempotency_key=idem,
        )
    except stripe.error.CardError as exc:
        audit_event("billing_wallet_deposit", user_id, req, outcome="failure", amount_cents=int(body.amount_cents), reason=str(exc), **admin_tags)
        raise HTTPException(402, str(exc))

    state = "settled" if pi.get("status") == "succeeded" else "pending"
    led_sk, led_item = new_ledger_entry(
        key_name="pk",
        key_value=pk,
        entry_type="credit",
        amount_cents=int(body.amount_cents),
        state=state,
        reason="wallet_deposit",
        meta={"idempotency_key": idem, "payment_method_id": payment_method_id},
        extra={"stripe_payment_intent_id": pi["id"], "provider": "stripe"},
    )
    ddb_put(T.billing, led_item)

    wallet_balance_cents = 0
    if pi.get("status") == "succeeded":
        wallet_balance_cents = apply_wallet_delta(T.billing, pk, int(body.amount_cents), currency=currency)
        settle_or_reverse_ledger(T.billing, "pk", pk, led_sk, "settled")
        # FIN-001: generate an invoice for the settled wallet deposit (best-effort)
        try:
            from app.services.invoices import create_invoice_safe
            from app.services.profile import get_profile_identity
            _buyer = get_profile_identity(user_id)
            create_invoice_safe(
                user_sub=user_id,
                invoice_type="deposit",
                amount_cents=int(body.amount_cents),
                line_items=[{"description": "Wallet deposit", "quantity": 1, "amount_cents": int(body.amount_cents)}],
                ledger_entry_id=led_item.get("entry_id", ""),
                seller_name="Platform",
                buyer_name=_buyer.get("display_name") or user_id,
                buyer_email=_buyer.get("email") or "",
                payment_method_summary=str(payment_method_id or ""),
                currency=currency,
            )
        except Exception:
            pass

    audit_event(
        "billing_wallet_deposit",
        user_id,
        req,
        outcome="success",
        amount_cents=int(body.amount_cents),
        currency=currency,
        payment_intent_id=pi.get("id"),
        status=pi.get("status"),
        ledger_sk=led_sk,
        **admin_tags,
    )
    return {"status": pi.get("status"), "payment_intent_id": pi["id"], "wallet_balance_cents": wallet_balance_cents}


@dual_route("POST", "/billing/wallet/withdraw")
def wallet_withdraw(body: WalletWithdrawReq, req: Request = None, ctx=Depends(require_ui_session), actor: AuthenticatedUser = Depends(get_authenticated_user), user_sub: Optional[str] = None) -> Dict[str, Any]:
    user_id, admin_tags = _billing_write_user_context(ctx, user_sub, actor)
    pk = user_pk(user_id)

    try:
        wallet_balance_cents = apply_wallet_delta(T.billing, pk, -int(body.amount_cents))
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise HTTPException(400, "Insufficient wallet balance")
        raise

    led_sk, led_item = new_ledger_entry(
        key_name="pk",
        key_value=pk,
        entry_type="debit",
        amount_cents=int(body.amount_cents),
        state="settled",
        reason="wallet_withdrawal",
        meta={},
    )
    ddb_put(T.billing, led_item)

    audit_event(
        "billing_wallet_withdraw",
        user_id,
        req,
        outcome="success",
        amount_cents=int(body.amount_cents),
        ledger_sk=led_sk,
        **admin_tags,
    )
    return {"ok": True, "wallet_balance_cents": wallet_balance_cents}
