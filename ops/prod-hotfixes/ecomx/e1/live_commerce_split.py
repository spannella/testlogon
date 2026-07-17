"""Live-stream commerce commission split (LIVECOM L4).

On a STREAM-ATTRIBUTED cart purchase, redistribute the SELLER earnings for each
pinned product between the platform, the host and the seller -- WITHOUT touching
the buyer payment. Reuses the ecom fee model (platform fee) + a _split_revenue-style
type:"credit" ledger. Idempotent per order via a claim marker in LiveStreamProducts.

Money model (per seller product line, gross = the line's pro-rata of the paid total):
    platform_fee = gross * LIVECOM_PLATFORM_FEE_BPS        (platform keeps its fee)
    seller_pool  = gross - platform_fee                    (the seller-earnings pool)
  AFFILIATE (host != seller):
    host_commission = seller_pool * affiliate_commission_bps   (seller-set %)
    seller_net      = seller_pool - host_commission
    invariant: host_commission + seller_net == seller_pool
  OWN (host == seller):
    host keeps the whole seller_pool (no extra split), host_commission = 0
  invariant (both): platform_fee + seller_pool == gross  (== buyer payment share)
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List

from botocore.exceptions import ClientError

from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import new_ledger_entry, user_pk
from app.services import live_stream_products as lsp

logger = logging.getLogger("livecom.split")

# Reuse the ecom platform fee (models.py platform_fee_bps default 1500 = 15%).
LIVECOM_PLATFORM_FEE_BPS = int(os.environ.get("LIVECOM_PLATFORM_FEE_BPS", "1500"))


def _order_pk(order_id: str) -> str:
    return f"ORDER#{order_id}"


def _credit(user_id: str, amount_cents: int, reason: str, meta: Dict[str, Any],
            *, idem_suffix: str = "") -> str:
    """Write a type:'credit' ledger entry (surfaces in earnings/payouts). Returns sk.

    ECOMX-16 (A7/A8): when ``idem_suffix`` is supplied the credit is written with
    a DETERMINISTIC sk (LEDGER#<order>#<suffix>) under an attribute_not_exists
    condition, so a crash-and-replay of settle_stream_order re-drives the same
    credit exactly once (no double-credit). Without a suffix it keeps the legacy
    auto-id behaviour.
    """
    if amount_cents <= 0 or not user_id:
        return ""
    sk, credit_item = new_ledger_entry(
        key_name="pk",
        key_value=user_pk(user_id),
        entry_type="credit",
        amount_cents=int(amount_cents),
        state="settled",
        reason=reason,
        meta=meta,
    )
    if idem_suffix:
        det_sk = f"LEDGER#{idem_suffix}"
        credit_item["sk"] = det_sk
        credit_item["entry_id"] = idem_suffix
        try:
            T.billing.put_item(
                Item=credit_item,
                ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)",
            )
        except ClientError as exc:
            if exc.response["Error"].get("Code") == "ConditionalCheckFailedException":
                return det_sk  # already written by a prior (crashed) attempt
            raise
        return det_sk
    T.billing.put_item(Item=credit_item)
    return sk


def _platform_fee_record(order_id: str, session_id: str, amount_cents: int, meta: Dict[str, Any]) -> None:
    if amount_cents <= 0:
        return
    ts = now_ts()
    # ECOMX-16 (A7): DETERMINISTIC sk (no ts) + attribute_not_exists so a
    # crash-replay of settle_stream_order re-records the platform fee exactly
    # once. content_type distinguishes shop vs livecom fee rows for the same order.
    _ct = str((meta or {}).get("content_type") or "livecom")
    # Deterministic sk keyed on the fields that make a fee row unique for the
    # order: product_id (livecom, per pinned product) OR seller_id (shop, one
    # fee row per seller). Falls back to content_type so a bare call is stable.
    _disc = str((meta or {}).get("product_id") or (meta or {}).get("seller_id") or _ct)
    _sk = f"{_ct.upper()}FEE#{order_id}#{_disc}"
    try:
        T.ad_billing.put_item(
            Item={
                "pk": "PLATFORM#revenue",
                "sk": _sk,
                "entry_type": f"{_ct}_platform_fee",
                "amount_cents": int(amount_cents),
                "state": "settled",
                "reason": "Live-stream commerce platform fee",
                "meta": {**meta, "order_id": order_id, "session_id": session_id},
                "created_at": ts,
            },
            ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)",
        )
    except ClientError as exc:
        if exc.response["Error"].get("Code") == "ConditionalCheckFailedException":
            return  # already recorded by a prior attempt
        logger.warning("livecom_platform_fee_record_failed order=%s", order_id)
    except Exception:
        logger.warning("livecom_platform_fee_record_failed order=%s", order_id)


def settle_stream_order(
    *,
    order_id: str,
    session_id: str,
    host_id: str,
    buyer_sub: str,
    items: List[Dict[str, Any]],
    final_total: int,
    currency: str = "USD",
    cart_id: str = "",
    txn_id: str = "",
) -> Dict[str, Any]:
    """Idempotently settle the commission split for a stream-attributed order.

    Returns the settlement summary. Repeat calls (same order_id) short-circuit on
    the claim marker and return the stored summary WITHOUT writing new credits.
    """
    if not host_id and session_id:
        # Resolve the host from the broadcast session when not passed explicitly.
        try:
            from app.services.broadcast_store import get_session
            host_id = get_session(session_id).created_by
        except Exception:
            host_id = ""
    if not order_id or not session_id or not host_id:
        return {"ok": False, "reason": "missing_attribution"}

    # 1. Idempotency claim (atomic). ECOMX-16 (A7/A8): the replay short-circuit
    #    gates on status=="settled" (the TERMINAL marker written AFTER all
    #    credits), NOT on mere marker existence. A crash between the "settling"
    #    claim and the terminal marker leaves status=="settling"; the replay then
    #    FALLS THROUGH and re-drives the (now-deterministic, attribute_not_exists
    #    guarded) credits so the seller/host are never stranded un-paid.
    ts = now_ts()
    try:
        T.live_stream_products.put_item(
            Item={
                "session_id": _order_pk(order_id),
                "SK": "SETTLEMENT",
                "order_id": order_id,
                "broadcast_session_id": session_id,
                "host_id": host_id,
                "buyer_sub": buyer_sub,
                "status": "settling",
                "created_at": ts,
            },
            ConditionExpression="attribute_not_exists(session_id) AND attribute_not_exists(SK)",
        )
    except ClientError as exc:
        if exc.response["Error"].get("Code") == "ConditionalCheckFailedException":
            existing = T.live_stream_products.get_item(
                Key={"session_id": _order_pk(order_id), "SK": "SETTLEMENT"}
            ).get("Item", {})
            if str(existing.get("status") or "") == "settled":
                logger.info("livecom.settle idempotent no-op (settled) order=%s", order_id)
                return {"ok": True, "idempotent": True, **{k: existing.get(k) for k in
                        ("host_commission_total_cents", "seller_net_total_cents",
                         "platform_fee_total_cents", "pool_total_cents", "gross_total_cents")}}
            # Marker exists but is NOT terminal -> a prior attempt crashed
            # mid-settle. Re-drive the credits (each idempotent) and finalize.
            logger.warning("livecom.settle re-driving un-finalized marker order=%s", order_id)
        else:
            raise

    # 2. Per-item split. Pro-rate each line against the paid total (mirrors the
    #    legacy per-creator seller-credit proration).
    gross_line_sum = sum(int(i.get("line_total_cents", 0) or 0) for i in items) or 0
    lines: List[Dict[str, Any]] = []
    host_commission_total = 0
    seller_net_total = 0
    platform_fee_total = 0
    gross_total = 0
    pool_total = 0

    for it in items:
        product_id = it.get("item_id")
        category_id = it.get("category_id")
        line_total = int(it.get("line_total_cents", 0) or 0)
        if not product_id or line_total <= 0:
            continue
        gross = int(round(line_total * (final_total / gross_line_sum))) if gross_line_sum > 0 else line_total

        pinned = lsp.get_pinned(session_id, product_id)
        if not pinned:
            # Not a pinned stream product -> fall back to normal full seller credit
            # (no fee/commission). Attribution ambiguous; keep the seller whole.
            seller_id = it.get("creator_user_id") or it.get("seller_id") or ""
            if seller_id and seller_id != buyer_sub:
                _credit(seller_id, gross, "Shop sale",
                        {"content_type": "shop", "order_id": order_id, "cart_id": cart_id,
                         "buyer_id": buyer_sub, "purchase_txn_id": txn_id, "product_id": product_id},
                        idem_suffix=f"{order_id}#{product_id}#unpinned")
            gross_total += gross
            lines.append({"product_id": product_id, "unpinned": True, "gross_cents": gross})
            continue

        seller_id = pinned.get("seller_id") or ""
        is_affiliate = bool(pinned.get("is_affiliate"))
        platform_fee = int(round(gross * LIVECOM_PLATFORM_FEE_BPS / 10000))
        seller_pool = gross - platform_fee

        base_meta = {
            "content_type": "livecom", "order_id": order_id, "cart_id": cart_id,
            "broadcast_session_id": session_id, "host_id": host_id,
            "buyer_id": buyer_sub, "purchase_txn_id": txn_id,
            "product_id": product_id, "seller_id": seller_id,
            "is_affiliate": is_affiliate, "gross_cents": gross,
            "platform_fee_cents": platform_fee, "seller_pool_cents": seller_pool,
            "platform_fee_bps": LIVECOM_PLATFORM_FEE_BPS,
        }

        if is_affiliate:
            aff_bps = lsp.get_affiliate_commission_bps(category_id, product_id)
            host_commission = int(round(seller_pool * aff_bps / 10000))
            seller_net = seller_pool - host_commission
            hc_sk = _credit(host_id, host_commission,
                            "Live-stream affiliate commission",
                            {**base_meta, "role": "host_commission", "affiliate_commission_bps": aff_bps},
                            idem_suffix=f"{order_id}#{product_id}#host_commission")
            sn_sk = _credit(seller_id, seller_net,
                            "Live-stream affiliate sale (net)",
                            {**base_meta, "role": "seller_net", "affiliate_commission_bps": aff_bps},
                            idem_suffix=f"{order_id}#{product_id}#seller_net")
            assert host_commission + seller_net == seller_pool, "affiliate split != pool"
            lines.append({**base_meta, "affiliate_commission_bps": aff_bps,
                          "host_commission_cents": host_commission, "seller_net_cents": seller_net,
                          "host_credit_sk": hc_sk, "seller_credit_sk": sn_sk})
            host_commission_total += host_commission
            seller_net_total += seller_net
        else:
            # OWN product: host (== seller) keeps the whole pool, no extra split.
            sn_sk = _credit(seller_id, seller_pool, "Live-stream sale",
                            {**base_meta, "role": "seller_own"},
                            idem_suffix=f"{order_id}#{product_id}#seller_own")
            lines.append({**base_meta, "host_commission_cents": 0,
                          "seller_net_cents": seller_pool, "seller_credit_sk": sn_sk})
            seller_net_total += seller_pool

        _platform_fee_record(order_id, session_id, platform_fee, base_meta)
        platform_fee_total += platform_fee
        gross_total += gross
        pool_total += seller_pool

    summary = {
        "ok": True,
        "order_id": order_id,
        "broadcast_session_id": session_id,
        "host_id": host_id,
        "host_commission_total_cents": host_commission_total,
        "seller_net_total_cents": seller_net_total,
        "platform_fee_total_cents": platform_fee_total,
        "pool_total_cents": pool_total,
        "gross_total_cents": gross_total,
        "lines": lines,
    }
    # 3. Finalize marker (best-effort).
    try:
        T.live_stream_products.update_item(
            Key={"session_id": _order_pk(order_id), "SK": "SETTLEMENT"},
            UpdateExpression=(
                "SET #s = :done, host_commission_total_cents = :h, seller_net_total_cents = :n, "
                "platform_fee_total_cents = :p, pool_total_cents = :pool, gross_total_cents = :g, "
                "settled_at = :t"
            ),
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":done": "settled", ":h": host_commission_total, ":n": seller_net_total,
                ":p": platform_fee_total, ":pool": pool_total, ":g": gross_total, ":t": now_ts(),
            },
        )
    except Exception:
        logger.warning("livecom.settle marker finalize failed order=%s", order_id)
    logger.info("livecom.settle order=%s host_comm=%d seller_net=%d platform=%d pool=%d gross=%d",
                order_id, host_commission_total, seller_net_total, platform_fee_total,
                pool_total, gross_total)
    return summary
