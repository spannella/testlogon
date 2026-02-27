from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from app.core.tables import T
from app.services.alerts import audit_event
from app.services.commercial_line_items import CommercialLineItem, validate_commercial_line_item


class CommerceOrderService:
    def __init__(self) -> None:
        self.orders = T.orders
        self.order_items = T.order_items

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _currency(item: CommercialLineItem) -> str:
        return str(item.pricing_ref.get("currency") or "USD").upper()

    @staticmethod
    def _line_amount_cents(item: CommercialLineItem) -> int:
        qty = int(item.quantity or 1)
        ref = item.pricing_ref or {}
        if ref.get("unit_price_cents") is not None:
            return max(0, int(ref.get("unit_price_cents") or 0)) * qty
        if ref.get("amount_cents") is not None:
            base = max(0, int(ref.get("amount_cents") or 0))
            return base * qty
        if ref.get("price_cents") is not None:
            return max(0, int(ref.get("price_cents") or 0)) * qty
        return 0

    def create_order(
        self,
        *,
        user_id: str,
        source_system: str,
        line_items: Iterable[Dict[str, Any] | CommercialLineItem],
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        parsed: List[CommercialLineItem] = []
        for item in line_items:
            if isinstance(item, CommercialLineItem):
                parsed.append(item)
            else:
                parsed.append(validate_commercial_line_item(dict(item)))
        if not parsed:
            raise ValueError("line_items must not be empty")

        normalized_source = str(source_system or "").strip()
        if normalized_source not in {"shopping_cart", "commercial_direct", "subscription_cycle"}:
            raise ValueError("source_system must be shopping_cart, commercial_direct, or subscription_cycle")
        for item in parsed:
            if item.source_system != normalized_source:
                raise ValueError("line_item.source_system must match order source_system")

        generated_order_id = uuid.uuid4().hex
        now = self._now_iso()
        corr = str(correlation_id or f"{normalized_source}:{generated_order_id}")
        order_id = hashlib.sha256(corr.encode("utf-8")).hexdigest()[:32]

        amount_cents = sum(self._line_amount_cents(it) for it in parsed)
        currency = self._currency(parsed[0])

        order_record = {
            "order_id": order_id,
            "user_id": user_id,
            "status": "pending_payment",
            "created_at": now,
            "updated_at": now,
            "source_system": normalized_source,
            "correlation_id": corr,
            "currency": currency,
            "amount_cents": int(amount_cents),
            "line_item_count": len(parsed),
            "metadata": dict(metadata or {}),
        }
        self.orders.put_item(Item=order_record)

        serialized_items: List[Dict[str, Any]] = []
        for idx, item in enumerate(parsed, start=1):
            row = {
                "order_id": order_id,
                "item_id": str(idx),
                "sku": item.sku,
                "product_type": item.product_type,
                "billing_model": item.billing_model,
                "source_system": item.source_system,
                "quantity": int(item.quantity),
                "scope": dict(item.scope or {}),
                "pricing_ref": dict(item.pricing_ref or {}),
                "amount_cents": self._line_amount_cents(item),
                "created_at": now,
                "correlation_id": corr,
            }
            self.order_items.put_item(Item=row)
            serialized_items.append(row)

        audit_event(
            "commerce_order_created",
            user_id,
            None,
            outcome="success",
            order_id=order_id,
            source_system=normalized_source,
            correlation_id=corr,
            line_item_count=len(parsed),
            amount_cents=int(amount_cents),
            currency=currency,
        )

        return {
            "order_id": order_id,
            "status": "pending_payment",
            "created_at": now,
            "source_system": normalized_source,
            "correlation_id": corr,
            "amount_cents": int(amount_cents),
            "currency": currency,
            "line_items": serialized_items,
            # compatibility outputs
            "checkout_session_id": str((metadata or {}).get("checkout_session_id") or ""),
        }

    def create_order_from_line_items(
        self,
        *,
        user_id: str,
        line_items: Iterable[Dict[str, Any] | CommercialLineItem],
        source_system: str,
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self.create_order(
            user_id=user_id,
            source_system=source_system,
            line_items=line_items,
            correlation_id=correlation_id,
            metadata=metadata,
        )


commerce_order_service = CommerceOrderService()
