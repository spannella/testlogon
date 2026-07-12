"""CUS-003: Cards as a managed resource — status lifecycle + attributes."""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from botocore.exceptions import ClientError

from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import user_pk, ddb_get, ddb_put, ddb_update, ddb_del

# ---------------------------------------------------------------------------
# Transition table + non-chargeable set
# ---------------------------------------------------------------------------

_VALID_TRANSITIONS: frozenset[tuple[str, str]] = frozenset({
    ("ACTIVE",   "INACTIVE"),
    ("ACTIVE",   "FROZEN"),
    ("ACTIVE",   "CANCELLED"),
    ("INACTIVE", "ACTIVE"),
    ("INACTIVE", "FROZEN"),
    ("INACTIVE", "CANCELLED"),
    ("FROZEN",   "ACTIVE"),
    ("FROZEN",   "INACTIVE"),
    ("FROZEN",   "CANCELLED"),
})

_NON_CHARGEABLE = frozenset({"FROZEN", "INACTIVE", "CANCELLED"})


# ---------------------------------------------------------------------------
# Error classes
# ---------------------------------------------------------------------------

class CardConflictError(Exception): ...
class CardIllegalTransitionError(Exception): ...
class CardNotFoundError(Exception): ...


# ---------------------------------------------------------------------------
# CardResourceStore
# ---------------------------------------------------------------------------

@dataclass
class CardResourceStore:
    _table: Any = field(default=None)

    def __post_init__(self) -> None:
        if self._table is None:
            object.__setattr__(self, "_table", T.billing)

    # ---- list / project ----

    def list_cards(self, user_id: str) -> list[dict]:
        try:
            from app.routers.billing import list_payment_methods_ddb, current_default_pm
        except ImportError:
            return []
        default = current_default_pm(user_id)
        pms = list_payment_methods_ddb(user_id)
        return [self._pm_to_card(it, default) for it in pms if it.get("method_type") == "card"]

    @staticmethod
    def _pm_to_card(item: dict, default_pm_id: Optional[str]) -> dict:
        return {
            "card_id":      item["payment_method_id"],
            "brand":        item.get("brand"),
            "last4":        item.get("last4"),
            "exp_month":    item.get("exp_month"),
            "exp_year":     item.get("exp_year"),
            "label":        item.get("label"),
            "is_default":   item.get("payment_method_id") == default_pm_id,
            "card_status":  item.get("card_status", "ACTIVE"),
            "card_version": int(item.get("card_version", 1)),
            "created_at":   item.get("created_at"),
        }

    def get_card(self, user_id: str, card_id: str) -> dict | None:
        item = ddb_get(self._table, user_pk(user_id), f"PM#{card_id}")
        if not item:
            return None
        try:
            from app.routers.billing import current_default_pm
            default = current_default_pm(user_id)
        except ImportError:
            default = None
        return self._pm_to_card(item, default)

    # ---- stamp ----

    def stamp_new_card(self, user_id: str, pm_id: str, *, actor_sub: str, request=None) -> None:
        """Called AFTER billing.add_card writes the PM# row. Adds card_status/version."""
        ddb_update(
            self._table, user_pk(user_id), f"PM#{pm_id}",
            "SET card_status = :s, card_status_at = :t, card_version = :v",
            {":s": "ACTIVE", ":t": now_ts(), ":v": 1},
        )
        try:
            from app.services.alerts import audit_event
            audit_event("card.created", actor_sub, request, outcome="success", card_id=pm_id, user_id=user_id)
        except Exception:
            pass

    # ---- status lifecycle ----

    def set_card_status(
        self,
        user_id: str,
        card_id: str,
        new_status: str,
        *,
        expected_version: int,
        actor_sub: str,
        request=None,
    ) -> dict:
        item = ddb_get(self._table, user_pk(user_id), f"PM#{card_id}")
        if not item:
            raise CardNotFoundError(card_id)

        current_status = item.get("card_status", "ACTIVE")
        current_version = int(item.get("card_version", 1))

        if current_version != int(expected_version):
            raise CardConflictError("card_update_conflict")

        transition = (current_status, new_status)
        if transition not in _VALID_TRANSITIONS:
            raise CardIllegalTransitionError(f"{current_status}->{new_status}")

        next_version = current_version + 1
        ts = now_ts()
        try:
            self._table.update_item(
                Key={"pk": user_pk(user_id), "sk": f"PM#{card_id}"},
                UpdateExpression="SET card_status = :s, card_status_at = :t, card_version = :v",
                ConditionExpression="card_version = :ev",
                ExpressionAttributeValues={
                    ":s": new_status, ":t": ts, ":v": next_version, ":ev": current_version,
                },
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise CardConflictError("card_update_conflict") from exc
            raise

        # If card is non-chargeable and was default, clear default
        if new_status in _NON_CHARGEABLE:
            try:
                from app.routers.billing import current_default_pm, set_default_pm
                if current_default_pm(user_id) == card_id:
                    set_default_pm(user_id, None)
            except ImportError:
                pass

        try:
            from app.services.alerts import audit_event
            audit_event(
                "card.status_changed", actor_sub, request,
                outcome="success", card_id=card_id, user_id=user_id,
                old_status=current_status, new_status=new_status,
            )
        except Exception:
            pass

        return self.get_card(user_id, card_id) or {}

    # ---- attributes ----

    def set_card_attribute(
        self,
        user_id: str,
        card_id: str,
        name: str,
        attr_type: str,
        value: str,
        *,
        actor_sub: str,
        request=None,
    ) -> dict:
        ts = now_ts()
        sk = f"CARDATTR#{card_id}#{name}"
        existing = ddb_get(self._table, user_pk(user_id), sk)
        attr_id = existing["attribute_id"] if existing else uuid.uuid4().hex[:12]
        ddb_put(self._table, {
            "pk": user_pk(user_id),
            "sk": sk,
            "attribute_id": attr_id,
            "card_id": card_id,
            "name": name,
            "type": attr_type,
            "value": str(value),
            "created_at": existing["created_at"] if existing else ts,
            "updated_at": ts,
        })
        try:
            from app.services.alerts import audit_event
            audit_event("card.attribute_set", actor_sub, request, outcome="success", card_id=card_id, attr_name=name)
        except Exception:
            pass
        return {
            "attribute_id": attr_id,
            "name": name,
            "type": attr_type,
            "value": str(value),
            "created_at": existing["created_at"] if existing else ts,
        }

    def list_card_attributes(self, user_id: str, card_id: str) -> list[dict]:
        pk = user_pk(user_id)
        resp = self._table.query(
            KeyConditionExpression="pk = :pk AND begins_with(sk, :pfx)",
            ExpressionAttributeValues={":pk": pk, ":pfx": f"CARDATTR#{card_id}#"},
        )
        return [
            {
                "attribute_id": it["attribute_id"],
                "name": it["name"],
                "type": it["type"],
                "value": it["value"],
                "created_at": it.get("created_at"),
            }
            for it in resp.get("Items", [])
        ]

    def delete_card_attribute(
        self, user_id: str, card_id: str, name: str, *, actor_sub: str, request=None
    ) -> None:
        ddb_del(self._table, user_pk(user_id), f"CARDATTR#{card_id}#{name}")
        try:
            from app.services.alerts import audit_event
            audit_event("card.attribute_deleted", actor_sub, request, outcome="success", card_id=card_id, attr_name=name)
        except Exception:
            pass


CARD_STORE = CardResourceStore()
