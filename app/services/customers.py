"""CUS-001 + CUS-002: Customer entity store + user-link + message thread."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from botocore.exceptions import ClientError

from app.core.tables import T
from app.core.time import now_ts
from app.core.cursor import encode_cursor, decode_cursor

# ---------------------------------------------------------------------------
# Error classes
# ---------------------------------------------------------------------------

class CustomerNotFoundError(ValueError): ...
class CustomerConflictError(ValueError): ...
class CustomerAttributeValidationError(ValueError): ...
class CustomerLinkConflictError(ValueError):
    def __init__(self, existing_customer_id: str) -> None:
        self.existing_customer_id = existing_customer_id
        super().__init__(f"User already linked to customer {existing_customer_id}")


_VALID_ATTR_TYPES = frozenset({"STRING", "INTEGER", "DOUBLE", "DATE_WITH_DAY"})


# ---------------------------------------------------------------------------
# Helper key builders
# ---------------------------------------------------------------------------

def _cust_pk(customer_id: str) -> str:
    return f"CUST#{customer_id}"


def _link_user_sk(user_sub: str) -> str:
    return f"LINK#USER#{user_sub}"


def _custlink_pk(user_sub: str) -> str:
    return f"CUSTLINK#{user_sub}"


def _attr_sk(name: str) -> str:
    return f"ATTR#{name}"


# ---------------------------------------------------------------------------
# CustomerStore — CUS-001 CRUD + CUS-002 link/resolve
# ---------------------------------------------------------------------------

@dataclass
class CustomerStore:
    _table: Any = field(default=None)

    def __post_init__(self) -> None:
        if self._table is None:
            object.__setattr__(self, "_table", T.customers)

    # ---- CUS-001: core CRUD ------------------------------------------------

    def create_customer(
        self,
        *,
        legal_name: str,
        date_of_birth: str | None = None,
        mobile_phone: str | None = None,
        email: str | None = None,
        branch_id: str | None = None,
        actor_sub: str,
        request=None,
    ) -> dict[str, Any]:
        customer_id = f"cust_{uuid4().hex[:12]}"
        ts = now_ts()
        customer_number = str(ts)
        item: dict[str, Any] = {
            "pk": _cust_pk(customer_id),
            "sk": "META",
            "entity_type": "customer",
            "customer_id": customer_id,
            "customer_number": customer_number,
            "gsi_number_pk": "CUSTNUM",
            "legal_name": legal_name,
            "kyc_status": "none",
            "created_at": ts,
            "updated_at": ts,
            "version": 1,
        }
        if date_of_birth is not None:
            item["date_of_birth"] = date_of_birth
        if mobile_phone is not None:
            item["mobile_phone"] = mobile_phone
        if email is not None:
            item["email"] = email.lower()
        if branch_id is not None:
            item["branch_id"] = branch_id
            item["gsi_branch_pk"] = f"BRANCH#{branch_id}"
        self._table.put_item(Item=item, ConditionExpression="attribute_not_exists(pk)")
        try:
            from app.services.alerts import audit_event
            audit_event("customer.created", actor_sub, request, customer_id=customer_id)
        except Exception:
            pass
        return item

    def get_customer(self, customer_id: str) -> dict[str, Any] | None:
        resp = self._table.get_item(Key={"pk": _cust_pk(customer_id), "sk": "META"})
        return resp.get("Item")

    def get_by_number(self, customer_number: str) -> dict[str, Any] | None:
        resp = self._table.query(
            IndexName="GSI_NUMBER",
            KeyConditionExpression="gsi_number_pk = :pk AND customer_number = :num",
            ExpressionAttributeValues={":pk": "CUSTNUM", ":num": customer_number},
            Limit=1,
        )
        items = resp.get("Items", [])
        return items[0] if items else None

    def list_by_branch(
        self,
        branch_id: str,
        *,
        cursor: str | None = None,
        limit: int = 50,
    ) -> tuple[list[dict[str, Any]], str | None]:
        kwargs: dict[str, Any] = {
            "IndexName": "GSI_BRANCH",
            "KeyConditionExpression": "gsi_branch_pk = :pk",
            "ExpressionAttributeValues": {":pk": f"BRANCH#{branch_id}"},
            "Limit": limit,
            "ScanIndexForward": False,
        }
        start_key = decode_cursor(cursor)
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = self._table.query(**kwargs)
        items = resp.get("Items", [])
        lek = resp.get("LastEvaluatedKey")
        return items, encode_cursor(lek)

    def _list_all(
        self,
        *,
        cursor: str | None = None,
        limit: int = 50,
    ) -> tuple[list[dict[str, Any]], str | None]:
        kwargs: dict[str, Any] = {
            "FilterExpression": "entity_type = :et AND sk = :sk",
            "ExpressionAttributeValues": {":et": "customer", ":sk": "META"},
            "Limit": limit,
        }
        start_key = decode_cursor(cursor)
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = self._table.scan(**kwargs)
        items = resp.get("Items", [])
        lek = resp.get("LastEvaluatedKey")
        return items, encode_cursor(lek)

    def update_customer(
        self,
        *,
        customer_id: str,
        expected_version: int,
        actor_sub: str,
        request=None,
        **fields: Any,
    ) -> dict[str, Any]:
        existing = self.get_customer(customer_id)
        if not existing:
            raise CustomerNotFoundError(customer_id)
        current_version = int(existing.get("version", 1))
        if current_version != int(expected_version):
            raise CustomerConflictError("version_mismatch")

        ts = now_ts()
        set_parts: list[str] = ["updated_at = :updated_at", "version = :new_version"]
        attr_values: dict[str, Any] = {
            ":updated_at": ts,
            ":new_version": current_version + 1,
            ":expected_version": current_version,
        }
        remove_parts: list[str] = []

        field_map = {
            "legal_name": "legal_name",
            "date_of_birth": "date_of_birth",
            "mobile_phone": "mobile_phone",
            "email": "email",
            "branch_id": "branch_id",
            "kyc_status": "kyc_status",
        }
        for key, attr in field_map.items():
            if key in fields and fields[key] is not None:
                val = fields[key]
                if key == "email":
                    val = val.lower()
                set_parts.append(f"{attr} = :{attr}")
                attr_values[f":{attr}"] = val

        # Handle branch_id → gsi_branch_pk
        if "branch_id" in fields:
            new_branch = fields["branch_id"]
            if new_branch is not None:
                set_parts.append("gsi_branch_pk = :gsi_branch_pk")
                attr_values[":gsi_branch_pk"] = f"BRANCH#{new_branch}"
            else:
                remove_parts.append("gsi_branch_pk")

        update_expr = "SET " + ", ".join(set_parts)
        if remove_parts:
            update_expr += " REMOVE " + ", ".join(remove_parts)

        try:
            self._table.update_item(
                Key={"pk": _cust_pk(customer_id), "sk": "META"},
                UpdateExpression=update_expr,
                ConditionExpression="version = :expected_version",
                ExpressionAttributeValues=attr_values,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise CustomerConflictError("concurrent_modification") from exc
            raise

        try:
            from app.services.alerts import audit_event
            audit_event("customer.updated", actor_sub, request, customer_id=customer_id)
        except Exception:
            pass

        result = self.get_customer(customer_id)
        return result  # type: ignore[return-value]

    def set_attribute(
        self,
        customer_id: str,
        *,
        name: str,
        type: str,
        value: str,
        actor_sub: str,
        request=None,
    ) -> dict[str, Any]:
        if type not in _VALID_ATTR_TYPES:
            raise CustomerAttributeValidationError(f"Invalid type: {type!r}")
        existing = self.get_customer(customer_id)
        if not existing:
            raise CustomerNotFoundError(customer_id)
        ts = now_ts()
        # Upsert-by-name: SK = ATTR#{name}
        item: dict[str, Any] = {
            "pk": _cust_pk(customer_id),
            "sk": _attr_sk(name),
            "attribute_id": name,  # deterministic
            "name": name,
            "type": type,
            "value": value,
            "created_at": ts,
        }
        self._table.put_item(Item=item)
        try:
            from app.services.alerts import audit_event
            audit_event("customer.attribute_set", actor_sub, request, customer_id=customer_id, attr_name=name)
        except Exception:
            pass
        return item

    def list_attributes(self, customer_id: str) -> list[dict[str, Any]]:
        resp = self._table.query(
            KeyConditionExpression="pk = :pk AND begins_with(sk, :pfx)",
            ExpressionAttributeValues={":pk": _cust_pk(customer_id), ":pfx": "ATTR#"},
        )
        return resp.get("Items", [])

    def delete_attribute(
        self, customer_id: str, attribute_id: str, *, actor_sub: str, request=None
    ) -> bool:
        self._table.delete_item(Key={"pk": _cust_pk(customer_id), "sk": _attr_sk(attribute_id)})
        try:
            from app.services.alerts import audit_event
            audit_event("customer.attribute_deleted", actor_sub, request, customer_id=customer_id, attribute_id=attribute_id)
        except Exception:
            pass
        return True

    # ---- CUS-002: user link ------------------------------------------------

    def link_user(
        self,
        customer_id: str,
        user_sub: str,
        actor_sub: str,
    ) -> dict[str, Any]:
        ts = now_ts()
        forward_item = {
            "pk": _cust_pk(customer_id),
            "sk": _link_user_sk(user_sub),
            "customer_id": customer_id,
            "user_sub": user_sub,
            "linked_at": ts,
            "linked_by": actor_sub,
            "entity_type": "customer_link",
        }
        reverse_item = {
            "pk": _custlink_pk(user_sub),
            "sk": "META",
            "user_sub": user_sub,
            "customer_id": customer_id,
            "linked_at": ts,
            "entity_type": "customer_reverse_link",
        }
        # Check for existing reverse pointer first (prevents dual-link)
        existing_reverse = self._get_reverse_link(user_sub)
        if existing_reverse:
            existing_cid = existing_reverse.get("customer_id")
            if existing_cid == customer_id:
                # Idempotent - already linked to this customer
                existing_fwd = self.get_link(customer_id, user_sub)
                return existing_fwd or forward_item
            else:
                raise CustomerLinkConflictError(existing_cid)

        # Check if forward link exists
        existing_fwd = self.get_link(customer_id, user_sub)
        if existing_fwd:
            return existing_fwd

        # Write forward link
        try:
            self._table.put_item(
                Item=forward_item,
                ConditionExpression="attribute_not_exists(sk)",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                existing_fwd = self.get_link(customer_id, user_sub)
                return existing_fwd or forward_item
            raise

        # Write reverse pointer
        try:
            self._table.put_item(
                Item=reverse_item,
                ConditionExpression="attribute_not_exists(pk)",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                # Reverse already exists; check if conflict
                existing_reverse = self._get_reverse_link(user_sub)
                if existing_reverse:
                    existing_cid = existing_reverse.get("customer_id")
                    if existing_cid != customer_id:
                        raise CustomerLinkConflictError(existing_cid) from exc
            # Otherwise - another concurrent write got there first, that's ok
            pass

        # Best-effort: back-fill kyc_status from user's latest KYC case
        try:
            customer = self.get_customer(customer_id)
            if customer:
                try:
                    from app.services.kyc_cases import KycCaseStore
                    cases = KycCaseStore().list_cases_by_owner(user_sub=user_sub, limit=1)
                    if cases:
                        self.update_customer(
                            customer_id=customer_id,
                            expected_version=int(customer.get("version", 1)),
                            actor_sub=actor_sub,
                            kyc_status=cases[0].get("status", "none"),
                        )
                except Exception:
                    pass
        except Exception:
            pass

        return forward_item

    def get_link(self, customer_id: str, user_sub: str) -> dict[str, Any] | None:
        resp = self._table.get_item(
            Key={"pk": _cust_pk(customer_id), "sk": _link_user_sk(user_sub)}
        )
        return resp.get("Item")

    def list_links(self, customer_id: str) -> list[dict[str, Any]]:
        resp = self._table.query(
            KeyConditionExpression="pk = :pk AND begins_with(sk, :pfx)",
            ExpressionAttributeValues={":pk": _cust_pk(customer_id), ":pfx": "LINK#USER#"},
        )
        items = resp.get("Items", [])
        items.sort(key=lambda x: int(x.get("linked_at", 0)))
        return items

    def resolve_customer_for_user(self, user_sub: str) -> dict[str, Any] | None:
        return self._get_reverse_link(user_sub)

    def _get_reverse_link(self, user_sub: str) -> dict[str, Any] | None:
        resp = self._table.get_item(Key={"pk": _custlink_pk(user_sub), "sk": "META"})
        return resp.get("Item")


# Module-level singleton
STORE = CustomerStore()
