"""CUS-004: Financial Products + Product Collections."""
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

class ProductNotFoundError(Exception): ...
class ProductAlreadyExistsError(Exception): ...
class ProductConflictError(Exception): ...
class CollectionNotFoundError(Exception): ...


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------

def _prod_pk(product_code: str) -> str:
    return f"PRODUCT#{product_code}"


def _coll_pk(collection_code: str) -> str:
    return f"COLLECTION#{collection_code}"


# ---------------------------------------------------------------------------
# FinancialProductStore
# ---------------------------------------------------------------------------

@dataclass
class FinancialProductStore:
    _table: Any = field(default=None)

    def __post_init__(self) -> None:
        if self._table is None:
            object.__setattr__(self, "_table", T.financial_products)

    # ---- products ----

    def create_product(
        self,
        *,
        product_code: str,
        name: str,
        parent_product_code: str | None = None,
        category: str | None = None,
        family: str | None = None,
        super_family: str | None = None,
        more_info_url: str | None = None,
        description: str | None = None,
    ) -> dict[str, Any]:
        ts = now_ts()
        item: dict[str, Any] = {
            "PK": _prod_pk(product_code),
            "SK": "META",
            "entity": "product",
            "product_code": product_code,
            "name": name,
            "created_at": ts,
            "updated_at": ts,
            "version": 1,
        }
        if parent_product_code is not None:
            item["parent_product_code"] = parent_product_code
        if category is not None:
            item["category"] = category
            item["gsi_cat_pk"] = f"CATEGORY#{category}"
        if family is not None:
            item["family"] = family
        if super_family is not None:
            item["super_family"] = super_family
        if more_info_url is not None:
            item["more_info_url"] = more_info_url
        if description is not None:
            item["description"] = description

        try:
            self._table.put_item(
                Item=item,
                ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise ProductAlreadyExistsError(product_code) from exc
            raise
        return item

    def get_product(self, product_code: str) -> dict[str, Any]:
        resp = self._table.get_item(Key={"PK": _prod_pk(product_code), "SK": "META"})
        item = resp.get("Item")
        if not item:
            raise ProductNotFoundError(product_code)
        return item

    def update_product(
        self,
        product_code: str,
        *,
        expected_version: int,
        actor_sub: str,
        **fields: Any,
    ) -> dict[str, Any]:
        try:
            existing = self.get_product(product_code)
        except ProductNotFoundError:
            raise

        ts = now_ts()
        set_parts: list[str] = ["updated_at = :updated_at", "#v = :new_version"]
        attr_values: dict[str, Any] = {
            ":updated_at": ts,
            ":new_version": int(expected_version) + 1,
            ":expected_version": int(expected_version),
        }
        attr_names: dict[str, str] = {"#v": "version"}
        remove_parts: list[str] = []

        # DynamoDB reserved keywords must use ExpressionAttributeNames
        reserved = {"name": "#fname", "description": "#fdesc", "family": "#ffamily"}
        field_map = {
            "name": "name",
            "parent_product_code": "parent_product_code",
            "category": "category",
            "family": "family",
            "super_family": "super_family",
            "more_info_url": "more_info_url",
            "description": "description",
        }
        for key, attr in field_map.items():
            if key in fields:
                val = fields[key]
                alias = reserved.get(attr)
                col_expr = alias if alias else attr
                if alias:
                    attr_names[alias] = attr
                if val is not None:
                    set_parts.append(f"{col_expr} = :{attr}")
                    attr_values[f":{attr}"] = val
                else:
                    remove_parts.append(col_expr)

        # GSI_CATEGORY maintenance
        if "category" in fields:
            new_cat = fields["category"]
            if new_cat is not None:
                set_parts.append("gsi_cat_pk = :gsi_cat_pk")
                attr_values[":gsi_cat_pk"] = f"CATEGORY#{new_cat}"
            else:
                remove_parts.append("gsi_cat_pk")

        update_expr = "SET " + ", ".join(set_parts)
        if remove_parts:
            update_expr += " REMOVE " + ", ".join(remove_parts)

        try:
            self._table.update_item(
                Key={"PK": _prod_pk(product_code), "SK": "META"},
                UpdateExpression=update_expr,
                ConditionExpression="#v = :expected_version",
                ExpressionAttributeValues=attr_values,
                ExpressionAttributeNames=attr_names,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise ProductConflictError(f"Stale version for {product_code}") from exc
            raise

        try:
            from app.services.alerts import audit_event
            audit_event("product.updated", actor_sub, None, product_code=product_code)
        except Exception:
            pass

        return self.get_product(product_code)

    def list_products(
        self,
        *,
        category: str | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ) -> tuple[list[dict[str, Any]], str | None]:
        start_key = decode_cursor(cursor)
        if category is not None:
            kwargs: dict[str, Any] = {
                "IndexName": "GSI_CATEGORY",
                "KeyConditionExpression": "gsi_cat_pk = :pk",
                "ExpressionAttributeValues": {":pk": f"CATEGORY#{category}"},
                "Limit": limit,
                "ScanIndexForward": False,
            }
            if start_key:
                kwargs["ExclusiveStartKey"] = start_key
            resp = self._table.query(**kwargs)
        else:
            kwargs = {
                "FilterExpression": "entity = :et AND SK = :sk",
                "ExpressionAttributeValues": {":et": "product", ":sk": "META"},
                "Limit": limit,
            }
            if start_key:
                kwargs["ExclusiveStartKey"] = start_key
            resp = self._table.scan(**kwargs)
        items = resp.get("Items", [])
        lek = resp.get("LastEvaluatedKey")
        return items, encode_cursor(lek)

    def delete_product(self, product_code: str) -> None:
        # Delete META
        self._table.delete_item(Key={"PK": _prod_pk(product_code), "SK": "META"})
        # Delete all ATTR# rows
        try:
            resp = self._table.query(
                KeyConditionExpression="PK = :pk AND begins_with(SK, :pfx)",
                ExpressionAttributeValues={":pk": _prod_pk(product_code), ":pfx": "ATTR#"},
            )
            for item in resp.get("Items", []):
                self._table.delete_item(Key={"PK": item["PK"], "SK": item["SK"]})
        except Exception:
            pass

    # ---- attributes ----

    def set_attribute(
        self,
        product_code: str,
        *,
        name: str,
        type: str,
        value: str,
    ) -> dict[str, Any]:
        ts = now_ts()
        attribute_id = uuid4().hex[:12]
        item: dict[str, Any] = {
            "PK": _prod_pk(product_code),
            "SK": f"ATTR#{attribute_id}",
            "entity": "product_attribute",
            "product_code": product_code,
            "attribute_id": attribute_id,
            "name": name,
            "type": type,
            "value": value,
            "created_at": ts,
        }
        self._table.put_item(Item=item)
        return item

    def list_attributes(self, product_code: str) -> list[dict[str, Any]]:
        resp = self._table.query(
            KeyConditionExpression="PK = :pk AND begins_with(SK, :pfx)",
            ExpressionAttributeValues={":pk": _prod_pk(product_code), ":pfx": "ATTR#"},
        )
        return resp.get("Items", [])

    def delete_attribute(self, product_code: str, attribute_id: str) -> None:
        self._table.delete_item(Key={"PK": _prod_pk(product_code), "SK": f"ATTR#{attribute_id}"})

    # ---- collections ----

    def upsert_collection(
        self,
        collection_code: str,
        *,
        name: str,
        product_codes: list[str],
    ) -> dict[str, Any]:
        ts = now_ts()
        # Dedupe order-preserving
        deduped = list(dict.fromkeys(product_codes))
        item: dict[str, Any] = {
            "PK": _coll_pk(collection_code),
            "SK": "META",
            "entity": "collection",
            "collection_code": collection_code,
            "name": name,
            "product_codes": deduped,
            "updated_at": ts,
        }
        self._table.put_item(Item=item)
        return item

    def get_collection(self, collection_code: str) -> dict[str, Any]:
        resp = self._table.get_item(Key={"PK": _coll_pk(collection_code), "SK": "META"})
        item = resp.get("Item")
        if not item:
            raise CollectionNotFoundError(collection_code)
        return item

    def list_collections(
        self,
        *,
        limit: int = 50,
        cursor: str | None = None,
    ) -> tuple[list[dict[str, Any]], str | None]:
        start_key = decode_cursor(cursor)
        kwargs: dict[str, Any] = {
            "FilterExpression": "entity = :et AND SK = :sk",
            "ExpressionAttributeValues": {":et": "collection", ":sk": "META"},
            "Limit": limit,
        }
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = self._table.scan(**kwargs)
        items = resp.get("Items", [])
        lek = resp.get("LastEvaluatedKey")
        return items, encode_cursor(lek)

    def add_to_collection(self, collection_code: str, product_code: str) -> dict[str, Any]:
        try:
            current = self.get_collection(collection_code)
        except CollectionNotFoundError:
            raise
        codes = list(current.get("product_codes", []))
        if product_code not in codes:
            codes.append(product_code)
        return self.upsert_collection(
            collection_code,
            name=current["name"],
            product_codes=codes,
        )

    def remove_from_collection(self, collection_code: str, product_code: str) -> dict[str, Any]:
        try:
            current = self.get_collection(collection_code)
        except CollectionNotFoundError:
            raise
        codes = [c for c in current.get("product_codes", []) if c != product_code]
        return self.upsert_collection(
            collection_code,
            name=current["name"],
            product_codes=codes,
        )


PRODUCT_STORE = FinancialProductStore()
