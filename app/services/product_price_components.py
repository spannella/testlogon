"""
OFBiz Catalog Depth — Product price components service.
PRD-012: per-product, per-type, date-windowed price rows on T.product_depth.

Public surface:
  set_price_component(item_id, creator_id, body) -> ProductPriceComponentOut
  set_price_components(item_id, price_type, components, creator_id) -> List[...]
  list_price_components(item_id, price_type=None) -> List[ProductPriceComponentOut]
  resolve_effective_price(item_id, as_of, price_type="DEFAULT") -> PriceResolution

This is a READ-ONLY ENRICHMENT layer: never calls new_ledger_entry,
refund_payment, or any payment SDK.  Cart/checkout pricing continues to use
the scalar price_cents from T.catalog unchanged.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, NamedTuple

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.models import PriceTypeEnum, ProductPriceComponentIn, ProductPriceComponentOut, PriceResolution

_ALL_PRICE_TYPES = [e.value for e in PriceTypeEnum]
_FETCH_WINDOW = 20  # rows fetched per GSI page for resolve (filter may discard some)


# ---------------------------------------------------------------------------
# Flag guard
# ---------------------------------------------------------------------------

def _require_enabled() -> None:
    if not getattr(S, "product_depth_enabled", False):
        raise HTTPException(status_code=404, detail="Product depth is not enabled.")
    if not getattr(S, "product_depth_price_components_enabled", True):
        raise HTTPException(status_code=404, detail="Price components are not enabled.")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _make_component_id(item_id: str, price_type: str, effective_at: int) -> str:
    """Deterministic 16-char hex id: sha256(item_id|price_type|effective_at)[:16]."""
    key = f"{item_id}|{price_type}|{effective_at}".encode()
    return hashlib.sha256(key).hexdigest()[:16]


def _row_to_out(row: dict, as_of: Optional[int] = None) -> ProductPriceComponentOut:
    now = as_of if as_of is not None else now_ts()
    eff = int(row["effective_at"])
    exp_raw = row.get("expires_at")
    exp = int(exp_raw) if exp_raw is not None else None
    active = eff <= now and (exp is None or now <= exp)
    return ProductPriceComponentOut(
        price_component_id=row["price_component_id"],
        item_id=row["item_id"],
        price_type=row["price_type"],
        amount_cents=int(row["amount_cents"]),
        currency=row.get("currency", "USD"),
        effective_at=eff,
        expires_at=exp,
        is_active=active,
    )


# ---------------------------------------------------------------------------
# set_price_component — single-row upsert
# ---------------------------------------------------------------------------

def set_price_component(
    item_id: str,
    creator_id: str,
    body: ProductPriceComponentIn,
) -> ProductPriceComponentOut:
    """Upsert a single price-component row.

    Idempotent: (item_id, price_type, effective_at) uniquely identifies the row.
    Calling twice with the same triple updates amount_cents / expires_at / updated_at
    but never creates a second row.

    Does NOT modify T.catalog.  Does NOT write a ledger entry.
    """
    _require_enabled()

    eff = int(body.effective_at)
    pt = body.price_type.value if hasattr(body.price_type, "value") else str(body.price_type)

    if body.expires_at is not None and body.expires_at < eff:
        raise HTTPException(
            status_code=422,
            detail="expires_at must be >= effective_at.",
        )

    pc_id = _make_component_id(item_id, pt, eff)
    now = now_ts()
    row: Dict[str, Any] = {
        "PK": f"ITEM#{item_id}",
        "SK": f"PRICE#{pt}#{eff:010d}",
        "entity": "price_component",
        "price_component_id": pc_id,
        "item_id": item_id,
        "price_type": pt,
        "amount_cents": int(body.amount_cents),
        "currency": body.currency,
        "effective_at": eff,
        "creator_id": creator_id,
        "created_at": now,
        "updated_at": now,
        "GSI_PRICE_PK": f"PRICE#{item_id}#{pt}",
        "GSI_PRICE_SK": eff,
    }
    if body.expires_at is not None:
        row["expires_at"] = int(body.expires_at)

    # Remove None values so DynamoDB doesn't store NULL attributes
    row = {k: v for k, v in row.items() if v is not None}

    T.product_depth.put_item(Item=row)
    return _row_to_out(row)


# ---------------------------------------------------------------------------
# set_price_components — full-replace for one (item_id, price_type)
# ---------------------------------------------------------------------------

def set_price_components(
    item_id: str,
    price_type: str,
    components: List[ProductPriceComponentIn],
    creator_id: str,
) -> List[ProductPriceComponentOut]:
    """Full idempotent replace for all price-component rows of one (item_id, price_type).

    Algorithm:
      1. SK-prefix scan: PK=ITEM#{item_id}, SK begins_with PRICE#{price_type}#.
      2. batch_writer().delete_item for each existing row.
      3. Call set_price_component(item_id, creator_id, comp) for each comp.
      4. Return the list of ProductPriceComponentOut from the writes.
    If components is empty, all existing rows for this type are deleted (clear).
    """
    _require_enabled()

    # 1. Fetch existing rows for this type
    existing_resp = T.product_depth.query(
        KeyConditionExpression=(
            Key("PK").eq(f"ITEM#{item_id}") & Key("SK").begins_with(f"PRICE#{price_type}#")
        ),
    )
    existing_rows = existing_resp.get("Items", [])

    # 2. Delete existing rows
    with T.product_depth.batch_writer() as batch:
        for row in existing_rows:
            batch.delete_item(Key={"PK": row["PK"], "SK": row["SK"]})

    # 3. Write new components
    results: List[ProductPriceComponentOut] = []
    for comp in components:
        results.append(set_price_component(item_id, creator_id, comp))

    return results


# ---------------------------------------------------------------------------
# list_price_components
# ---------------------------------------------------------------------------

def list_price_components(
    item_id: str,
    price_type: Optional[str] = None,
) -> List[ProductPriceComponentOut]:
    """Return all price components for an item, optionally filtered by price_type.

    When price_type is None, queries each type in _ALL_PRICE_TYPES and merges.
    Rows are returned newest-effective-at first within each type.
    """
    _require_enabled()

    types_to_query = [price_type] if price_type else _ALL_PRICE_TYPES
    now = now_ts()
    results: List[ProductPriceComponentOut] = []

    for pt in types_to_query:
        last_key = None
        while True:
            kwargs: Dict[str, Any] = {
                "IndexName": "ByItemPrice",
                "KeyConditionExpression": Key("GSI_PRICE_PK").eq(f"PRICE#{item_id}#{pt}"),
                "ScanIndexForward": False,
            }
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = T.product_depth.query(**kwargs)
            for row in resp.get("Items", []):
                results.append(_row_to_out(row, as_of=now))
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break

    return results


# ---------------------------------------------------------------------------
# resolve_effective_price
# ---------------------------------------------------------------------------

def resolve_effective_price(
    item_id: str,
    as_of: int,
    price_type: str = "DEFAULT",
) -> PriceResolution:
    """Return the active price for (item_id, price_type) as of as_of.

    Algorithm:
      1. Query ByItemPrice GSI: GSI_PRICE_PK = PRICE#{item_id}#{price_type},
         GSI_PRICE_SK <= as_of, ScanIndexForward=False, Limit=_FETCH_WINDOW.
      2. For each row (newest-effective first), check expires_at:
         accept the first row where expires_at IS NULL OR expires_at >= as_of.
      3. If no active component AND price_type == "DEFAULT":
         fall back to scalar price_cents from T.catalog.
      4. If no active component and price_type != "DEFAULT": return 0.

    This function DOES NOT call _require_enabled(): safe to call from
    cart/checkout regardless of the product_depth flag state.  When flags are
    off and no rows exist, the scalar fallback always applies.

    Never raises.  Returns PriceResolution(amount_cents=0, ...) as last resort.
    """
    try:
        resp = T.product_depth.query(
            IndexName="ByItemPrice",
            KeyConditionExpression=(
                Key("GSI_PRICE_PK").eq(f"PRICE#{item_id}#{price_type}")
                & Key("GSI_PRICE_SK").lte(as_of)
            ),
            ScanIndexForward=False,
            Limit=_FETCH_WINDOW,
        )
        for row in resp.get("Items", []):
            exp_raw = row.get("expires_at")
            exp = int(exp_raw) if exp_raw is not None else None
            if exp is None or exp >= as_of:
                return PriceResolution(
                    amount_cents=int(row["amount_cents"]),
                    currency=str(row.get("currency", "USD")),
                    price_component_id=str(row["price_component_id"]),
                    source="price_component",
                )
    except Exception:
        pass

    # Fallback for DEFAULT type: use scalar from T.catalog
    if price_type == "DEFAULT":
        return _scalar_price_fallback(item_id)

    return PriceResolution(
        amount_cents=0,
        currency="USD",
        price_component_id=None,
        source="scalar_fallback",
    )


def _scalar_price_fallback(item_id: str) -> PriceResolution:
    """Read the scalar price_cents from T.catalog via the ByItemId GSI."""
    try:
        resp = T.catalog.query(
            IndexName="ByItemId",
            KeyConditionExpression=Key("item_id").eq(item_id),
            FilterExpression="entity = :ent",
            ExpressionAttributeValues={":ent": "item"},
            Limit=1,
        )
        items = resp.get("Items", [])
        if items:
            amount = int(items[0].get("price_cents", 0))
            currency = str(items[0].get("currency", "USD"))
            return PriceResolution(
                amount_cents=amount,
                currency=currency,
                price_component_id=None,
                source="scalar_fallback",
            )
    except Exception:
        pass
    return PriceResolution(
        amount_cents=0,
        currency="USD",
        price_component_id=None,
        source="scalar_fallback",
    )
