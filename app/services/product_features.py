"""
OFBiz Catalog Depth — Feature Category / Feature Value / Feature Application service.
PRD-006: product feature & feature-category model.

Guard every public function with _require_enabled() checking both:
  S.product_depth_enabled  (master, default False)
  S.product_depth_features_enabled  (sub-flag, default True when master is on)

With either flag off all public functions raise HTTP 404; no existing
catalog / cart / billing paths are affected.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts


# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------

def _flag_on() -> bool:
    return (
        bool(getattr(S, "product_depth_enabled", False))
        and bool(getattr(S, "product_depth_features_enabled", True))
    )


def _require_enabled() -> None:
    if not _flag_on():
        raise HTTPException(status_code=404, detail="Product features are not enabled.")


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------

def _fc_pk(fc_id: str) -> str:
    return f"FTCAT#{fc_id}"


def _fv_sk(fv_id: str) -> str:
    return f"FTVAL#{fv_id}"


def _appl_sk(fc_id: str) -> str:
    return f"FTAPPL#{fc_id}"


def _item_pk(item_id: str) -> str:
    return f"ITEM#{item_id}"


def _fv_id(fc_id: str, name: str) -> str:
    """Deterministic feature-value id: sha256(fc_id:name_lower)[:16]."""
    import hashlib
    raw = f"{fc_id}:{name.strip().lower()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Audit helper
# ---------------------------------------------------------------------------

def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event  # type: ignore[import]
        audit_event(event, user_sub or "system", None, **fields)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Feature category operations
# ---------------------------------------------------------------------------

def create_feature_category(
    name: str,
    user_sub: str,
    *,
    feature_category_id: Optional[str] = None,
    description: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a new feature category (e.g. 'Color', 'Size').

    Idempotent: supplying the same feature_category_id twice raises HTTP 409.
    """
    _require_enabled()

    if not name or len(name) > 128:
        raise HTTPException(status_code=400, detail="name must be 1–128 characters.")

    fc_id = feature_category_id or uuid.uuid4().hex
    ts = now_ts()
    item: Dict[str, Any] = {
        "PK": _fc_pk(fc_id),
        "SK": "META",
        "entity": "feature_category",
        "feature_category_id": fc_id,
        "name": name.strip(),
        "creator_id": user_sub,
        "created_at": ts,
        "updated_at": ts,
    }
    if description is not None:
        item["description"] = description

    try:
        T.product_depth.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise HTTPException(status_code=409, detail="Feature category already exists.")
        raise

    _audit("product_feature_category.created", user_sub, fc_id=fc_id, name=name)
    return item


def get_feature_category(fc_id: str) -> Optional[Dict[str, Any]]:
    """Fetch the META row for a feature category. Returns None if not found."""
    resp = T.product_depth.get_item(Key={"PK": _fc_pk(fc_id), "SK": "META"})
    return resp.get("Item")


def list_feature_categories(
    user_sub: str,
    *,
    include_values: bool = False,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """List all feature categories owned by user_sub (scan + filter)."""
    _require_enabled()

    results: List[Dict[str, Any]] = []
    last_key = None
    fetched = 0
    while fetched < limit:
        kwargs: Dict[str, Any] = {
            "FilterExpression": Attr("entity").eq("feature_category") & Attr("creator_id").eq(user_sub),
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.product_depth.scan(**kwargs)
        for item in resp.get("Items", []):
            if include_values:
                item = dict(item)
                item["values"] = _list_values_for_category(item["feature_category_id"])
            results.append(item)
            fetched += 1
            if fetched >= limit:
                break
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return results


# ---------------------------------------------------------------------------
# Feature value operations
# ---------------------------------------------------------------------------

def add_feature_value(
    fc_id: str,
    name: str,
    user_sub: str,
    *,
    price_delta_cents: int = 0,
    position: int = 0,
) -> Dict[str, Any]:
    """Add a feature value (e.g. 'Red') to a feature category."""
    _require_enabled()

    if not name or len(name) > 128:
        raise HTTPException(status_code=400, detail="name must be 1–128 characters.")
    if abs(price_delta_cents) > 10_000_000_00:
        raise HTTPException(status_code=400, detail="price_delta_cents out of range.")
    if not (0 <= position <= 9999):
        raise HTTPException(status_code=400, detail="position must be 0–9999.")

    fc = get_feature_category(fc_id)
    if fc is None:
        raise HTTPException(status_code=404, detail="Feature category not found.")
    if fc.get("creator_id") != user_sub:
        raise HTTPException(status_code=403, detail="Not authorized.")

    fv_id = _fv_id(fc_id, name)
    ts = now_ts()
    item: Dict[str, Any] = {
        "PK": _fc_pk(fc_id),
        "SK": _fv_sk(fv_id),
        "entity": "feature_value",
        "feature_value_id": fv_id,
        "feature_category_id": fc_id,
        "name": name.strip(),
        "price_delta_cents": price_delta_cents,
        "position": position,
        "creator_id": user_sub,
        "created_at": ts,
        "updated_at": ts,
        "GSI_FTCAT_PK": _fc_pk(fc_id),
        "GSI_FTCAT_SK": position,
    }

    try:
        T.product_depth.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            # Idempotent: return existing row
            existing = get_feature_value(fc_id, fv_id)
            if existing:
                return existing
        raise

    _audit("product_feature_value.added", user_sub, fc_id=fc_id, fv_id=fv_id, name=name)
    return item


def get_feature_value(fc_id: str, fv_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a single feature value row."""
    resp = T.product_depth.get_item(
        Key={"PK": _fc_pk(fc_id), "SK": _fv_sk(fv_id)}
    )
    return resp.get("Item")


def _list_values_for_category(
    fc_id: str,
    *,
    limit: int = 500,
) -> List[Dict[str, Any]]:
    """Query ByFeatureCategory GSI for all values of a category, ordered by position."""
    resp = T.product_depth.query(
        IndexName="ByFeatureCategory",
        KeyConditionExpression=Key("GSI_FTCAT_PK").eq(_fc_pk(fc_id)),
        ScanIndexForward=True,
        Limit=limit,
    )
    items = resp.get("Items", [])
    # secondary sort by (position, name) for deterministic tie-breaking
    return sorted(items, key=lambda x: (int(x.get("position", 0)), x.get("name", "")))


def delete_feature_value(fc_id: str, fv_id: str, user_sub: str) -> None:
    """Delete a single feature value."""
    _require_enabled()

    fc = get_feature_category(fc_id)
    if fc is None:
        raise HTTPException(status_code=404, detail="Feature category not found.")
    if fc.get("creator_id") != user_sub:
        raise HTTPException(status_code=403, detail="Not authorized.")

    T.product_depth.delete_item(Key={"PK": _fc_pk(fc_id), "SK": _fv_sk(fv_id)})
    _audit("product_feature_value.deleted", user_sub, fc_id=fc_id, fv_id=fv_id)


def delete_feature_category(fc_id: str, user_sub: str) -> None:
    """Delete a feature category and all its values (blocked if in use by products)."""
    _require_enabled()

    fc = get_feature_category(fc_id)
    if fc is None:
        raise HTTPException(status_code=404, detail="Feature category not found.")
    if fc.get("creator_id") != user_sub:
        raise HTTPException(status_code=403, detail="Not authorized.")

    # In-use guard: scan for any FTAPPL#{fc_id} rows.
    # NOTE: DynamoDB FilterExpression is applied after fetching pages, so Limit does
    # not reduce the pre-filter page. We scan without Limit to find any match.
    appl_sk = _appl_sk(fc_id)
    last_key = None
    found_in_use = False
    while True:
        scan_kwargs: Dict[str, Any] = {
            "FilterExpression": Attr("SK").eq(appl_sk),
        }
        if last_key:
            scan_kwargs["ExclusiveStartKey"] = last_key
        scan_resp = T.product_depth.scan(**scan_kwargs)
        if scan_resp.get("Items"):
            found_in_use = True
            break
        last_key = scan_resp.get("LastEvaluatedKey")
        if not last_key:
            break

    if found_in_use:
        raise HTTPException(
            status_code=409,
            detail="Feature category is in use by one or more products. Detach it first.",
        )

    # Delete all child values
    values = _list_values_for_category(fc_id)
    with T.product_depth.batch_writer() as batch:
        for v in values:
            batch.delete_item(Key={"PK": _fc_pk(fc_id), "SK": _fv_sk(v["feature_value_id"])})

    # Delete META row
    T.product_depth.delete_item(Key={"PK": _fc_pk(fc_id), "SK": "META"})
    _audit("product_feature_category.deleted", user_sub, fc_id=fc_id)


# ---------------------------------------------------------------------------
# Feature application operations (product ↔ feature-category binding)
# ---------------------------------------------------------------------------

def attach_feature_category_to_product(
    item_id: str,
    fc_id: str,
    user_sub: str,
) -> Dict[str, Any]:
    """Write an FTAPPL row linking a feature category to a product.

    Verifies that the caller owns the feature category.
    Does NOT verify item ownership — that is the router's responsibility.
    Idempotent: re-attaching the same (item_id, fc_id) pair is a no-op.
    """
    _require_enabled()

    fc = get_feature_category(fc_id)
    if fc is None:
        raise HTTPException(status_code=404, detail="Feature category not found.")
    if fc.get("creator_id") != user_sub:
        raise HTTPException(status_code=403, detail="Not authorized.")

    ts = now_ts()
    item: Dict[str, Any] = {
        "PK": _item_pk(item_id),
        "SK": _appl_sk(fc_id),
        "entity": "feature_appl",
        "item_id": item_id,
        "feature_category_id": fc_id,
        "creator_id": user_sub,
        "created_at": ts,
    }
    T.product_depth.put_item(Item=item)  # unconditional — idempotent overwrite

    _audit("product_feature_appl.created", user_sub, item_id=item_id, fc_id=fc_id)
    return item


def detach_feature_category_from_product(
    item_id: str,
    fc_id: str,
    user_sub: str,
) -> None:
    """Remove the FTAPPL link between a product and a feature category."""
    _require_enabled()

    T.product_depth.delete_item(
        Key={"PK": _item_pk(item_id), "SK": _appl_sk(fc_id)}
    )
    _audit("product_feature_appl.deleted", user_sub, item_id=item_id, fc_id=fc_id)


def list_product_features(item_id: str) -> List[Dict[str, Any]]:
    """Return all feature categories attached to a product, each with ordered values.

    Returns [] for items with no FTAPPL rows (standalone items; no HTTP error raised).
    """
    _require_enabled()

    resp = T.product_depth.query(
        KeyConditionExpression=(
            Key("PK").eq(_item_pk(item_id)) & Key("SK").begins_with("FTAPPL#")
        ),
    )
    appl_rows = resp.get("Items", [])
    result = []
    for appl in appl_rows:
        fc_id = appl["feature_category_id"]
        fc = get_feature_category(fc_id)
        if fc is None:
            continue  # orphaned FTAPPL row — skip gracefully
        fc = dict(fc)
        fc["values"] = _list_values_for_category(fc_id)
        result.append(fc)
    return result
