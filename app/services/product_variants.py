"""
OFBiz Catalog Depth — Virtual / Variant product service.
PRD-007: virtual↔variant product relationship.

Responsibilities:
  - Promote a scalar catalog item to product_type="virtual".
  - Create variant rows (VAR#) under a virtual parent.
  - Reject duplicate feature combinations idempotently (sha256 variant_id).
  - List variants via the ByVirtualParent GSI in O(1).
  - Compute effective price as a pure function.

No router endpoints ship here — those are PRD-008.
All functions raise HTTPException on error so they compose with FastAPI.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Key
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
        and bool(getattr(S, "product_depth_variants_enabled", True))
    )


def _require_enabled() -> None:
    if not _flag_on():
        raise HTTPException(status_code=404, detail="Product variants are not enabled.")


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------

def _item_pk(item_id: str) -> str:
    return f"ITEM#{item_id}"


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
# Pure functions (no DB writes; unit-testable in isolation)
# ---------------------------------------------------------------------------

def derive_variant_id(
    parent_item_id: str,
    feature_values: Dict[str, str],
) -> str:
    """Deterministic 16-char hex id for a feature-value combination.

    Sorting by feature_category_id guarantees that dict insertion order
    does not affect the resulting id.

    >>> derive_variant_id("p1", {"color": "red", "size": "L"}) ==
    ...     derive_variant_id("p1", {"size": "L", "color": "red"})
    True
    """
    canonical_tuple = sorted(feature_values.items())
    raw = parent_item_id + "|" + "|".join(f"{fc}:{fv}" for fc, fv in canonical_tuple)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def compute_price_delta(
    feature_values: Dict[str, str],
    feature_value_deltas: Dict[str, int],
) -> int:
    """Pure function: return Σ(price_delta_cents) for the selected feature values.

    Args:
        feature_values:      {feature_category_id: feature_value_id}
        feature_value_deltas: {feature_value_id: price_delta_cents}
    """
    return sum(feature_value_deltas.get(fv_id, 0) for fv_id in feature_values.values())


# ---------------------------------------------------------------------------
# Helper: find item in T.catalog
# ---------------------------------------------------------------------------

def _find_catalog_item(item_id: str) -> Dict[str, Any]:
    """Resolve an item_id to its T.catalog row via the ByItemId GSI.

    Raises HTTP 404 if not found.
    """
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
            return items[0]
    except Exception:
        pass
    raise HTTPException(status_code=404, detail=f"Catalog item '{item_id}' not found.")


# ---------------------------------------------------------------------------
# Product type (TYPE marker row)
# ---------------------------------------------------------------------------

def set_product_type(
    item_id: str,
    product_type: str,
    user_sub: str,
) -> Dict[str, Any]:
    """Write (or overwrite) the TYPE marker row for an item on T.product_depth.

    Validates that the item exists on T.catalog first.
    Last-write-wins unconditional put_item (idempotent re-promotion is fine).
    """
    _require_enabled()

    # Verify item exists
    _find_catalog_item(item_id)

    ts = now_ts()
    row: Dict[str, Any] = {
        "PK": _item_pk(item_id),
        "SK": "TYPE",
        "entity": "product_type",
        "product_type": product_type,
        "creator_id": user_sub,
        "created_at": ts,
        "updated_at": ts,
    }
    T.product_depth.put_item(Item=row)
    _audit("product_type.set", user_sub, item_id=item_id, product_type=product_type)
    return row


def get_product_type(item_id: str) -> Optional[str]:
    """Return the product_type string, or None when no TYPE row exists (standalone)."""
    resp = T.product_depth.get_item(Key={"PK": _item_pk(item_id), "SK": "TYPE"})
    item = resp.get("Item")
    if item:
        return str(item.get("product_type", "standalone"))
    return None


# ---------------------------------------------------------------------------
# Variant creation / listing / deletion
# ---------------------------------------------------------------------------

def create_variant(
    parent_item_id: str,
    feature_values: Dict[str, str],
    user_sub: str,
    sku_override: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a variant child under a virtual parent.

    Steps:
    1. _require_enabled()
    2. Read parent from T.catalog — 404 if absent.
    3. Read parent TYPE row — 422 if not "virtual".
    4. Validate every feature_category_id in feature_values is attached via
       product_features.list_product_features — 422 if any axis missing.
    5. For each selected feature_value_id, call get_feature_value — 422 if unknown.
    6. derive_variant_id(parent_item_id, feature_values)
    7. compute_price_delta(feature_values, deltas_map)
    8. effective_price = parent_price + price_delta
    9. Conditional put on T.product_depth — 409 if duplicate.
    10. Return written row.
    """
    _require_enabled()

    # Step 2: parent must exist
    parent = _find_catalog_item(parent_item_id)

    # Step 3: parent must be virtual
    ptype = get_product_type(parent_item_id)
    if ptype != "virtual":
        raise HTTPException(
            status_code=422,
            detail="Parent item must be of type 'virtual' before variants can be added.",
        )

    # Step 4 & 5: validate feature_values against attached axes + individual values
    from app.services.product_features import (
        list_product_features,
        get_feature_value,
    )

    # Enable features sub-flag temporarily? No — we only need to read, bypass flag:
    attached_features = T.product_depth.query(
        KeyConditionExpression=(
            Key("PK").eq(_item_pk(parent_item_id)) & Key("SK").begins_with("FTAPPL#")
        ),
    ).get("Items", [])
    attached_fc_ids = {f["feature_category_id"] for f in attached_features}

    for fc_id in feature_values:
        if fc_id not in attached_fc_ids:
            raise HTTPException(
                status_code=422,
                detail=f"Feature category '{fc_id}' is not attached to this product.",
            )
    # Also ensure all attached axes are covered (partial selections not allowed)
    for fc_id in attached_fc_ids:
        if fc_id not in feature_values:
            raise HTTPException(
                status_code=422,
                detail=f"Feature category '{fc_id}' must be selected (partial selections not allowed).",
            )

    # Validate individual values and collect deltas
    deltas_map: Dict[str, int] = {}
    for fc_id, fv_id in feature_values.items():
        fv = get_feature_value(fc_id, fv_id)
        if fv is None:
            raise HTTPException(
                status_code=422,
                detail=f"Feature value '{fv_id}' not found in category '{fc_id}'.",
            )
        deltas_map[fv_id] = int(fv.get("price_delta_cents", 0))

    # Step 6–8: compute ids and price
    variant_id = derive_variant_id(parent_item_id, feature_values)
    price_delta = compute_price_delta(feature_values, deltas_map)
    parent_price = int(parent.get("price_cents", 0))
    effective_price = parent_price + price_delta

    # Check max variants per parent
    max_variants = int(getattr(S, "product_depth_max_variants_per_item", 1000))
    existing_count_resp = T.product_depth.query(
        IndexName="ByVirtualParent",
        KeyConditionExpression=Key("GSI_VIRT_PK").eq(f"VIRTUAL#{parent_item_id}"),
        Select="COUNT",
    )
    if existing_count_resp.get("Count", 0) >= max_variants:
        raise HTTPException(
            status_code=422,
            detail=f"Maximum variant count ({max_variants}) reached for this product.",
        )

    # Step 9: validate sku_override uniqueness if provided
    sku: str
    if sku_override:
        if sku_override.startswith("variant:"):
            raise HTTPException(
                status_code=422,
                detail="sku_override must not start with 'variant:'.",
            )
        sku = sku_override
    else:
        sku = f"variant:{parent_item_id}:{variant_id}"

    ts = now_ts()
    row: Dict[str, Any] = {
        "PK": _item_pk(parent_item_id),
        "SK": f"VAR#{variant_id}",
        "entity": "variant",
        "variant_id": variant_id,
        "parent_item_id": parent_item_id,
        "sku": sku,
        "feature_values": feature_values,
        "price_delta_cents": price_delta,
        "effective_price_cents": effective_price,
        "creator_id": user_sub,
        "created_at": ts,
        "GSI_VIRT_PK": f"VIRTUAL#{parent_item_id}",
        "GSI_VIRT_SK": ts,
    }

    try:
        T.product_depth.put_item(
            Item=row,
            ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise HTTPException(
                status_code=409,
                detail="Variant already exists for this feature combination.",
            )
        raise

    _audit("product_variant.created", user_sub, parent_item_id=parent_item_id, variant_id=variant_id)
    return row


def list_variants(
    parent_item_id: str,
    limit: int = 100,
    start_key: Optional[Dict[str, Any]] = None,
) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Return all variant rows for a virtual parent (chronological order).

    Non-virtual or standalone items return an empty list — safe to call on any item.
    """
    kwargs: Dict[str, Any] = {
        "IndexName": "ByVirtualParent",
        "KeyConditionExpression": Key("GSI_VIRT_PK").eq(f"VIRTUAL#{parent_item_id}"),
        "ScanIndexForward": True,
        "Limit": limit,
    }
    if start_key:
        kwargs["ExclusiveStartKey"] = start_key

    resp = T.product_depth.query(**kwargs)
    return resp.get("Items", []), resp.get("LastEvaluatedKey")


def delete_variant(
    parent_item_id: str,
    variant_id: str,
    user_sub: str,
) -> None:
    """Hard-delete a variant row. Raises 404 if it does not exist."""
    _require_enabled()

    key = {"PK": _item_pk(parent_item_id), "SK": f"VAR#{variant_id}"}
    resp = T.product_depth.get_item(Key=key)
    if not resp.get("Item"):
        raise HTTPException(status_code=404, detail="Variant not found.")

    T.product_depth.delete_item(Key=key)
    _audit("product_variant.deleted", user_sub, parent_item_id=parent_item_id, variant_id=variant_id)


# ---------------------------------------------------------------------------
# Bundle / kit component membership (PRD follow-up)
# ---------------------------------------------------------------------------

def _bundles_flag_on() -> bool:
    return (
        bool(getattr(S, "product_depth_enabled", False))
        and bool(getattr(S, "product_depth_bundles_enabled", True))
    )


def _require_bundles_enabled() -> None:
    if not _bundles_flag_on():
        raise HTTPException(status_code=404, detail="Product bundles are not enabled.")


_BUNDLE_PARENT_TYPES = {"bundle", "kit"}


def add_bundle_component(
    parent_item_id: str,
    component_item_id: str,
    quantity: int,
    user_sub: str,
) -> Dict[str, Any]:
    """Add a component to a bundle/kit parent item.

    Validations:
      * flag on (404 otherwise)
      * parent exists (404) and its product_type is bundle/kit (422 otherwise)
      * component exists (422 otherwise)
      * no self-reference (422)
      * no obvious cycle: the component must not itself be a bundle that already
        contains the parent (422)
    Stored as ``SK=BUNDLE#{component_item_id}`` on the parent's partition
    (last-write-wins, so re-adding updates quantity idempotently).
    """
    _require_bundles_enabled()

    if component_item_id == parent_item_id:
        raise HTTPException(status_code=422, detail="A bundle cannot contain itself.")

    # Parent must exist and be a bundle/kit.
    _find_catalog_item(parent_item_id)
    ptype = get_product_type(parent_item_id)
    if ptype not in _BUNDLE_PARENT_TYPES:
        raise HTTPException(
            status_code=422,
            detail="Parent item must be of product_type 'bundle' or 'kit'.",
        )

    # Component must exist in the catalog.
    _find_catalog_item(component_item_id)

    # Obvious-cycle guard: if the component is itself a bundle that already lists
    # the parent as a component, adding it back would create a 2-cycle.
    component_children = {
        c["component_item_id"] for c in _list_bundle_component_rows(component_item_id)
    }
    if parent_item_id in component_children:
        raise HTTPException(
            status_code=422,
            detail="Adding this component would create a bundle cycle.",
        )

    qty = max(1, int(quantity))
    ts = now_ts()
    row: Dict[str, Any] = {
        "PK": _item_pk(parent_item_id),
        "SK": f"BUNDLE#{component_item_id}",
        "entity": "bundle_component",
        "parent_item_id": parent_item_id,
        "component_item_id": component_item_id,
        "quantity": qty,
        "creator_id": user_sub,
        "created_at": ts,
        "updated_at": ts,
    }
    T.product_depth.put_item(Item=row)
    _audit(
        "product_bundle.component_added",
        user_sub,
        parent_item_id=parent_item_id,
        component_item_id=component_item_id,
        quantity=qty,
    )
    return row


def _list_bundle_component_rows(parent_item_id: str) -> List[Dict[str, Any]]:
    """Raw BUNDLE# rows for a parent (no flag check, no enrichment)."""
    resp = T.product_depth.query(
        KeyConditionExpression=(
            Key("PK").eq(_item_pk(parent_item_id)) & Key("SK").begins_with("BUNDLE#")
        ),
    )
    return resp.get("Items", [])


def list_bundle_components(parent_item_id: str) -> List[Dict[str, Any]]:
    """List a bundle's components enriched with component catalog details.

    Each returned dict matches the BundleComponentOut shape. Never raises for a
    missing/deleted component — those fields are simply left None.
    """
    _require_bundles_enabled()
    rows = _list_bundle_component_rows(parent_item_id)
    out: List[Dict[str, Any]] = []
    for row in rows:
        component_item_id = str(row.get("component_item_id") or "")
        details: Dict[str, Any] = {}
        try:
            details = _find_catalog_item(component_item_id)
        except HTTPException:
            details = {}
        price = details.get("price_cents")
        out.append(
            {
                "parent_item_id": parent_item_id,
                "component_item_id": component_item_id,
                "quantity": int(row.get("quantity") or 1),
                "component_sku": details.get("sku"),
                "component_name": details.get("name") or details.get("title"),
                "component_price_cents": int(price) if price is not None else None,
                "created_at": int(row.get("created_at") or 0),
            }
        )
    return out


def remove_bundle_component(
    parent_item_id: str,
    component_item_id: str,
    user_sub: str,
) -> None:
    """Remove a component from a bundle. Raises 404 if the row does not exist."""
    _require_bundles_enabled()
    key = {"PK": _item_pk(parent_item_id), "SK": f"BUNDLE#{component_item_id}"}
    resp = T.product_depth.get_item(Key=key)
    if not resp.get("Item"):
        raise HTTPException(status_code=404, detail="Bundle component not found.")
    T.product_depth.delete_item(Key=key)
    _audit(
        "product_bundle.component_removed",
        user_sub,
        parent_item_id=parent_item_id,
        component_item_id=component_item_id,
    )
