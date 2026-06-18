"""
OFBiz Catalog Depth — Category Tree Service.
PRD-004: hierarchical category tree built on T.product_depth.

Responsibilities:
  - Link an existing flat catalog category as a child of another (add_child).
  - Re-parent a category with cycle detection (move_category).
  - List direct children via the ByParent GSI (list_children).
  - Return ancestor chain from the materialized path field (get_ancestry).
  - Return breadcrumb dicts [{category_id, name}] for UI (get_breadcrumb).
  - Recursively collect all descendants (list_descendants, depth-limited).
  - Feature flag guard: all public functions call _require_product_depth_enabled().

Schema on T.product_depth (category tree rows):
  PK:  CAT#{category_id}
  SK:  META
  GSI: ByParent  →  GSI_PARENT_PK = PARENT#{parent_id}  /  GSI_PARENT_SK = position (N)

Fields stored per row:
  category_id, parent_category_id, path (materialized, e.g. "root/child/grandchild"),
  position, name, owner_sub, created_at, updated_at.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

# Max depth for recursive descendant collection
_MAX_DESCENDANT_DEPTH = 10


# ---------------------------------------------------------------------------
# Feature flag
# ---------------------------------------------------------------------------

def _require_product_depth_enabled() -> None:
    if not getattr(S, "product_depth_enabled", False):
        raise HTTPException(status_code=501, detail="product_depth_not_enabled")


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------

def _cat_pk(category_id: str) -> str:
    return f"CAT#{category_id}"


def _parent_gsi_pk(parent_id: str) -> str:
    return f"PARENT#{parent_id}"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_tree_row(category_id: str) -> Optional[Dict[str, Any]]:
    """Fetch the tree row for a category from T.product_depth (or None if absent)."""
    resp = T.product_depth.get_item(Key={"PK": _cat_pk(category_id), "SK": "META"})
    return resp.get("Item")


def _build_path(parent_path: Optional[str], category_id: str) -> str:
    """Construct a materialized path string like 'grandparent/parent/child'."""
    if parent_path:
        return f"{parent_path}/{category_id}"
    return category_id


def _detect_cycle(category_id: str, proposed_parent_id: str) -> None:
    """
    Walk up the tree from proposed_parent_id.  If we reach category_id before
    reaching root, a cycle would be created — raise ValueError.
    """
    visited: set[str] = set()
    current = proposed_parent_id
    while current:
        if current == category_id:
            raise ValueError(
                f"Cycle detected: '{category_id}' is an ancestor of '{proposed_parent_id}'"
            )
        if current in visited:
            break  # defensive: prevent infinite loop on corrupt data
        visited.add(current)
        row = _get_tree_row(current)
        if not row:
            break
        current = row.get("parent_category_id") or ""


def _update_descendant_paths(category_id: str, old_prefix: str, new_prefix: str) -> None:
    """
    After a move, recursively update path fields for all descendants.
    Walks breadth-first via _list_children_raw (no flag check).
    Limited to _MAX_DESCENDANT_DEPTH to avoid runaway updates.
    """
    queue: List[Tuple[str, int]] = [(category_id, 0)]
    while queue:
        cid, depth = queue.pop(0)
        if depth >= _MAX_DESCENDANT_DEPTH:
            continue
        children, _ = _list_children_raw(cid, limit=200, cursor=None)
        for child in children:
            child_id = child["category_id"]
            old_path: str = child.get("path", "")
            new_path = (
                old_path.replace(old_prefix, new_prefix, 1)
                if old_prefix in old_path
                else new_prefix + "/" + child_id
            )
            ts = now_ts()
            T.product_depth.update_item(
                Key={"PK": _cat_pk(child_id), "SK": "META"},
                UpdateExpression="SET #p = :p, updated_at = :u",
                ExpressionAttributeNames={"#p": "path"},
                ExpressionAttributeValues={":p": new_path, ":u": ts},
            )
            queue.append((child_id, depth + 1))


def _list_children_raw(
    parent_category_id: str,
    limit: int = 50,
    cursor: Optional[Dict[str, Any]] = None,
) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Query ByParent GSI — no flag check, used internally."""
    kwargs: Dict[str, Any] = {
        "IndexName": "ByParent",
        "KeyConditionExpression": Key("GSI_PARENT_PK").eq(_parent_gsi_pk(parent_category_id)),
        "Limit": limit,
        "ScanIndexForward": True,
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = cursor
    resp = T.product_depth.query(**kwargs)
    return resp.get("Items", []), resp.get("LastEvaluatedKey")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def add_child(
    parent_category_id: str,
    category_id: str,
    owner_sub: str,
    name: str,
    position: int = 0,
) -> Dict[str, Any]:
    """
    Link an existing flat catalog category as a child of parent_category_id.

    Validates:
      - parent ownership when a tree row exists for it
      - no cycle would be created

    Writes a new tree row to T.product_depth.
    Returns the created row.
    """
    _require_product_depth_enabled()

    # Resolve parent path.  The parent may be a root node (no tree row yet) — in
    # that case we treat its path as just the parent's own id.
    parent_row = _get_tree_row(parent_category_id)
    if parent_row is not None:
        if parent_row.get("owner_sub") != owner_sub:
            raise HTTPException(status_code=403, detail="Not authorized to manage parent category.")
        parent_path = parent_row.get("path", parent_category_id)
    else:
        # Parent has no tree row yet — treat it as a root-level node
        parent_path = parent_category_id

    # Cycle detection: child must not already be an ancestor of the parent
    _detect_cycle(category_id, parent_category_id)

    path = _build_path(parent_path, category_id)
    ts = now_ts()
    row: Dict[str, Any] = {
        "PK": _cat_pk(category_id),
        "SK": "META",
        "category_id": category_id,
        "parent_category_id": parent_category_id,
        "path": path,
        "position": position,
        "name": name,
        "owner_sub": owner_sub,
        "created_at": ts,
        "updated_at": ts,
        # GSI ByParent
        "GSI_PARENT_PK": _parent_gsi_pk(parent_category_id),
        "GSI_PARENT_SK": position,
    }
    T.product_depth.put_item(Item=row)
    return row


def move_category(
    category_id: str,
    new_parent_id: str,
    owner_sub: str,
) -> Dict[str, Any]:
    """
    Re-parent category_id under new_parent_id.

    Validates ownership, cycle detection, and updates materialized path for
    the category and all its descendants.
    Returns the updated row.
    """
    _require_product_depth_enabled()

    row = _get_tree_row(category_id)
    if not row:
        raise HTTPException(status_code=404, detail="Category tree node not found.")
    if row.get("owner_sub") != owner_sub:
        raise HTTPException(status_code=403, detail="Not authorized to manage this category.")

    # Cycle detection
    _detect_cycle(category_id, new_parent_id)

    # Resolve new parent path
    new_parent_row = _get_tree_row(new_parent_id)
    if new_parent_row is not None:
        new_parent_path = new_parent_row.get("path", new_parent_id)
    else:
        new_parent_path = new_parent_id

    old_path = row.get("path", category_id)
    new_path = _build_path(new_parent_path, category_id)
    ts = now_ts()

    T.product_depth.update_item(
        Key={"PK": _cat_pk(category_id), "SK": "META"},
        UpdateExpression=(
            "SET parent_category_id = :pid, #p = :path, "
            "GSI_PARENT_PK = :gpk, updated_at = :u"
        ),
        ExpressionAttributeNames={"#p": "path"},
        ExpressionAttributeValues={
            ":pid": new_parent_id,
            ":path": new_path,
            ":gpk": _parent_gsi_pk(new_parent_id),
            ":u": ts,
        },
    )

    # Propagate path change to descendants
    _update_descendant_paths(category_id, old_path, new_path)

    updated = _get_tree_row(category_id) or {}
    return updated


def list_children(
    parent_category_id: str,
    limit: int = 50,
    cursor: Optional[Dict[str, Any]] = None,
) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """
    Return direct children of parent_category_id ordered by position (ascending).
    Returns (items, last_evaluated_key).
    """
    _require_product_depth_enabled()
    return _list_children_raw(parent_category_id, limit=limit, cursor=cursor)


def get_ancestry(category_id: str) -> List[str]:
    """
    Return list of ancestor category_ids from root to the immediate parent,
    derived from the materialized path field.

    E.g. for path "root/child/grandchild" → ["root", "child"]
    (the category itself is NOT included).
    """
    _require_product_depth_enabled()
    row = _get_tree_row(category_id)
    if not row:
        return []
    path: str = row.get("path", category_id)
    parts = [p for p in path.split("/") if p]
    # Exclude the category itself (last element)
    return parts[:-1] if len(parts) > 1 else []


def get_breadcrumb(category_id: str) -> List[Dict[str, str]]:
    """
    Return list of {category_id, name} dicts from root to the category itself
    (inclusive), suitable for UI breadcrumbs.
    """
    _require_product_depth_enabled()
    row = _get_tree_row(category_id)
    if not row:
        return [{"category_id": category_id, "name": category_id}]

    path: str = row.get("path", category_id)
    parts = [p for p in path.split("/") if p]

    breadcrumb: List[Dict[str, str]] = []
    for part in parts:
        part_row = _get_tree_row(part)
        name = part_row.get("name", part) if part_row else part
        breadcrumb.append({"category_id": part, "name": name})
    return breadcrumb


def list_descendants(
    category_id: str,
) -> List[Dict[str, Any]]:
    """
    Recursively collect all descendants of category_id (breadth-first).
    Limited to _MAX_DESCENDANT_DEPTH levels.
    Returns flat list of tree row dicts.
    """
    _require_product_depth_enabled()
    return _collect_descendants(category_id, depth=0)


def _collect_descendants(category_id: str, depth: int) -> List[Dict[str, Any]]:
    """Internal recursive helper — no flag check."""
    if depth >= _MAX_DESCENDANT_DEPTH:
        return []
    children, _ = _list_children_raw(category_id, limit=200)
    result: List[Dict[str, Any]] = list(children)
    for child in children:
        result.extend(_collect_descendants(child["category_id"], depth + 1))
    return result
