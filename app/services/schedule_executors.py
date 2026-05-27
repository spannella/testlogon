"""
Module-specific executors for scheduled actions.

Each executor receives (user_sub, payload) and performs the action
on behalf of the user.
"""
from __future__ import annotations

import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)


async def execute_scheduled_post(user_sub: str, payload: Dict[str, Any]) -> None:
    """Create a newsfeed post from a scheduled action payload."""
    # Import at call-time to avoid circular imports
    from app.routers.newsfeed import (
        ddb_put_item,
        new_id,
        now_iso,
        pk_post,
        sk_post,
        _write_feed_ref_for_published_post,
        _content_from_payload,
    )

    text = payload.get("text", "")
    image_urls = payload.get("image_urls", [])
    lock_price_cents = payload.get("lock_price_cents", 0) or 0
    visibility = payload.get("visibility", "public")

    locked = lock_price_cents > 0
    post_id = new_id("post")
    created_at = now_iso()

    # Build a minimal payload-like object for _content_from_payload
    class _FakeReq:
        def __init__(self):
            self.text = text
            self.body_format = "plain"
            self.body_markdown = None
            self.body_rich = None

    content = _content_from_payload(_FakeReq())

    post_item: Dict[str, Any] = {
        "pk": pk_post(post_id),
        "sk": sk_post(),
        "Entity": "Post",
        "post_id": post_id,
        "user_id": user_sub,
        "created_at": created_at,
        "published_at": created_at,
        "status": "published",
        "publish_at": None,
        "GSI2PK": f"POST_AUTHOR#{user_sub}",
        "GSI2SK": f"{created_at}#POST#{post_id}",
        **content,
        "image_urls": image_urls,
        "visibility": visibility,
        "locked": locked,
        "lock_type": "fixed_price" if locked else None,
        "unlock_price_cents": lock_price_cents if locked else None,
        "like_count": 0,
        "comment_count": 0,
    }
    ddb_put_item(post_item)

    _write_feed_ref_for_published_post(user_id=user_sub, post_id=post_id, created_at=created_at)

    # Fan out to followers (best-effort)
    try:
        from app.services.newsfeed_fanout import fan_out_post_to_followers
        fan_out_post_to_followers(author_id=user_sub, post_id=post_id, created_at=created_at)
    except Exception:
        logger.warning("Fan-out failed for scheduled post %s", post_id)

    # Increment post_count on profile
    try:
        from app.core.tables import T
        T.profile.update_item(
            Key={"user_sub": user_sub},
            UpdateExpression="ADD post_count :one",
            ExpressionAttributeValues={":one": 1},
        )
    except Exception:
        logger.warning("Failed to increment post_count for %s", user_sub)

    logger.info("Executed scheduled post %s for user %s", post_id, user_sub)


async def execute_scheduled_file_share(user_sub: str, payload: Dict[str, Any]) -> None:
    """Send a file share message from a scheduled action payload."""
    from app.routers.messaging import (
        tbl_msgs,
        tbl_parts,
        require_participant_active,
        _get_conversation_or_404,
    )
    from app.services.filemanager import get_node, share_node, norm_path
    from app.core.time import now_ts
    from boto3.dynamodb.conditions import Key
    import uuid

    conversation_id = payload.get("conversation_id", "")
    file_path = payload.get("file_path", "")
    permission = payload.get("permission", "view")

    if not conversation_id:
        raise ValueError("conversation_id is required in file_share payload")
    if not file_path:
        raise ValueError("file_path is required in file_share payload")

    # Validate participation
    require_participant_active(user_sub, conversation_id)
    _get_conversation_or_404(conversation_id)

    # Resolve file
    file_path_norm = norm_path(file_path, is_folder=None)
    node = get_node(user_sub, file_path_norm)

    # Share with participants
    try:
        resp = tbl_parts.query(IndexName="GSI1", KeyConditionExpression=Key("GSI1PK").eq(conversation_id))
        participants = resp.get("Items", [])
    except Exception:
        participants = []

    for participant in participants:
        pid = participant.get("user_id")
        if pid and pid != user_sub:
            try:
                share_node(user_sub, file_path_norm, pid, permission)
            except Exception:
                pass

    ts = now_ts()
    mid = "m_" + uuid.uuid4().hex

    file_share_data = {
        "path": node.get("path", file_path_norm),
        "name": node.get("name") or file_path_norm.rstrip("/").rsplit("/", 1)[-1],
        "size": int(node["size"]) if node.get("size") is not None else None,
        "content_type": node.get("content_type"),
        "permission": permission,
        "owner": user_sub,
        "is_encrypted": bool(node.get("is_encrypted")),
    }

    item = {
        "conversation_id": conversation_id,
        "message_id": mid,
        "sender_id": user_sub,
        "created_at": ts,
        "kind": "file_share",
        "reactions": {},
        "file_share": file_share_data,
    }

    tbl_msgs.put_item(Item=item)
    logger.info("Executed scheduled file_share message %s for user %s", mid, user_sub)


async def execute_scheduled_catalog_sale(user_sub: str, payload: Dict[str, Any]) -> None:
    """Activate or deactivate a catalog sale."""
    from app.core.tables import T

    product_id = payload.get("product_id", "")
    activate = payload.get("activate", True)

    if not product_id:
        raise ValueError("product_id is required in catalog_sale payload")

    # Find the product item -- catalog uses PK/SK pattern
    # The product is under catalog table with pk=CAT#<category_id>, sk=ITEM#<item_id>
    # We need to scan for the product_id. Products have an item_id field.
    # For simplicity, try to update using the stored category info from payload.
    category_id = payload.get("category_id", "")
    item_id = payload.get("item_id", product_id)

    if not category_id:
        raise ValueError("category_id is required in catalog_sale payload")

    cat_pk = f"CAT#{category_id}"
    item_sk = f"ITEM#{item_id}"

    if activate:
        sale_price = payload.get("sale_price_cents")
        sale_label = payload.get("sale_label", "")
        original_price = payload.get("original_price_cents")

        update_expr = "SET sale_price_cents = :sp, sale_label = :sl"
        vals = {":sp": sale_price, ":sl": sale_label}
        if original_price:
            update_expr += ", original_price_cents = :op"
            vals[":op"] = original_price

        T.catalog.update_item(
            Key={"PK": cat_pk, "SK": item_sk},
            UpdateExpression=update_expr,
            ExpressionAttributeValues=vals,
        )
        logger.info("Activated sale for product %s/%s", category_id, item_id)
    else:
        T.catalog.update_item(
            Key={"PK": cat_pk, "SK": item_sk},
            UpdateExpression="REMOVE sale_price_cents, sale_label",
        )
        logger.info("Deactivated sale for product %s/%s", category_id, item_id)
