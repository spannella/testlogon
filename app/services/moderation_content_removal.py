from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from boto3.dynamodb.conditions import Attr, Key
from fastapi import HTTPException

from app.core.aws import ddb
from app.core.tables import T

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
MESSAGES_TABLE = os.environ.get("DDB_MESSAGES", "Messages")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _latest_metadata(reports: list[dict[str, Any]]) -> dict[str, Any]:
    if not reports:
        return {}
    md = reports[0].get("metadata")
    return md if isinstance(md, dict) else {}


def _mark_feed_post_removed(*, post_id: str, ticket_id: str, admin_user_id: str) -> None:
    if not post_id:
        return
    ddb.Table(APP_TABLE).update_item(
        Key={"pk": f"POST#{post_id}", "sk": "META"},
        UpdateExpression=(
            "SET moderation_removed = :t, moderation_removed_at = :ts, "
            "moderation_removed_by_admin_user_id = :admin, moderation_source_ticket_id = :ticket, updated_at = :updated"
        ),
        ExpressionAttributeValues={
            ":t": True,
            ":ts": _now_iso(),
            ":admin": admin_user_id,
            ":ticket": ticket_id,
            ":updated": _now_iso(),
        },
    )


def _mark_feed_comment_removed(*, post_id: str, comment_id: str, ticket_id: str, admin_user_id: str) -> None:
    if not post_id or not comment_id:
        return
    resp = ddb.Table(APP_TABLE).query(
        KeyConditionExpression=Key("pk").eq(f"POST#{post_id}#COMMENTS"),
        FilterExpression=Attr("comment_id").eq(comment_id),
        Limit=1,
    )
    row = (resp.get("Items") or [None])[0]
    if not row:
        return
    ddb.Table(APP_TABLE).update_item(
        Key={"pk": row["pk"], "sk": row["sk"]},
        UpdateExpression=(
            "SET deleted = :t, moderation_removed = :t, moderation_removed_at = :ts, "
            "moderation_removed_by_admin_user_id = :admin, moderation_source_ticket_id = :ticket, updated_at = :updated, "
            "#body = :null, body_plain = :null, body_markdown = :null, body_markdown_html = :null, body_rich = :null"
        ),
        ExpressionAttributeNames={"#body": "body"},
        ExpressionAttributeValues={
            ":t": True,
            ":ts": _now_iso(),
            ":admin": admin_user_id,
            ":ticket": ticket_id,
            ":updated": _now_iso(),
            ":null": None,
        },
    )


def _mark_feed_media_removed(*, post_id: str, media_index: int | None, ticket_id: str, admin_user_id: str) -> None:
    if not post_id:
        return
    table = ddb.Table(APP_TABLE)
    post = table.get_item(Key={"pk": f"POST#{post_id}", "sk": "META"}).get("Item") or {}
    image_urls = list(post.get("image_urls") or [])
    removed_media: list[str] = list(post.get("moderation_removed_media") or [])
    if media_index is not None and 0 <= media_index < len(image_urls):
        removed_media.append(str(image_urls[media_index]))
        image_urls.pop(media_index)

    table.update_item(
        Key={"pk": f"POST#{post_id}", "sk": "META"},
        UpdateExpression=(
            "SET image_urls = :image_urls, moderation_removed_media = :removed_media, moderation_removed = :t, "
            "moderation_removed_at = :ts, moderation_removed_by_admin_user_id = :admin, "
            "moderation_source_ticket_id = :ticket, updated_at = :updated"
        ),
        ExpressionAttributeValues={
            ":image_urls": image_urls,
            ":removed_media": removed_media,
            ":t": True,
            ":ts": _now_iso(),
            ":admin": admin_user_id,
            ":ticket": ticket_id,
            ":updated": _now_iso(),
        },
    )


def _mark_message_removed(*, conversation_id: str, message_id: str, ticket_id: str, admin_user_id: str, media_only: bool) -> None:
    if not conversation_id or not message_id:
        return
    table = ddb.Table(MESSAGES_TABLE)
    item = table.get_item(Key={"conversation_id": conversation_id, "message_id": message_id}).get("Item") or {}
    if not item:
        return

    expr = (
        "SET moderation_hidden = :t, moderation_removed_at = :ts, moderation_removed_by_admin_user_id = :admin, "
        "moderation_source_ticket_id = :ticket, updated_at = :updated"
    )
    names: dict[str, str] | None = None
    values: dict[str, Any] = {
        ":t": True,
        ":ts": int(datetime.now(timezone.utc).timestamp()),
        ":admin": admin_user_id,
        ":ticket": ticket_id,
        ":updated": int(datetime.now(timezone.utc).timestamp()),
    }

    if media_only:
        expr += ", attachments = :empty_attachments, image = :null, file = :null, audio = :null, video = :null"
        values[":empty_attachments"] = []
        values[":null"] = None
    else:
        expr += ", #text = :removed_text, attachments = :empty_attachments, image = :null, file = :null, audio = :null, video = :null"
        names = {"#text": "text"}
        values[":removed_text"] = "[removed by moderation]"
        values[":empty_attachments"] = []
        values[":null"] = None

    kwargs: dict[str, Any] = {
        "Key": {"conversation_id": conversation_id, "message_id": message_id},
        "UpdateExpression": expr,
        "ExpressionAttributeValues": values,
    }
    if names:
        kwargs["ExpressionAttributeNames"] = names
    table.update_item(**kwargs)


def _revert_profile_photo(*, user_sub: str, ticket_id: str, admin_user_id: str) -> None:
    if not user_sub:
        return
    item = T.profile.get_item(Key={"user_sub": user_sub}).get("Item") or {"user_sub": user_sub, "profile": {}, "audit": []}
    profile = dict(item.get("profile") or {})
    current = profile.get("profile_photo_url")
    previous = profile.get("previous_approved_profile_photo_url")

    profile["moderation_last_removed_profile_photo_url"] = current
    profile["moderation_last_removed_ticket_id"] = ticket_id
    profile["moderation_last_removed_by_admin_user_id"] = admin_user_id
    profile["moderation_last_removed_at"] = _now_iso()
    profile["profile_photo_url"] = previous or None

    T.profile.put_item(
        Item={
            **item,
            "user_sub": user_sub,
            "profile": profile,
        }
    )


def apply_content_removal(*, ticket: dict[str, Any], reports: list[dict[str, Any]], ticket_id: str, admin_user_id: str) -> None:
    content_type = str(ticket.get("content_type") or "")
    content_id = str(ticket.get("content_id") or "")
    metadata = _latest_metadata(reports)

    if content_type == "feed_post":
        post_id = str(metadata.get("post_id") or content_id)
        _mark_feed_post_removed(post_id=post_id, ticket_id=ticket_id, admin_user_id=admin_user_id)
        return

    if content_type == "feed_comment":
        _mark_feed_comment_removed(
            post_id=str(metadata.get("post_id") or ""),
            comment_id=content_id,
            ticket_id=ticket_id,
            admin_user_id=admin_user_id,
        )
        return

    if content_type == "feed_media":
        post_id = str(metadata.get("post_id") or content_id)
        media_index_raw = metadata.get("media_index")
        media_index = int(media_index_raw) if media_index_raw is not None else None
        _mark_feed_media_removed(post_id=post_id, media_index=media_index, ticket_id=ticket_id, admin_user_id=admin_user_id)
        return

    if content_type == "message":
        _mark_message_removed(
            conversation_id=str(metadata.get("conversation_id") or ""),
            message_id=content_id,
            ticket_id=ticket_id,
            admin_user_id=admin_user_id,
            media_only=False,
        )
        return

    if content_type == "message_media":
        _mark_message_removed(
            conversation_id=str(metadata.get("conversation_id") or ""),
            message_id=content_id,
            ticket_id=ticket_id,
            admin_user_id=admin_user_id,
            media_only=True,
        )
        return

    if content_type == "profile_photo":
        _revert_profile_photo(user_sub=content_id, ticket_id=ticket_id, admin_user_id=admin_user_id)
        return

    raise HTTPException(status_code=400, detail="unsupported content type for removal")
