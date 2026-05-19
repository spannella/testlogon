#!/usr/bin/env python3
from __future__ import annotations

from typing import Any, Dict, Optional

from boto3.dynamodb.conditions import Attr

from app.core.aws import ddb
from app.core.settings import S


APP_TABLE = S.app_table or "app_single_table"


def _scan_posts(last_key: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    table = ddb.Table(APP_TABLE)
    kwargs: Dict[str, Any] = {
        "FilterExpression": Attr("Entity").eq("Post"),
        "ProjectionExpression": "pk, sk, post_id, user_id, created_at, GSI2PK, GSI2SK",
    }
    if last_key:
        kwargs["ExclusiveStartKey"] = last_key
    return table.scan(**kwargs)


def migrate() -> None:
    table = ddb.Table(APP_TABLE)
    updated = 0
    scanned = 0
    last_key: Optional[Dict[str, Any]] = None

    while True:
        resp = _scan_posts(last_key)
        items = resp.get("Items") or []
        for item in items:
            scanned += 1
            if item.get("GSI2PK") and item.get("GSI2SK"):
                continue
            user_id = str(item.get("user_id") or "").strip()
            post_id = str(item.get("post_id") or "").strip()
            created_at = str(item.get("created_at") or "").strip()
            if not user_id or not post_id or not created_at:
                continue
            table.update_item(
                Key={"pk": item["pk"], "sk": item["sk"]},
                UpdateExpression="SET GSI2PK = :gpk, GSI2SK = :gsk",
                ExpressionAttributeValues={
                    ":gpk": f"POST_AUTHOR#{user_id}",
                    ":gsk": f"{created_at}#POST#{post_id}",
                },
            )
            updated += 1

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    print({"table": APP_TABLE, "scanned_posts": scanned, "updated_posts": updated})


if __name__ == "__main__":
    migrate()
