"""Marketing Agent service (AGENT-017).

The Marketing Agent is an agent *type* that turns completed feature work into
marketing collateral: release notes, blog posts, social copy, newsletters and
SEO metadata. It owns:

* marketing content CRUD on the ``marketing_content`` table (per-user scoped)
* a deterministic content lifecycle state machine
  (draft -> review -> approved -> scheduled -> published -> archived)
* a content calendar query (scheduled + published in a month)
* engagement tracking (views/clicks/signups/shares) on ``marketing_engagement``
* per-user Marketing Agent configuration (brand voice / audience / cadence)
  stored on the ``agent_types`` registry table
* deterministic, mockable content generation from feature tickets

Real LLM-backed generation is gated behind
``S.marketing_agent_execute_commands`` (default off, always off in E2E). When
disabled the generation path is deterministic so tests are reproducible.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from app.core.aws import ddb
from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services import tickets as tickets_svc

logger = logging.getLogger("app.agent_marketing")

MARKETING_AGENT_TYPE = "marketing"

CONTENT_TYPES = (
    "blog_post",
    "social_twitter",
    "social_linkedin",
    "social_instagram",
    "newsletter",
    "release_notes",
    "changelog",
    "landing_page",
    "meta_seo",
)

CONTENT_STATUSES = (
    "draft",
    "review",
    "approved",
    "scheduled",
    "published",
    "archived",
)

ENGAGEMENT_EVENTS = ("view", "click", "signup", "share")
_EVENT_TO_FIELD = {
    "view": "views",
    "click": "clicks",
    "signup": "signups",
    "share": "shares",
}

_MAX_BODY = 20_000
_MAX_TITLE = 200
_MAX_SUMMARY = 500
_MAX_FEATURE_REFS = 10
_MAX_VARIATIONS = 5
_ENGAGEMENT_TTL_SECONDS = 365 * 86400

# JSON-serialized fields stored as strings on the content item.
_JSON_FIELDS = ("feature_refs", "tags", "seo_meta", "variations")

_DEFAULT_MARKETING_CONFIG: Dict[str, Any] = {
    "trigger_on_feature_completion": True,
    "auto_generate_content_types": ["blog_post", "social_twitter", "changelog", "release_notes"],
    "brand_voice": {
        "tone": "professional yet approachable",
        "vocabulary_level": "accessible",
        "personality_traits": ["helpful", "innovative", "reliable"],
        "words_to_avoid": ["synergy", "leverage", "disrupt"],
        "tagline": "Build better, ship faster",
    },
    "target_audience": {
        "primary": "SaaS platform operators",
        "secondary": "developers",
        "demographics": "tech-savvy, 25-45",
    },
    "social_platforms": ["twitter", "linkedin"],
    "content_calendar_enabled": True,
    "newsletter_frequency": "weekly",
    "newsletter_day": "friday",
    "ab_test_variations": 2,
    "seo_keywords": ["saas platform", "messaging", "creator economy"],
    "max_content_per_feature": 3,
}

_CONFIG_FIELDS = tuple(_DEFAULT_MARKETING_CONFIG.keys())


# ---------------------------------------------------------------------------
# Table bootstrap (idempotent; additive per AGENT-001/017)
# ---------------------------------------------------------------------------

_BOOTSTRAPPED = False


def ensure_tables() -> None:
    """Create the marketing_content / marketing_engagement / agent_types tables
    on first use if absent. The canonical definitions live in local-ddb-init,
    but this keeps the feature self-contained in any environment.
    """
    global _BOOTSTRAPPED
    if _BOOTSTRAPPED:
        return
    client = ddb.meta.client
    specs = [
        (
            S.marketing_content_table_name,
            [
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            [
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "GSI1PK", "AttributeType": "S"},
                {"AttributeName": "GSI1SK", "AttributeType": "N"},
                {"AttributeName": "GSI2PK", "AttributeType": "S"},
                {"AttributeName": "GSI2SK", "AttributeType": "N"},
                {"AttributeName": "GSI3PK", "AttributeType": "S"},
                {"AttributeName": "GSI3SK", "AttributeType": "N"},
            ],
            [
                {
                    "IndexName": "GSI1",
                    "KeySchema": [
                        {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
                {
                    "IndexName": "GSI2",
                    "KeySchema": [
                        {"AttributeName": "GSI2PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI2SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
                {
                    "IndexName": "GSI3",
                    "KeySchema": [
                        {"AttributeName": "GSI3PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI3SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
        ),
        (
            S.marketing_engagement_table_name,
            [
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            [
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            [],
        ),
        (
            S.agent_types_table_name,
            [
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            [
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            [],
        ),
    ]
    for name, key_schema, attr_defs, gsi in specs:
        kwargs: Dict[str, Any] = {
            "TableName": name,
            "KeySchema": key_schema,
            "AttributeDefinitions": attr_defs,
            "BillingMode": "PAY_PER_REQUEST",
        }
        if gsi:
            kwargs["GlobalSecondaryIndexes"] = gsi
        try:
            client.create_table(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("ResourceInUseException",):
                logger.warning("ensure_tables: could not create %s: %s", name, exc)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("ensure_tables: %s create error: %s", name, exc)
    _BOOTSTRAPPED = True


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------


def _user_pk(user_id: str) -> str:
    return f"USER#{user_id}"


def _content_sk(content_id: str) -> str:
    return f"CONTENT#{content_id}"


def _content_pk_engagement(content_id: str) -> str:
    return f"CONTENT#{content_id}"


def _type_pk(type_id: str) -> str:
    return f"TYPE#{type_id}"


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------


def _to_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _decode_json_field(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (list, dict)):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            return None
    return value


def _item_to_content(item: Dict[str, Any]) -> Dict[str, Any]:
    """Render a stored DDB item into the public content dict."""
    out: Dict[str, Any] = {
        "content_id": item.get("content_id", ""),
        "user_id": item.get("user_id", ""),
        "agent_id": item.get("agent_id"),
        "content_type": item.get("content_type", ""),
        "title": item.get("title", ""),
        "body": item.get("body", ""),
        "summary": item.get("summary"),
        "status": item.get("status", "draft"),
        "target_platform": item.get("target_platform"),
        "scheduled_publish_at": _to_int(item.get("scheduled_publish_at")),
        "published_at": _to_int(item.get("published_at")),
        "created_at": _to_int(item.get("created_at")) or 0,
        "updated_at": _to_int(item.get("updated_at")) or 0,
    }
    for f in _JSON_FIELDS:
        out[f] = _decode_json_field(item.get(f))
    return out


# ---------------------------------------------------------------------------
# Content CRUD
# ---------------------------------------------------------------------------


def _validate_content_type(content_type: str) -> None:
    if content_type not in CONTENT_TYPES:
        raise ValueError(f"Invalid content_type: {content_type}")


def create_content(
    *,
    user_id: str,
    agent_id: Optional[str] = None,
    content_type: str,
    title: str,
    body: str,
    summary: Optional[str] = None,
    feature_refs: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
    seo_meta: Optional[Dict[str, Any]] = None,
    variations: Optional[List[Dict[str, str]]] = None,
    target_platform: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a marketing content draft."""
    ensure_tables()
    _validate_content_type(content_type)
    if not title or len(title) > _MAX_TITLE:
        raise ValueError("title must be 1..200 characters")
    if not body or len(body) > _MAX_BODY:
        raise ValueError(f"body must not exceed {_MAX_BODY} characters")
    if feature_refs and len(feature_refs) > _MAX_FEATURE_REFS:
        raise ValueError(f"Maximum {_MAX_FEATURE_REFS} feature references per content piece")
    if variations and len(variations) > _MAX_VARIATIONS:
        raise ValueError(f"Maximum {_MAX_VARIATIONS} A/B variations per content piece")

    content_id = uuid.uuid4().hex
    ts = now_ts()
    item: Dict[str, Any] = {
        "pk": _user_pk(user_id),
        "sk": _content_sk(content_id),
        "content_id": content_id,
        "user_id": user_id,
        "content_type": content_type,
        "title": title,
        "body": body,
        "status": "draft",
        "created_at": ts,
        "updated_at": ts,
        "GSI1PK": f"USER#{user_id}#TYPE#{content_type}",
        "GSI1SK": ts,
        "GSI2PK": f"USER#{user_id}#STATUS#draft",
        "GSI2SK": ts,
    }
    if agent_id:
        item["agent_id"] = agent_id
    if summary:
        item["summary"] = summary
    if target_platform:
        item["target_platform"] = target_platform
    if feature_refs is not None:
        item["feature_refs"] = json.dumps(list(feature_refs))
    if tags is not None:
        item["tags"] = json.dumps(list(tags))
    if seo_meta is not None:
        item["seo_meta"] = json.dumps(seo_meta)
    if variations is not None:
        item["variations"] = json.dumps(list(variations))

    T.marketing_content.put_item(Item=item)
    return _item_to_content(item)


def _get_item(*, user_id: str, content_id: str) -> Optional[Dict[str, Any]]:
    ensure_tables()
    resp = T.marketing_content.get_item(
        Key={"pk": _user_pk(user_id), "sk": _content_sk(content_id)}
    )
    return resp.get("Item")


def get_content(*, user_id: str, content_id: str) -> Optional[Dict[str, Any]]:
    """Get a single content piece. Returns None when not found / not owned."""
    item = _get_item(user_id=user_id, content_id=content_id)
    if not item:
        return None
    return _item_to_content(item)


def list_content(
    *,
    user_id: str,
    content_type: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 25,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List marketing content, filtered by type or status (status wins)."""
    ensure_tables()
    limit = max(1, min(int(limit or 25), 100))
    query_kwargs: Dict[str, Any] = {"Limit": limit, "ScanIndexForward": False}
    last_key = decode_cursor(cursor) if cursor else None
    if last_key:
        query_kwargs["ExclusiveStartKey"] = last_key

    if status:
        if status not in CONTENT_STATUSES:
            raise ValueError(f"Invalid status: {status}")
        query_kwargs["IndexName"] = "GSI2"
        query_kwargs["KeyConditionExpression"] = Key("GSI2PK").eq(
            f"USER#{user_id}#STATUS#{status}"
        )
    elif content_type:
        _validate_content_type(content_type)
        query_kwargs["IndexName"] = "GSI1"
        query_kwargs["KeyConditionExpression"] = Key("GSI1PK").eq(
            f"USER#{user_id}#TYPE#{content_type}"
        )
    else:
        query_kwargs["KeyConditionExpression"] = Key("pk").eq(_user_pk(user_id)) & Key(
            "sk"
        ).begins_with("CONTENT#")

    resp = T.marketing_content.query(**query_kwargs)
    items = [_item_to_content(it) for it in resp.get("Items", [])]
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))
    return {"items": items, "cursor": next_cursor, "count": len(items)}


def update_content(*, user_id: str, content_id: str, **fields: Any) -> Optional[Dict[str, Any]]:
    """Update content fields (title, body, status, etc.). Returns None if absent."""
    item = _get_item(user_id=user_id, content_id=content_id)
    if not item:
        return None

    set_parts: List[str] = ["updated_at = :ts"]
    names: Dict[str, str] = {}
    values: Dict[str, Any] = {":ts": now_ts()}

    simple = {
        "title": _MAX_TITLE,
        "body": _MAX_BODY,
        "summary": _MAX_SUMMARY,
        "target_platform": 50,
    }
    for key, max_len in simple.items():
        if key in fields and fields[key] is not None:
            val = fields[key]
            if isinstance(val, str) and len(val) > max_len:
                raise ValueError(f"{key} exceeds maximum length")
            placeholder = f":{key}"
            names[f"#{key}"] = key
            set_parts.append(f"#{key} = {placeholder}")
            values[placeholder] = val

    if "content_type" in fields and fields["content_type"] is not None:
        ct = fields["content_type"]
        _validate_content_type(ct)
        names["#content_type"] = "content_type"
        set_parts.append("#content_type = :content_type")
        values[":content_type"] = ct
        names["#g1pk"] = "GSI1PK"
        set_parts.append("#g1pk = :g1pk")
        values[":g1pk"] = f"USER#{user_id}#TYPE#{ct}"

    for jf in _JSON_FIELDS:
        if jf in fields and fields[jf] is not None:
            if jf == "feature_refs" and len(fields[jf]) > _MAX_FEATURE_REFS:
                raise ValueError(f"Maximum {_MAX_FEATURE_REFS} feature references per content piece")
            if jf == "variations" and len(fields[jf]) > _MAX_VARIATIONS:
                raise ValueError(f"Maximum {_MAX_VARIATIONS} A/B variations per content piece")
            names[f"#{jf}"] = jf
            set_parts.append(f"#{jf} = :{jf}")
            values[f":{jf}"] = json.dumps(fields[jf])

    T.marketing_content.update_item(
        Key={"pk": _user_pk(user_id), "sk": _content_sk(content_id)},
        UpdateExpression="SET " + ", ".join(set_parts),
        ExpressionAttributeNames=names or None,
        ExpressionAttributeValues=values,
    )
    return get_content(user_id=user_id, content_id=content_id)


def _set_status(
    *, user_id: str, content_id: str, status: str, extra: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    ts = now_ts()
    set_parts = [
        "#st = :st",
        "updated_at = :ts",
        "GSI2PK = :g2pk",
        "GSI2SK = :g2sk",
    ]
    values: Dict[str, Any] = {
        ":st": status,
        ":ts": ts,
        ":g2pk": f"USER#{user_id}#STATUS#{status}",
        ":g2sk": ts,
    }
    for key, val in (extra or {}).items():
        set_parts.append(f"{key} = :{key}")
        values[f":{key}"] = val
    T.marketing_content.update_item(
        Key={"pk": _user_pk(user_id), "sk": _content_sk(content_id)},
        UpdateExpression="SET " + ", ".join(set_parts),
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues=values,
    )
    return get_content(user_id=user_id, content_id=content_id)  # type: ignore[return-value]


def approve_content(*, user_id: str, content_id: str) -> Optional[Dict[str, Any]]:
    """Approve content for publishing or scheduling."""
    item = _get_item(user_id=user_id, content_id=content_id)
    if not item:
        return None
    status = item.get("status")
    if status not in ("draft", "review"):
        raise PermissionError(f"Cannot approve content with status: {status}")
    return _set_status(user_id=user_id, content_id=content_id, status="approved")


def schedule_content(*, user_id: str, content_id: str, publish_at: int) -> Optional[Dict[str, Any]]:
    """Schedule approved content for future publish."""
    item = _get_item(user_id=user_id, content_id=content_id)
    if not item:
        return None
    status = item.get("status")
    if status != "approved":
        raise PermissionError(f"Cannot schedule content with status: {status}")
    if publish_at <= now_ts():
        raise ValueError("publish_at must be in the future")
    return _set_status(
        user_id=user_id,
        content_id=content_id,
        status="scheduled",
        extra={
            "scheduled_publish_at": int(publish_at),
            "GSI3PK": f"USER#{user_id}#SCHEDULED",
            "GSI3SK": int(publish_at),
        },
    )


def publish_content(*, user_id: str, content_id: str) -> Optional[Dict[str, Any]]:
    """Publish content immediately."""
    item = _get_item(user_id=user_id, content_id=content_id)
    if not item:
        return None
    status = item.get("status")
    if status not in ("approved", "scheduled"):
        raise PermissionError(f"Cannot publish content with status: {status}")
    return _set_status(
        user_id=user_id,
        content_id=content_id,
        status="published",
        extra={"published_at": now_ts()},
    )


def archive_content(*, user_id: str, content_id: str) -> Optional[Dict[str, Any]]:
    """Archive content."""
    item = _get_item(user_id=user_id, content_id=content_id)
    if not item:
        return None
    return _set_status(user_id=user_id, content_id=content_id, status="archived")


def delete_content(*, user_id: str, content_id: str) -> Optional[Dict[str, Any]]:
    """Hard-delete a draft content piece. Only allowed for status=draft."""
    item = _get_item(user_id=user_id, content_id=content_id)
    if not item:
        return None
    if item.get("status") != "draft":
        raise PermissionError("Only draft content can be deleted; use archive instead")
    T.marketing_content.delete_item(
        Key={"pk": _user_pk(user_id), "sk": _content_sk(content_id)}
    )
    return {"ok": True, "content_id": content_id, "deleted": True}


# ---------------------------------------------------------------------------
# Content calendar
# ---------------------------------------------------------------------------


def _month_bounds(month: str) -> tuple[int, int]:
    """Return (start_ts, end_ts) Unix seconds for a YYYY-MM month string."""
    try:
        year_s, mon_s = month.split("-", 1)
        year = int(year_s)
        mon = int(mon_s)
        if not (1 <= mon <= 12):
            raise ValueError
    except (ValueError, AttributeError) as exc:
        raise ValueError("month must be in YYYY-MM format") from exc
    start = datetime(year, mon, 1, tzinfo=timezone.utc)
    if mon == 12:
        end = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
    else:
        end = datetime(year, mon + 1, 1, tzinfo=timezone.utc)
    return int(start.timestamp()), int(end.timestamp())


def get_calendar(*, user_id: str, month: str) -> List[Dict[str, Any]]:
    """Get content calendar for a given month (YYYY-MM): scheduled + published."""
    ensure_tables()
    start, end = _month_bounds(month)
    entries: Dict[str, Dict[str, Any]] = {}

    # Scheduled content via GSI3 (scheduled_publish_at within month).
    try:
        resp = T.marketing_content.query(
            IndexName="GSI3",
            KeyConditionExpression=Key("GSI3PK").eq(f"USER#{user_id}#SCHEDULED")
            & Key("GSI3SK").between(start, end - 1),
        )
        for it in resp.get("Items", []):
            cid = it.get("content_id", "")
            entries[cid] = {
                "content_id": cid,
                "title": it.get("title", ""),
                "content_type": it.get("content_type", ""),
                "status": it.get("status", ""),
                "date": _to_int(it.get("scheduled_publish_at")) or 0,
            }
    except ClientError:
        pass

    # Published content within month (scan owner partition, filter on published_at).
    resp = T.marketing_content.query(
        KeyConditionExpression=Key("pk").eq(_user_pk(user_id))
        & Key("sk").begins_with("CONTENT#")
    )
    for it in resp.get("Items", []):
        published_at = _to_int(it.get("published_at"))
        if it.get("status") == "published" and published_at and start <= published_at < end:
            cid = it.get("content_id", "")
            entries[cid] = {
                "content_id": cid,
                "title": it.get("title", ""),
                "content_type": it.get("content_type", ""),
                "status": "published",
                "date": published_at,
            }
    return sorted(entries.values(), key=lambda e: e["date"])


# ---------------------------------------------------------------------------
# Engagement tracking
# ---------------------------------------------------------------------------


def _day_key(ts: Optional[int] = None) -> str:
    dt = datetime.fromtimestamp(ts if ts is not None else now_ts(), tz=timezone.utc)
    return dt.strftime("%Y-%m-%d")


def record_engagement(
    *, content_id: str, event_type: str, variant_id: Optional[str] = None
) -> None:
    """Record an engagement event (view, click, signup, share). Atomic increment."""
    ensure_tables()
    if event_type not in ENGAGEMENT_EVENTS:
        raise ValueError(f"Invalid event_type: {event_type}")
    field = _EVENT_TO_FIELD[event_type]
    day = _day_key()
    set_extra = ""
    values: Dict[str, Any] = {":one": 1, ":ttl": now_ts() + _ENGAGEMENT_TTL_SECONDS}
    if variant_id:
        set_extra = ", variant_id = :variant"
        values[":variant"] = variant_id
    T.marketing_engagement.update_item(
        Key={"pk": _content_pk_engagement(content_id), "sk": f"DAY#{day}"},
        UpdateExpression=(
            f"ADD #f :one SET #ttl = :ttl{set_extra}"
        ),
        ExpressionAttributeNames={"#f": field, "#ttl": "ttl"},
        ExpressionAttributeValues=values,
    )


def get_engagement_stats(*, user_id: str, content_id: str, days: int = 30) -> Optional[Dict[str, Any]]:
    """Get engagement stats for a content piece. None if content not owned."""
    ensure_tables()
    # Ownership check.
    if _get_item(user_id=user_id, content_id=content_id) is None:
        return None
    days = max(1, min(int(days or 30), 365))
    cutoff = _day_key(now_ts() - days * 86400)
    resp = T.marketing_engagement.query(
        KeyConditionExpression=Key("pk").eq(_content_pk_engagement(content_id))
        & Key("sk").between(f"DAY#{cutoff}", "DAY#9999-99-99"),
    )
    total = {"views": 0, "clicks": 0, "signups": 0, "shares": 0}
    by_day: List[Dict[str, Any]] = []
    by_variant: Dict[str, Dict[str, int]] = {}
    for it in resp.get("Items", []):
        v = _to_int(it.get("views")) or 0
        c = _to_int(it.get("clicks")) or 0
        s = _to_int(it.get("signups")) or 0
        sh = _to_int(it.get("shares")) or 0
        total["views"] += v
        total["clicks"] += c
        total["signups"] += s
        total["shares"] += sh
        date = str(it.get("sk", "")).replace("DAY#", "")
        by_day.append({"date": date, "views": v, "clicks": c, "signups": s})
        variant = it.get("variant_id")
        if variant:
            agg = by_variant.setdefault(variant, {"views": 0, "clicks": 0, "signups": 0})
            agg["views"] += v
            agg["clicks"] += c
            agg["signups"] += s
    by_day.sort(key=lambda d: d["date"])
    views = total["views"]
    click_rate = round(total["clicks"] / views, 4) if views else 0.0
    signup_rate = round(total["signups"] / views, 4) if views else 0.0
    out: Dict[str, Any] = {
        "content_id": content_id,
        "total_views": total["views"],
        "total_clicks": total["clicks"],
        "total_signups": total["signups"],
        "total_shares": total["shares"],
        "click_rate": click_rate,
        "signup_rate": signup_rate,
        "by_day": by_day,
    }
    if by_variant:
        out["by_variant"] = [
            {"variant_id": k, **v} for k, v in sorted(by_variant.items())
        ]
    return out


def get_engagement_summary(*, user_id: str, days: int = 30) -> Dict[str, Any]:
    """Get aggregate engagement across all of the user's content."""
    ensure_tables()
    resp = T.marketing_content.query(
        KeyConditionExpression=Key("pk").eq(_user_pk(user_id))
        & Key("sk").begins_with("CONTENT#")
    )
    items = resp.get("Items", [])
    total_views = total_clicks = total_signups = 0
    performers: List[Dict[str, Any]] = []
    rate_count = 0
    sum_click_rate = 0.0
    sum_signup_rate = 0.0
    for it in items:
        cid = it.get("content_id", "")
        stats = get_engagement_stats(user_id=user_id, content_id=cid, days=days) or {}
        v = int(stats.get("total_views", 0) or 0)
        c = int(stats.get("total_clicks", 0) or 0)
        s = int(stats.get("total_signups", 0) or 0)
        total_views += v
        total_clicks += c
        total_signups += s
        if v:
            rate_count += 1
            sum_click_rate += float(stats.get("click_rate", 0.0) or 0.0)
            sum_signup_rate += float(stats.get("signup_rate", 0.0) or 0.0)
        performers.append({"content_id": cid, "title": it.get("title", ""), "clicks": c})
    performers.sort(key=lambda p: p["clicks"], reverse=True)
    return {
        "total_content": len(items),
        "total_views": total_views,
        "total_clicks": total_clicks,
        "total_signups": total_signups,
        "avg_click_rate": round(sum_click_rate / rate_count, 4) if rate_count else 0.0,
        "avg_signup_rate": round(sum_signup_rate / rate_count, 4) if rate_count else 0.0,
        "top_performing": performers[:5],
    }


# ---------------------------------------------------------------------------
# Marketing Agent configuration (on agent_types registry table)
# ---------------------------------------------------------------------------


def _config_pk(user_id: str) -> str:
    return f"TYPE#marketing#{user_id}"


def get_marketing_config(*, user_id: str) -> Optional[Dict[str, Any]]:
    """Fetch the user's Marketing Agent config (None if never set)."""
    ensure_tables()
    resp = T.agent_types.get_item(
        Key={"pk": _config_pk(user_id), "sk": "CONFIG"}
    )
    item = resp.get("Item")
    if not item:
        return None
    config = item.get("marketing_config")
    if not config:
        return None
    return _coerce_config_numbers(dict(config))


def _coerce_config_numbers(config: Dict[str, Any]) -> Dict[str, Any]:
    for field in ("ab_test_variations", "max_content_per_feature"):
        if field in config and config[field] is not None:
            try:
                config[field] = int(config[field])
            except (TypeError, ValueError):
                pass
    return config


def update_marketing_config(*, user_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """Validate and persist the user's Marketing Agent config (merge over default)."""
    ensure_tables()
    current = get_marketing_config(user_id=user_id) or dict(_DEFAULT_MARKETING_CONFIG)
    merged = dict(current)
    for key in _CONFIG_FIELDS:
        if key in config and config[key] is not None:
            merged[key] = config[key]
    merged = _coerce_config_numbers(merged)
    ts = now_ts()
    T.agent_types.put_item(
        Item={
            "pk": _config_pk(user_id),
            "sk": "CONFIG",
            "agent_type": MARKETING_AGENT_TYPE,
            "owner_sub": user_id,
            "marketing_config": merged,
            "updated_at": ts,
        }
    )
    result = dict(merged)
    result["updated_at"] = ts
    return result


def default_marketing_config() -> Dict[str, Any]:
    return dict(_DEFAULT_MARKETING_CONFIG)


# ---------------------------------------------------------------------------
# Deterministic content generation (mockable; gated)
# ---------------------------------------------------------------------------


def _ticket_summary(ticket: Dict[str, Any]) -> tuple[str, str]:
    subject = ticket.get("subject", "")
    description = ""
    messages = ticket.get("messages") or []
    if messages:
        description = messages[0].get("body", "") or ""
    return subject, description


def _generate_one(
    *,
    content_type: str,
    tickets: List[Dict[str, Any]],
    feature_ticket_ids: List[str],
    config: Dict[str, Any],
    tone_override: Optional[str],
    audience_override: Optional[str],
) -> Dict[str, Any]:
    """Produce a single deterministic content draft from feature tickets."""
    brand_voice = config.get("brand_voice") or {}
    tone = tone_override or brand_voice.get("tone", "professional")
    audience = audience_override or (config.get("target_audience") or {}).get(
        "primary", "customers"
    )
    subjects = [s for s, _ in (_ticket_summary(t) for t in tickets) if s]
    feature_list = ", ".join(subjects) or "recent platform updates"
    seo_keywords = config.get("seo_keywords") or []

    if content_type == "social_twitter":
        title = f"New: {feature_list[:80]}"
        body = (f"🚀 We just shipped {feature_list}! "
                f"Built for {audience}. #shipit")[:280]
        target_platform = "twitter"
    elif content_type == "social_linkedin":
        title = f"Announcing {feature_list[:120]}"
        body = (f"We are excited to share that we've shipped {feature_list}. "
                f"Designed with {audience} in mind. Tone: {tone}.")
        target_platform = "linkedin"
    elif content_type == "changelog":
        title = f"Changelog: {feature_list[:140]}"
        lines = [f"- {s}" for s in subjects] or ["- General improvements"]
        body = "## Changelog\n\n" + "\n".join(lines)
        target_platform = "changelog"
    elif content_type == "release_notes":
        title = f"Release Notes: {feature_list[:140]}"
        lines = [f"### {s}\n\nShipped and available now." for s in subjects] or [
            "### Improvements\n\nVarious enhancements."
        ]
        body = "# Release Notes\n\n" + "\n\n".join(lines)
        target_platform = "release_notes"
    elif content_type == "newsletter":
        title = f"This week: {feature_list[:120]}"
        body = (f"Hi there,\n\nHere's what's new: {feature_list}.\n\n"
                f"Written for {audience}.\n\nThanks for reading!")
        target_platform = "email"
    elif content_type == "meta_seo":
        title = f"{feature_list[:60]}"
        body = f"Discover {feature_list}. Built for {audience}."
        target_platform = "seo"
    elif content_type == "landing_page":
        title = f"{feature_list[:120]}"
        body = (f"# {feature_list}\n\nThe new way for {audience} to build better.\n\n"
                f"Tone: {tone}.")
        target_platform = "landing"
    else:  # blog_post and fallback
        content_type = "blog_post"
        title = f"Introducing {feature_list[:120]}"
        body = (f"## Introducing {feature_list}\n\n"
                f"We're thrilled to announce {feature_list}, built for {audience}.\n\n"
                f"This update reflects our commitment to shipping value. (tone: {tone})")
        target_platform = "blog"

    seo_meta = {
        "title": title[:60],
        "description": body[:155],
        "keywords": list(seo_keywords)[:10],
    }
    return {
        "content_type": content_type,
        "title": title[:_MAX_TITLE],
        "body": body[:_MAX_BODY],
        "summary": (body[:200]),
        "feature_refs": list(feature_ticket_ids)[:_MAX_FEATURE_REFS],
        "tags": ["auto-generated"],
        "seo_meta": seo_meta,
        "target_platform": target_platform,
    }


def generate_content_for_feature(
    *,
    user_id: str,
    agent_id: Optional[str],
    feature_ticket_ids: List[str],
    content_types: Optional[List[str]] = None,
    tone_override: Optional[str] = None,
    target_audience_override: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate marketing content drafts for one or more feature tickets.

    Deterministic + mockable. When ``S.marketing_agent_execute_commands`` is on
    this would dispatch to a real LLM via the Worker Agent Framework; for now the
    mock path is always used so the workflow is fully testable. Always creates
    drafts (never auto-publishes — security §7).
    """
    ensure_tables()
    config = get_marketing_config(user_id=user_id) or default_marketing_config()
    if not content_types:
        content_types = list(config.get("auto_generate_content_types") or ["blog_post", "changelog"])
    max_per = int(config.get("max_content_per_feature", 3) or 3)
    content_types = list(content_types)[:max_per]

    tickets: List[Dict[str, Any]] = []
    missing: List[str] = []
    for tid in feature_ticket_ids:
        ticket = tickets_svc.STORE.get_ticket(tid)
        if ticket:
            tickets.append(ticket)
        else:
            missing.append(tid)

    created: List[Dict[str, Any]] = []
    for ct in content_types:
        if ct not in CONTENT_TYPES:
            continue
        draft = _generate_one(
            content_type=ct,
            tickets=tickets,
            feature_ticket_ids=feature_ticket_ids,
            config=config,
            tone_override=tone_override,
            audience_override=target_audience_override,
        )
        created.append(
            create_content(
                user_id=user_id,
                agent_id=agent_id,
                **draft,
            )
        )
    return {
        "status": "completed",
        "executed": bool(getattr(S, "marketing_agent_execute_commands", False)),
        "content_types_requested": list(content_types),
        "feature_ticket_ids": list(feature_ticket_ids),
        "missing_ticket_ids": missing,
        "contents": created,
        "count": len(created),
    }
