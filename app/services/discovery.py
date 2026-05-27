from __future__ import annotations

import json
import logging
import math
import os
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError

from app.core.aws import ddb
from app.core.cursor import decode_cursor, encode_cursor
from app.core.tables import T

logger = logging.getLogger(__name__)

DDB_DISCOVERY_INDEX = os.getenv("DDB_DISCOVERY_INDEX", "DiscoveryIndex")
tbl_discovery = ddb.Table(DDB_DISCOVERY_INDEX)

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
tbl_app = ddb.Table(APP_TABLE)

MAX_PREFIX_LEN = 12
MAX_WORDS_FOR_PREFIX = 4


def build_discovery_tokens(display_name: str, username: Optional[str] = None) -> Set[str]:
    tokens: Set[str] = set()
    for field_value in [display_name, username]:
        if not field_value:
            continue
        normalized = field_value.strip().lower()
        words = normalized.split()[:MAX_WORDS_FOR_PREFIX]
        for word in words:
            word = word.strip()
            if not word:
                continue
            start = 1 if len(word) >= 2 else 2
            for i in range(start, min(len(word), MAX_PREFIX_LEN) + 1):
                tokens.add(word[:i])
        if normalized:
            tokens.add(normalized)
    return tokens


def index_user_for_discovery(user_id: str) -> int:
    from app.services.profile_discoverability import resolve_discoverability_state

    item = T.profile.get_item(Key={"user_sub": user_id}).get("Item")
    if not item:
        return 0
    prof = item.get("profile") or item
    display_name = (prof.get("display_name") or "").strip()
    if not display_name:
        return 0

    acct_item = None
    try:
        acct_item = T.account_state.get_item(Key={"user_sub": user_id}).get("Item")
    except Exception:
        pass

    discoverability = "active"
    try:
        if acct_item:
            discoverability = resolve_discoverability_state(acct_item).value
    except Exception:
        discoverability = "active"

    tokens = build_discovery_tokens(display_name)
    follower_count = int(item.get("follower_count", 0))
    description = (prof.get("description") or prof.get("title") or "")[:200]
    photo_url = prof.get("profile_photo_url")
    now = int(time.time())

    with tbl_discovery.batch_writer() as bw:
        for token in tokens:
            item: Dict[str, Any] = {
                "pk": f"TOKEN#{token}",
                "sk": f"USER#{user_id}",
                "user_id": user_id,
                "display_name": display_name,
                "follower_count": follower_count,
                "discoverability": discoverability,
                "indexed_at": now,
                "GSI1PK": "TRENDING",
                "GSI1SK": follower_count,
            }
            if photo_url:
                item["profile_photo_url"] = photo_url
            if description:
                item["description"] = description
            bw.put_item(Item=item)
    return len(tokens)


def search_users(
    query: str,
    *,
    viewer_id: Optional[str] = None,
    limit: int = 20,
    cursor: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    normalized = query.strip().lower()
    if not normalized:
        return [], None

    query_tokens = [t.strip() for t in normalized.split() if t.strip()]
    if not query_tokens:
        return [], None

    candidate_sets: List[Dict[str, Dict]] = []
    for token in query_tokens:
        resp = tbl_discovery.query(
            KeyConditionExpression=Key("pk").eq(f"TOKEN#{token}"),
            Limit=200,
        )
        items = resp.get("Items", [])
        by_user: Dict[str, Dict] = {}
        for it in items:
            uid = it.get("user_id")
            if uid:
                by_user[uid] = it
        candidate_sets.append(by_user)

    if not candidate_sets:
        return [], None

    common_ids = set(candidate_sets[0].keys())
    for cs in candidate_sets[1:]:
        common_ids &= set(cs.keys())

    results = []
    for uid in common_ids:
        item = candidate_sets[0][uid]
        disc = item.get("discoverability", "active")
        if disc != "active":
            continue
        if viewer_id and uid == viewer_id:
            continue
        score = _score_search_result(item, query_tokens)
        results.append((score, item))

    results.sort(key=lambda x: x[0], reverse=True)

    offset = 0
    if cursor:
        try:
            offset = int(cursor)
        except (ValueError, TypeError):
            offset = 0
    page = results[offset : offset + limit]
    next_cursor = str(offset + limit) if offset + limit < len(results) else None

    items_out = []
    for _score, item in page:
        out = {
            "user_id": item.get("user_id"),
            "display_name": item.get("display_name"),
            "profile_photo_url": item.get("profile_photo_url"),
            "description": item.get("description"),
            "follower_count": int(item.get("follower_count", 0)),
            "is_following": False,
            "is_followed_by": False,
            "is_mutual": False,
        }
        items_out.append(out)

    if viewer_id:
        _enrich_with_follow_status(items_out, viewer_id)

    return items_out, next_cursor


def get_suggested_users(
    viewer_id: str,
    *,
    limit: int = 12,
) -> List[Dict[str, Any]]:
    cache_item = tbl_app.get_item(
        Key={"pk": f"DISCOVERY_CACHE#{viewer_id}", "sk": "SUGGESTED"}
    ).get("Item")
    if cache_item and int(cache_item.get("expires_at", 0)) > int(time.time()):
        return json.loads(cache_item.get("data", "[]"))[:limit]

    following_ids: Set[str] = set()
    last_key = None
    while len(following_ids) < 100:
        kw: Dict[str, Any] = {
            "KeyConditionExpression": (
                Key("pk").eq(f"USER#{viewer_id}")
                & Key("sk").begins_with("FOLLOWING#")
            ),
            "FilterExpression": Attr("state").eq("following"),
            "Limit": 100,
        }
        if last_key:
            kw["ExclusiveStartKey"] = last_key
        r = tbl_app.query(**kw)
        for it in r.get("Items", []):
            tid = it.get("target_user_id")
            if tid:
                following_ids.add(tid)
        last_key = r.get("LastEvaluatedKey")
        if not last_key:
            break

    if not following_ids:
        return get_trending_creators(viewer_id=viewer_id, limit=limit)

    candidate_scores: Dict[str, int] = {}
    for fid in following_ids:
        fof_key = None
        count = 0
        while count < 50:
            fof_kw: Dict[str, Any] = {
                "KeyConditionExpression": (
                    Key("pk").eq(f"USER#{fid}")
                    & Key("sk").begins_with("FOLLOWING#")
                ),
                "FilterExpression": Attr("state").eq("following"),
                "Limit": 50,
            }
            if fof_key:
                fof_kw["ExclusiveStartKey"] = fof_key
            fof_r = tbl_app.query(**fof_kw)
            for it in fof_r.get("Items", []):
                cid = it.get("target_user_id")
                if cid and cid != viewer_id and cid not in following_ids:
                    candidate_scores[cid] = candidate_scores.get(cid, 0) + 1
                count += 1
            fof_key = fof_r.get("LastEvaluatedKey")
            if not fof_key:
                break

    sorted_candidates = sorted(candidate_scores.items(), key=lambda x: x[1], reverse=True)
    top_ids = [uid for uid, _ in sorted_candidates[:limit * 2]]

    results = []
    for uid in top_ids[:limit]:
        item = T.profile.get_item(Key={"user_sub": uid}).get("Item")
        if not item:
            continue
        prof = item.get("profile") or item
        results.append({
            "user_id": uid,
            "display_name": prof.get("display_name", uid),
            "profile_photo_url": prof.get("profile_photo_url"),
            "description": (prof.get("description") or prof.get("title") or "")[:200],
            "follower_count": int(item.get("follower_count", 0)),
            "is_following": False,
            "is_followed_by": False,
            "is_mutual": False,
        })

    _enrich_with_follow_status(results, viewer_id)

    tbl_app.put_item(Item={
        "pk": f"DISCOVERY_CACHE#{viewer_id}",
        "sk": "SUGGESTED",
        "data": json.dumps(results),
        "expires_at": int(time.time()) + 3600,
        "ttl": int(time.time()) + 7200,
    })

    return results


def get_trending_creators(
    *,
    viewer_id: Optional[str] = None,
    limit: int = 20,
) -> List[Dict[str, Any]]:
    resp = tbl_discovery.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq("TRENDING"),
        ScanIndexForward=False,
        Limit=limit * 2,
    )
    items = resp.get("Items", [])

    seen: Set[str] = set()
    results = []
    for item in items:
        uid = item.get("user_id")
        if not uid or uid in seen:
            continue
        if item.get("discoverability", "active") != "active":
            continue
        seen.add(uid)
        results.append({
            "user_id": uid,
            "display_name": item.get("display_name"),
            "profile_photo_url": item.get("profile_photo_url"),
            "description": item.get("description"),
            "follower_count": int(item.get("follower_count", 0)),
            "is_following": False,
            "is_followed_by": False,
            "is_mutual": False,
        })
        if len(results) >= limit:
            break

    if viewer_id:
        _enrich_with_follow_status(results, viewer_id)

    return results


def get_discovery_profile(user_id: str, viewer_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    from app.services.social import get_follow_counts, get_follow_status

    item = T.profile.get_item(Key={"user_sub": user_id}).get("Item")
    if not item:
        return None
    prof = item.get("profile") or item
    counts = get_follow_counts(user_id)
    follow_status = {"is_following": False, "is_followed_by": False, "is_mutual": False}
    if viewer_id:
        follow_status = get_follow_status(viewer_id, user_id)
    return {
        "user_id": user_id,
        "display_name": prof.get("display_name"),
        "profile_photo_url": prof.get("profile_photo_url"),
        "cover_photo_url": prof.get("cover_photo_url"),
        "description": prof.get("description"),
        "location": prof.get("location"),
        **counts,
        **follow_status,
    }


def _score_search_result(user_item: dict, query_tokens: list) -> float:
    score = 0.0
    name = (user_item.get("display_name") or "").lower()
    joined_query = " ".join(query_tokens)
    if name == joined_query:
        score += 100.0
    for token in query_tokens:
        if name.startswith(token):
            score += 50.0
        elif token in name:
            score += 20.0
    followers = int(user_item.get("follower_count", 0))
    if followers > 0:
        score += min(math.log10(followers) * 5, 25.0)
    return score


def _enrich_with_follow_status(items: List[Dict], viewer_id: str) -> None:
    from app.services.social import get_follow_status
    for item in items:
        uid = item.get("user_id")
        if not uid:
            continue
        try:
            status = get_follow_status(viewer_id, uid)
            item["is_following"] = status["is_following"]
            item["is_followed_by"] = status["is_followed_by"]
            item["is_mutual"] = status["is_mutual"]
        except Exception:
            pass
