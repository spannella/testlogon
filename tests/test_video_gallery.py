"""Unit tests for video gallery hub service (VOD-017).

Tests: publish/unpublish, record view, like/unlike, browse, search,
comment CRUD, trending score.
"""

from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

import pytest
from fastapi import HTTPException

from app.services import video_gallery as gallery_mod
from app.services import video_comments as comments_mod
from app.services import video_metadata_store
from app.services.video_gallery import (
    publish_to_gallery,
    unpublish_from_gallery,
    record_view,
    toggle_like,
    check_liked,
    browse_gallery,
    search_gallery,
    compute_trending_score,
    update_trending_score,
    GALLERY_CATEGORIES,
    VALID_CATEGORY_SLUGS,
)
from app.services.video_comments import (
    add_comment,
    list_comments,
    delete_comment,
)
from app.services.video_metadata_store import (
    create_video,
    get_video,
    video_to_item,
    video_from_item,
)
from app.models_video import VideoMetadataModel


# ─── In-memory table stubs ──────────────────────────────────────────────────


def _split_set_assignments(set_part: str) -> list:
    """Split SET clause by commas, respecting parentheses."""
    result = []
    depth = 0
    current = []
    for ch in set_part:
        if ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            result.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        result.append("".join(current).strip())
    return result


class _ConditionalCheckFailed(Exception):
    pass


def _filter_by_kce(items: list, kce) -> list:
    """Filter items using a boto3 Key ConditionExpression."""
    return [item for item in items if _matches_kce(item, kce)]


def _matches_kce(item: dict, cond) -> bool:
    """Recursively check if item matches a boto3 condition object."""
    from boto3.dynamodb.conditions import And

    if isinstance(cond, And):
        left, right = cond._values
        return _matches_kce(item, left) and _matches_kce(item, right)

    # Simple condition (Equals, GreaterThanEquals, etc.)
    operator = getattr(cond, "expression_operator", "=")
    values = getattr(cond, "_values", ())

    if len(values) >= 2:
        field_obj = values[0]
        compare_val = values[1]

        # Get field name — field_obj is a boto3.dynamodb.conditions.Key
        field_name = getattr(field_obj, "name", str(field_obj))

        item_val = item.get(field_name)

        if operator == "=":
            return item_val == compare_val
        elif operator == ">=":
            if item_val is None:
                return False
            return item_val >= compare_val
        elif operator == "<=":
            return (item_val or 0) <= compare_val
        elif operator == ">":
            return (item_val or 0) > compare_val
        elif operator == "<":
            return (item_val or 0) < compare_val

    return True


class _FakeClient:
    class exceptions:
        ConditionalCheckFailedException = _ConditionalCheckFailed


class _FakeTable:
    """In-memory DynamoDB table stub for unit tests."""

    def __init__(self) -> None:
        self.items: dict = {}
        self.meta = SimpleNamespace(client=_FakeClient())

    def _key(self, key_dict):
        if "pk" in key_dict and "sk" in key_dict:
            return (key_dict["pk"], key_dict["sk"])
        if "video_id" in key_dict:
            return key_dict["video_id"]
        vals = tuple(key_dict.values())
        return vals if len(vals) > 1 else vals[0]

    def put_item(self, *, Item, ConditionExpression=None, **kwargs):
        key = self._key(Item) if ("pk" in Item or "video_id" in Item) else tuple(Item.values())[:2]
        if "pk" in Item and "sk" in Item:
            key = (Item["pk"], Item["sk"])
        elif "video_id" in Item:
            key = Item["video_id"]

        if ConditionExpression and "attribute_not_exists" in str(ConditionExpression):
            if key in self.items:
                raise _ConditionalCheckFailed("already exists")
        self.items[key] = dict(Item)

    def get_item(self, *, Key, ConsistentRead=False, ProjectionExpression=None, **kwargs):
        key = self._key(Key)
        item = self.items.get(key)
        return {"Item": dict(item)} if item else {}

    def delete_item(self, *, Key, **kwargs):
        key = self._key(Key)
        self.items.pop(key, None)

    def update_item(self, *, Key, UpdateExpression="", ExpressionAttributeValues=None,
                    ExpressionAttributeNames=None, ReturnValues=None, **kwargs):
        if "video_id" in Key:
            key = Key["video_id"]
        else:
            key = self._key(Key)

        item = self.items.get(key)
        if item is None:
            item = dict(Key)
            self.items[key] = item

        expr_vals = ExpressionAttributeValues or {}

        # Simplified SET expression parser
        if "SET" in UpdateExpression:
            set_part = UpdateExpression.split("SET ", 1)[1]
            if " REMOVE " in set_part:
                set_part = set_part.split(" REMOVE ")[0]
            # Split by commas but not inside parentheses
            assignments = _split_set_assignments(set_part)
            for assign in assignments:
                if "=" not in assign:
                    continue
                lhs, rhs = assign.split("=", 1)
                lhs = lhs.strip()
                rhs = rhs.strip()

                # Resolve ExpressionAttributeNames
                if ExpressionAttributeNames:
                    for alias, real in ExpressionAttributeNames.items():
                        lhs = lhs.replace(alias, real)
                        rhs = rhs.replace(alias, real)

                # Handle if_not_exists(field, :z) + :one
                if "if_not_exists" in rhs:
                    import re
                    m = re.match(r"if_not_exists\((\w+),\s*(:\w+)\)\s*([+-])\s*(:\w+)", rhs)
                    if m:
                        field, default_ref, op, inc_ref = m.groups()
                        current = item.get(field, expr_vals.get(default_ref, 0))
                        inc = expr_vals.get(inc_ref, 1)
                        if op == "+":
                            item[lhs] = int(current) + int(inc)
                        else:
                            item[lhs] = int(current) - int(inc)
                        continue

                # Handle simple subtraction: field - :val
                if " - " in rhs:
                    parts = rhs.split(" - ")
                    field_ref = parts[0].strip()
                    val_ref = parts[1].strip()
                    current = item.get(field_ref, expr_vals.get(field_ref, 0))
                    dec = expr_vals.get(val_ref, 1)
                    item[lhs] = int(current) - int(dec)
                    continue

                # Handle simple addition: field + :val
                if " + " in rhs:
                    parts = rhs.split(" + ")
                    field_ref = parts[0].strip()
                    val_ref = parts[1].strip()
                    current = item.get(field_ref, expr_vals.get(field_ref, 0))
                    inc = expr_vals.get(val_ref, 1)
                    item[lhs] = int(current) + int(inc)
                    continue

                # Simple assignment
                if rhs in expr_vals:
                    item[lhs] = expr_vals[rhs]
                else:
                    item[lhs] = rhs

        # Handle REMOVE
        if "REMOVE" in UpdateExpression:
            remove_part = UpdateExpression.split("REMOVE ", 1)[1]
            for field in remove_part.split(","):
                field = field.strip()
                item.pop(field, None)

        if ReturnValues == "UPDATED_NEW":
            return {"Attributes": dict(item)}
        return {}

    def query(self, **kwargs):
        index = kwargs.get("IndexName")
        limit = kwargs.get("Limit", 200)
        scan_forward = kwargs.get("ScanIndexForward", True)
        all_items = list(self.items.values())

        # Parse KeyConditionExpression
        kce = kwargs.get("KeyConditionExpression")
        if kce is not None:
            items = _filter_by_kce(all_items, kce)
        else:
            items = all_items

        # Apply FilterExpression (simplified — just check basic attrs)
        fe = kwargs.get("FilterExpression")
        if fe:
            fe_str = str(fe)
            expr_vals = kwargs.get("ExpressionAttributeValues", {})
            expr_names = kwargs.get("ExpressionAttributeNames", {})
            filtered = []
            for item in items:
                keep = True
                if "gallery_published = :gp" in fe_str:
                    if item.get("gallery_published") != expr_vals.get(":gp"):
                        keep = False
                if "#st = :pub" in fe_str or "status = :pub" in fe_str:
                    status_key = expr_names.get("#st", "status")
                    if item.get(status_key) != expr_vals.get(":pub"):
                        keep = False
                if "visibility = :vis" in fe_str:
                    if item.get("visibility") != expr_vals.get(":vis"):
                        keep = False
                if "comment_id = :cid" in fe_str:
                    if item.get("comment_id") != expr_vals.get(":cid"):
                        keep = False
                if keep:
                    filtered.append(item)
            items = filtered

        # Sort
        sort_key = "created_at"
        if index and "ViewedAt" in index:
            sort_key = "viewed_at"
        elif index and "LikedAt" in index:
            sort_key = "liked_at"
        elif index and "Published" in index:
            sort_key = "published_at"
        elif index and "Category" in index:
            sort_key = "trending_score_sort"

        items.sort(key=lambda x: x.get(sort_key, 0), reverse=not scan_forward)

        if kwargs.get("Select") == "COUNT":
            return {"Count": len(items)}

        result_items = items[:limit]
        last_key = None
        if len(items) > limit:
            last_key = {"pk": result_items[-1].get("pk", ""), "sk": result_items[-1].get("sk", "")}

        return {"Items": result_items, "LastEvaluatedKey": last_key}


def _make_tables():
    """Create a namespace with all the table stubs needed for gallery tests."""
    return SimpleNamespace(
        video_metadata=_FakeTable(),
        video_views=_FakeTable(),
        video_likes=_FakeTable(),
        video_comments=_FakeTable(),  # added when video_comments service was wired in
    )


def _seed_published_video(tables, video_id="v_test1", owner="alice", category="tutorials",
                          status="published"):
    """Seed a video directly into the fake video_metadata table."""
    item = {
        "video_id": video_id,
        "owner_user_id": owner,
        "title": f"Test Video {video_id}",
        "description": "A test video",
        "status": status,
        "created_at": 1000000,
        "updated_at": 1000000,
        "source_type": "upload",
        "visibility": "public",
        "drm_enabled": False,
        "gallery_published": True,
        "gallery_status": "published",
        "category": category,
        "tags": ["test", "demo"],
        "view_count": 0,
        "like_count": 0,
        "comment_count": 0,
        "trending_score": 0,
        "trending_score_sort": 0,
        "published_at": 1000000,
        "allow_download": False,
        "download_mp4_key": "",
        "download_mp4_size_bytes": 0,
        "download_mp4_status": "",
        "download_count": 0,
    }
    tables.video_metadata.items[video_id] = item
    return item


def _seed_approved_video(tables, video_id="v_approved", owner="alice"):
    """Seed an approved (but not gallery-published) video."""
    item = {
        "video_id": video_id,
        "owner_user_id": owner,
        "title": "Approved Video",
        "description": "Waiting for gallery publish",
        "status": "approved",
        "created_at": 1000000,
        "updated_at": 1000000,
        "source_type": "upload",
        "visibility": "private",
        "drm_enabled": False,
        "gallery_published": False,
        "view_count": 0,
        "like_count": 0,
        "comment_count": 0,
        "allow_download": False,
        "download_mp4_key": "",
        "download_mp4_size_bytes": 0,
        "download_mp4_status": "",
        "download_count": 0,
    }
    tables.video_metadata.items[video_id] = item
    return item


def _seed_encoding_video(tables, video_id="v_encoding", owner="alice"):
    """Seed a video still in encoding status."""
    item = {
        "video_id": video_id,
        "owner_user_id": owner,
        "title": "Encoding Video",
        "status": "encoding",
        "created_at": 1000000,
        "updated_at": 1000000,
        "source_type": "upload",
        "visibility": "private",
        "drm_enabled": False,
        "gallery_published": False,
        "view_count": 0,
        "like_count": 0,
        "comment_count": 0,
        "allow_download": False,
        "download_mp4_key": "",
        "download_mp4_size_bytes": 0,
        "download_mp4_status": "",
        "download_count": 0,
    }
    tables.video_metadata.items[video_id] = item
    return item


# ─── Publish / Unpublish Tests ──────────────────────────────────────────────


def test_publish_to_gallery_sets_fields():
    tables = _make_tables()
    _seed_approved_video(tables)
    with patch.object(gallery_mod, "T", tables), \
         patch.object(video_metadata_store, "T", tables):
        result = publish_to_gallery(
            video_id="v_approved",
            user_id="alice",
            category="tutorials",
            tags=["python", "fastapi"],
        )
    assert result["gallery_published"] is True
    assert result["category"] == "tutorials"
    assert result["tags"] == ["python", "fastapi"]
    # Check the DDB item was updated
    item = tables.video_metadata.items["v_approved"]
    assert item["gallery_published"] is True
    assert item["gallery_status"] == "published"
    assert item["category"] == "tutorials"
    assert item["visibility"] == "public"


def test_publish_to_gallery_invalid_category():
    tables = _make_tables()
    _seed_approved_video(tables)
    with patch.object(gallery_mod, "T", tables), \
         patch.object(video_metadata_store, "T", tables):
        with pytest.raises(HTTPException) as exc:
            publish_to_gallery(
                video_id="v_approved",
                user_id="alice",
                category="invalid_cat",
                tags=[],
            )
        assert exc.value.status_code == 400


def test_publish_to_gallery_not_owner():
    tables = _make_tables()
    _seed_approved_video(tables)
    with patch.object(gallery_mod, "T", tables), \
         patch.object(video_metadata_store, "T", tables):
        with pytest.raises(HTTPException) as exc:
            publish_to_gallery(
                video_id="v_approved",
                user_id="bob",
                category="tutorials",
                tags=[],
            )
        assert exc.value.status_code == 403


def test_publish_to_gallery_unapproved():
    tables = _make_tables()
    _seed_encoding_video(tables)
    with patch.object(gallery_mod, "T", tables), \
         patch.object(video_metadata_store, "T", tables):
        with pytest.raises(HTTPException) as exc:
            publish_to_gallery(
                video_id="v_encoding",
                user_id="alice",
                category="tutorials",
                tags=[],
            )
        assert exc.value.status_code == 400


def test_publish_tags_max_10():
    tables = _make_tables()
    _seed_approved_video(tables)
    with patch.object(gallery_mod, "T", tables), \
         patch.object(video_metadata_store, "T", tables):
        with pytest.raises(HTTPException) as exc:
            publish_to_gallery(
                video_id="v_approved",
                user_id="alice",
                category="tutorials",
                tags=[f"t{i}" for i in range(11)],
            )
        assert exc.value.status_code == 400


def test_unpublish_from_gallery():
    tables = _make_tables()
    _seed_published_video(tables)
    with patch.object(gallery_mod, "T", tables), \
         patch.object(video_metadata_store, "T", tables):
        result = unpublish_from_gallery(video_id="v_test1", user_id="alice")
    assert result["gallery_published"] is False
    item = tables.video_metadata.items["v_test1"]
    assert item["gallery_published"] is False


# ─── View Tests ─────────────────────────────────────────────────────────────


def test_record_view_new_user():
    tables = _make_tables()
    _seed_published_video(tables)
    with patch.object(gallery_mod, "T", tables):
        result = record_view(video_id="v_test1", user_id="alice")
    assert result["is_new_view"] is True
    assert result["view_count"] == 1


def test_record_view_dedup_same_day():
    tables = _make_tables()
    _seed_published_video(tables)
    with patch.object(gallery_mod, "T", tables):
        record_view(video_id="v_test1", user_id="alice")
        result = record_view(video_id="v_test1", user_id="alice")
    assert result["is_new_view"] is False
    assert result["view_count"] == 1


def test_record_view_different_users():
    tables = _make_tables()
    _seed_published_video(tables)
    with patch.object(gallery_mod, "T", tables):
        record_view(video_id="v_test1", user_id="alice")
        result = record_view(video_id="v_test1", user_id="bob")
    assert result["view_count"] == 2


# ─── Like Tests ─────────────────────────────────────────────────────────────


def test_toggle_like_on():
    tables = _make_tables()
    _seed_published_video(tables)
    with patch.object(gallery_mod, "T", tables):
        result = toggle_like(video_id="v_test1", user_id="alice")
    assert result["liked"] is True
    assert result["like_count"] == 1


def test_toggle_like_off():
    tables = _make_tables()
    _seed_published_video(tables)
    with patch.object(gallery_mod, "T", tables):
        toggle_like(video_id="v_test1", user_id="alice")
        result = toggle_like(video_id="v_test1", user_id="alice")
    assert result["liked"] is False
    assert result["like_count"] == 0


def test_check_liked_false():
    tables = _make_tables()
    with patch.object(gallery_mod, "T", tables):
        assert check_liked(video_id="v_test1", user_id="alice") is False


def test_check_liked_true():
    tables = _make_tables()
    _seed_published_video(tables)
    with patch.object(gallery_mod, "T", tables):
        toggle_like(video_id="v_test1", user_id="alice")
        assert check_liked(video_id="v_test1", user_id="alice") is True


# ─── Browse Tests ───────────────────────────────────────────────────────────


def test_gallery_list_returns_published():
    tables = _make_tables()
    _seed_published_video(tables, "v_pub1", category="tutorials")
    _seed_published_video(tables, "v_pub2", category="gaming")
    with patch.object(gallery_mod, "T", tables):
        result = browse_gallery()
    assert len(result["items"]) == 2


def test_gallery_filter_by_category():
    tables = _make_tables()
    _seed_published_video(tables, "v_tut", category="tutorials")
    _seed_published_video(tables, "v_game", category="gaming")
    with patch.object(gallery_mod, "T", tables):
        result = browse_gallery(category="tutorials")
    items = result["items"]
    assert all(v.category == "tutorials" for v in items)


def test_gallery_invalid_category():
    tables = _make_tables()
    with patch.object(gallery_mod, "T", tables):
        with pytest.raises(HTTPException) as exc:
            browse_gallery(category="invalid_cat")
        assert exc.value.status_code == 400


# ─── Search Tests ───────────────────────────────────────────────────────────


def test_search_gallery_by_title():
    tables = _make_tables()
    item = _seed_published_video(tables, "v_py")
    item["title"] = "Python Tutorial"
    _seed_published_video(tables, "v_cook")
    tables.video_metadata.items["v_cook"]["title"] = "Cooking Tips"

    with patch.object(gallery_mod, "T", tables):
        result = search_gallery(query="python")
    assert len(result["items"]) == 1
    assert result["items"][0].title == "Python Tutorial"


def test_search_gallery_empty_query():
    tables = _make_tables()
    with patch.object(gallery_mod, "T", tables):
        result = search_gallery(query="")
    assert len(result["items"]) == 0


# ─── Comment Tests ──────────────────────────────────────────────────────────


def test_add_and_list_comments():
    tables = _make_tables()
    _seed_published_video(tables)
    with patch.object(comments_mod, "T", tables):
        c1 = add_comment(video_id="v_test1", user_id="alice", text="Great video!")
        c2 = add_comment(video_id="v_test1", user_id="bob", text="Thanks for sharing")
    assert c1["comment_id"].startswith("vc_")
    assert c1["text"] == "Great video!"

    with patch.object(comments_mod, "T", tables):
        result = list_comments(video_id="v_test1")
    assert len(result["comments"]) == 2


def test_delete_comment_author_only():
    tables = _make_tables()
    _seed_published_video(tables)
    with patch.object(comments_mod, "T", tables):
        c = add_comment(video_id="v_test1", user_id="alice", text="My comment")

    with patch.object(comments_mod, "T", tables):
        with pytest.raises(HTTPException) as exc:
            delete_comment(video_id="v_test1", comment_id=c["comment_id"], user_id="bob")
        assert exc.value.status_code == 403

    with patch.object(comments_mod, "T", tables):
        delete_comment(video_id="v_test1", comment_id=c["comment_id"], user_id="alice")

    with patch.object(comments_mod, "T", tables):
        result = list_comments(video_id="v_test1")
    assert len(result["comments"]) == 0


def test_comment_empty_text():
    tables = _make_tables()
    with patch.object(comments_mod, "T", tables):
        with pytest.raises(HTTPException) as exc:
            add_comment(video_id="v_test1", user_id="alice", text="")
        assert exc.value.status_code == 400


# ─── Trending Score Tests ───────────────────────────────────────────────────


def test_compute_trending_score_basic():
    score = compute_trending_score(
        views_24h=100,
        likes_24h=10,
        comments_24h=5,
        hours_since_published=0,
    )
    # 100*1 + 10*5 + 5*3 = 165, decay=1.0 at 0 hours
    assert score == 165.0


def test_compute_trending_score_with_decay():
    score = compute_trending_score(
        views_24h=100,
        likes_24h=0,
        comments_24h=0,
        hours_since_published=72,
    )
    # 100 * 0.5^(72/72) = 50
    assert abs(score - 50.0) < 0.01


def test_update_trending_score():
    tables = _make_tables()
    _seed_published_video(tables)
    with patch.object(gallery_mod, "T", tables), \
         patch.object(video_metadata_store, "T", tables):
        score = update_trending_score("v_test1")
    assert isinstance(score, int)


# ─── Categories ─────────────────────────────────────────────────────────────


def test_categories_list():
    assert len(GALLERY_CATEGORIES) > 0
    assert "tutorials" in VALID_CATEGORY_SLUGS
    assert "entertainment" in VALID_CATEGORY_SLUGS


# ─── Serialization roundtrip ────────────────────────────────────────────────


def test_video_from_item_gallery_fields():
    """video_from_item correctly deserializes gallery fields."""
    item = {
        "video_id": "v_rt",
        "owner_user_id": "alice",
        "title": "Roundtrip",
        "status": "published",
        "created_at": 1000,
        "updated_at": 1000,
        "source_type": "upload",
        "visibility": "public",
        "drm_enabled": False,
        "gallery_published": True,
        "gallery_status": "published",
        "category": "gaming",
        "tags": ["fps", "multiplayer"],
        "view_count": 42,
        "like_count": 7,
        "comment_count": 3,
        "trending_score": Decimal("15.5"),
        "trending_score_sort": 15,
    }
    video = video_from_item(item)
    assert video.gallery_published is True
    assert video.gallery_status == "published"
    assert video.category == "gaming"
    assert video.tags == ["fps", "multiplayer"]
    assert video.view_count == 42
    assert video.like_count == 7
    assert video.comment_count == 3
    assert video.trending_score == 15.5
    assert video.trending_score_sort == 15


def test_video_to_item_gallery_fields():
    """video_to_item correctly serializes gallery fields."""
    video = VideoMetadataModel(
        id="v_ser",
        owner_user_id="alice",
        title="Serialize",
        status="published",
        visibility="public",
        gallery_published=True,
        gallery_status="published",
        category="education",
        tags=["math"],
        view_count=10,
        like_count=5,
        comment_count=2,
        trending_score=8.0,
        trending_score_sort=8,
    )
    item = video_to_item(video)
    assert item["gallery_published"] is True
    assert item["gallery_status"] == "published"
    assert item["category"] == "education"
    assert item["tags"] == ["math"]
    assert item["view_count"] == 10
    assert item["like_count"] == 5
