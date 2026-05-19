import sys
import types
import pytest

from app.core.cursor import encode_cursor
from app.routers import newsfeed as newsfeed_router

# Ensure ddb_delete_item exists on the module so monkeypatch.setattr can target it.
# The production code references it but the helper definition may be missing.
if not hasattr(newsfeed_router, "ddb_delete_item"):
    def _ddb_delete_item_stub(key):
        from app.routers.newsfeed import T
        T.newsfeed.delete_item(Key=key)
    newsfeed_router.ddb_delete_item = _ddb_delete_item_stub
from app.routers.newsfeed import (
    HTTPException,
    _build_file_attachments_for_post,
    _is_drafts_feature_enabled_for_user,
    _validate_and_normalize_draft_payload,
    build_draft_item,
    build_draft_list_query,
    drafts_index_name,
    gsi_drafts_pk,
    gsi_drafts_sk,
    CreateDraftPostRequest,
    UpdateDraftPostRequest,
    PublishDraftPostRequest,
    CreatePostRequest,
    create_draft_post,
    list_draft_posts,
    get_draft_post,
    update_draft_post,
    delete_draft_post,
    publish_draft_post,
    pk_user,
    sk_draft,
)


def test_build_draft_item_includes_schema_and_index_fields():
    payload = {
        "body_plain": "hello",
        "body_format": "plain",
        "image_urls": ["https://cdn.example.com/image.jpg"],
    }

    item = build_draft_item(user_id="u1", draft_id="d1", payload=payload, created_at="2026-04-01T00:00:00Z")

    assert item["pk"] == pk_user("u1")
    assert item["sk"] == sk_draft("d1")
    assert item["entity_type"] == "draft_post"
    assert item["status"] == "draft"
    assert item["author_id"] == "u1"
    assert item["payload"] == payload
    assert item["GSI4PK"] == gsi_drafts_pk("u1")
    assert item["GSI4SK"] == gsi_drafts_sk("2026-04-01T00:00:00Z", "d1")


def test_build_draft_list_query_uses_desc_order_and_cursor_paging():
    cursor = encode_cursor({"pk": "USER#u1", "sk": "DRAFT#d1"})

    query = build_draft_list_query(user_id="u1", cursor=cursor, limit=20)

    assert query["IndexName"] == drafts_index_name()
    assert query["KeyConditionExpression"] == "GSI4PK = :pk"
    assert query["ExpressionAttributeValues"] == {":pk": gsi_drafts_pk("u1")}
    assert query["ScanIndexForward"] is False
    assert query["Limit"] == 20
    assert query["ExclusiveStartKey"] == {"pk": "USER#u1", "sk": "DRAFT#d1"}


def test_build_draft_list_query_limit_is_bounded():
    low = build_draft_list_query(user_id="u1", cursor=None, limit=0)
    high = build_draft_list_query(user_id="u1", cursor=None, limit=999)

    assert low["Limit"] == 1
    assert high["Limit"] == 100


def test_validate_and_normalize_draft_payload_rejects_invalid_unlock_price(monkeypatch):
    monkeypatch.setattr("app.routers.newsfeed.get_node", lambda user_id, path: {"path": path})

    payload = {
        "body_plain": "hello",
        "body_format": "plain",
        "image_urls": ["https://cdn.example.com/a.jpg"],
        "file_paths": ["/docs/spec.pdf"],
        "unlock_price_cents": 0,
    }

    try:
        _validate_and_normalize_draft_payload(user_id="u1", payload=payload)
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "unlock_price_cents must be greater than zero" in str(exc)


def test_validate_and_normalize_draft_payload_rejects_non_https_image_url(monkeypatch):
    monkeypatch.setattr("app.routers.newsfeed.get_node", lambda user_id, path: {"path": path})

    payload = {
        "body_plain": "hello",
        "body_format": "plain",
        "image_urls": ["http://cdn.example.com/a.jpg"],
        "file_paths": ["/docs/spec.pdf"],
    }

    try:
        _validate_and_normalize_draft_payload(user_id="u1", payload=payload)
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "must be an https URL or an /uploads/object URL" in str(exc)


def test_validate_and_normalize_draft_payload_rejects_unowned_file_reference(monkeypatch):
    def _missing_node(user_id, path):
        raise HTTPException(status_code=404, detail="Not found")

    monkeypatch.setattr("app.routers.newsfeed.get_node", _missing_node)

    payload = {
        "body_plain": "hello",
        "body_format": "plain",
        "image_urls": ["https://cdn.example.com/a.jpg"],
        "file_paths": ["/docs/spec.pdf"],
    }

    try:
        _validate_and_normalize_draft_payload(user_id="u1", payload=payload)
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "must reference an existing file owned by the current user" in str(exc)


def test_validate_and_normalize_draft_payload_rejects_unowned_upload_object_url(monkeypatch):
    monkeypatch.setattr("app.routers.newsfeed.get_node", lambda user_id, path: {"path": path})

    payload = {
        "body_plain": "hello",
        "body_format": "plain",
        "image_urls": ["/uploads/object?s3_key=uploads/other-user/a.png"],
        "file_paths": ["/docs/spec.pdf"],
    }

    try:
        _validate_and_normalize_draft_payload(user_id="u1", payload=payload)
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "must reference an upload owned by the current user" in str(exc)


def test_build_file_attachments_for_post_returns_actionable_422_on_missing_file(monkeypatch):
    def _missing_node(user_id, path):
        raise HTTPException(status_code=404, detail="Not found")

    monkeypatch.setattr("app.routers.newsfeed.get_node", _missing_node)

    try:
        _build_file_attachments_for_post(user_id="u1", file_paths=["/docs/spec.pdf"])
        assert False, "expected HTTPException"
    except HTTPException as exc:
        assert exc.status_code == 422
        assert "Invalid attachment reference at file_paths[0]" in str(exc.detail)


def test_drafts_feature_flag_respects_enabled_and_disabled_user_cohorts(monkeypatch):
    from app.core.settings import S as _settings_obj
    original_enabled = _settings_obj.newsfeed_drafts_enabled
    original_enabled_ids = _settings_obj.newsfeed_drafts_enabled_user_ids
    original_disabled_ids = getattr(_settings_obj, "newsfeed_drafts_disabled_user_ids", "")
    object.__setattr__(_settings_obj, "newsfeed_drafts_enabled", False)
    object.__setattr__(_settings_obj, "newsfeed_drafts_enabled_user_ids", "u_enabled")
    object.__setattr__(_settings_obj, "newsfeed_drafts_disabled_user_ids", "u_disabled")
    try:
        assert _is_drafts_feature_enabled_for_user("u_enabled") is True
        assert _is_drafts_feature_enabled_for_user("u_disabled") is False
        assert _is_drafts_feature_enabled_for_user("u_other") is False
    finally:
        object.__setattr__(_settings_obj, "newsfeed_drafts_enabled", original_enabled)
        object.__setattr__(_settings_obj, "newsfeed_drafts_enabled_user_ids", original_enabled_ids)
        object.__setattr__(_settings_obj, "newsfeed_drafts_disabled_user_ids", original_disabled_ids)


def test_draft_crud_endpoints_roundtrip(monkeypatch):
    store = {}

    monkeypatch.setattr("app.routers.newsfeed._ensure_drafts_feature_enabled", lambda user_id: None)
    monkeypatch.setattr("app.routers.newsfeed._enforce_draft_count_quota", lambda user_id: None)
    monkeypatch.setattr("app.routers.newsfeed._validate_and_normalize_draft_payload", lambda user_id, payload: payload)
    monkeypatch.setattr("app.routers.newsfeed.ddb_put_item", lambda item: store.__setitem__((item["pk"], item["sk"]), item))
    monkeypatch.setattr("app.routers.newsfeed.ddb_get_item", lambda key: store.get((key["pk"], key["sk"])))
    monkeypatch.setattr("app.routers.newsfeed.ddb_delete_item", lambda key: store.pop((key["pk"], key["sk"]), None))

    def _query(**kwargs):
        pk = kwargs["ExpressionAttributeValues"][":pk"]
        items = [item for item in store.values() if item.get("GSI4PK") == pk]
        items.sort(key=lambda it: it.get("updated_at", ""), reverse=True)
        return {"Items": items, "LastEvaluatedKey": None}

    monkeypatch.setattr("app.routers.newsfeed.ddb_query", _query)

    created = create_draft_post(CreateDraftPostRequest(body_plain="hello", body_format="plain"), "u1")
    assert created.author_id == "u1"

    listed = list_draft_posts(user_id="u1", cursor=None, limit=20)
    assert len(listed.items) == 1
    draft_id = listed.items[0].draft_id

    fetched = get_draft_post(draft_id, "u1")
    assert fetched.body_plain == "hello"

    updated = update_draft_post(draft_id, UpdateDraftPostRequest(body_plain="updated"), "u1")
    assert updated.body_plain == "updated"

    deleted = delete_draft_post(draft_id, "u1", expected_updated_at=updated.updated_at)
    assert deleted["ok"] is True
    assert len(list_draft_posts(user_id="u1", cursor=None, limit=20).items) == 0


def test_publish_draft_post_happy_path_removes_draft(monkeypatch):
    deleted_keys = []
    draft_item = {
        "draft_id": "d1",
        "author_id": "u1",
        "created_at": "2026-04-01T00:00:00Z",
        "updated_at": "2026-04-01T00:00:00Z",
        "payload": {"body_plain": "publish me", "body_format": "plain", "image_urls": [], "file_paths": []},
    }

    monkeypatch.setattr("app.routers.newsfeed._ensure_drafts_feature_enabled", lambda user_id: None)
    monkeypatch.setattr("app.routers.newsfeed._get_draft_or_404", lambda user_id, draft_id: draft_item)
    monkeypatch.setattr("app.routers.newsfeed._validate_and_normalize_draft_payload", lambda user_id, payload: payload)
    monkeypatch.setattr("app.routers.newsfeed.create_post", lambda req, user_id: {"post_id": "p1", "author_id": user_id, "body": req.body_plain})
    monkeypatch.setattr("app.routers.newsfeed.ddb_delete_item", lambda key: deleted_keys.append(key))

    resp = publish_draft_post("d1", PublishDraftPostRequest(keep_copy=False), "u1")
    assert resp["post_id"] == "p1"
    assert deleted_keys and deleted_keys[0]["sk"] == "DRAFT#d1"


def test_draft_get_rejects_non_owner(monkeypatch):
    monkeypatch.setattr(
        "app.routers.newsfeed.ddb_get_item",
        lambda key: {"entity_type": "draft_post", "author_id": "another_user", "draft_id": "d1"},
    )
    with pytest.raises(HTTPException) as exc:
        newsfeed_router._get_draft_or_404(user_id="u1", draft_id="d1")
    assert exc.value.status_code == 404


def test_create_draft_post_returns_quota_error(monkeypatch):
    monkeypatch.setattr("app.routers.newsfeed._ensure_drafts_feature_enabled", lambda user_id: None)
    monkeypatch.setattr("app.routers.newsfeed._enforce_draft_count_quota", lambda user_id: (_ for _ in ()).throw(HTTPException(status_code=403, detail="quota")))

    with pytest.raises(HTTPException) as exc:
        create_draft_post(CreateDraftPostRequest(body_plain="blocked", body_format="plain"), "u1")
    assert exc.value.status_code == 403


def test_publish_draft_post_rejects_invalid_attachment_references(monkeypatch):
    monkeypatch.setattr("app.routers.newsfeed._ensure_drafts_feature_enabled", lambda user_id: None)
    monkeypatch.setattr(
        "app.routers.newsfeed._get_draft_or_404",
        lambda user_id, draft_id: {"payload": {"body_plain": "bad", "body_format": "plain", "file_paths": ["/missing.pdf"]}},
    )
    monkeypatch.setattr(
        "app.routers.newsfeed._validate_and_normalize_draft_payload",
        lambda user_id, payload: (_ for _ in ()).throw(ValueError("invalid_draft_payload: file_paths[0] invalid")),
    )

    with pytest.raises(HTTPException) as exc:
        publish_draft_post("d1", PublishDraftPostRequest(keep_copy=True), "u1")
    assert exc.value.status_code == 422
    assert "Invalid draft attachment reference" in str(exc.value.detail)


def test_publish_from_draft_matches_direct_create_post_contract_fields(monkeypatch):
    deleted_keys = []
    captured_req = {}
    payload = {
        "body_plain": "parity body",
        "body_format": "plain",
        "image_urls": ["https://cdn.example.com/pic.jpg"],
        "file_paths": ["/docs/a.pdf"],
        "unlock_price_cents": 299,
    }

    monkeypatch.setattr("app.routers.newsfeed._ensure_drafts_feature_enabled", lambda user_id: None)
    monkeypatch.setattr(
        "app.routers.newsfeed._get_draft_or_404",
        lambda user_id, draft_id: {"payload": payload},
    )
    monkeypatch.setattr("app.routers.newsfeed._validate_and_normalize_draft_payload", lambda user_id, payload: payload)

    def _fake_create_post(req, user_id):
        assert isinstance(req, CreatePostRequest)
        captured_req["req"] = req
        return {
            "post_id": "p_parity",
            "author_id": user_id,
            "created_at": "2026-04-01T00:00:00Z",
            "body": req.body_plain,
            "body_plain": req.body_plain,
            "body_format": req.body_format,
            "body_version": req.body_version,
            "image_urls": req.image_urls,
            "visibility": "followers",
            "locked": True,
            "unlock_price_cents": req.unlock_price_cents,
            "like_count": 0,
            "comment_count": 0,
        }

    monkeypatch.setattr("app.routers.newsfeed.create_post", _fake_create_post)
    monkeypatch.setattr("app.routers.newsfeed.ddb_delete_item", lambda key: deleted_keys.append(key))

    published = publish_draft_post("d_1", PublishDraftPostRequest(keep_copy=False), "u1")

    req = captured_req["req"]
    assert req.body_plain == "parity body"
    assert req.image_urls == ["https://cdn.example.com/pic.jpg"]
    assert req.file_paths == ["/docs/a.pdf"]
    assert req.unlock_price_cents == 299

    assert published["post_id"] == "p_parity"
    assert published["image_urls"] == ["https://cdn.example.com/pic.jpg"]
    assert published["locked"] is True
    assert published["unlock_price_cents"] == 299
    assert deleted_keys and deleted_keys[0]["sk"] == "DRAFT#d_1"


def test_publish_from_draft_keep_copy_true_does_not_delete(monkeypatch):
    deleted_keys = []
    monkeypatch.setattr("app.routers.newsfeed._ensure_drafts_feature_enabled", lambda user_id: None)
    monkeypatch.setattr(
        "app.routers.newsfeed._get_draft_or_404",
        lambda user_id, draft_id: {"payload": {"body_plain": "keep me", "body_format": "plain", "image_urls": [], "file_paths": []}},
    )
    monkeypatch.setattr("app.routers.newsfeed._validate_and_normalize_draft_payload", lambda user_id, payload: payload)
    monkeypatch.setattr("app.routers.newsfeed.create_post", lambda req, user_id: {"post_id": "p_keep", "author_id": user_id, "body": req.body_plain})
    monkeypatch.setattr("app.routers.newsfeed.ddb_delete_item", lambda key: deleted_keys.append(key))

    publish_draft_post("d_keep", PublishDraftPostRequest(keep_copy=True), "u1")
    assert deleted_keys == []


def test_update_draft_post_rejects_stale_expected_updated_at(monkeypatch):
    monkeypatch.setattr("app.routers.newsfeed._ensure_drafts_feature_enabled", lambda user_id: None)
    monkeypatch.setattr(
        "app.routers.newsfeed._get_draft_or_404",
        lambda user_id, draft_id: {
            "draft_id": "d1",
            "author_id": "u1",
            "created_at": "2026-04-01T00:00:00Z",
            "updated_at": "2026-04-01T00:10:00Z",
            "payload": {"body_plain": "hello", "body_format": "plain", "image_urls": [], "file_paths": []},
        },
    )

    with pytest.raises(HTTPException) as exc:
        update_draft_post(
            "d1",
            UpdateDraftPostRequest(body_plain="new", expected_updated_at="2026-04-01T00:00:00Z"),
            "u1",
        )
    assert exc.value.status_code == 409
    assert exc.value.detail["code"] == "newsfeed_draft_version_conflict"
    assert exc.value.detail["actual_updated_at"] == "2026-04-01T00:10:00Z"


def test_publish_draft_post_rejects_stale_expected_updated_at(monkeypatch):
    monkeypatch.setattr("app.routers.newsfeed._ensure_drafts_feature_enabled", lambda user_id: None)
    monkeypatch.setattr(
        "app.routers.newsfeed._get_draft_or_404",
        lambda user_id, draft_id: {
            "draft_id": "d1",
            "author_id": "u1",
            "created_at": "2026-04-01T00:00:00Z",
            "updated_at": "2026-04-01T00:10:00Z",
            "payload": {"body_plain": "hello", "body_format": "plain", "image_urls": [], "file_paths": []},
        },
    )

    with pytest.raises(HTTPException) as exc:
        publish_draft_post("d1", PublishDraftPostRequest(keep_copy=True, expected_updated_at="2026-04-01T00:00:00Z"), "u1")
    assert exc.value.status_code == 409
    assert exc.value.detail["code"] == "newsfeed_draft_version_conflict"


def test_update_draft_post_excludes_expected_updated_at_from_payload(monkeypatch):
    saved = {}
    existing = {
        "draft_id": "d1",
        "author_id": "u1",
        "created_at": "2026-04-01T00:00:00Z",
        "updated_at": "2026-04-01T00:10:00Z",
        "payload": {"body_plain": "hello", "body_format": "plain", "image_urls": [], "file_paths": []},
    }

    monkeypatch.setattr("app.routers.newsfeed._ensure_drafts_feature_enabled", lambda user_id: None)
    monkeypatch.setattr("app.routers.newsfeed._get_draft_or_404", lambda user_id, draft_id: existing)
    monkeypatch.setattr("app.routers.newsfeed._validate_and_normalize_draft_payload", lambda user_id, payload: payload)
    monkeypatch.setattr("app.routers.newsfeed.ddb_put_item", lambda item: saved.update(item))

    update_draft_post(
        "d1",
        UpdateDraftPostRequest(body_plain="updated", expected_updated_at="2026-04-01T00:10:00Z"),
        "u1",
    )

    assert "expected_updated_at" not in (saved.get("payload") or {})


def test_delete_draft_post_rejects_stale_expected_updated_at(monkeypatch):
    monkeypatch.setattr("app.routers.newsfeed._ensure_drafts_feature_enabled", lambda user_id: None)
    monkeypatch.setattr(
        "app.routers.newsfeed._get_draft_or_404",
        lambda user_id, draft_id: {
            "draft_id": "d1",
            "author_id": "u1",
            "created_at": "2026-04-01T00:00:00Z",
            "updated_at": "2026-04-01T00:10:00Z",
            "payload": {"body_plain": "hello", "body_format": "plain", "image_urls": [], "file_paths": []},
        },
    )

    with pytest.raises(HTTPException) as exc:
        delete_draft_post("d1", "u1", expected_updated_at="2026-04-01T00:00:00Z")
    assert exc.value.status_code == 409
    assert exc.value.detail["code"] == "newsfeed_draft_version_conflict"
