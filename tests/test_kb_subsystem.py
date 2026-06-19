"""Hermetic offline tests for the Knowledge Base (KB-001..KB-011) backend subsystem.

Uses moto in-process DynamoDB — no real AWS. T.kb_articles is patched onto the
frozen Tables singleton via object.__setattr__ following the established pattern
from tests/test_gap_0220_0221_ssh_stored_key.py.

Cross-cluster collaborators (audit_event, s3_client, cursor helpers) are patched
at import time where needed.
"""
from __future__ import annotations

import asyncio
import types
import uuid
from types import SimpleNamespace
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch, call

import boto3
import pytest
from moto import mock_aws


# ─── Fixtures / helpers ───────────────────────────────────────────────────────

_TABLE_NAME = "crm_kb_articles"


def _create_kb_table(ddb_resource):
    table = ddb_resource.create_table(
        TableName=_TABLE_NAME,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "category", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "author_sub", "AttributeType": "S"},
            {"AttributeName": "tag", "AttributeType": "S"},
            {"AttributeName": "published_at", "AttributeType": "N"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByCategory",
                "KeySchema": [
                    {"AttributeName": "category", "KeyType": "HASH"},
                    {"AttributeName": "published_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByStatus",
                "KeySchema": [
                    {"AttributeName": "status", "KeyType": "HASH"},
                    {"AttributeName": "published_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByAuthor",
                "KeySchema": [
                    {"AttributeName": "author_sub", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByTag",
                "KeySchema": [
                    {"AttributeName": "tag", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    table.wait_until_exists()
    return table


# ─── KB-001: Settings & Table ─────────────────────────────────────────────────


class TestKb001Settings:
    def test_knowledge_base_enabled_defaults_false(self):
        from app.core.settings import S
        assert S.knowledge_base_enabled is False

    def test_kb_articles_table_default(self):
        from app.core.settings import S
        assert S.kb_articles_table == "crm_kb_articles"

    def test_kb_s3_settings_defaults(self):
        from app.core.settings import S
        assert S.kb_attachments_bucket == "local-uploads"
        assert S.kb_attachments_s3_prefix == "kb-attachments/"
        assert S.kb_attachment_max_bytes == 20 * 1024 * 1024

    def test_kb_expiry_interval_default(self):
        from app.core.settings import S
        assert S.kb_expiry_checker_interval_seconds == 3600

    def test_flag_toggles_via_object_setattr(self):
        from app.core import settings as settings_mod
        S_orig = settings_mod.S
        try:
            obj = object.__new__(settings_mod.Settings)
            object.__setattr__(obj, "knowledge_base_enabled", True)
            settings_mod.S = obj
            assert settings_mod.S.knowledge_base_enabled is True
        finally:
            settings_mod.S = S_orig

    def test_t_kb_articles_handle(self):
        from app.core.tables import T
        assert T.kb_articles is not None
        assert T.kb_articles.name == "crm_kb_articles"


@mock_aws
def test_crm_kb_articles_table_gsis():
    """Verify crm_kb_articles can be created with all four GSIs and queried."""
    ddb = boto3.resource("dynamodb", region_name="us-east-1")
    table = _create_kb_table(ddb)
    gsi_names = {g["IndexName"] for g in table.global_secondary_indexes or []}
    assert {"ByCategory", "ByStatus", "ByAuthor", "ByTag"} == gsi_names

    # Confirm numeric GSI sort keys work
    table.put_item(Item={
        "pk": "ARTICLE#test-001",
        "sk": "META",
        "article_id": "test-001",
        "author_sub": "user-123",
        "tag": "billing",
        "created_at": 1718000000,
        "published_at": 1718001000,
        "status": "published",
        "category": "Support",
    })
    resp = table.query(
        IndexName="ByAuthor",
        KeyConditionExpression="author_sub = :a",
        ExpressionAttributeValues={":a": "user-123"},
    )
    assert resp["Count"] == 1

    resp2 = table.query(
        IndexName="ByTag",
        KeyConditionExpression="tag = :t",
        ExpressionAttributeValues={":t": "billing"},
    )
    assert resp2["Count"] == 1

    resp3 = table.query(
        IndexName="ByStatus",
        KeyConditionExpression="#s = :s",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "published"},
    )
    assert resp3["Count"] == 1


# ─── KB-002..KB-006: Service tests ────────────────────────────────────────────


class TestKbArticleService:
    """Hermetic service tests using moto-backed T.kb_articles."""

    def setup_method(self):
        """Start moto mock and patch T.kb_articles for each test."""
        # Ensure clean event loop state
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        from moto import mock_aws as _mock_aws
        self._mock = _mock_aws()
        self._mock.start()

        import boto3 as _boto3
        ddb = _boto3.resource("dynamodb", region_name="us-east-1")
        self._table = _create_kb_table(ddb)

        from app.core import tables as tables_mod
        self._T_orig = tables_mod.T
        # Patch T.kb_articles onto the frozen singleton
        object.__setattr__(tables_mod.T, "kb_articles", self._table)

        # Enable the KB flag
        from app.core import settings as settings_mod
        self._S_orig = settings_mod.S
        new_s = object.__new__(settings_mod.Settings)
        # Copy all attrs from original S
        for field in settings_mod.Settings.__dataclass_fields__:
            object.__setattr__(new_s, field, getattr(settings_mod.S, field))
        object.__setattr__(new_s, "knowledge_base_enabled", True)
        object.__setattr__(new_s, "dev_mode", True)
        settings_mod.S = new_s

        # Patch audit_event to no-op
        import app.services.kb_articles as svc_mod
        self._audit_patcher = patch.object(svc_mod, "_audit", lambda *a, **kw: None)
        self._audit_patcher.start()

    def teardown_method(self):
        from app.core import tables as tables_mod, settings as settings_mod
        tables_mod.T = self._T_orig
        settings_mod.S = self._S_orig
        self._audit_patcher.stop()
        self._mock.stop()
        self._loop.close()
        asyncio.set_event_loop(asyncio.new_event_loop())

    def _svc(self):
        from app.services.kb_articles import KbArticleService
        return KbArticleService()

    # ── Article CRUD ──────────────────────────────────────────────────────────

    def test_create_article(self):
        svc = self._svc()
        item = svc.create_article("admin-1", title="Hello World", body_html="<p>content</p>")
        assert item["title"] == "Hello World"
        assert item["status"] == "draft"
        assert item["author_sub"] == "admin-1"
        assert item["article_id"].startswith("kb_")

    def test_get_article_not_found_raises_404(self):
        from fastapi import HTTPException
        svc = self._svc()
        with pytest.raises(HTTPException) as exc_info:
            svc.get_article("nonexistent")
        assert exc_info.value.status_code == 404

    def test_get_article_published_only_hides_draft(self):
        from fastapi import HTTPException
        svc = self._svc()
        item = svc.create_article("admin-1", title="Draft article")
        with pytest.raises(HTTPException) as exc_info:
            svc.get_article(item["article_id"], published_only=True)
        assert exc_info.value.status_code == 404

    def test_update_article(self):
        svc = self._svc()
        item = svc.create_article("admin-1", title="Old title")
        updated = svc.update_article(item["article_id"], "admin-1", title="New title")
        assert updated["title"] == "New title"

    def test_delete_article(self):
        from fastapi import HTTPException
        svc = self._svc()
        item = svc.create_article("admin-1", title="To delete")
        svc.delete_article(item["article_id"], "admin-1")
        with pytest.raises(HTTPException) as exc_info:
            svc.get_article(item["article_id"])
        assert exc_info.value.status_code == 404

    # ── KB-002: Status lifecycle ──────────────────────────────────────────────

    def test_publish_draft_article(self):
        from app.services.kb_articles import KbArticleStateError
        svc = self._svc()
        item = svc.create_article("admin-1", title="Test")
        published = svc.publish_article(item["article_id"], "admin-1")
        assert published["status"] == "published"
        assert published.get("published_at") is not None

    def test_publish_already_published_raises(self):
        from app.services.kb_articles import KbArticleStateError
        svc = self._svc()
        item = svc.create_article("admin-1", title="Test")
        svc.publish_article(item["article_id"], "admin-1")
        with pytest.raises(KbArticleStateError) as exc_info:
            svc.publish_article(item["article_id"], "admin-1")
        assert "published" in str(exc_info.value)

    def test_publish_expired_article_raises(self):
        from app.services.kb_articles import KbArticleStateError
        svc = self._svc()
        # Directly insert an expired article
        article_id = "kb_" + uuid.uuid4().hex
        self._table.put_item(Item={
            "pk": f"ARTICLE#{article_id}",
            "sk": "META",
            "article_id": article_id,
            "title": "Expired",
            "status": "expired",
            "author_sub": "admin-1",
            "created_at": 1000,
            "updated_at": 1000,
            "view_count": 0,
            "helpful_count": 0,
            "not_helpful_count": 0,
        })
        with pytest.raises(KbArticleStateError):
            svc.publish_article(article_id, "admin-1")

    def test_expire_published_article(self):
        from app.services.kb_articles import KbArticleStateError
        svc = self._svc()
        item = svc.create_article("admin-1", title="Test")
        svc.publish_article(item["article_id"], "admin-1")
        expired = svc.expire_article(item["article_id"], "admin-1", reason="outdated")
        assert expired["status"] == "expired"
        assert expired.get("expired_at") is not None
        assert expired.get("expiry_reason") == "outdated"

    def test_expire_draft_raises(self):
        from app.services.kb_articles import KbArticleStateError
        svc = self._svc()
        item = svc.create_article("admin-1", title="Test")
        with pytest.raises(KbArticleStateError) as exc_info:
            svc.expire_article(item["article_id"], "admin-1")
        assert "draft" in str(exc_info.value)

    def test_unpublish_to_draft(self):
        from app.services.kb_articles import KbArticleStateError
        svc = self._svc()
        item = svc.create_article("admin-1", title="Test")
        svc.publish_article(item["article_id"], "admin-1")
        drafted = svc.unpublish_to_draft(item["article_id"], "admin-1")
        assert drafted["status"] == "draft"
        # published_at should be removed
        assert drafted.get("published_at") is None

    def test_unpublish_draft_raises(self):
        from app.services.kb_articles import KbArticleStateError
        svc = self._svc()
        item = svc.create_article("admin-1", title="Test")
        with pytest.raises(KbArticleStateError):
            svc.unpublish_to_draft(item["article_id"], "admin-1")

    # ── KB-002: Expiry checker ────────────────────────────────────────────────

    def test_expiry_checker_expires_due_articles(self):
        from app.services.kb_articles import _run_kb_expiry_check_once, now_ts
        svc = self._svc()
        now = now_ts()

        item_due = svc.create_article("admin-1", title="Due", expires_at=now - 1)
        svc.publish_article(item_due["article_id"], "admin-1")
        # Set expires_at on the published item
        self._table.update_item(
            Key={"pk": f"ARTICLE#{item_due['article_id']}", "sk": "META"},
            UpdateExpression="SET expires_at = :exp",
            ExpressionAttributeValues={":exp": now - 1},
        )

        item_future = svc.create_article("admin-1", title="Future", expires_at=now + 7200)
        svc.publish_article(item_future["article_id"], "admin-1")
        self._table.update_item(
            Key={"pk": f"ARTICLE#{item_future['article_id']}", "sk": "META"},
            UpdateExpression="SET expires_at = :exp",
            ExpressionAttributeValues={":exp": now + 7200},
        )

        item_no_expiry = svc.create_article("admin-1", title="No expiry")
        svc.publish_article(item_no_expiry["article_id"], "admin-1")

        count = _run_kb_expiry_check_once()
        assert count >= 1

        due_after = svc.get_article(item_due["article_id"])
        assert due_after["status"] == "expired"

        future_after = svc.get_article(item_future["article_id"])
        assert future_after["status"] == "published"

        no_expiry_after = svc.get_article(item_no_expiry["article_id"])
        assert no_expiry_after["status"] == "published"

    def test_expiry_checker_idempotent(self):
        from app.services.kb_articles import _run_kb_expiry_check_once, now_ts
        svc = self._svc()
        now = now_ts()

        item = svc.create_article("admin-1", title="Due2", expires_at=now - 1)
        svc.publish_article(item["article_id"], "admin-1")
        self._table.update_item(
            Key={"pk": f"ARTICLE#{item['article_id']}", "sk": "META"},
            UpdateExpression="SET expires_at = :exp",
            ExpressionAttributeValues={":exp": now - 1},
        )

        c1 = _run_kb_expiry_check_once()
        c2 = _run_kb_expiry_check_once()
        assert c1 >= 1
        assert c2 == 0  # second run finds no due articles

    # ── KB-005: Ratings ───────────────────────────────────────────────────────

    def test_rate_article_helpful(self):
        svc = self._svc()
        item = svc.create_article("admin-1", title="Rate me")
        svc.publish_article(item["article_id"], "admin-1")
        result = svc.rate_article(item["article_id"], "user-1", helpful=True)
        assert result["ok"] is True
        assert result["already_rated"] is False
        assert result["helpful_count"] == 1
        assert result["not_helpful_count"] == 0

    def test_rate_article_same_vote_idempotent(self):
        svc = self._svc()
        item = svc.create_article("admin-1", title="Rate me")
        svc.publish_article(item["article_id"], "admin-1")
        svc.rate_article(item["article_id"], "user-1", helpful=True)
        result = svc.rate_article(item["article_id"], "user-1", helpful=True)
        assert result["already_rated"] is True
        assert result["helpful_count"] == 1  # not double-counted

    def test_rate_article_vote_change(self):
        svc = self._svc()
        item = svc.create_article("admin-1", title="Rate me")
        svc.publish_article(item["article_id"], "admin-1")
        svc.rate_article(item["article_id"], "user-1", helpful=True)
        result = svc.rate_article(item["article_id"], "user-1", helpful=False)
        assert result["helpful_count"] == 0
        assert result["not_helpful_count"] == 1

    def test_rate_unpublished_article_raises_404(self):
        from fastapi import HTTPException
        svc = self._svc()
        item = svc.create_article("admin-1", title="Draft")
        with pytest.raises(HTTPException) as exc_info:
            svc.rate_article(item["article_id"], "user-1", helpful=True)
        assert exc_info.value.status_code == 404

    # ── KB-006: View counter ──────────────────────────────────────────────────

    def test_increment_view_count(self):
        svc = self._svc()
        item = svc.create_article("admin-1", title="View me")
        svc.increment_view_count(item["article_id"])
        after = svc.get_article(item["article_id"])
        assert int(after["view_count"]) == 1

    def test_record_view_deduplicates(self):
        svc = self._svc()
        item = svc.create_article("admin-1", title="View dedup")
        # Two calls from same viewer should only increment once
        svc.record_view(item["article_id"], "viewer-abc")
        svc.record_view(item["article_id"], "viewer-abc")
        after = svc.get_article(item["article_id"])
        assert int(after["view_count"]) == 1

    def test_record_view_different_viewers(self):
        svc = self._svc()
        item = svc.create_article("admin-1", title="View dedup2")
        svc.record_view(item["article_id"], "viewer-1")
        svc.record_view(item["article_id"], "viewer-2")
        after = svc.get_article(item["article_id"])
        assert int(after["view_count"]) == 2

    # ── KB-004: Categories ────────────────────────────────────────────────────

    def test_create_and_get_category(self):
        svc = self._svc()
        cat = svc.create_category("admin-1", name="Support", description="Support articles")
        assert cat["name"] == "Support"
        assert cat["category_id"].startswith("cat_")

        fetched = svc.get_category(cat["category_id"])
        assert fetched["name"] == "Support"

    def test_category_hierarchy_path(self):
        svc = self._svc()
        parent = svc.create_category("admin-1", name="Support")
        child = svc.create_category("admin-1", name="Billing", parent_id=parent["category_id"])
        assert "Support" in child["path"]
        assert "Billing" in child["path"]

    def test_list_categories(self):
        svc = self._svc()
        svc.create_category("admin-1", name="Cat A")
        svc.create_category("admin-1", name="Cat B")
        cats = svc.list_categories()
        names = [c["name"] for c in cats]
        assert "Cat A" in names
        assert "Cat B" in names

    def test_update_category(self):
        svc = self._svc()
        cat = svc.create_category("admin-1", name="Old name")
        updated = svc.update_category(cat["category_id"], "admin-1", name="New name")
        assert updated["name"] == "New name"

    def test_delete_category(self):
        from fastapi import HTTPException
        svc = self._svc()
        cat = svc.create_category("admin-1", name="To delete")
        svc.delete_category(cat["category_id"], "admin-1")
        with pytest.raises(HTTPException) as exc_info:
            svc.get_category(cat["category_id"])
        assert exc_info.value.status_code == 404

    # ── KB-003: Attachments (S3 stub) ─────────────────────────────────────────

    def test_list_attachments_empty(self):
        svc = self._svc()
        item = svc.create_article("admin-1", title="No attachments")
        atts = svc.list_attachments(item["article_id"])
        assert atts == []

    def test_add_and_list_attachment(self):
        import app.services.kb_articles as svc_mod

        fake_s3 = MagicMock()
        with patch.object(svc_mod, "_attachment_url", return_value="/mock/s3/test-key"):
            with patch("app.services.kb_articles.S3") if False else \
                    patch("app.core.aws_clients.s3_client", return_value=fake_s3):
                svc = svc_mod.KbArticleService()
                item = svc.create_article("admin-1", title="Has attachment")
                att = svc.add_attachment(
                    item["article_id"],
                    "admin-1",
                    filename="test.pdf",
                    content_type="application/pdf",
                    content=b"fake pdf bytes",
                )
                assert att["filename"] == "test.pdf"
                assert att["size_bytes"] == 14
                atts = svc.list_attachments(item["article_id"])
                assert len(atts) == 1
                assert atts[0]["filename"] == "test.pdf"

    def test_attachment_size_limit(self):
        import app.services.kb_articles as svc_mod
        from fastapi import HTTPException
        from app.core import settings as settings_mod

        svc = svc_mod.KbArticleService()
        item = svc.create_article("admin-1", title="Big file")

        # Patch S in the service module directly (S was imported at module level)
        orig_s = svc_mod.S
        try:
            new_s = object.__new__(settings_mod.Settings)
            for field in settings_mod.Settings.__dataclass_fields__:
                object.__setattr__(new_s, field, getattr(settings_mod.S, field))
            object.__setattr__(new_s, "kb_attachment_max_bytes", 5)
            # Patch the service module's reference to S
            svc_mod.S = new_s

            with pytest.raises(HTTPException) as exc_info:
                svc.add_attachment(
                    item["article_id"],
                    "admin-1",
                    filename="big.pdf",
                    content_type="application/pdf",
                    content=b"123456",  # 6 bytes > limit of 5
                )
            assert exc_info.value.status_code == 413
        finally:
            svc_mod.S = orig_s

    # ── KB-011: Search ────────────────────────────────────────────────────────

    def test_search_articles_by_title(self):
        svc = self._svc()
        item1 = svc.create_article("admin-1", title="billing invoice", body_html="<p>billing</p>")
        svc.publish_article(item1["article_id"], "admin-1")
        # Add published_at so ByStatus works
        from app.core.time import now_ts
        self._table.update_item(
            Key={"pk": f"ARTICLE#{item1['article_id']}", "sk": "META"},
            UpdateExpression="SET published_at = :ts",
            ExpressionAttributeValues={":ts": now_ts()},
        )
        item2 = svc.create_article("admin-1", title="account settings")
        svc.publish_article(item2["article_id"], "admin-1")
        self._table.update_item(
            Key={"pk": f"ARTICLE#{item2['article_id']}", "sk": "META"},
            UpdateExpression="SET published_at = :ts",
            ExpressionAttributeValues={":ts": now_ts()},
        )

        results, cursor = svc.search_articles("billing")
        titles = [r["title"] for r in results]
        assert any("billing" in t for t in titles)

    def test_search_empty_query_returns_empty(self):
        svc = self._svc()
        results, cursor = svc.search_articles("")
        assert results == []
        assert cursor is None

    # ── KB-007: Tag index ─────────────────────────────────────────────────────

    def test_list_popular_tags_empty(self):
        svc = self._svc()
        tags = svc.list_popular_tags()
        assert isinstance(tags, list)

    def test_set_article_tags(self):
        svc = self._svc()
        item = svc.create_article("admin-1", title="Tagged article", tags=["python", "billing"])
        svc.set_article_tags(item["article_id"], ["python", "billing"], "admin-1")
        # Check tag index rows exist
        resp = self._table.query(
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": "TAG#python"},
        )
        assert resp["Count"] >= 1


# ─── KB-002: Expiry checker flag gate ────────────────────────────────────────


def test_expiry_checker_disabled_when_flag_off():
    """run_kb_expiry_checker_loop should be a coroutine that returns early when flag is off."""
    import inspect
    from app.services.kb_articles import run_kb_expiry_checker_loop, S as svc_S
    # Verify it's a coroutine function
    assert inspect.iscoroutinefunction(run_kb_expiry_checker_loop)

    from app.core import settings as settings_mod
    import app.services.kb_articles as svc_mod
    orig_s = svc_mod.S
    try:
        new_s = object.__new__(settings_mod.Settings)
        for field in settings_mod.Settings.__dataclass_fields__:
            object.__setattr__(new_s, field, getattr(settings_mod.S, field))
        object.__setattr__(new_s, "knowledge_base_enabled", False)
        svc_mod.S = new_s

        # Create a fresh isolated event loop for this test
        old_loop = asyncio.get_event_loop_policy().get_event_loop() if True else None
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(run_kb_expiry_checker_loop())
        finally:
            loop.close()
            asyncio.set_event_loop(asyncio.new_event_loop())
        # If we get here without hanging, the flag-off guard works
    finally:
        svc_mod.S = orig_s


def test_start_kb_expiry_checker_task_no_op_when_flag_off():
    """start_kb_expiry_checker_task should not create a task when flag is off."""
    from app.core import settings as settings_mod
    import app.services.kb_articles as svc_mod
    orig_s = svc_mod.S
    try:
        new_s = object.__new__(settings_mod.Settings)
        for field in settings_mod.Settings.__dataclass_fields__:
            object.__setattr__(new_s, field, getattr(settings_mod.S, field))
        object.__setattr__(new_s, "knowledge_base_enabled", False)
        svc_mod.S = new_s

        from app.services.kb_articles import start_kb_expiry_checker_task
        # Should not raise and should return quickly (flag is off)
        start_kb_expiry_checker_task()
    finally:
        svc_mod.S = orig_s


# ─── Router-layer tests ───────────────────────────────────────────────────────


class TestKbRouter:
    """Smoke-test router handlers directly without a TestClient."""

    def setup_method(self):
        # Use a fresh event loop for this class
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        self._mock = mock_aws()
        self._mock.start()

        import boto3 as _boto3
        ddb = _boto3.resource("dynamodb", region_name="us-east-1")
        self._table = _create_kb_table(ddb)

        from app.core import tables as tables_mod, settings as settings_mod
        # Save the ATTRIBUTE VALUES (not the T object reference) so teardown can restore them
        self._orig_kb_articles = getattr(tables_mod.T, "kb_articles", None)
        self._S_orig = settings_mod.S
        object.__setattr__(tables_mod.T, "kb_articles", self._table)

        new_s = object.__new__(settings_mod.Settings)
        for field in settings_mod.Settings.__dataclass_fields__:
            object.__setattr__(new_s, field, getattr(settings_mod.S, field))
        object.__setattr__(new_s, "knowledge_base_enabled", True)
        object.__setattr__(new_s, "dev_mode", True)
        settings_mod.S = new_s

        import app.services.kb_articles as svc_mod
        self._audit_patcher = patch.object(svc_mod, "_audit", lambda *a, **kw: None)
        self._audit_patcher.start()

    def teardown_method(self):
        from app.core import tables as tables_mod, settings as settings_mod
        # Restore the T.kb_articles attribute to its original value
        if self._orig_kb_articles is not None:
            object.__setattr__(tables_mod.T, "kb_articles", self._orig_kb_articles)
        settings_mod.S = self._S_orig
        self._audit_patcher.stop()
        self._mock.stop()
        self._loop.close()
        asyncio.set_event_loop(asyncio.new_event_loop())

    def _make_admin_user(self):
        from app.auth.deps import AuthenticatedUser
        from app.auth.roles import Role
        return AuthenticatedUser(sub="admin-user", role=Role.ADMIN)

    def _make_user(self):
        from app.auth.deps import AuthenticatedUser
        from app.auth.roles import Role
        return AuthenticatedUser(sub="regular-user", role=Role.USER)

    def _run(self, coro):
        return self._loop.run_until_complete(coro)

    def test_publish_article_admin(self):
        from app.routers.kb_articles import publish_article
        from app.services.kb_articles import KbArticleService

        svc = KbArticleService()
        item = svc.create_article("admin-user", title="Test")
        user = self._make_admin_user()
        session = {"user_sub": user.sub}

        result = self._run(publish_article(item["article_id"], user=user, _session=session))
        assert result.status == "published"

    def test_publish_article_user_forbidden(self):
        from fastapi import HTTPException
        from app.routers.kb_articles import publish_article
        from app.services.kb_articles import KbArticleService

        svc = KbArticleService()
        item = svc.create_article("admin-user", title="Test")
        user = self._make_user()
        session = {"user_sub": user.sub}

        with pytest.raises(HTTPException) as exc_info:
            self._run(publish_article(item["article_id"], user=user, _session=session))
        assert exc_info.value.status_code == 403

    def test_publish_article_flag_off_404(self):
        from fastapi import HTTPException
        from app.routers.kb_articles import publish_article
        from app.core import settings as settings_mod

        # Disable flag
        new_s = object.__new__(settings_mod.Settings)
        for field in settings_mod.Settings.__dataclass_fields__:
            object.__setattr__(new_s, field, getattr(settings_mod.S, field))
        object.__setattr__(new_s, "knowledge_base_enabled", False)
        settings_mod.S = new_s

        try:
            user = self._make_admin_user()
            session = {"user_sub": user.sub}
            with pytest.raises(HTTPException) as exc_info:
                self._run(publish_article("any-id", user=user, _session=session))
            assert exc_info.value.status_code == 404
        finally:
            pass  # S will be reset in teardown_method

    def test_expire_article_admin(self):
        from app.routers.kb_articles import expire_article
        from app.services.kb_articles import KbArticleService
        from app.models import KbExpireReq

        svc = KbArticleService()
        item = svc.create_article("admin-user", title="To expire")
        svc.publish_article(item["article_id"], "admin-user")
        user = self._make_admin_user()
        session = {"user_sub": user.sub}
        body = KbExpireReq(reason="outdated")

        result = self._run(expire_article(item["article_id"], body, user=user, _session=session))
        assert result.status == "expired"
        assert result.expiry_reason == "outdated"

    def test_unpublish_article_admin(self):
        from app.routers.kb_articles import unpublish_article
        from app.services.kb_articles import KbArticleService

        svc = KbArticleService()
        item = svc.create_article("admin-user", title="To unpublish")
        svc.publish_article(item["article_id"], "admin-user")
        user = self._make_admin_user()
        session = {"user_sub": user.sub}

        result = self._run(unpublish_article(item["article_id"], user=user, _session=session))
        assert result.status == "draft"

    def test_rate_article_endpoint(self):
        from app.routers.kb_articles import rate_article
        from app.services.kb_articles import KbArticleService
        from app.models import KbRateReq

        svc = KbArticleService()
        item = svc.create_article("admin-user", title="Rate me")
        svc.publish_article(item["article_id"], "admin-user")
        session = {"user_sub": "user-1"}
        body = KbRateReq(helpful=True)

        result = self._run(rate_article(item["article_id"], body, _session=session))
        assert result.ok is True
        assert result.helpful_count == 1

    def test_publish_already_published_returns_409(self):
        from fastapi import HTTPException
        from app.routers.kb_articles import publish_article
        from app.services.kb_articles import KbArticleService

        svc = KbArticleService()
        item = svc.create_article("admin-user", title="Test")
        svc.publish_article(item["article_id"], "admin-user")

        user = self._make_admin_user()
        session = {"user_sub": user.sub}
        with pytest.raises(HTTPException) as exc_info:
            self._run(publish_article(item["article_id"], user=user, _session=session))
        assert exc_info.value.status_code == 409

    def test_create_and_get_article_admin(self):
        from app.routers.kb_articles import create_article, get_article
        from app.models import KbArticleCreateIn

        user = self._make_admin_user()
        session = {"user_sub": user.sub}
        body = KbArticleCreateIn(title="My Article", body_html="<p>Hello</p>")

        created = self._run(create_article(body, user=user, _session=session))
        assert created.title == "My Article"
        assert created.status == "draft"

        fetched = self._run(get_article(created.article_id, user=user, _session=session))
        assert fetched.article_id == created.article_id

    def test_list_categories_endpoint(self):
        from app.routers.kb_articles import list_categories
        from app.services.kb_articles import KbArticleService

        svc = KbArticleService()
        svc.create_category("admin-user", name="Support")
        session: dict = {}

        result = self._run(list_categories(_session=session))
        assert len(result.categories) >= 1

    def test_public_list_articles(self):
        from app.routers.kb_articles import public_list_articles
        from app.services.kb_articles import KbArticleService
        from app.core.time import now_ts

        svc = KbArticleService()
        item = svc.create_article("admin-user", title="Public article")
        svc.publish_article(item["article_id"], "admin-user")
        # Patch published_at so ByStatus GSI returns it
        self._table.update_item(
            Key={"pk": f"ARTICLE#{item['article_id']}", "sk": "META"},
            UpdateExpression="SET published_at = :ts",
            ExpressionAttributeValues={":ts": now_ts()},
        )

        result = self._run(public_list_articles(category_id=None, tag=None, limit=20, cursor=None))
        assert len(result.items) >= 1

    def test_public_get_article(self):
        from app.routers.kb_articles import public_get_article
        from app.services.kb_articles import KbArticleService

        svc = KbArticleService()
        item = svc.create_article("admin-user", title="Public get test")
        svc.publish_article(item["article_id"], "admin-user")

        result = self._run(public_get_article(item["article_id"]))
        assert result.title == "Public get test"
        assert result.status == "published"

    def test_public_search_endpoint(self):
        from app.routers.kb_articles import public_kb_search
        from app.services.kb_articles import KbArticleService
        from app.core.time import now_ts

        svc = KbArticleService()
        item = svc.create_article("admin-user", title="searchable content about payments")
        svc.publish_article(item["article_id"], "admin-user")
        self._table.update_item(
            Key={"pk": f"ARTICLE#{item['article_id']}", "sk": "META"},
            UpdateExpression="SET published_at = :ts",
            ExpressionAttributeValues={":ts": now_ts()},
        )

        result = self._run(public_kb_search(q="payments", limit=20, cursor=None))
        assert result.query == "payments"
        assert isinstance(result.items, list)
