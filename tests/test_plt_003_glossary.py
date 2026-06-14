"""PLT-003 hermetic unit tests: Glossary endpoint."""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch
from fastapi import HTTPException


@pytest.fixture(autouse=True, scope="module")
def _setup_glossary():
    """Create moto glossary table, bind to T.glossary, set S flags, restore."""
    import boto3
    from moto import mock_aws

    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        tbl = ddb.create_table(
            TableName="glossary_test",
            KeySchema=[
                {"AttributeName": "term_id", "KeyType": "HASH"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "term_id", "AttributeType": "S"},
                {"AttributeName": "GSI1PK", "AttributeType": "S"},
                {"AttributeName": "GSI1SK", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "GSI_BY_TERM",
                    "KeySchema": [
                        {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
        )
        tbl.meta.client.get_waiter("table_exists").wait(TableName="glossary_test")

        from app.core.tables import T
        from app.core.settings import S

        orig_glossary = T.glossary
        orig_enabled = S.glossary_enabled
        orig_max_chars = S.glossary_definition_max_chars
        orig_admin = getattr(S, "filemgr_admin_users", "")

        object.__setattr__(T, "glossary", tbl)
        object.__setattr__(S, "glossary_enabled", True)
        object.__setattr__(S, "glossary_definition_max_chars", 4096)
        object.__setattr__(S, "filemgr_admin_users", "admin_sub_test")

        yield tbl

        object.__setattr__(T, "glossary", orig_glossary)
        object.__setattr__(S, "glossary_enabled", orig_enabled)
        object.__setattr__(S, "glossary_definition_max_chars", orig_max_chars)
        object.__setattr__(S, "filemgr_admin_users", orig_admin)


def _clear_table(tbl):
    resp = tbl.scan()
    with tbl.batch_writer() as batch:
        for item in resp.get("Items", []):
            batch.delete_item(Key={"term_id": item["term_id"]})


# Test 1: Create term
def test_create_term(_setup_glossary):
    from app.routers.glossary import create_term
    from app.models import GlossaryCreateIn

    _clear_table(_setup_glossary)

    req = MagicMock()
    body = GlossaryCreateIn(term="account", definition="A customer account.", tags=["accounts"])

    with patch("app.routers.glossary.audit_event"):
        result = create_term(body=body, req=req, admin_user="admin_sub_test")

    assert result.term_id.startswith("gloss_")
    assert result.term == "account"
    assert result.created_at > 0
    assert result.updated_at == result.created_at
    assert result.updated_by == "admin_sub_test"


# Test 2: List empty
def test_list_empty(_setup_glossary):
    _clear_table(_setup_glossary)

    from app.services.glossary import list_glossary
    result = list_glossary()

    assert result["terms"] == []
    assert result["count"] == 0
    assert result["next_cursor"] is None


# Test 3: List returns terms alphabetically
def test_list_alphabetical(_setup_glossary):
    _clear_table(_setup_glossary)

    from app.routers.glossary import create_term
    from app.models import GlossaryCreateIn
    from app.services.glossary import list_glossary

    req = MagicMock()
    with patch("app.routers.glossary.audit_event"):
        for name in ["zebra", "apple", "mango"]:
            create_term(body=GlossaryCreateIn(term=name, definition=f"def of {name}"), req=req, admin_user="admin_sub_test")

    result = list_glossary()

    terms = [t["term"] for t in result["terms"]]
    assert terms == sorted(terms)  # alphabetical
    assert "apple" in terms
    assert "mango" in terms
    assert "zebra" in terms


# Test 4: Search filter
def test_list_search_filter(_setup_glossary):
    _clear_table(_setup_glossary)

    from app.routers.glossary import create_term
    from app.models import GlossaryCreateIn
    from app.services.glossary import list_glossary

    req = MagicMock()
    with patch("app.routers.glossary.audit_event"):
        for name in ["foo_bar", "foo_baz", "qux"]:
            create_term(body=GlossaryCreateIn(term=name, definition=f"def {name}"), req=req, admin_user="admin_sub_test")

    result = list_glossary(search="foo")

    terms = [t["term"] for t in result["terms"]]
    assert "foo_bar" in terms
    assert "foo_baz" in terms
    assert "qux" not in terms


# Test 5: Get term found
def test_get_term_found(_setup_glossary):
    _clear_table(_setup_glossary)

    from app.routers.glossary import create_term, get_term
    from app.models import GlossaryCreateIn

    req = MagicMock()
    with patch("app.routers.glossary.audit_event"):
        created = create_term(body=GlossaryCreateIn(term="test_term", definition="A test."), req=req, admin_user="admin_sub_test")

    found = get_term(term_id=created.term_id)
    assert found.term_id == created.term_id
    assert found.term == "test_term"


# Test 6: Get term not found
def test_get_term_not_found(_setup_glossary):
    from app.routers.glossary import get_term

    with pytest.raises(HTTPException) as exc_info:
        get_term(term_id="gloss_doesnotexist")
    assert exc_info.value.status_code == 404


# Test 7: Patch term
def test_patch_term(_setup_glossary):
    _clear_table(_setup_glossary)

    from app.routers.glossary import create_term, patch_term
    from app.models import GlossaryCreateIn, GlossaryPatchIn

    req = MagicMock()
    with patch("app.routers.glossary.audit_event"):
        created = create_term(body=GlossaryCreateIn(term="old", definition="old def"), req=req, admin_user="admin_sub_test")
        updated = patch_term(
            term_id=created.term_id,
            body=GlossaryPatchIn(definition="Updated def"),
            req=req,
            admin_user="admin_sub_test",
        )

    assert updated.definition == "Updated def"
    assert updated.term == "old"
    assert updated.updated_at >= created.created_at


# Test 8: Patch nonexistent
def test_patch_nonexistent(_setup_glossary):
    from app.routers.glossary import patch_term
    from app.models import GlossaryPatchIn

    req = MagicMock()
    with pytest.raises(HTTPException) as exc_info:
        with patch("app.routers.glossary.audit_event"):
            patch_term(term_id="gloss_none", body=GlossaryPatchIn(definition="x"), req=req, admin_user="admin_sub_test")
    assert exc_info.value.status_code == 404


# Test 9: Delete term
def test_delete_term(_setup_glossary):
    _clear_table(_setup_glossary)

    from app.routers.glossary import create_term, delete_term, get_term
    from app.models import GlossaryCreateIn

    req = MagicMock()
    with patch("app.routers.glossary.audit_event"):
        created = create_term(body=GlossaryCreateIn(term="del_me", definition="to delete"), req=req, admin_user="admin_sub_test")
        delete_term(term_id=created.term_id, req=req, admin_user="admin_sub_test")

    with pytest.raises(HTTPException):
        get_term(term_id=created.term_id)


# Test 10: Delete nonexistent
def test_delete_nonexistent(_setup_glossary):
    from app.routers.glossary import delete_term

    req = MagicMock()
    with pytest.raises(HTTPException) as exc_info:
        with patch("app.routers.glossary.audit_event"):
            delete_term(term_id="gloss_none", req=req, admin_user="admin_sub_test")
    assert exc_info.value.status_code == 404


# Test 11: Definition max length enforced
def test_definition_max_length_enforced(_setup_glossary):
    from app.core.settings import S
    from app.services.glossary import upsert_glossary_term

    object.__setattr__(S, "glossary_definition_max_chars", 10)
    try:
        with pytest.raises(HTTPException) as exc_info:
            upsert_glossary_term(term="x", definition="y" * 11, updated_by="admin")
        assert exc_info.value.status_code == 422
    finally:
        object.__setattr__(S, "glossary_definition_max_chars", 4096)


# Test 12: Audit event emitted on create/patch/delete
def test_audit_event_on_mutations(_setup_glossary):
    _clear_table(_setup_glossary)

    from app.routers.glossary import create_term, patch_term, delete_term
    from app.models import GlossaryCreateIn, GlossaryPatchIn

    req = MagicMock()
    with patch("app.routers.glossary.audit_event") as mock_audit:
        created = create_term(body=GlossaryCreateIn(term="ev_test", definition="ev def"), req=req, admin_user="admin_sub_test")
        patch_term(term_id=created.term_id, body=GlossaryPatchIn(definition="ev def 2"), req=req, admin_user="admin_sub_test")
        delete_term(term_id=created.term_id, req=req, admin_user="admin_sub_test")

    calls = [c[0][0] for c in mock_audit.call_args_list]
    assert "glossary_upsert" in calls
    assert "glossary_delete" in calls
