"""PMD-002 hermetic offline tests for property_documents service.

Uses a local link store (EVT-011 not yet built).
Pattern: moto in-memory DynamoDB + frozen T/S, no real AWS.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException


@pytest.fixture(scope="module", autouse=True)
def _pmd002_isolation():
    """Set up moto-backed T.property_documents and flip flags."""
    import moto
    import boto3

    with moto.mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        tbl = ddb.create_table(
            TableName="property_documents",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "owner_sub", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "owner-index",
                    "KeySchema": [
                        {"AttributeName": "owner_sub", "KeyType": "HASH"},
                        {"AttributeName": "sk", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
        )

        from app.core import tables as T_module
        from app.core.settings import S

        _orig = getattr(T_module.T, "property_documents", None)
        _orig_flag = getattr(S, "property_dashboard_enabled", False)

        object.__setattr__(T_module.T, "property_documents", tbl)
        object.__setattr__(S, "property_dashboard_enabled", True)

        yield tbl

        if _orig is not None:
            object.__setattr__(T_module.T, "property_documents", _orig)
        object.__setattr__(S, "property_dashboard_enabled", _orig_flag)


class TestPropertyDocumentService:

    def test_valid_record_types_accepted(self):
        import app.services.property_documents as svc
        for rt in ("property", "unit", "lease", "tenant"):
            result = svc.link_document(
                "alice", record_type=rt, record_id=f"ID_{rt}",
                doc_id=f"doc_{rt}", file_path=f"/files/{rt}.pdf",
            )
            assert result["record_type"] == rt
            assert result["doc_id"] == f"doc_{rt}"

    def test_invalid_record_type_raises_400(self):
        import app.services.property_documents as svc
        with pytest.raises(HTTPException) as exc:
            svc.link_document(
                "alice", record_type="invoice", record_id="R1",
                doc_id="doc1",
            )
        assert exc.value.status_code == 400

    def test_list_by_lease(self):
        import app.services.property_documents as svc
        svc.link_document("bob", record_type="lease", record_id="LSE-42",
                          doc_id="lease_doc", file_path="/leases/l42.pdf")
        result = svc.list_documents("bob", record_type="lease", record_id="LSE-42")
        assert result["count"] == 1
        assert result["items"][0]["file_path"] == "/leases/l42.pdf"

    def test_list_by_property(self):
        import app.services.property_documents as svc
        svc.link_document("carol", record_type="property", record_id="P1",
                          doc_id="prop_doc", crm_category="Deed")
        result = svc.list_documents("carol", record_type="property", record_id="P1")
        assert result["count"] == 1
        assert result["items"][0]["crm_category"] == "Deed"

    def test_list_by_unit(self):
        import app.services.property_documents as svc
        svc.link_document("dave", record_type="unit", record_id="U9",
                          doc_id="unit_doc")
        result = svc.list_documents("dave", record_type="unit", record_id="U9")
        assert result["count"] == 1

    def test_list_by_tenant(self):
        import app.services.property_documents as svc
        svc.link_document("eve", record_type="tenant", record_id="T5",
                          doc_id="tenant_doc")
        result = svc.list_documents("eve", record_type="tenant", record_id="T5")
        assert result["count"] == 1

    def test_cross_user_isolation(self):
        """Bob's links are not visible to alice."""
        import app.services.property_documents as svc
        svc.link_document("bob_iso", record_type="lease", record_id="LSE-SHARED",
                          doc_id="bob_doc")
        # Alice queries same record_id but should see 0 results
        result = svc.list_documents("alice_iso", record_type="lease",
                                    record_id="LSE-SHARED")
        assert result["count"] == 0

    def test_unlink_removes_document(self):
        import app.services.property_documents as svc
        svc.link_document("frank", record_type="lease", record_id="LSE-99",
                          doc_id="frank_doc")
        # Confirm it's there
        r1 = svc.list_documents("frank", record_type="lease", record_id="LSE-99")
        assert r1["count"] == 1
        # Unlink
        found = svc.unlink_document("frank", record_type="lease",
                                    record_id="LSE-99", doc_id="frank_doc")
        assert found is True
        # Confirm gone
        r2 = svc.list_documents("frank", record_type="lease", record_id="LSE-99")
        assert r2["count"] == 0

    def test_unlink_nonexistent_returns_false(self):
        import app.services.property_documents as svc
        found = svc.unlink_document("nobody", record_type="lease",
                                    record_id="LSE-NONE", doc_id="no_doc")
        assert found is False

    def test_flag_off_raises_404(self):
        from app.core.settings import S
        import app.services.property_documents as svc
        object.__setattr__(S, "property_dashboard_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc:
                svc.list_documents("user", record_type="lease", record_id="R1")
            assert exc.value.status_code == 404
        finally:
            object.__setattr__(S, "property_dashboard_enabled", True)

    def test_idempotent_link_overwrites(self):
        """Linking the same doc_id twice overwrites (no error)."""
        import app.services.property_documents as svc
        svc.link_document("greta", record_type="lease", record_id="LSE-77",
                          doc_id="idempotent_doc", crm_category="Old")
        svc.link_document("greta", record_type="lease", record_id="LSE-77",
                          doc_id="idempotent_doc", crm_category="New")
        result = svc.list_documents("greta", record_type="lease", record_id="LSE-77")
        # Should still be 1 item (put_item replaces)
        assert result["count"] == 1
        assert result["items"][0]["crm_category"] == "New"
