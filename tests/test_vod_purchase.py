"""Unit tests for VOD purchase service (MON-001)."""
import os
import boto3
import pytest
from moto import mock_aws


@pytest.fixture(autouse=True)
def _env():
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
    os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
    os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")
    os.environ.setdefault("DDB_ENDPOINT_URL", "")
    os.environ.setdefault("DEV_MODE", "1")
    os.environ.setdefault("UI_ACCESS_TOKEN_SECRET", "test-secret")
    os.environ.setdefault("API_KEY_PEPPER", "test-pepper")


@pytest.fixture
def ddb_tables():
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        # VodEntitlements
        ddb.create_table(
            TableName="VodEntitlements",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "video_id", "AttributeType": "S"},
                {"AttributeName": "created_at", "AttributeType": "N"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "ByVideoCreatedAt",
                    "KeySchema": [
                        {"AttributeName": "video_id", "KeyType": "HASH"},
                        {"AttributeName": "created_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        # VideoMetadata
        ddb.create_table(
            TableName="VideoMetadata",
            KeySchema=[{"AttributeName": "video_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "video_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )

        # billing table
        ddb.create_table(
            TableName="billing",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        # Patch table handles
        import app.core.tables as tables_mod
        original_vod_ent = tables_mod.T.vod_entitlements
        original_video = tables_mod.T.video_metadata
        original_billing = tables_mod.T.billing

        object.__setattr__(tables_mod.T, "vod_entitlements", ddb.Table("VodEntitlements"))
        object.__setattr__(tables_mod.T, "video_metadata", ddb.Table("VideoMetadata"))
        object.__setattr__(tables_mod.T, "billing", ddb.Table("billing"))

        yield ddb

        object.__setattr__(tables_mod.T, "vod_entitlements", original_vod_ent)
        object.__setattr__(tables_mod.T, "video_metadata", original_video)
        object.__setattr__(tables_mod.T, "billing", original_billing)


class TestCheckEntitlement:
    def test_not_entitled(self, ddb_tables):
        from app.services.vod_purchase import check_entitlement
        result = check_entitlement("user1", "v_test123")
        assert result["entitled"] is False
        assert result["reason"] == "not_purchased"

    def test_entitled_after_purchase(self, ddb_tables):
        from app.services.vod_purchase import check_entitlement, purchase_video

        # Seed video
        ddb_tables.Table("VideoMetadata").put_item(Item={
            "video_id": "v_test456",
            "owner_user_id": "seller1",
            "title": "Test",
            "status": "published",
            "created_at": 1000,
            "updated_at": 1000,
            "source_type": "upload",
            "visibility": "public",
            "drm_enabled": False,
        })

        purchase_video(
            buyer_id="buyer1",
            video_id="v_test456",
            price_cents=500,
            seller_id="seller1",
        )

        result = check_entitlement("buyer1", "v_test456")
        assert result["entitled"] is True
        assert result["reason"] == "purchase"


class TestPurchaseVideo:
    def test_creates_entitlement(self, ddb_tables):
        from app.services.vod_purchase import purchase_video

        ddb_tables.Table("VideoMetadata").put_item(Item={
            "video_id": "v_buy1",
            "owner_user_id": "seller1",
            "title": "Buy Test",
            "status": "published",
            "created_at": 1000,
            "updated_at": 1000,
            "source_type": "upload",
            "visibility": "public",
            "drm_enabled": False,
        })

        result = purchase_video(
            buyer_id="buyer2",
            video_id="v_buy1",
            price_cents=999,
            seller_id="seller1",
        )
        assert result["already_owned"] is False
        assert result["amount_cents"] == 999
        assert result["purchase_id"].startswith("vpurch_")

    def test_idempotent_purchase(self, ddb_tables):
        from app.services.vod_purchase import purchase_video

        ddb_tables.Table("VideoMetadata").put_item(Item={
            "video_id": "v_idem",
            "owner_user_id": "seller1",
            "title": "Idem Test",
            "status": "published",
            "created_at": 1000,
            "updated_at": 1000,
            "source_type": "upload",
            "visibility": "public",
            "drm_enabled": False,
        })

        r1 = purchase_video(buyer_id="buyer3", video_id="v_idem", price_cents=500, seller_id="seller1")
        r2 = purchase_video(buyer_id="buyer3", video_id="v_idem", price_cents=500, seller_id="seller1")
        assert r1["already_owned"] is False
        assert r2["already_owned"] is True

    def test_writes_debit_and_credit_ledger(self, ddb_tables):
        from app.services.vod_purchase import purchase_video

        ddb_tables.Table("VideoMetadata").put_item(Item={
            "video_id": "v_ledger",
            "owner_user_id": "seller_ledger",
            "title": "Ledger Test",
            "status": "published",
            "created_at": 1000,
            "updated_at": 1000,
            "source_type": "upload",
            "visibility": "public",
            "drm_enabled": False,
        })

        purchase_video(buyer_id="buyer_ledger", video_id="v_ledger", price_cents=750, seller_id="seller_ledger")

        billing = ddb_tables.Table("billing")
        # Check buyer debit
        buyer_items = billing.query(
            KeyConditionExpression="pk = :pk AND begins_with(sk, :prefix)",
            ExpressionAttributeValues={":pk": "USER#buyer_ledger", ":prefix": "LEDGER#"},
        )["Items"]
        assert len(buyer_items) >= 1
        debit = buyer_items[0]
        assert debit["type"] == "vod_purchase_debit"
        assert int(debit["amount_cents"]) == 750

        # Check seller credit
        seller_items = billing.query(
            KeyConditionExpression="pk = :pk AND begins_with(sk, :prefix)",
            ExpressionAttributeValues={":pk": "USER#seller_ledger", ":prefix": "LEDGER#"},
        )["Items"]
        assert len(seller_items) >= 1
        credit = seller_items[0]
        assert credit["type"] == "vod_purchase_credit"
        assert int(credit["amount_cents"]) == 750

    def test_increments_purchase_stats(self, ddb_tables):
        from app.services.vod_purchase import purchase_video

        ddb_tables.Table("VideoMetadata").put_item(Item={
            "video_id": "v_stats",
            "owner_user_id": "seller_stats",
            "title": "Stats Test",
            "status": "published",
            "created_at": 1000,
            "updated_at": 1000,
            "source_type": "upload",
            "visibility": "public",
            "drm_enabled": False,
        })

        purchase_video(buyer_id="buyer_stats", video_id="v_stats", price_cents=300, seller_id="seller_stats")

        item = ddb_tables.Table("VideoMetadata").get_item(Key={"video_id": "v_stats"})["Item"]
        assert int(item.get("purchase_count", 0)) == 1
        assert int(item.get("revenue_cents", 0)) == 300


class TestListPurchases:
    def test_empty_list(self, ddb_tables):
        from app.services.vod_purchase import list_purchases
        result = list_purchases("nobody")
        assert result == []

    def test_lists_purchased_videos(self, ddb_tables):
        from app.services.vod_purchase import purchase_video, list_purchases

        ddb_tables.Table("VideoMetadata").put_item(Item={
            "video_id": "v_list1",
            "owner_user_id": "seller_list",
            "title": "List Test",
            "status": "published",
            "created_at": 1000,
            "updated_at": 1000,
            "source_type": "upload",
            "visibility": "public",
            "drm_enabled": False,
        })

        purchase_video(buyer_id="buyer_list", video_id="v_list1", price_cents=100, seller_id="seller_list")
        result = list_purchases("buyer_list")
        assert len(result) >= 1
        found = [r for r in result if r["video_id"] == "v_list1"]
        assert len(found) == 1


class TestGrantEntitlement:
    def test_grant_subscription_access(self, ddb_tables):
        from app.services.vod_purchase import grant_entitlement, check_entitlement
        result = grant_entitlement(user_id="sub_user", video_id="v_sub1", grant_type="subscription", seller_id="creator1")
        assert result["already_owned"] is False
        assert result["grant_type"] == "subscription"

        ent = check_entitlement("sub_user", "v_sub1")
        assert ent["entitled"] is True
        assert ent["reason"] == "subscription"

    def test_grant_idempotent(self, ddb_tables):
        from app.services.vod_purchase import grant_entitlement
        r1 = grant_entitlement(user_id="sub_user2", video_id="v_sub2", grant_type="promo")
        r2 = grant_entitlement(user_id="sub_user2", video_id="v_sub2", grant_type="promo")
        assert r1["already_owned"] is False
        assert r2["already_owned"] is True
