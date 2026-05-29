"""Unit tests for VOD-019 purchase tiers (view-once, rental, download)."""
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
    os.environ.setdefault("VOD_PURCHASE_TIERS_ENABLED", "1")


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


ALICE_ID = "alice_creator"
BOB_ID = "bob_viewer"


def _seed_video(ddb, video_id, *, owner=ALICE_ID, price=999, access_mode="ppv"):
    """Seed a video metadata record."""
    from app.core.time import now_ts
    ddb.Table("VideoMetadata").put_item(Item={
        "video_id": video_id,
        "owner_user_id": owner,
        "title": f"Test Video {video_id}",
        "status": "published",
        "visibility": "public",
        "created_at": now_ts(),
        "updated_at": now_ts(),
        "source_type": "upload",
        "drm_enabled": False,
        "price_cents": price,
        "access_mode": access_mode,
    })


def _seed_video_with_tiers(ddb, video_id, *, owner=ALICE_ID):
    """Seed a video with all purchase tiers configured."""
    from app.core.time import now_ts
    ddb.Table("VideoMetadata").put_item(Item={
        "video_id": video_id,
        "owner_user_id": owner,
        "title": f"Tiered Video {video_id}",
        "status": "published",
        "visibility": "public",
        "created_at": now_ts(),
        "updated_at": now_ts(),
        "source_type": "upload",
        "drm_enabled": False,
        "price_cents": 999,
        "access_mode": "ppv",
        "available_purchase_types": ["view_once", "rental", "permanent", "download"],
        "view_once_price_cents": 199,
        "rental_price_cents": 299,
        "rental_duration_hours": 48,
        "download_price_cents": 1299,
        "allow_download": True,
        "download_mp4_key": "s3://bucket/test.mp4",
        "download_mp4_status": "ready",
    })


def _delete_entitlement(ddb, user_id, video_id):
    """Delete an entitlement record."""
    ddb.Table("VodEntitlements").delete_item(
        Key={"pk": f"USER#{user_id}", "sk": f"VIDEO#{video_id}"}
    )


# ─── Standard Purchase (backward compatibility) ──────────────────────────────


class TestStandardPurchase:
    def test_default_purchase_type_is_permanent(self, ddb_tables):
        from app.services.vod_purchase import purchase_video
        _seed_video(ddb_tables, "v_std1")

        result = purchase_video(
            buyer_id=BOB_ID,
            video_id="v_std1",
            price_cents=999,
            seller_id=ALICE_ID,
        )
        assert result["already_owned"] is False
        assert result["purchase_type"] == "permanent"
        assert result["views_remaining"] == -1
        assert result["expires_at"] is None
        assert result["download_allowed"] is False

    def test_permanent_entitlement_check(self, ddb_tables):
        from app.services.vod_purchase import purchase_video, check_entitlement_purchase_only
        _seed_video(ddb_tables, "v_std2")

        purchase_video(
            buyer_id=BOB_ID,
            video_id="v_std2",
            price_cents=999,
            seller_id=ALICE_ID,
        )

        ent = check_entitlement_purchase_only(user_id=BOB_ID, video_id="v_std2")
        assert ent.entitled is True
        assert ent.purchase_type == "permanent"
        assert ent.views_remaining == -1
        assert ent.download_allowed is False

    def test_legacy_entitlement_treated_as_permanent(self, ddb_tables):
        """Entitlement records without purchase_type are treated as permanent."""
        from app.services.vod_purchase import check_entitlement_purchase_only

        # Write a legacy record (no VOD-019 fields)
        ddb_tables.Table("VodEntitlements").put_item(Item={
            "pk": f"USER#{BOB_ID}",
            "sk": "VIDEO#v_legacy",
            "video_id": "v_legacy",
            "buyer_id": BOB_ID,
            "grant_type": "purchase",
            "created_at": 1000,
            "amount_cents": 999,
        })

        ent = check_entitlement_purchase_only(user_id=BOB_ID, video_id="v_legacy")
        assert ent.entitled is True
        assert ent.purchase_type == "permanent"
        assert ent.views_remaining == -1
        assert ent.download_allowed is False


# ─── View-Once Lifecycle ──────────────────────────────────────────────────────


class TestViewOncePurchase:
    def test_view_once_purchase(self, ddb_tables):
        from app.services.vod_purchase import purchase_video
        _seed_video_with_tiers(ddb_tables, "v_vo1")

        result = purchase_video(
            buyer_id=BOB_ID,
            video_id="v_vo1",
            price_cents=199,
            seller_id=ALICE_ID,
            purchase_type="view_once",
        )
        assert result["purchase_type"] == "view_once"
        assert result["views_remaining"] == 1
        assert result["expires_at"] is None
        assert result["download_allowed"] is False

    def test_view_once_entitled_before_watch(self, ddb_tables):
        from app.services.vod_purchase import purchase_video, check_entitlement_purchase_only
        _seed_video_with_tiers(ddb_tables, "v_vo2")

        purchase_video(
            buyer_id=BOB_ID,
            video_id="v_vo2",
            price_cents=199,
            seller_id=ALICE_ID,
            purchase_type="view_once",
        )

        ent = check_entitlement_purchase_only(user_id=BOB_ID, video_id="v_vo2")
        assert ent.entitled is True
        assert ent.purchase_type == "view_once"
        assert ent.views_remaining == 1

    def test_view_once_consumed_after_playback(self, ddb_tables):
        from app.services.vod_purchase import (
            purchase_video,
            record_playback_complete,
            check_entitlement_purchase_only,
        )
        _seed_video_with_tiers(ddb_tables, "v_vo3")

        purchase_video(
            buyer_id=BOB_ID,
            video_id="v_vo3",
            price_cents=199,
            seller_id=ALICE_ID,
            purchase_type="view_once",
        )

        result = record_playback_complete(user_id=BOB_ID, video_id="v_vo3")
        assert result["ok"] is True
        assert result["views_remaining"] == 0

        ent = check_entitlement_purchase_only(user_id=BOB_ID, video_id="v_vo3")
        assert ent.entitled is False
        assert ent.reason == "consumed"

    def test_view_once_playback_complete_idempotent(self, ddb_tables):
        from app.services.vod_purchase import purchase_video, record_playback_complete
        _seed_video_with_tiers(ddb_tables, "v_vo4")

        purchase_video(
            buyer_id=BOB_ID,
            video_id="v_vo4",
            price_cents=199,
            seller_id=ALICE_ID,
            purchase_type="view_once",
        )

        r1 = record_playback_complete(user_id=BOB_ID, video_id="v_vo4")
        assert r1["views_remaining"] == 0

        r2 = record_playback_complete(user_id=BOB_ID, video_id="v_vo4")
        assert r2["ok"] is True
        assert r2["views_remaining"] == 0

    def test_view_once_repurchase_after_consumption(self, ddb_tables):
        from app.services.vod_purchase import (
            purchase_video,
            record_playback_complete,
            check_entitlement_purchase_only,
        )
        _seed_video_with_tiers(ddb_tables, "v_vo5")

        # First purchase
        purchase_video(
            buyer_id=BOB_ID,
            video_id="v_vo5",
            price_cents=199,
            seller_id=ALICE_ID,
            purchase_type="view_once",
        )
        record_playback_complete(user_id=BOB_ID, video_id="v_vo5")

        # Re-purchase after consumption
        result = purchase_video(
            buyer_id=BOB_ID,
            video_id="v_vo5",
            price_cents=199,
            seller_id=ALICE_ID,
            purchase_type="view_once",
        )
        assert result["already_owned"] is False
        assert result["views_remaining"] == 1

        ent = check_entitlement_purchase_only(user_id=BOB_ID, video_id="v_vo5")
        assert ent.entitled is True
        assert ent.views_remaining == 1


# ─── Rental Lifecycle ─────────────────────────────────────────────────────────


class TestRentalPurchase:
    def test_rental_purchase_sets_expiry(self, ddb_tables):
        from app.services.vod_purchase import purchase_video
        from app.core.time import now_ts
        _seed_video_with_tiers(ddb_tables, "v_rent1")

        result = purchase_video(
            buyer_id=BOB_ID,
            video_id="v_rent1",
            price_cents=299,
            seller_id=ALICE_ID,
            purchase_type="rental",
            rental_duration_hours=48,
        )
        assert result["purchase_type"] == "rental"
        assert result["expires_at"] is not None
        assert result["expires_at"] > now_ts()
        # Should be ~48 hours from now
        assert result["expires_at"] - now_ts() >= 47 * 3600

    def test_rental_entitled_within_window(self, ddb_tables):
        from app.services.vod_purchase import purchase_video, check_entitlement_purchase_only
        _seed_video_with_tiers(ddb_tables, "v_rent2")

        purchase_video(
            buyer_id=BOB_ID,
            video_id="v_rent2",
            price_cents=299,
            seller_id=ALICE_ID,
            purchase_type="rental",
        )

        ent = check_entitlement_purchase_only(user_id=BOB_ID, video_id="v_rent2")
        assert ent.entitled is True
        assert ent.purchase_type == "rental"
        assert ent.expires_at > 0

    def test_rental_expired(self, ddb_tables):
        """Expired rental is not entitled."""
        from app.services.vod_purchase import check_entitlement_purchase_only
        from app.core.time import now_ts

        ddb_tables.Table("VodEntitlements").put_item(Item={
            "pk": f"USER#{BOB_ID}",
            "sk": "VIDEO#v_rent_exp",
            "video_id": "v_rent_exp",
            "buyer_id": BOB_ID,
            "seller_id": ALICE_ID,
            "grant_type": "purchase",
            "purchase_type": "rental",
            "views_remaining": -1,
            "expires_at": now_ts() - 3600,  # 1 hour in the past
            "created_at": now_ts() - 7200,
            "amount_cents": 299,
        })

        ent = check_entitlement_purchase_only(user_id=BOB_ID, video_id="v_rent_exp")
        assert ent.entitled is False
        assert ent.reason == "expired"

    def test_rental_repurchase_after_expiry(self, ddb_tables):
        from app.services.vod_purchase import purchase_video
        from app.core.time import now_ts
        _seed_video_with_tiers(ddb_tables, "v_rent3")

        # Seed expired rental
        ddb_tables.Table("VodEntitlements").put_item(Item={
            "pk": f"USER#{BOB_ID}",
            "sk": "VIDEO#v_rent3",
            "video_id": "v_rent3",
            "buyer_id": BOB_ID,
            "seller_id": ALICE_ID,
            "grant_type": "purchase",
            "purchase_type": "rental",
            "views_remaining": -1,
            "expires_at": now_ts() - 3600,
            "created_at": now_ts() - 7200,
            "amount_cents": 299,
        })

        # Re-purchase should succeed (expired rental allows re-purchase)
        result = purchase_video(
            buyer_id=BOB_ID,
            video_id="v_rent3",
            price_cents=299,
            seller_id=ALICE_ID,
            purchase_type="rental",
        )
        assert result["already_owned"] is False
        assert result["purchase_type"] == "rental"
        assert result["expires_at"] > now_ts()


# ─── Download Purchase ────────────────────────────────────────────────────────


class TestDownloadPurchase:
    def test_download_purchase_grants_download(self, ddb_tables):
        from app.services.vod_purchase import purchase_video
        _seed_video_with_tiers(ddb_tables, "v_dl1")

        result = purchase_video(
            buyer_id=BOB_ID,
            video_id="v_dl1",
            price_cents=1299,
            seller_id=ALICE_ID,
            purchase_type="download",
        )
        assert result["purchase_type"] == "download"
        assert result["download_allowed"] is True
        assert result["views_remaining"] == -1
        assert result["expires_at"] is None

    def test_download_entitlement_check(self, ddb_tables):
        from app.services.vod_purchase import purchase_video, check_entitlement_purchase_only
        _seed_video_with_tiers(ddb_tables, "v_dl2")

        purchase_video(
            buyer_id=BOB_ID,
            video_id="v_dl2",
            price_cents=1299,
            seller_id=ALICE_ID,
            purchase_type="download",
        )

        ent = check_entitlement_purchase_only(user_id=BOB_ID, video_id="v_dl2")
        assert ent.entitled is True
        assert ent.purchase_type == "download"
        assert ent.download_allowed is True

    def test_permanent_purchase_no_download(self, ddb_tables):
        from app.services.vod_purchase import purchase_video, check_entitlement_purchase_only
        _seed_video_with_tiers(ddb_tables, "v_dl3")

        purchase_video(
            buyer_id=BOB_ID,
            video_id="v_dl3",
            price_cents=999,
            seller_id=ALICE_ID,
            purchase_type="permanent",
        )

        ent = check_entitlement_purchase_only(user_id=BOB_ID, video_id="v_dl3")
        assert ent.entitled is True
        assert ent.download_allowed is False


# ─── Idempotent Purchase ─────────────────────────────────────────────────────


class TestIdempotentPurchase:
    def test_already_owned_returns_existing(self, ddb_tables):
        from app.services.vod_purchase import purchase_video
        _seed_video_with_tiers(ddb_tables, "v_idem1")

        r1 = purchase_video(
            buyer_id=BOB_ID,
            video_id="v_idem1",
            price_cents=999,
            seller_id=ALICE_ID,
            purchase_type="permanent",
        )
        r2 = purchase_video(
            buyer_id=BOB_ID,
            video_id="v_idem1",
            price_cents=999,
            seller_id=ALICE_ID,
            purchase_type="permanent",
        )
        assert r1["already_owned"] is False
        assert r2["already_owned"] is True
        assert r2["purchase_type"] == "permanent"


# ─── Batch Check Filters Expired/Consumed ────────────────────────────────────


class TestBatchCheckEntitlements:
    def test_batch_filters_consumed_view_once(self, ddb_tables):
        from app.services.vod_purchase import _batch_check_entitlements
        from app.core.time import now_ts

        # Seed a consumed view-once entitlement
        ddb_tables.Table("VodEntitlements").put_item(Item={
            "pk": f"USER#{BOB_ID}",
            "sk": "VIDEO#v_batch_vo",
            "video_id": "v_batch_vo",
            "buyer_id": BOB_ID,
            "grant_type": "purchase",
            "purchase_type": "view_once",
            "views_remaining": 0,
            "expires_at": 0,
            "created_at": now_ts(),
            "amount_cents": 199,
        })

        # Seed a valid permanent entitlement
        ddb_tables.Table("VodEntitlements").put_item(Item={
            "pk": f"USER#{BOB_ID}",
            "sk": "VIDEO#v_batch_perm",
            "video_id": "v_batch_perm",
            "buyer_id": BOB_ID,
            "grant_type": "purchase",
            "purchase_type": "permanent",
            "views_remaining": -1,
            "expires_at": 0,
            "created_at": now_ts(),
            "amount_cents": 999,
        })

        result = _batch_check_entitlements(
            user_id=BOB_ID,
            video_ids=["v_batch_vo", "v_batch_perm"],
        )
        assert "v_batch_vo" not in result  # consumed = excluded
        assert "v_batch_perm" in result  # valid = included

    def test_batch_filters_expired_rental(self, ddb_tables):
        from app.services.vod_purchase import _batch_check_entitlements
        from app.core.time import now_ts

        # Seed an expired rental
        ddb_tables.Table("VodEntitlements").put_item(Item={
            "pk": f"USER#{BOB_ID}",
            "sk": "VIDEO#v_batch_rent",
            "video_id": "v_batch_rent",
            "buyer_id": BOB_ID,
            "grant_type": "purchase",
            "purchase_type": "rental",
            "views_remaining": -1,
            "expires_at": now_ts() - 3600,
            "created_at": now_ts() - 7200,
            "amount_cents": 299,
        })

        result = _batch_check_entitlements(
            user_id=BOB_ID,
            video_ids=["v_batch_rent"],
        )
        assert "v_batch_rent" not in result  # expired = excluded


# ─── List Purchases Shows Purchase Type ───────────────────────────────────────


class TestListPurchases:
    def test_list_includes_purchase_type(self, ddb_tables):
        from app.services.vod_purchase import purchase_video, list_purchases
        _seed_video_with_tiers(ddb_tables, "v_list_vo")

        purchase_video(
            buyer_id=BOB_ID,
            video_id="v_list_vo",
            price_cents=199,
            seller_id=ALICE_ID,
            purchase_type="view_once",
        )

        items = list_purchases(BOB_ID)
        found = [i for i in items if i["video_id"] == "v_list_vo"]
        assert len(found) == 1
        assert found[0]["purchase_type"] == "view_once"
        assert found[0]["views_remaining"] == 1

    def test_list_includes_download_flag(self, ddb_tables):
        from app.services.vod_purchase import purchase_video, list_purchases
        _seed_video_with_tiers(ddb_tables, "v_list_dl")

        purchase_video(
            buyer_id=BOB_ID,
            video_id="v_list_dl",
            price_cents=1299,
            seller_id=ALICE_ID,
            purchase_type="download",
        )

        items = list_purchases(BOB_ID)
        found = [i for i in items if i["video_id"] == "v_list_dl"]
        assert len(found) == 1
        assert found[0]["download_allowed"] is True


# ─── Playback Complete Edge Cases ─────────────────────────────────────────────


class TestPlaybackComplete:
    def test_no_entitlement_returns_error(self, ddb_tables):
        from app.services.vod_purchase import record_playback_complete
        result = record_playback_complete(user_id=BOB_ID, video_id="v_no_ent")
        assert result["ok"] is False

    def test_permanent_purchase_playback_noop(self, ddb_tables):
        from app.services.vod_purchase import purchase_video, record_playback_complete
        _seed_video_with_tiers(ddb_tables, "v_perm_pb")

        purchase_video(
            buyer_id=BOB_ID,
            video_id="v_perm_pb",
            price_cents=999,
            seller_id=ALICE_ID,
            purchase_type="permanent",
        )

        result = record_playback_complete(user_id=BOB_ID, video_id="v_perm_pb")
        assert result["ok"] is True
        assert result["views_remaining"] == -1  # unchanged
        assert result["purchase_type"] == "permanent"

    def test_rental_playback_noop(self, ddb_tables):
        from app.services.vod_purchase import purchase_video, record_playback_complete
        _seed_video_with_tiers(ddb_tables, "v_rent_pb")

        purchase_video(
            buyer_id=BOB_ID,
            video_id="v_rent_pb",
            price_cents=299,
            seller_id=ALICE_ID,
            purchase_type="rental",
        )

        result = record_playback_complete(user_id=BOB_ID, video_id="v_rent_pb")
        assert result["ok"] is True
        assert result["views_remaining"] == -1  # rental = unlimited views


# ─── VodAccessResult Integration ──────────────────────────────────────────────


class TestVodAccessWithTiers:
    def test_purchased_view_once_shows_in_access(self, ddb_tables):
        from app.services.vod_purchase import purchase_video, check_vod_access
        from app.services.video_metadata_store import get_video
        _seed_video_with_tiers(ddb_tables, "v_acc_vo")

        purchase_video(
            buyer_id=BOB_ID,
            video_id="v_acc_vo",
            price_cents=199,
            seller_id=ALICE_ID,
            purchase_type="view_once",
        )

        video = get_video("v_acc_vo")
        access = check_vod_access(user_id=BOB_ID, video_id="v_acc_vo", video=video)
        assert access.entitled is True
        assert access.reason == "purchased"
        assert access.purchase_type == "view_once"
        assert access.views_remaining == 1

    def test_consumed_view_once_shows_consumed(self, ddb_tables):
        from app.services.vod_purchase import (
            purchase_video,
            record_playback_complete,
            check_vod_access,
        )
        from app.services.video_metadata_store import get_video
        _seed_video_with_tiers(ddb_tables, "v_acc_vo2")

        purchase_video(
            buyer_id=BOB_ID,
            video_id="v_acc_vo2",
            price_cents=199,
            seller_id=ALICE_ID,
            purchase_type="view_once",
        )
        record_playback_complete(user_id=BOB_ID, video_id="v_acc_vo2")

        video = get_video("v_acc_vo2")
        access = check_vod_access(user_id=BOB_ID, video_id="v_acc_vo2", video=video)
        assert access.entitled is False
        assert access.reason == "consumed"

    def test_expired_rental_shows_expired(self, ddb_tables):
        from app.services.vod_purchase import check_vod_access
        from app.services.video_metadata_store import get_video
        from app.core.time import now_ts
        _seed_video_with_tiers(ddb_tables, "v_acc_rent")

        # Seed expired rental
        ddb_tables.Table("VodEntitlements").put_item(Item={
            "pk": f"USER#{BOB_ID}",
            "sk": "VIDEO#v_acc_rent",
            "video_id": "v_acc_rent",
            "buyer_id": BOB_ID,
            "seller_id": ALICE_ID,
            "grant_type": "purchase",
            "purchase_type": "rental",
            "views_remaining": -1,
            "expires_at": now_ts() - 3600,
            "created_at": now_ts() - 7200,
            "amount_cents": 299,
        })

        video = get_video("v_acc_rent")
        access = check_vod_access(user_id=BOB_ID, video_id="v_acc_rent", video=video)
        assert access.entitled is False
        assert access.reason == "expired"
