"""Unit tests for VOD-018 ad placement service."""
import os
import boto3
import pytest
from moto import mock_aws
from unittest.mock import patch


@pytest.fixture(autouse=True)
def _env():
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
    os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
    os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")
    os.environ.setdefault("DDB_ENDPOINT_URL", "")
    os.environ.setdefault("DEV_MODE", "1")
    os.environ.setdefault("UI_ACCESS_TOKEN_SECRET", "test-secret")
    os.environ.setdefault("API_KEY_PEPPER", "test-pepper")
    os.environ.setdefault("VOD_ADS_ENABLED", "1")
    os.environ.setdefault("VOD_AD_CPM_CENTS", "500")


@pytest.fixture
def ddb_tables():
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

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

        # AdImpressions
        ddb.create_table(
            TableName="AdImpressions",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "video_id", "AttributeType": "S"},
                {"AttributeName": "created_at", "AttributeType": "N"},
                {"AttributeName": "creator_id", "AttributeType": "S"},
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
                {
                    "IndexName": "ByCreatorCreatedAt",
                    "KeySchema": [
                        {"AttributeName": "creator_id", "KeyType": "HASH"},
                        {"AttributeName": "created_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        # Subscriptions table (for has_active_subscription)
        ddb.create_table(
            TableName="subscriptions",
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

        # VodEntitlements (needed by check_vod_access)
        ddb.create_table(
            TableName="VodEntitlements",
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
        originals = {
            "video_metadata": tables_mod.T.video_metadata,
            "billing": tables_mod.T.billing,
            "ad_impressions": tables_mod.T.ad_impressions,
            "subscriptions": tables_mod.T.subscriptions,
            "vod_entitlements": tables_mod.T.vod_entitlements,
        }

        object.__setattr__(tables_mod.T, "video_metadata", ddb.Table("VideoMetadata"))
        object.__setattr__(tables_mod.T, "billing", ddb.Table("billing"))
        object.__setattr__(tables_mod.T, "ad_impressions", ddb.Table("AdImpressions"))
        object.__setattr__(tables_mod.T, "subscriptions", ddb.Table("subscriptions"))
        object.__setattr__(tables_mod.T, "vod_entitlements", ddb.Table("VodEntitlements"))

        yield ddb

        for name, orig in originals.items():
            object.__setattr__(tables_mod.T, name, orig)


def _seed_video(ddb, video_id, owner_id="alice", access_mode="ad_supported",
                price_cents=0, duration_seconds=600, ads_free_for_subscribers=False,
                ad_config=None):
    """Seed a video record in DynamoDB."""
    item = {
        "video_id": video_id,
        "owner_user_id": owner_id,
        "title": f"Test Video {video_id}",
        "status": "published",
        "visibility": "public",
        "created_at": 1000,
        "updated_at": 1000,
        "source_type": "upload",
        "drm_enabled": False,
        "access_mode": access_mode,
        "price_cents": price_cents,
        "duration_seconds": int(duration_seconds),
        "ads_free_for_subscribers": ads_free_for_subscribers,
        "ad_impression_count": 0,
        "ad_revenue_cents": 0,
    }
    if ad_config is not None:
        item["ad_config"] = ad_config
    ddb.Table("VideoMetadata").put_item(Item=item)


def _seed_subscription(ddb, subscriber_id, creator_id):
    """Seed an active subscription in DynamoDB."""
    ddb.Table("subscriptions").put_item(Item={
        "pk": f"SUBSCRIBER#{subscriber_id}",
        "sk": "SUB#sub_active_001",
        "creator_id": creator_id,
        "status": "active",
    })


# ─── Ad Config Tests ────────────────────────────────────────────────────────


class TestGetDefaultAdConfig:
    def test_short_video_pre_roll_only(self):
        from app.services.ad_placement import get_default_ad_config
        config = get_default_ad_config(300)  # 5 min
        assert config["pre_roll"] is True
        assert config["mid_roll_intervals_seconds"] == []

    def test_long_video_has_mid_rolls(self):
        from app.services.ad_placement import get_default_ad_config
        config = get_default_ad_config(900)  # 15 min
        assert config["pre_roll"] is True
        assert 300 in config["mid_roll_intervals_seconds"]
        assert len(config["mid_roll_intervals_seconds"]) >= 1

    def test_very_long_video_multiple_mid_rolls(self):
        from app.services.ad_placement import get_default_ad_config
        config = get_default_ad_config(1800)  # 30 min
        assert len(config["mid_roll_intervals_seconds"]) >= 3
        # Should be at 300, 600, 900, 1200, 1500 (stop 60s before end)
        for ts in config["mid_roll_intervals_seconds"]:
            assert ts < 1800 - 60

    def test_default_skip_is_5s(self):
        from app.services.ad_placement import get_default_ad_config
        config = get_default_ad_config(600)
        assert config["skip_after_seconds"] == 5


class TestValidateAdConfig:
    def test_clamps_skip_to_max_30(self):
        from app.services.ad_placement import validate_ad_config
        config = validate_ad_config({"skip_after_seconds": 100}, duration_seconds=600)
        assert config["skip_after_seconds"] == 30

    def test_clamps_skip_to_min_0(self):
        from app.services.ad_placement import validate_ad_config
        config = validate_ad_config({"skip_after_seconds": -5}, duration_seconds=600)
        assert config["skip_after_seconds"] == 0

    def test_mid_rolls_capped_at_1_per_5_min(self):
        from app.services.ad_placement import validate_ad_config
        config = validate_ad_config(
            {"mid_roll_intervals_seconds": [60, 120, 180, 240, 300, 360]},
            duration_seconds=600,
        )
        # 600s / 300 = 2 max mid-rolls
        assert len(config["mid_roll_intervals_seconds"]) <= 2

    def test_mid_rolls_filtered_by_bounds(self):
        from app.services.ad_placement import validate_ad_config
        # Timestamps < 30 or >= duration-30 are dropped
        config = validate_ad_config(
            {"mid_roll_intervals_seconds": [10, 50, 570, 580]},
            duration_seconds=600,
        )
        for ts in config["mid_roll_intervals_seconds"]:
            assert 30 <= ts < 570

    def test_non_list_mid_rolls_handled(self):
        from app.services.ad_placement import validate_ad_config
        config = validate_ad_config(
            {"mid_roll_intervals_seconds": "invalid"},
            duration_seconds=600,
        )
        assert config["mid_roll_intervals_seconds"] == []


class TestCalculateAdSlots:
    def test_pre_roll_slot(self):
        from app.services.ad_placement import calculate_ad_slots
        ad_config = {"pre_roll": True, "mid_roll_intervals_seconds": [], "overlay_enabled": False, "skip_after_seconds": 5}
        slots = calculate_ad_slots(300, ad_config)
        assert len(slots) == 1
        assert slots[0]["type"] == "pre_roll"
        assert slots[0]["timestamp_seconds"] == 0
        assert slots[0]["slot_index"] == 0

    def test_pre_roll_plus_mid_rolls(self):
        from app.services.ad_placement import calculate_ad_slots
        ad_config = {
            "pre_roll": True,
            "mid_roll_intervals_seconds": [300, 600],
            "overlay_enabled": False,
            "skip_after_seconds": 5,
        }
        slots = calculate_ad_slots(900, ad_config)
        assert len(slots) == 3
        assert slots[0]["type"] == "pre_roll"
        assert slots[1]["type"] == "mid_roll"
        assert slots[1]["timestamp_seconds"] == 300
        assert slots[2]["type"] == "mid_roll"
        assert slots[2]["timestamp_seconds"] == 600

    def test_overlay_slot(self):
        from app.services.ad_placement import calculate_ad_slots
        ad_config = {
            "pre_roll": False,
            "mid_roll_intervals_seconds": [],
            "overlay_enabled": True,
            "skip_after_seconds": 5,
        }
        slots = calculate_ad_slots(300, ad_config)
        assert len(slots) == 1
        assert slots[0]["type"] == "overlay"
        assert slots[0]["timestamp_seconds"] == 30

    def test_no_pre_roll_returns_empty_for_short_video(self):
        from app.services.ad_placement import calculate_ad_slots
        ad_config = {
            "pre_roll": False,
            "mid_roll_intervals_seconds": [],
            "overlay_enabled": False,
            "skip_after_seconds": 5,
        }
        slots = calculate_ad_slots(120, ad_config)
        assert len(slots) == 0


# ─── Ad Placement Resolution Tests ──────────────────────────────────────────


class TestGetAdConfig:
    def test_non_ad_supported_video_returns_empty(self, ddb_tables):
        _seed_video(ddb_tables, "v_ppv1", access_mode="ppv", price_cents=500)
        from app.services.ad_placement import get_ad_config
        result = get_ad_config("v_ppv1", "bob")
        assert result["ads_enabled"] is False
        assert result["slots"] == []
        assert result["ad_free"] is True

    def test_ad_supported_video_returns_slots(self, ddb_tables):
        _seed_video(ddb_tables, "v_ad1", access_mode="ad_supported", duration_seconds=300)
        from app.services.ad_placement import get_ad_config
        result = get_ad_config("v_ad1", "bob")
        assert result["ads_enabled"] is True
        assert result["ad_free"] is False
        assert len(result["slots"]) >= 1
        assert result["slots"][0]["type"] == "pre_roll"

    def test_subscriber_ad_free(self, ddb_tables):
        _seed_video(ddb_tables, "v_ad_sub", access_mode="ad_supported",
                    ads_free_for_subscribers=True, duration_seconds=300)
        _seed_subscription(ddb_tables, "bob", "alice")
        from app.services.ad_placement import get_ad_config
        result = get_ad_config("v_ad_sub", "bob")
        assert result["ads_enabled"] is False
        assert result["slots"] == []
        assert result["ad_free"] is True

    def test_non_subscriber_still_gets_ads(self, ddb_tables):
        _seed_video(ddb_tables, "v_ad_nosub", access_mode="ad_supported",
                    ads_free_for_subscribers=True, duration_seconds=300)
        # No subscription seeded for charlie
        from app.services.ad_placement import get_ad_config
        result = get_ad_config("v_ad_nosub", "charlie")
        assert result["ads_enabled"] is True
        assert result["ad_free"] is False


# ─── Impression Recording Tests ──────────────────────────────────────────────


class TestRecordAdImpression:
    def test_writes_to_ddb(self, ddb_tables):
        _seed_video(ddb_tables, "v_imp1", access_mode="ad_supported")
        from app.services.ad_placement import record_ad_impression
        result = record_ad_impression(
            video_id="v_imp1",
            user_id="bob",
            slot_type="pre_roll",
            slot_index=0,
            creative_id="dev_ad_preroll_15s",
            event_type="impression",
        )
        assert result["ok"] is True
        assert result["event_id"].startswith("adimp_")

    def test_increments_impression_count(self, ddb_tables):
        _seed_video(ddb_tables, "v_imp2", access_mode="ad_supported")
        from app.services.ad_placement import record_ad_impression
        record_ad_impression(
            video_id="v_imp2", user_id="bob",
            slot_type="pre_roll", slot_index=0,
            event_type="impression",
        )
        # Check counter was incremented
        item = ddb_tables.Table("VideoMetadata").get_item(
            Key={"video_id": "v_imp2"}
        ).get("Item", {})
        assert int(item.get("ad_impression_count", 0)) == 1

    def test_complete_event_credits_revenue(self, ddb_tables):
        _seed_video(ddb_tables, "v_imp3", access_mode="ad_supported")
        from app.services.ad_placement import record_ad_impression
        record_ad_impression(
            video_id="v_imp3", user_id="bob",
            slot_type="pre_roll", slot_index=0,
            creative_id="dev_ad_preroll_15s",
            event_type="complete",
        )
        # Check revenue was incremented
        item = ddb_tables.Table("VideoMetadata").get_item(
            Key={"video_id": "v_imp3"}
        ).get("Item", {})
        assert int(item.get("ad_revenue_cents", 0)) > 0

    def test_skip_event_no_revenue(self, ddb_tables):
        _seed_video(ddb_tables, "v_imp4", access_mode="ad_supported")
        from app.services.ad_placement import record_ad_impression
        record_ad_impression(
            video_id="v_imp4", user_id="bob",
            slot_type="pre_roll", slot_index=0,
            event_type="skip",
        )
        # Revenue should remain 0
        item = ddb_tables.Table("VideoMetadata").get_item(
            Key={"video_id": "v_imp4"}
        ).get("Item", {})
        assert int(item.get("ad_revenue_cents", 0)) == 0

    def test_complete_writes_billing_ledger(self, ddb_tables):
        _seed_video(ddb_tables, "v_imp5", access_mode="ad_supported")
        from app.services.ad_placement import record_ad_impression
        record_ad_impression(
            video_id="v_imp5", user_id="bob",
            slot_type="pre_roll", slot_index=0,
            creative_id="dev_ad_preroll_15s",
            event_type="complete",
        )
        # Scan billing table for ad revenue credit
        items = ddb_tables.Table("billing").scan().get("Items", [])
        ledger_entries = [i for i in items if i.get("type") == "ad_revenue_credit"]
        assert len(ledger_entries) >= 1
        entry = ledger_entries[0]
        assert entry["reason"] == "Ad revenue"
        assert entry["pk"] == "USER#alice"


# ─── Ad Stats Tests ──────────────────────────────────────────────────────────


class TestGetAdStats:
    def test_returns_stats(self, ddb_tables):
        _seed_video(ddb_tables, "v_stats1", access_mode="ad_supported")
        # Record some impressions
        from app.services.ad_placement import record_ad_impression, get_ad_stats
        record_ad_impression(video_id="v_stats1", user_id="bob",
                            slot_type="pre_roll", slot_index=0, event_type="impression")
        record_ad_impression(video_id="v_stats1", user_id="bob",
                            slot_type="pre_roll", slot_index=0, event_type="complete")

        stats = get_ad_stats("v_stats1")
        assert stats["video_id"] == "v_stats1"
        assert stats["ad_impression_count"] == 2
        assert stats["ad_revenue_cents"] > 0
        assert stats["estimated_cpm_cents"] == 500


# ─── VOD Access Cascade Tests ───────────────────────────────────────────────


class TestVodAccessCascadeAdSupported:
    def test_ad_supported_entitled_with_ads(self, ddb_tables):
        _seed_video(ddb_tables, "v_cascade1", access_mode="ad_supported", price_cents=0)
        from app.services.vod_purchase import check_vod_access
        from app.services.video_metadata_store import get_video
        video = get_video("v_cascade1")
        result = check_vod_access(user_id="bob", video_id="v_cascade1", video=video)
        assert result.entitled is True
        assert result.reason == "ad"
        assert result.ads_enabled is True

    def test_owner_always_no_ads(self, ddb_tables):
        _seed_video(ddb_tables, "v_cascade2", access_mode="ad_supported")
        from app.services.vod_purchase import check_vod_access
        from app.services.video_metadata_store import get_video
        video = get_video("v_cascade2")
        result = check_vod_access(user_id="alice", video_id="v_cascade2", video=video)
        assert result.entitled is True
        assert result.reason == "owner"
        assert result.ads_enabled is False

    def test_subscriber_ad_free_on_ad_supported(self, ddb_tables):
        _seed_video(ddb_tables, "v_cascade3", access_mode="ad_supported",
                    ads_free_for_subscribers=True)
        _seed_subscription(ddb_tables, "bob", "alice")
        from app.services.vod_purchase import check_vod_access
        from app.services.video_metadata_store import get_video
        video = get_video("v_cascade3")
        result = check_vod_access(user_id="bob", video_id="v_cascade3", video=video)
        assert result.entitled is True
        assert result.reason == "ad"
        assert result.ads_enabled is False

    def test_to_dict_includes_ads_enabled(self, ddb_tables):
        _seed_video(ddb_tables, "v_cascade4", access_mode="ad_supported")
        from app.services.vod_purchase import check_vod_access
        from app.services.video_metadata_store import get_video
        video = get_video("v_cascade4")
        result = check_vod_access(user_id="bob", video_id="v_cascade4", video=video)
        d = result.to_dict()
        assert "ads_enabled" in d
        assert d["ads_enabled"] is True

    def test_free_video_no_ads(self, ddb_tables):
        _seed_video(ddb_tables, "v_cascade5", access_mode="free", price_cents=0)
        from app.services.vod_purchase import check_vod_access
        from app.services.video_metadata_store import get_video
        video = get_video("v_cascade5")
        result = check_vod_access(user_id="bob", video_id="v_cascade5", video=video)
        assert result.entitled is True
        assert result.reason == "free"
        assert result.ads_enabled is False

    def test_cpm_calculation(self):
        """Verify CPM rate: 500 cents CPM = max(1, 500//1000) = 1 cent per impression."""
        from app.services.ad_placement import DEFAULT_CPM_CENTS
        revenue_per_impression = max(1, DEFAULT_CPM_CENTS // 1000)
        assert revenue_per_impression == 1  # $5 CPM = 0.5 cents, floored to 1 cent minimum
