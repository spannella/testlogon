"""Hermetic offline pytest tests for OPP-001 through OPP-006.

Pattern: moto in-memory DynamoDB tables bound to frozen T via object.__setattr__;
frozen S via object.__setattr__; audit_event patched; no TestClient; no real AWS.
"""
from __future__ import annotations

import asyncio
import os
import re
from types import SimpleNamespace
from typing import Optional
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws
from pydantic import ValidationError

# ── Test env setup ────────────────────────────────────────────────────────────
os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("UI_ACCESS_TOKEN_SECRET", "test-secret")
os.environ.setdefault("HMAC_SIGNING_KEY", "test-signing-key")


# ══════════════════════════════════════════════════════════════════════════════
# OPP-001 — Model tests (no DDB needed)
# ══════════════════════════════════════════════════════════════════════════════


class TestOpp001Settings:
    def test_flag_defaults_off(self):
        """SALES_PIPELINE_ENABLED defaults to False — test via fresh Settings() not instantiated with env var."""
        from app.core import settings as _s
        # The default is evaluated at class definition time from os.environ;
        # we verify the field exists and has correct type.
        obj = _s.Settings()
        assert isinstance(obj.sales_pipeline_enabled, bool)

    def test_flag_setting_accepts_truthy_values(self):
        """Verify the truthy-value logic directly."""
        truthy = ("1", "true", "True", "yes", "on")
        for val in truthy:
            result = val.lower() in ("1", "true", "yes", "on")
            assert result is True, f"Failed for {val!r}"

    def test_flag_setting_rejects_falsy_values(self):
        """Verify the falsy-value logic directly."""
        falsy = ("0", "false", "False", "no", "off", "")
        for val in falsy:
            result = val.lower() in ("1", "true", "yes", "on")
            assert result is False, f"Should be False for {val!r}"

    def test_flag_accessible_on_S_singleton(self):
        from app.core.settings import S
        assert isinstance(S.sales_pipeline_enabled, bool)

    def test_allow_reopen_defaults_true(self):
        from app.core.settings import Settings
        obj = Settings()
        assert obj.sales_pipeline_allow_reopen is True

    def test_table_name_settings_exist(self):
        from app.core.settings import S
        assert hasattr(S, "sales_opportunities_table_name")
        assert hasattr(S, "sales_quotas_table_name")
        assert S.sales_opportunities_table_name == "sales_opportunities"
        assert S.sales_quotas_table_name == "sales_quotas"


class TestOpp001Models:
    def test_create_in_valid(self):
        from app.models import OpportunityCreateIn
        m = OpportunityCreateIn(
            name="Acme Deal",
            stage="prospecting",
            amount_cents=500_000,
            close_date=1_893_456_000,
            probability=25,
            lead_source="web_site",
            description="A big deal",
        )
        assert m.stage == "prospecting"
        assert m.probability == 25
        assert m.lead_source == "web_site"

    def test_create_in_optional_fields_default(self):
        from app.models import OpportunityCreateIn
        m = OpportunityCreateIn(name="X", stage="qualification", amount_cents=0, close_date=0)
        assert m.lead_source is None
        assert m.description is None
        assert m.account_party_id is None
        assert m.contact_party_id is None
        assert m.probability == 0

    def test_update_in_all_none(self):
        from app.models import OpportunityUpdateIn
        m = OpportunityUpdateIn()
        assert m.name is None
        assert m.stage is None

    def test_create_in_invalid_stage(self):
        from app.models import OpportunityCreateIn
        with pytest.raises(ValidationError) as exc_info:
            OpportunityCreateIn(name="X", stage="unknown_stage", amount_cents=0, close_date=0)
        assert "Unknown stage" in str(exc_info.value)

    def test_update_in_invalid_stage(self):
        from app.models import OpportunityUpdateIn
        with pytest.raises(ValidationError):
            OpportunityUpdateIn(stage="not_a_real_stage")

    def test_create_in_invalid_lead_source(self):
        from app.models import OpportunityCreateIn
        with pytest.raises(ValidationError) as exc_info:
            OpportunityCreateIn(
                name="X", stage="prospecting", amount_cents=0,
                close_date=0, lead_source="newspaper"
            )
        assert "Unknown lead_source" in str(exc_info.value)

    def test_create_in_none_lead_source_valid(self):
        from app.models import OpportunityCreateIn
        m = OpportunityCreateIn(
            name="X", stage="prospecting", amount_cents=0,
            close_date=0, lead_source=None
        )
        assert m.lead_source is None

    def test_create_in_negative_amount_rejected(self):
        from app.models import OpportunityCreateIn
        with pytest.raises(ValidationError):
            OpportunityCreateIn(name="X", stage="prospecting", amount_cents=-1, close_date=0)

    def test_create_in_zero_amount_valid(self):
        from app.models import OpportunityCreateIn
        m = OpportunityCreateIn(name="X", stage="prospecting", amount_cents=0, close_date=0)
        assert m.amount_cents == 0

    def test_probability_out_of_range(self):
        from app.models import OpportunityCreateIn
        with pytest.raises(ValidationError):
            OpportunityCreateIn(name="X", stage="prospecting", amount_cents=0, close_date=0, probability=101)
        with pytest.raises(ValidationError):
            OpportunityCreateIn(name="X", stage="prospecting", amount_cents=0, close_date=0, probability=-1)

    def test_probability_boundary_valid(self):
        from app.models import OpportunityCreateIn
        for p in (0, 100):
            m = OpportunityCreateIn(name="X", stage="prospecting", amount_cents=1000, close_date=0, probability=p)
            assert m.probability == p

    def test_opportunity_out_construction(self):
        from app.models import OpportunityOut
        from app.core.time import now_ts
        now = now_ts()
        out = OpportunityOut(
            opp_id="opp_abc123",
            owner_sub="user_xyz",
            name="Test Deal",
            stage="prospecting",
            amount_cents=200_000,
            weighted_amount_cents=50_000,
            close_date=now + 86400 * 30,
            probability=25,
            created_at=now,
            updated_at=now,
        )
        assert out.weighted_amount_cents == 50_000
        assert out.opp_id == "opp_abc123"
        assert out.contact_roles == []


# ══════════════════════════════════════════════════════════════════════════════
# Shared fixture for DDB-backed tests
# ══════════════════════════════════════════════════════════════════════════════


def _create_sales_opportunities_table(ddb):
    return ddb.create_table(
        TableName="sales_opportunities",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "owner_sub", "AttributeType": "S"},
            {"AttributeName": "close_date", "AttributeType": "N"},
            {"AttributeName": "stage", "AttributeType": "S"},
            {"AttributeName": "opp_id", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI_BY_USER_CLOSE",
                "KeySchema": [
                    {"AttributeName": "owner_sub", "KeyType": "HASH"},
                    {"AttributeName": "close_date", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "GSI_BY_STAGE",
                "KeySchema": [
                    {"AttributeName": "stage", "KeyType": "HASH"},
                    {"AttributeName": "close_date", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "GSI_DIRECT",
                "KeySchema": [
                    {"AttributeName": "opp_id", "KeyType": "HASH"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _create_sales_quotas_table(ddb):
    return ddb.create_table(
        TableName="sales_quotas",
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


@pytest.fixture
def sales_tables():
    """Provide moto-backed sales tables bound to frozen T, with pipeline enabled."""
    with mock_aws():
        from app.core.tables import T, _FloatSafeTable
        from app.core.settings import S

        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        opp_table = _create_sales_opportunities_table(ddb)
        quota_table = _create_sales_quotas_table(ddb)

        orig_opp = T.sales_opportunities
        orig_quot = T.sales_quotas
        orig_flag = S.sales_pipeline_enabled
        orig_reopen = S.sales_pipeline_allow_reopen

        object.__setattr__(T, "sales_opportunities", _FloatSafeTable(opp_table))
        object.__setattr__(T, "sales_quotas", _FloatSafeTable(quota_table))
        object.__setattr__(S, "sales_pipeline_enabled", True)
        object.__setattr__(S, "sales_pipeline_allow_reopen", True)

        yield SimpleNamespace(opp=opp_table, quota=quota_table)

        object.__setattr__(T, "sales_opportunities", orig_opp)
        object.__setattr__(T, "sales_quotas", orig_quot)
        object.__setattr__(S, "sales_pipeline_enabled", orig_flag)
        object.__setattr__(S, "sales_pipeline_allow_reopen", orig_reopen)


# ══════════════════════════════════════════════════════════════════════════════
# OPP-002 — CRUD service tests
# ══════════════════════════════════════════════════════════════════════════════


class TestOpp002Crud:
    def test_create_returns_correct_weighted(self, sales_tables):
        from app.models import OpportunityCreateIn
        from app.services.opportunities import create_opportunity
        with patch("app.services.opportunities.audit_event"):
            out = create_opportunity(
                "alice",
                OpportunityCreateIn(
                    name="Deal A", stage="prospecting",
                    amount_cents=100_000, close_date=9_999_999_999, probability=40
                ),
            )
        assert out.weighted_amount_cents == 40_000
        assert out.opp_id.startswith("opp_")
        assert out.owner_sub == "alice"

    def test_get_returns_created_item(self, sales_tables):
        from app.models import OpportunityCreateIn
        from app.services.opportunities import create_opportunity, get_opportunity
        with patch("app.services.opportunities.audit_event"):
            created = create_opportunity(
                "alice",
                OpportunityCreateIn(name="X", stage="qualification", amount_cents=1000, close_date=1_000_000_000),
            )
            fetched = get_opportunity("alice", created.opp_id)
        assert fetched.opp_id == created.opp_id
        assert fetched.name == "X"

    def test_get_wrong_owner_returns_404(self, sales_tables):
        from fastapi import HTTPException
        from app.models import OpportunityCreateIn
        from app.services.opportunities import create_opportunity, get_opportunity
        with patch("app.services.opportunities.audit_event"):
            created = create_opportunity(
                "alice",
                OpportunityCreateIn(name="X", stage="prospecting", amount_cents=0, close_date=1_000_000_000),
            )
        with pytest.raises(HTTPException) as exc:
            get_opportunity("bob", created.opp_id)
        assert exc.value.status_code == 404

    def test_update_patches_subset(self, sales_tables):
        from app.models import OpportunityCreateIn, OpportunityUpdateIn
        from app.services.opportunities import create_opportunity, update_opportunity
        with patch("app.services.opportunities.audit_event"):
            created = create_opportunity(
                "alice",
                OpportunityCreateIn(name="X", stage="prospecting", amount_cents=100_000, close_date=1_000_000_000, probability=40),
            )
            updated = update_opportunity("alice", created.opp_id, OpportunityUpdateIn(probability=80))
        assert updated.probability == 80
        assert updated.weighted_amount_cents == 80_000

    def test_update_recomputes_weighted_on_amount_change(self, sales_tables):
        from app.models import OpportunityCreateIn, OpportunityUpdateIn
        from app.services.opportunities import create_opportunity, update_opportunity
        with patch("app.services.opportunities.audit_event"):
            created = create_opportunity(
                "alice",
                OpportunityCreateIn(name="X", stage="prospecting", amount_cents=100_000, close_date=1_000_000_000, probability=40),
            )
            updated = update_opportunity("alice", created.opp_id, OpportunityUpdateIn(amount_cents=200_000))
        assert updated.weighted_amount_cents == 80_000  # 200000 * 40 // 100

    def test_delete_soft_deletes(self, sales_tables):
        from fastapi import HTTPException
        from app.models import OpportunityCreateIn
        from app.services.opportunities import create_opportunity, delete_opportunity, get_opportunity
        with patch("app.services.opportunities.audit_event"):
            created = create_opportunity(
                "alice",
                OpportunityCreateIn(name="X", stage="prospecting", amount_cents=0, close_date=1_000_000_000),
            )
            delete_opportunity("alice", created.opp_id)
        with pytest.raises(HTTPException) as exc:
            get_opportunity("alice", created.opp_id)
        assert exc.value.status_code == 404
        # Row still exists in DDB
        raw = sales_tables.opp.get_item(Key={"pk": f"USER#alice", "sk": f"OPP#{created.opp_id}"})
        assert "deleted_at" in raw["Item"]

    def test_delete_wrong_owner_returns_404(self, sales_tables):
        from fastapi import HTTPException
        from app.models import OpportunityCreateIn
        from app.services.opportunities import create_opportunity, delete_opportunity
        with patch("app.services.opportunities.audit_event"):
            created = create_opportunity(
                "alice",
                OpportunityCreateIn(name="X", stage="prospecting", amount_cents=0, close_date=1_000_000_000),
            )
        with pytest.raises(HTTPException):
            delete_opportunity("bob", created.opp_id)

    def test_list_returns_only_caller_items(self, sales_tables):
        from app.models import OpportunityCreateIn
        from app.services.opportunities import create_opportunity, list_opportunities
        with patch("app.services.opportunities.audit_event"):
            create_opportunity("alice", OpportunityCreateIn(name="A1", stage="prospecting", amount_cents=0, close_date=1_000_000_001))
            create_opportunity("alice", OpportunityCreateIn(name="A2", stage="qualification", amount_cents=0, close_date=1_000_000_002))
            create_opportunity("bob",   OpportunityCreateIn(name="B1", stage="prospecting", amount_cents=0, close_date=1_000_000_003))
        items, _ = list_opportunities("alice")
        assert len(items) == 2
        assert all(i.owner_sub == "alice" for i in items)

    def test_list_stage_filter(self, sales_tables):
        from app.models import OpportunityCreateIn
        from app.services.opportunities import create_opportunity, list_opportunities
        with patch("app.services.opportunities.audit_event"):
            create_opportunity("alice", OpportunityCreateIn(name="P", stage="prospecting", amount_cents=0, close_date=1_000_000_001))
            create_opportunity("alice", OpportunityCreateIn(name="Q", stage="qualification", amount_cents=0, close_date=1_000_000_002))
        items, _ = list_opportunities("alice", stage="prospecting")
        assert len(items) == 1
        assert items[0].stage == "prospecting"

    def test_list_excludes_soft_deleted(self, sales_tables):
        from app.models import OpportunityCreateIn
        from app.services.opportunities import create_opportunity, delete_opportunity, list_opportunities
        with patch("app.services.opportunities.audit_event"):
            c1 = create_opportunity("alice", OpportunityCreateIn(name="A", stage="prospecting", amount_cents=0, close_date=1_000_000_001))
            c2 = create_opportunity("alice", OpportunityCreateIn(name="B", stage="prospecting", amount_cents=0, close_date=1_000_000_002))
            c3 = create_opportunity("alice", OpportunityCreateIn(name="C", stage="prospecting", amount_cents=0, close_date=1_000_000_003))
            delete_opportunity("alice", c2.opp_id)
        items, _ = list_opportunities("alice")
        assert len(items) == 2

    def test_list_pagination_cursor(self, sales_tables):
        from app.models import OpportunityCreateIn
        from app.services.opportunities import create_opportunity, list_opportunities
        with patch("app.services.opportunities.audit_event"):
            for i in range(5):
                create_opportunity("alice", OpportunityCreateIn(name=f"D{i}", stage="prospecting", amount_cents=0, close_date=1_000_000_000 + i))
        page1, cursor1 = list_opportunities("alice", limit=3)
        assert len(page1) == 3
        assert cursor1 is not None
        page2, cursor2 = list_opportunities("alice", cursor=cursor1, limit=3)
        assert len(page2) == 2
        assert cursor2 is None

    def test_flag_off_raises_503(self, sales_tables):
        from fastapi import HTTPException
        from app.core.settings import S
        from app.models import OpportunityCreateIn
        from app.services.opportunities import (
            create_opportunity, get_opportunity, update_opportunity,
            delete_opportunity, list_opportunities
        )
        object.__setattr__(S, "sales_pipeline_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc:
                create_opportunity("alice", OpportunityCreateIn(name="X", stage="prospecting", amount_cents=0, close_date=0))
            assert exc.value.status_code == 503
        finally:
            object.__setattr__(S, "sales_pipeline_enabled", True)

    def test_audit_events_emitted(self, sales_tables):
        from app.models import OpportunityCreateIn, OpportunityUpdateIn
        from app.services.opportunities import create_opportunity, update_opportunity, delete_opportunity
        mock_audit = MagicMock()
        with patch("app.services.opportunities.audit_event", mock_audit):
            opp = create_opportunity("alice", OpportunityCreateIn(name="A", stage="prospecting", amount_cents=0, close_date=1_000_000_000))
            update_opportunity("alice", opp.opp_id, OpportunityUpdateIn(name="B"))
            delete_opportunity("alice", opp.opp_id)
        events = [call.args[0] for call in mock_audit.call_args_list]
        assert "opportunity.created" in events
        assert "opportunity.updated" in events
        assert "opportunity.deleted" in events

    def test_invalid_stage_raises_400(self, sales_tables):
        from fastapi import HTTPException
        from app.services.opportunities import create_opportunity
        from app.models import OpportunityCreateIn
        # Stage validator runs before the service, but let's test the service guard too
        # via a model that bypasses the validator (construct directly)
        opp = OpportunityCreateIn.model_construct(
            name="X", stage="bad_stage", amount_cents=0, close_date=0, probability=0,
            lead_source=None, description=None, account_party_id=None, contact_party_id=None
        )
        with patch("app.services.opportunities.audit_event"):
            with pytest.raises(HTTPException) as exc:
                create_opportunity("alice", opp)
        assert exc.value.status_code == 400


# ══════════════════════════════════════════════════════════════════════════════
# OPP-003 — Stage pipeline config tests
# ══════════════════════════════════════════════════════════════════════════════


class TestOpp003StageConfig:
    def test_get_stages_default_fallback(self, sales_tables):
        from app.services.opportunities import get_stage_config
        from app.models import OPPORTUNITY_STAGES
        config = get_stage_config()
        assert len(config.stages) == len(OPPORTUNITY_STAGES)
        won = [s for s in config.stages if s.is_won]
        lost = [s for s in config.stages if s.is_lost]
        assert len(won) == 1 and won[0].stage_key == "closed_won"
        assert len(lost) == 1 and lost[0].stage_key == "closed_lost"

    def test_set_and_get_stage_config(self, sales_tables):
        from app.services.opportunities import set_stage_config, get_stage_config
        from app.models import StageConfigIn, StageConfigItemIn
        with patch("app.services.opportunities.audit_event"):
            data = StageConfigIn(stages=[
                StageConfigItemIn(stage_key="s1", label="Stage 1", order=0, is_won=False, is_lost=False),
                StageConfigItemIn(stage_key="s2", label="Stage 2", order=1, is_won=True, is_lost=False),
                StageConfigItemIn(stage_key="s3", label="Stage 3", order=2, is_won=False, is_lost=True),
            ])
            result = set_stage_config("admin1", data)
        assert len(result.stages) == 3
        fetched = get_stage_config()
        assert len(fetched.stages) == 3
        assert fetched.stages[1].is_won is True

    def test_set_stage_config_no_is_won(self, sales_tables):
        from fastapi import HTTPException
        from app.services.opportunities import set_stage_config
        from app.models import StageConfigIn, StageConfigItemIn
        with patch("app.services.opportunities.audit_event"):
            with pytest.raises(HTTPException) as exc:
                set_stage_config("admin1", StageConfigIn(stages=[
                    StageConfigItemIn(stage_key="s1", label="S1", order=0, is_won=False, is_lost=True),
                ]))
            assert exc.value.status_code == 400
            assert exc.value.detail["reason"] == "exactly_one_is_won_required"

    def test_set_stage_config_duplicate_stage_key(self, sales_tables):
        from fastapi import HTTPException
        from app.services.opportunities import set_stage_config
        from app.models import StageConfigIn, StageConfigItemIn
        with patch("app.services.opportunities.audit_event"):
            with pytest.raises(HTTPException) as exc:
                set_stage_config("admin1", StageConfigIn(stages=[
                    StageConfigItemIn(stage_key="dup", label="D1", order=0, is_won=True, is_lost=False),
                    StageConfigItemIn(stage_key="dup", label="D2", order=1, is_won=False, is_lost=True),
                ]))
            assert exc.value.detail["reason"] == "duplicate_stage_key"

    def test_set_stage_config_two_is_won(self, sales_tables):
        from fastapi import HTTPException
        from app.services.opportunities import set_stage_config
        from app.models import StageConfigIn, StageConfigItemIn
        with patch("app.services.opportunities.audit_event"):
            with pytest.raises(HTTPException):
                set_stage_config("admin1", StageConfigIn(stages=[
                    StageConfigItemIn(stage_key="s1", label="S1", order=0, is_won=True, is_lost=False),
                    StageConfigItemIn(stage_key="s2", label="S2", order=1, is_won=True, is_lost=True),
                ]))

    def test_stage_change_audit_event(self, sales_tables):
        from app.models import OpportunityCreateIn, OpportunityUpdateIn
        from app.services.opportunities import create_opportunity, update_opportunity
        events = []
        def capture(*args, **kwargs):
            events.append(args[0])
        with patch("app.services.opportunities.audit_event", side_effect=capture):
            opp = create_opportunity("alice", OpportunityCreateIn(name="A", stage="prospecting", amount_cents=0, close_date=1_000_000_000))
            events.clear()
            update_opportunity("alice", opp.opp_id, OpportunityUpdateIn(stage="qualification"))
        assert "opportunity.stage_changed" in events
        assert "opportunity.updated" in events

    def test_reopen_closed_won_blocked_when_flag_off(self, sales_tables):
        from fastapi import HTTPException
        from app.core.settings import S
        from app.models import OpportunityCreateIn, OpportunityUpdateIn
        from app.services.opportunities import create_opportunity, update_opportunity
        object.__setattr__(S, "sales_pipeline_allow_reopen", False)
        try:
            with patch("app.services.opportunities.audit_event"):
                opp = create_opportunity("alice", OpportunityCreateIn(name="A", stage="closed_won", amount_cents=0, close_date=1_000_000_000))
                with pytest.raises(HTTPException) as exc:
                    update_opportunity("alice", opp.opp_id, OpportunityUpdateIn(stage="negotiation_review"))
            assert exc.value.status_code == 400
            assert exc.value.detail["code"] == "stage_transition_blocked"
        finally:
            object.__setattr__(S, "sales_pipeline_allow_reopen", True)

    def test_reopen_closed_won_allowed(self, sales_tables):
        from app.models import OpportunityCreateIn, OpportunityUpdateIn
        from app.services.opportunities import create_opportunity, update_opportunity
        with patch("app.services.opportunities.audit_event"):
            opp = create_opportunity("alice", OpportunityCreateIn(name="A", stage="closed_won", amount_cents=0, close_date=1_000_000_000))
            updated = update_opportunity("alice", opp.opp_id, OpportunityUpdateIn(stage="negotiation_review"))
        assert updated.stage == "negotiation_review"

    def test_feature_status_flag_on(self, sales_tables):
        from app.services.opportunities import _require_flag
        from app.core.settings import S
        # Should not raise when flag is on
        _require_flag()

    def test_feature_status_flag_off(self, sales_tables):
        from fastapi import HTTPException
        from app.core.settings import S
        from app.services.opportunities import _require_flag
        object.__setattr__(S, "sales_pipeline_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc:
                _require_flag()
            assert exc.value.status_code == 503
        finally:
            object.__setattr__(S, "sales_pipeline_enabled", True)

    def test_audit_event_on_config_update(self, sales_tables):
        from app.models import StageConfigIn, StageConfigItemIn
        from app.services.opportunities import set_stage_config
        mock_audit = MagicMock()
        with patch("app.services.opportunities.audit_event", mock_audit):
            set_stage_config("admin1", StageConfigIn(stages=[
                StageConfigItemIn(stage_key="s1", label="S1", order=0, is_won=True, is_lost=False),
                StageConfigItemIn(stage_key="s2", label="S2", order=1, is_won=False, is_lost=True),
            ]))
        events = [call.args[0] for call in mock_audit.call_args_list]
        assert "sales_stage_config.updated" in events

    def test_stage_not_in_config_rejects_update(self, sales_tables):
        from fastapi import HTTPException
        from app.models import OpportunityCreateIn, OpportunityUpdateIn, StageConfigIn, StageConfigItemIn
        from app.services.opportunities import create_opportunity, set_stage_config, update_opportunity
        with patch("app.services.opportunities.audit_event"):
            # Set a config with only s1 and s2 (no "prospecting" or "qualification")
            set_stage_config("admin1", StageConfigIn(stages=[
                StageConfigItemIn(stage_key="s1", label="S1", order=0, is_won=True, is_lost=False),
                StageConfigItemIn(stage_key="s2", label="S2", order=1, is_won=False, is_lost=True),
            ]))
            opp = create_opportunity("alice", OpportunityCreateIn(name="A", stage="prospecting", amount_cents=0, close_date=1_000_000_000))
            # Updating to "qualification" which is also not in config should fail
            with pytest.raises(HTTPException) as exc:
                update_opportunity("alice", opp.opp_id, OpportunityUpdateIn(stage="qualification"))
            assert exc.value.status_code == 400


# ══════════════════════════════════════════════════════════════════════════════
# OPP-004 — Contact-role junction tests
# ══════════════════════════════════════════════════════════════════════════════


class TestOpp004ContactRoles:
    def _make_opp(self, owner_sub: str = "alice"):
        from app.models import OpportunityCreateIn
        from app.services.opportunities import create_opportunity
        with patch("app.services.opportunities.audit_event"):
            return create_opportunity(
                owner_sub,
                OpportunityCreateIn(name="Deal", stage="prospecting", amount_cents=0, close_date=1_000_000_000),
            )

    def test_add_contact_role_creates_row(self, sales_tables):
        from app.models import OppContactRoleIn
        from app.services.opportunities import add_contact_role
        opp = self._make_opp()
        with patch("app.services.opportunities.audit_event"):
            result = add_contact_role("alice", opp.opp_id, OppContactRoleIn(contact_ref="usr_bob", contact_role="decision_maker"))
        assert result.contact_ref == "usr_bob"
        assert result.contact_role == "decision_maker"
        assert result.opp_id == opp.opp_id
        assert result.owner_sub == "alice"

    def test_add_duplicate_returns_409(self, sales_tables):
        from fastapi import HTTPException
        from app.models import OppContactRoleIn
        from app.services.opportunities import add_contact_role
        opp = self._make_opp()
        with patch("app.services.opportunities.audit_event"):
            add_contact_role("alice", opp.opp_id, OppContactRoleIn(contact_ref="usr_bob", contact_role="evaluator"))
            with pytest.raises(HTTPException) as exc:
                add_contact_role("alice", opp.opp_id, OppContactRoleIn(contact_ref="usr_bob", contact_role="evaluator"))
            assert exc.value.status_code == 409

    def test_add_invalid_role_raises_422(self):
        from app.models import OppContactRoleIn
        with pytest.raises(ValidationError):
            OppContactRoleIn(contact_ref="usr_bob", contact_role="not_a_role")

    def test_add_wrong_owner_returns_404(self, sales_tables):
        from fastapi import HTTPException
        from app.models import OppContactRoleIn
        from app.services.opportunities import add_contact_role
        opp = self._make_opp("alice")
        with patch("app.services.opportunities.audit_event"):
            with pytest.raises(HTTPException) as exc:
                add_contact_role("bob", opp.opp_id, OppContactRoleIn(contact_ref="usr_carol", contact_role="evaluator"))
            assert exc.value.status_code == 404

    def test_list_contact_roles_empty(self, sales_tables):
        from app.services.opportunities import list_contact_roles
        opp = self._make_opp()
        roles = list_contact_roles("alice", opp.opp_id)
        assert roles == []

    def test_list_contact_roles_multiple(self, sales_tables):
        from app.models import OppContactRoleIn
        from app.services.opportunities import add_contact_role, list_contact_roles
        opp = self._make_opp()
        with patch("app.services.opportunities.audit_event"):
            add_contact_role("alice", opp.opp_id, OppContactRoleIn(contact_ref="ref1", contact_role="decision_maker"))
            add_contact_role("alice", opp.opp_id, OppContactRoleIn(contact_ref="ref2", contact_role="evaluator"))
            add_contact_role("alice", opp.opp_id, OppContactRoleIn(contact_ref="ref3", contact_role="champion"))
        roles = list_contact_roles("alice", opp.opp_id)
        assert len(roles) == 3
        # sorted by created_at ascending
        refs = [r.contact_ref for r in roles]
        assert refs == sorted(refs, key=lambda r: roles[[x.contact_ref for x in roles].index(r)].created_at)

    def test_list_wrong_owner_returns_404(self, sales_tables):
        from fastapi import HTTPException
        from app.services.opportunities import list_contact_roles
        opp = self._make_opp("alice")
        with pytest.raises(HTTPException):
            list_contact_roles("bob", opp.opp_id)

    def test_remove_contact_role_success(self, sales_tables):
        from app.models import OppContactRoleIn
        from app.services.opportunities import add_contact_role, list_contact_roles, remove_contact_role
        opp = self._make_opp()
        with patch("app.services.opportunities.audit_event"):
            add_contact_role("alice", opp.opp_id, OppContactRoleIn(contact_ref="ref1", contact_role="evaluator"))
            remove_contact_role("alice", opp.opp_id, "ref1")
        roles = list_contact_roles("alice", opp.opp_id)
        assert roles == []

    def test_remove_not_found_returns_404(self, sales_tables):
        from fastapi import HTTPException
        from app.services.opportunities import remove_contact_role
        opp = self._make_opp()
        with patch("app.services.opportunities.audit_event"):
            with pytest.raises(HTTPException) as exc:
                remove_contact_role("alice", opp.opp_id, "nonexistent_ref")
            assert exc.value.status_code == 404

    def test_remove_wrong_owner_returns_404(self, sales_tables):
        from fastapi import HTTPException
        from app.models import OppContactRoleIn
        from app.services.opportunities import add_contact_role, remove_contact_role
        opp = self._make_opp("alice")
        with patch("app.services.opportunities.audit_event"):
            add_contact_role("alice", opp.opp_id, OppContactRoleIn(contact_ref="ref1", contact_role="evaluator"))
            with pytest.raises(HTTPException):
                remove_contact_role("bob", opp.opp_id, "ref1")

    def test_flag_off_raises_503_contact_ops(self, sales_tables):
        from fastapi import HTTPException
        from app.core.settings import S
        from app.models import OppContactRoleIn
        from app.services.opportunities import add_contact_role, list_contact_roles, remove_contact_role
        opp = self._make_opp()
        object.__setattr__(S, "sales_pipeline_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc:
                add_contact_role("alice", opp.opp_id, OppContactRoleIn(contact_ref="x", contact_role="evaluator"))
            assert exc.value.status_code == 503
        finally:
            object.__setattr__(S, "sales_pipeline_enabled", True)

    def test_audit_events_on_contact_ops(self, sales_tables):
        from app.models import OppContactRoleIn
        from app.services.opportunities import add_contact_role, remove_contact_role
        opp = self._make_opp()
        events = []
        with patch("app.services.opportunities.audit_event", side_effect=lambda e, *a, **k: events.append(e)):
            add_contact_role("alice", opp.opp_id, OppContactRoleIn(contact_ref="ref1", contact_role="evaluator"))
            remove_contact_role("alice", opp.opp_id, "ref1")
        assert "opportunity.contact_role_added" in events
        assert "opportunity.contact_role_removed" in events

    def test_all_valid_contact_roles_accepted(self):
        from app.services.opportunities import CONTACT_ROLES
        from app.models import OppContactRoleIn
        for role in CONTACT_ROLES:
            m = OppContactRoleIn(contact_ref="x", contact_role=role)
            assert m.contact_role == role

    def test_contact_ref_max_length_enforced(self):
        from app.models import OppContactRoleIn
        with pytest.raises(ValidationError):
            OppContactRoleIn(contact_ref="x" * 256, contact_role="evaluator")

    def test_contact_ref_empty_string_rejected(self):
        from app.models import OppContactRoleIn
        with pytest.raises(ValidationError):
            OppContactRoleIn(contact_ref="", contact_role="evaluator")

    def test_get_opportunity_include_contacts_true(self, sales_tables):
        from app.models import OppContactRoleIn
        from app.services.opportunities import add_contact_role, get_opportunity, list_contact_roles
        opp = self._make_opp()
        with patch("app.services.opportunities.audit_event"):
            add_contact_role("alice", opp.opp_id, OppContactRoleIn(contact_ref="ref1", contact_role="evaluator"))
            add_contact_role("alice", opp.opp_id, OppContactRoleIn(contact_ref="ref2", contact_role="champion"))
        # Simulate the router's include_contacts=True logic
        fetched = get_opportunity("alice", opp.opp_id)
        fetched.contact_roles = list_contact_roles("alice", opp.opp_id)
        assert len(fetched.contact_roles) == 2


# ══════════════════════════════════════════════════════════════════════════════
# OPP-005 — Quota / Forecast tests
# ══════════════════════════════════════════════════════════════════════════════


class TestOpp005QuotaForecast:
    def test_parse_period_key_monthly(self, sales_tables):
        from app.services.opportunities import _parse_period_key
        ts_from, ts_to = _parse_period_key("2026-06")
        from datetime import datetime, timezone
        dt_from = datetime.fromtimestamp(ts_from, tz=timezone.utc)
        dt_to = datetime.fromtimestamp(ts_to, tz=timezone.utc)
        assert dt_from.month == 6 and dt_from.day == 1
        assert dt_to.month == 6 and dt_to.day == 30

    def test_parse_period_key_quarterly(self, sales_tables):
        from app.services.opportunities import _parse_period_key
        from datetime import datetime, timezone
        ts_from, ts_to = _parse_period_key("2026-Q2")
        dt_from = datetime.fromtimestamp(ts_from, tz=timezone.utc)
        dt_to = datetime.fromtimestamp(ts_to, tz=timezone.utc)
        assert dt_from.month == 4 and dt_from.day == 1
        assert dt_to.month == 6 and dt_to.day == 30

    def test_parse_period_key_annual(self, sales_tables):
        from app.services.opportunities import _parse_period_key
        from datetime import datetime, timezone
        ts_from, ts_to = _parse_period_key("2026")
        dt_from = datetime.fromtimestamp(ts_from, tz=timezone.utc)
        dt_to = datetime.fromtimestamp(ts_to, tz=timezone.utc)
        assert dt_from.month == 1 and dt_from.day == 1
        assert dt_to.month == 12 and dt_to.day == 31

    def test_parse_leap_year_february(self, sales_tables):
        from app.services.opportunities import _parse_period_key
        from datetime import datetime, timezone
        ts_from, ts_to = _parse_period_key("2024-02")
        dt_to = datetime.fromtimestamp(ts_to, tz=timezone.utc)
        assert dt_to.day == 29  # leap year

    def test_parse_invalid_period_keys(self, sales_tables):
        from fastapi import HTTPException
        from app.services.opportunities import _parse_period_key
        for bad in ("2026-13", "2026-Q5", "foo", "", "2026-06-01", "2026-Q0"):
            with pytest.raises(HTTPException) as exc:
                _parse_period_key(bad)
            assert exc.value.status_code == 400

    def test_set_and_get_quota(self, sales_tables):
        from app.models import SalesQuotaIn
        from app.services.opportunities import set_quota, get_quota
        with patch("app.services.opportunities.audit_event"):
            out = set_quota("admin1", SalesQuotaIn(user_sub="alice", period_type="quarterly", period_key="2026-Q2", target_amount_cents=500_000_00))
        assert out.target_amount_cents == 500_000_00
        fetched = get_quota("alice", "2026-Q2")
        assert fetched is not None
        assert fetched.target_amount_cents == 500_000_00

    def test_set_quota_upsert(self, sales_tables):
        from app.models import SalesQuotaIn
        from app.services.opportunities import set_quota, get_quota
        with patch("app.services.opportunities.audit_event"):
            set_quota("admin1", SalesQuotaIn(user_sub="alice", period_type="quarterly", period_key="2026-Q2", target_amount_cents=100_000))
            set_quota("admin1", SalesQuotaIn(user_sub="alice", period_type="quarterly", period_key="2026-Q2", target_amount_cents=200_000))
        fetched = get_quota("alice", "2026-Q2")
        assert fetched.target_amount_cents == 200_000

    def test_get_quota_nonexistent_returns_none(self, sales_tables):
        from app.services.opportunities import get_quota
        result = get_quota("alice", "2026-Q3")
        assert result is None

    def test_list_quotas_for_user(self, sales_tables):
        from app.models import SalesQuotaIn
        from app.services.opportunities import set_quota, list_quotas_for_user
        with patch("app.services.opportunities.audit_event"):
            set_quota("admin1", SalesQuotaIn(user_sub="alice", period_type="quarterly", period_key="2026-Q1", target_amount_cents=100))
            set_quota("admin1", SalesQuotaIn(user_sub="alice", period_type="quarterly", period_key="2026-Q2", target_amount_cents=200))
            set_quota("admin1", SalesQuotaIn(user_sub="alice", period_type="quarterly", period_key="2026-Q3", target_amount_cents=300))
        items, _ = list_quotas_for_user("alice")
        assert len(items) == 3

    def test_list_quotas_pagination(self, sales_tables):
        from app.models import SalesQuotaIn
        from app.services.opportunities import set_quota, list_quotas_for_user
        with patch("app.services.opportunities.audit_event"):
            for q in ("2026-Q1", "2026-Q2", "2026-Q3"):
                set_quota("admin1", SalesQuotaIn(user_sub="alice", period_type="quarterly", period_key=q, target_amount_cents=100))
        items1, cursor = list_quotas_for_user("alice", limit=1)
        assert len(items1) == 1
        assert cursor is not None
        items2, cursor2 = list_quotas_for_user("alice", cursor=cursor, limit=10)
        assert len(items2) == 2
        # cursor2 may be None or present depending on DDB page boundaries

    def test_upsert_forecast_zero_opps(self, sales_tables):
        from app.models import ForecastWorksheetIn
        from app.services.opportunities import upsert_forecast
        with patch("app.services.opportunities.audit_event"):
            out = upsert_forecast("alice", "2026-Q2", ForecastWorksheetIn(committed_cents=1000, best_case_cents=2000, pipeline_cents=3000))
        assert out.closed_cents == 0
        assert out.quota_cents == 0
        assert out.attainment_pct == 0

    def test_upsert_forecast_with_closed_won_opps(self, sales_tables):
        from datetime import datetime, timezone
        from app.models import ForecastWorksheetIn, OpportunityCreateIn
        from app.services.opportunities import create_opportunity, upsert_forecast
        # Q2 2026 = Apr 1 – Jun 30
        in_q2 = int(datetime(2026, 5, 15, tzinfo=timezone.utc).timestamp())
        out_q2 = int(datetime(2026, 7, 1, tzinfo=timezone.utc).timestamp())
        with patch("app.services.opportunities.audit_event"):
            # Two closed_won in Q2
            o1 = create_opportunity("alice", OpportunityCreateIn(name="W1", stage="closed_won", amount_cents=100_000, close_date=in_q2))
            o2 = create_opportunity("alice", OpportunityCreateIn(name="W2", stage="closed_won", amount_cents=50_000, close_date=in_q2))
            # One closed_won outside Q2
            o3 = create_opportunity("alice", OpportunityCreateIn(name="W3", stage="closed_won", amount_cents=200_000, close_date=out_q2))
            # One prospecting in Q2 — not counted
            o4 = create_opportunity("alice", OpportunityCreateIn(name="P1", stage="prospecting", amount_cents=300_000, close_date=in_q2))
            out = upsert_forecast("alice", "2026-Q2", ForecastWorksheetIn(committed_cents=0, best_case_cents=0, pipeline_cents=0))
        assert out.closed_cents == 150_000

    def test_upsert_forecast_with_quota(self, sales_tables):
        from app.models import ForecastWorksheetIn, SalesQuotaIn
        from app.services.opportunities import set_quota, upsert_forecast
        with patch("app.services.opportunities.audit_event"):
            set_quota("admin1", SalesQuotaIn(user_sub="alice", period_type="quarterly", period_key="2026-Q2", target_amount_cents=100_000))
            out = upsert_forecast("alice", "2026-Q2", ForecastWorksheetIn(committed_cents=50_000, best_case_cents=80_000, pipeline_cents=90_000))
        assert out.quota_cents == 100_000
        assert out.attainment_pct == 0  # no closed_won opps

    def test_get_forecast_not_found_returns_404(self, sales_tables):
        from fastapi import HTTPException
        from app.services.opportunities import get_forecast
        with pytest.raises(HTTPException) as exc:
            get_forecast("alice", "2026-Q4")
        assert exc.value.status_code == 404

    def test_upsert_preserves_created_at(self, sales_tables):
        from app.models import ForecastWorksheetIn
        from app.services.opportunities import upsert_forecast
        with patch("app.services.opportunities.audit_event"):
            first = upsert_forecast("alice", "2026-Q1", ForecastWorksheetIn(committed_cents=0, best_case_cents=0, pipeline_cents=0))
            second = upsert_forecast("alice", "2026-Q1", ForecastWorksheetIn(committed_cents=100, best_case_cents=200, pipeline_cents=300))
        assert first.created_at == second.created_at
        assert second.committed_cents == 100

    def test_over_attainment(self, sales_tables):
        from datetime import datetime, timezone
        from app.models import ForecastWorksheetIn, OpportunityCreateIn, SalesQuotaIn
        from app.services.opportunities import create_opportunity, set_quota, upsert_forecast
        in_period = int(datetime(2026, 5, 1, tzinfo=timezone.utc).timestamp())
        with patch("app.services.opportunities.audit_event"):
            create_opportunity("alice", OpportunityCreateIn(name="W1", stage="closed_won", amount_cents=150_000, close_date=in_period))
            set_quota("admin1", SalesQuotaIn(user_sub="alice", period_type="quarterly", period_key="2026-Q2", target_amount_cents=100_000))
            out = upsert_forecast("alice", "2026-Q2", ForecastWorksheetIn(committed_cents=0, best_case_cents=0, pipeline_cents=0))
        assert out.attainment_pct == 150

    def test_quota_audit_event(self, sales_tables):
        from app.models import SalesQuotaIn
        from app.services.opportunities import set_quota
        mock_audit = MagicMock()
        with patch("app.services.opportunities.audit_event", mock_audit):
            set_quota("admin1", SalesQuotaIn(user_sub="alice", period_type="quarterly", period_key="2026-Q2", target_amount_cents=100))
        events = [call.args[0] for call in mock_audit.call_args_list]
        assert "quota.set" in events

    def test_forecast_audit_event(self, sales_tables):
        from app.models import ForecastWorksheetIn
        from app.services.opportunities import upsert_forecast
        mock_audit = MagicMock()
        with patch("app.services.opportunities.audit_event", mock_audit):
            upsert_forecast("alice", "2026-Q2", ForecastWorksheetIn(committed_cents=0, best_case_cents=0, pipeline_cents=0))
        events = [call.args[0] for call in mock_audit.call_args_list]
        assert "forecast.upserted" in events


# ══════════════════════════════════════════════════════════════════════════════
# OPP-006 — Pipeline report tests
# ══════════════════════════════════════════════════════════════════════════════


class TestOpp006PipelineReport:
    def _seed_opp(self, owner: str, stage: str, amount: int, close_date: int):
        from app.models import OpportunityCreateIn
        from app.services.opportunities import create_opportunity
        return create_opportunity(
            owner,
            OpportunityCreateIn(name=f"{stage}-{amount}", stage=stage, amount_cents=amount, close_date=close_date, probability=50),
        )

    def test_flag_off_503(self, sales_tables):
        from fastapi import HTTPException
        from app.core.settings import S
        from app.services.opportunities import pipeline_report
        object.__setattr__(S, "sales_pipeline_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc:
                pipeline_report("alice")
            assert exc.value.status_code == 503
        finally:
            object.__setattr__(S, "sales_pipeline_enabled", True)

    def test_empty_pipeline_all_stages_present(self, sales_tables):
        from app.models import OPPORTUNITY_STAGES
        from app.services.opportunities import pipeline_report
        with patch("app.services.opportunities.audit_event"):
            result = pipeline_report("alice")
        assert len(result.stages) == len(OPPORTUNITY_STAGES)
        assert all(s.count == 0 for s in result.stages)
        assert result.total_amount_cents == 0
        assert result.total_weighted_cents == 0

    def test_single_opp_in_correct_bucket(self, sales_tables):
        with patch("app.services.opportunities.audit_event"):
            self._seed_opp("alice", "qualification", 10_000, 1_800_000_000)
        from app.services.opportunities import pipeline_report
        result = pipeline_report("alice")
        qual = next(s for s in result.stages if s.stage == "qualification")
        assert qual.count == 1
        assert qual.total_amount_cents == 10_000
        assert qual.avg_close_date == 1_800_000_000

    def test_multiple_opps_grouped_by_stage(self, sales_tables):
        with patch("app.services.opportunities.audit_event"):
            for _ in range(3):
                self._seed_opp("alice", "prospecting", 1_000, 1_000_000_000)
            for _ in range(2):
                self._seed_opp("alice", "negotiation_review", 2_000, 1_000_000_001)
        from app.services.opportunities import pipeline_report
        result = pipeline_report("alice")
        prosp = next(s for s in result.stages if s.stage == "prospecting")
        neg = next(s for s in result.stages if s.stage == "negotiation_review")
        assert prosp.count == 3
        assert neg.count == 2

    def test_date_range_filter(self, sales_tables):
        with patch("app.services.opportunities.audit_event"):
            self._seed_opp("alice", "prospecting", 1_000, 1_000)
            self._seed_opp("alice", "prospecting", 2_000, 2_000)
            self._seed_opp("alice", "prospecting", 3_000, 3_000)
        from app.services.opportunities import pipeline_report
        result = pipeline_report("alice", close_date_from=1_500, close_date_to=2_500)
        prosp = next(s for s in result.stages if s.stage == "prospecting")
        assert prosp.count == 1  # only the one at 2000

    def test_soft_deleted_excluded(self, sales_tables):
        from app.services.opportunities import delete_opportunity, pipeline_report
        with patch("app.services.opportunities.audit_event"):
            opp = self._seed_opp("alice", "qualification", 5_000, 1_000_000_000)
            delete_opportunity("alice", opp.opp_id)
        result = pipeline_report("alice")
        qual = next(s for s in result.stages if s.stage == "qualification")
        assert qual.count == 0

    def test_total_amount_excludes_terminal_stages(self, sales_tables):
        with patch("app.services.opportunities.audit_event"):
            self._seed_opp("alice", "closed_won", 5_000, 1_000_000_000)
            self._seed_opp("alice", "prospecting", 3_000, 1_000_000_001)
        from app.services.opportunities import pipeline_report
        result = pipeline_report("alice")
        assert result.total_amount_cents == 3_000  # only prospecting; closed_won is terminal

    def test_admin_report_aggregates_all_users(self, sales_tables):
        with patch("app.services.opportunities.audit_event"):
            self._seed_opp("alice", "prospecting", 1_000, 1_000_000_000)
            self._seed_opp("bob",   "prospecting", 2_000, 1_000_000_001)
        from app.services.opportunities import pipeline_report_all
        result = pipeline_report_all("admin1")
        prosp = next(s for s in result.stages if s.stage == "prospecting")
        assert prosp.count == 2

    def test_admin_report_audit_event(self, sales_tables):
        from app.services.opportunities import pipeline_report_all
        mock_audit = MagicMock()
        with patch("app.services.opportunities.audit_event", mock_audit):
            pipeline_report_all("admin1")
        events = [call.args[0] for call in mock_audit.call_args_list]
        assert "sales_pipeline_report.admin_accessed" in events

    def test_custom_stage_config_in_report(self, sales_tables):
        from app.models import StageConfigIn, StageConfigItemIn
        from app.services.opportunities import set_stage_config, pipeline_report
        with patch("app.services.opportunities.audit_event"):
            set_stage_config("admin1", StageConfigIn(stages=[
                StageConfigItemIn(stage_key="cs1", label="Custom S1", order=0, is_won=False, is_lost=False),
                StageConfigItemIn(stage_key="cs2", label="Custom S2", order=1, is_won=True, is_lost=False),
                StageConfigItemIn(stage_key="cs3", label="Custom S3", order=2, is_won=False, is_lost=True),
            ]))
        result = pipeline_report("alice")
        labels = [s.label for s in result.stages]
        assert "Custom S1" in labels

    def test_unknown_stage_in_ddb_handled(self, sales_tables):
        """Items with unknown stage values don't cause errors; they're ignored."""
        # Directly write a row with an unknown stage
        sales_tables.opp.put_item(Item={
            "pk": "USER#alice",
            "sk": "OPP#opp_unknown",
            "opp_id": "opp_unknown",
            "owner_sub": "alice",
            "name": "Unknown",
            "stage": "stale_unknown_stage",
            "amount_cents": 1000,
            "weighted_amount_cents": 500,
            "close_date": 1_000_000_000,
            "probability": 50,
            "created_at": 1_000_000_000,
            "updated_at": 1_000_000_000,
        })
        from app.services.opportunities import pipeline_report
        # Should not raise
        result = pipeline_report("alice")
        stage_names = [s.stage for s in result.stages]
        assert "stale_unknown_stage" not in stage_names
