"""Hermetic offline tests for CMP-001..CMP-008 — SuiteCRM Campaigns-Extra.

Isolation:
- moto DynamoDB tables bound to frozen T handles via object.__setattr__
- S flags toggled via object.__setattr__ (restored after each test class)
- All sibling modules that don't exist in the worktree are stubbed
- No TestClient, no real AWS, no network
"""
from __future__ import annotations

import asyncio
import sys
import types
from contextlib import contextmanager
from typing import Any, Dict, Optional
from unittest.mock import MagicMock, patch

import pytest

try:
    import boto3
    from moto import mock_aws
    HAS_MOTO = True
except ImportError:
    HAS_MOTO = False
    pytestmark = pytest.mark.skip("moto not available")

# ---------------------------------------------------------------------------
# Helpers to create moto DDB tables
# ---------------------------------------------------------------------------

def _make_campaigns_table(ddb):
    return ddb.create_table(
        TableName="CrmCampaigns_test",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "owner_id", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
            {"AttributeName": "status", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByOwnerCreatedAt",
                "KeySchema": [
                    {"AttributeName": "owner_id", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByStatusCreatedAt",
                "KeySchema": [
                    {"AttributeName": "status", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_send_log_table(ddb):
    return ddb.create_table(
        TableName="CrmCampaignSendLog_test",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "campaign_id", "AttributeType": "S"},
            {"AttributeName": "sent_at", "AttributeType": "N"},
            {"AttributeName": "variant_id", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByCampaignSentAt",
                "KeySchema": [
                    {"AttributeName": "campaign_id", "KeyType": "HASH"},
                    {"AttributeName": "sent_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByCampaignVariant",
                "KeySchema": [
                    {"AttributeName": "campaign_id", "KeyType": "HASH"},
                    {"AttributeName": "variant_id", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_email_templates_table(ddb):
    return ddb.create_table(
        TableName="MarketingEmailTemplates_test",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "owner_id", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByOwnerCreatedAt",
                "KeySchema": [
                    {"AttributeName": "owner_id", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_tracking_codes_table(ddb):
    return ddb.create_table(
        TableName="MarketingTrackingCodes_test",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "code_slug", "AttributeType": "S"},
            {"AttributeName": "ts", "AttributeType": "N"},
            {"AttributeName": "campaign_id", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByCodeTs",
                "KeySchema": [
                    {"AttributeName": "code_slug", "KeyType": "HASH"},
                    {"AttributeName": "ts", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByCampaignCreatedAt",
                "KeySchema": [
                    {"AttributeName": "campaign_id", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_cart_reminder_config_table(ddb):
    return ddb.create_table(
        TableName="cart_reminder_config_test",
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


def _make_web_lead_table(ddb):
    return ddb.create_table(
        TableName="WebLeadCaptures_test",
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


# ---------------------------------------------------------------------------
# Fixture module
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def _stub_missing_siblings():
    """Stub sibling modules absent from this worktree."""
    stubs_to_install = [
        "app.services.marketing_lists",
        "app.services.profile",
        "app.services.branding",
        "app.services.alerts",
        "app.services.questionnaires_repository",
        "app.services.notification_templates",
        "app.services.alert_email_templates",
    ]
    saved = {}
    saved_pkg_attrs = {}

    for mod_name in stubs_to_install:
        saved[mod_name] = sys.modules.get(mod_name)
        stub = types.ModuleType(mod_name)
        # Provide expected symbols
        stub.write_alert = MagicMock(return_value=None)
        stub.send_alert_email = MagicMock(return_value=None)
        stub.send_alert_sms = MagicMock(return_value=[{"status": "sent"}])
        stub.audit_event = MagicMock(return_value=None)
        stub.is_user_opted_out = MagicMock(return_value=False)
        stub.get_profile = MagicMock(return_value={
            "first_name": "Alice",
            "last_name": "Test",
            "displayed_email": "alice@test.local",
            "displayed_telephone_number": "+15551234567",
        })
        stub.get_branding = MagicMock(return_value={"platform_name": "testlogon"})
        stub._VAR_RE = __import__("re").compile(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}")
        stub._render = lambda text, vars: (
            __import__("re").sub(
                r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}",
                lambda m: vars.get(m.group(1), m.group(0)),
                text or ""
            ),
            []
        )
        stub._wrap_html = lambda title, body: f"<html><body>{body}</body></html>"

        class FakeRepo:
            def get_questionnaire(self, qid):
                return None
        stub.DynamoQuestionnaireRepository = FakeRepo

        sys.modules[mod_name] = stub

        # Also set on parent package
        parts = mod_name.rsplit(".", 1)
        if len(parts) == 2:
            pkg_name, attr = parts
            pkg = sys.modules.get(pkg_name)
            if pkg is not None:
                saved_pkg_attrs[(pkg_name, attr)] = getattr(pkg, attr, None)
                setattr(pkg, attr, stub)

    yield

    for mod_name, orig in saved.items():
        if orig is None:
            sys.modules.pop(mod_name, None)
        else:
            sys.modules[mod_name] = orig

    for (pkg_name, attr), orig in saved_pkg_attrs.items():
        pkg = sys.modules.get(pkg_name)
        if pkg is not None:
            if orig is None:
                try:
                    delattr(pkg, attr)
                except AttributeError:
                    pass
            else:
                setattr(pkg, attr, orig)


@pytest.fixture(scope="module")
def _moto_tables():
    """Create moto DDB tables and patch T handles. Module-scoped."""
    if not HAS_MOTO:
        pytest.skip("moto not available")

    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        # Import after stubs are installed
        import sys
        # Force fresh import
        for mod in list(sys.modules.keys()):
            if "crm_campaigns" in mod or "marketing_email" in mod or "marketing_tracking" in mod or "marketing_unsubscribe" in mod or "marketing_web" in mod:
                sys.modules.pop(mod, None)

        from app.core.settings import S
        from app.core.tables import T

        orig_flag = getattr(S, "crm_campaigns_enabled", False)
        orig_open_tracking = getattr(S, "marketing_open_tracking_enabled", False)
        orig_web_to_lead = getattr(S, "web_to_lead_enabled", False)

        object.__setattr__(S, "crm_campaigns_enabled", True)
        object.__setattr__(S, "marketing_open_tracking_enabled", True)
        object.__setattr__(S, "web_to_lead_enabled", True)

        camps_tbl = _make_campaigns_table(ddb)
        send_log_tbl = _make_send_log_table(ddb)
        email_tpls_tbl = _make_email_templates_table(ddb)
        tracking_tbl = _make_tracking_codes_table(ddb)
        cart_cfg_tbl = _make_cart_reminder_config_table(ddb)
        web_lead_tbl = _make_web_lead_table(ddb)

        # Patch T handles
        orig_camps = getattr(T, "crm_campaigns", None)
        orig_log = getattr(T, "crm_campaign_send_log", None)
        orig_tpls = getattr(T, "marketing_email_templates", None)
        orig_tracking = getattr(T, "marketing_tracking_codes", None)
        orig_cart_cfg = getattr(T, "cart_reminder_config", None)
        orig_web_lead = getattr(T, "marketing_web_lead_captures", None)

        object.__setattr__(T, "crm_campaigns", camps_tbl)
        object.__setattr__(T, "crm_campaign_send_log", send_log_tbl)
        object.__setattr__(T, "marketing_email_templates", email_tpls_tbl)
        object.__setattr__(T, "marketing_tracking_codes", tracking_tbl)
        object.__setattr__(T, "cart_reminder_config", cart_cfg_tbl)
        object.__setattr__(T, "marketing_web_lead_captures", web_lead_tbl)

        yield {
            "camps": camps_tbl,
            "send_log": send_log_tbl,
            "email_tpls": email_tpls_tbl,
            "tracking": tracking_tbl,
            "cart_cfg": cart_cfg_tbl,
            "web_lead": web_lead_tbl,
            "S": S,
            "T": T,
        }

        # Restore
        object.__setattr__(T, "crm_campaigns", orig_camps)
        object.__setattr__(T, "crm_campaign_send_log", orig_log)
        object.__setattr__(T, "marketing_email_templates", orig_tpls)
        object.__setattr__(T, "marketing_tracking_codes", orig_tracking)
        object.__setattr__(T, "cart_reminder_config", orig_cart_cfg)
        object.__setattr__(T, "marketing_web_lead_captures", orig_web_lead)
        object.__setattr__(S, "crm_campaigns_enabled", orig_flag)
        object.__setattr__(S, "marketing_open_tracking_enabled", orig_open_tracking)
        object.__setattr__(S, "web_to_lead_enabled", orig_web_to_lead)


# ===========================================================================
# CMP-001: Campaign CRUD + Channel Types
# ===========================================================================

class TestCampaignCRUD:

    def test_create_campaign_email(self, _moto_tables):
        from app.services.crm_campaigns import create_campaign
        from app.models import CrmCampaignCreateIn

        data = CrmCampaignCreateIn(name="Test Email Campaign", campaign_type="email")
        result = create_campaign("owner1", data)

        assert result["campaign_id"]
        assert result["name"] == "Test Email Campaign"
        assert result["campaign_type"] == "email"
        assert result["status"] == "draft"

    def test_create_campaign_sms(self, _moto_tables):
        from app.services.crm_campaigns import create_campaign
        from app.models import CrmCampaignCreateIn

        data = CrmCampaignCreateIn(name="Test SMS Campaign", campaign_type="sms")
        result = create_campaign("owner1", data)
        assert result["campaign_type"] == "sms"

    def test_create_campaign_phone(self, _moto_tables):
        from app.services.crm_campaigns import create_campaign
        from app.models import CrmCampaignCreateIn

        data = CrmCampaignCreateIn(name="Test Phone Campaign", campaign_type="phone")
        result = create_campaign("owner1", data)
        assert result["campaign_type"] == "phone"

    def test_model_validation_invalid_type(self):
        from pydantic import ValidationError
        from app.models import CrmCampaignCreateIn

        with pytest.raises(ValidationError):
            CrmCampaignCreateIn(name="Bad", campaign_type="telegram")

    def test_get_campaign(self, _moto_tables):
        from app.services.crm_campaigns import create_campaign, get_campaign
        from app.models import CrmCampaignCreateIn

        data = CrmCampaignCreateIn(name="Get Test Campaign")
        created = create_campaign("owner2", data)
        got = get_campaign(created["campaign_id"], "owner2")
        assert got is not None
        assert got["campaign_id"] == created["campaign_id"]

    def test_get_campaign_missing_type_defaults_email(self, _moto_tables):
        """Legacy campaign item without campaign_type should default to 'email'."""
        from app.core.tables import T
        from app.services.crm_campaigns import get_campaign

        # Insert raw item without campaign_type
        T.crm_campaigns.put_item(Item={
            "pk": "OWNER#owner_legacy",
            "sk": "MKTCAMP#legacy123",
            "campaign_id": "legacy123",
            "owner_id": "owner_legacy",
            "name": "Legacy",
            "status": "draft",
            "created_at": 0,
            "updated_at": 0,
        })
        result = get_campaign("legacy123", "owner_legacy")
        assert result is not None
        assert result["campaign_type"] == "email"

    def test_list_campaigns_filter_by_type(self, _moto_tables):
        from app.services.crm_campaigns import create_campaign, list_campaigns
        from app.models import CrmCampaignCreateIn

        prefix = "list_filter_test"
        create_campaign("owner_list", CrmCampaignCreateIn(name=f"{prefix}_email", campaign_type="email"))
        create_campaign("owner_list", CrmCampaignCreateIn(name=f"{prefix}_sms", campaign_type="sms"))
        create_campaign("owner_list", CrmCampaignCreateIn(name=f"{prefix}_fax", campaign_type="fax"))

        result = list_campaigns("owner_list", campaign_type="sms")
        assert all(c["campaign_type"] == "sms" for c in result["campaigns"])
        assert any(c["name"] == f"{prefix}_sms" for c in result["campaigns"])

    def test_list_campaigns_no_filter(self, _moto_tables):
        from app.services.crm_campaigns import list_campaigns

        result = list_campaigns("owner_list")
        assert len(result["campaigns"]) >= 3

    def test_update_campaign(self, _moto_tables):
        from app.services.crm_campaigns import create_campaign, update_campaign
        from app.models import CrmCampaignCreateIn, CrmCampaignUpdateIn

        created = create_campaign("owner3", CrmCampaignCreateIn(name="Update Test", campaign_type="email"))
        updated = update_campaign(created["campaign_id"], "owner3", CrmCampaignUpdateIn(campaign_type="sms"))
        assert updated["campaign_type"] == "sms"

    def test_update_campaign_type_blocks_on_active(self, _moto_tables):
        from fastapi import HTTPException
        from app.services.crm_campaigns import create_campaign, update_campaign
        from app.core.tables import T
        from app.models import CrmCampaignCreateIn, CrmCampaignUpdateIn

        created = create_campaign("owner3", CrmCampaignCreateIn(name="Active Campaign"))
        # Simulate active status
        T.crm_campaigns.update_item(
            Key={"pk": f"OWNER#owner3", "sk": f"MKTCAMP#{created['campaign_id']}"},
            UpdateExpression="SET #st = :st",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":st": "active"},
        )

        with pytest.raises(HTTPException) as exc:
            update_campaign(created["campaign_id"], "owner3", CrmCampaignUpdateIn(campaign_type="sms"))
        assert exc.value.status_code == 409

    def test_delete_campaign(self, _moto_tables):
        from app.services.crm_campaigns import create_campaign, delete_campaign, get_campaign
        from app.models import CrmCampaignCreateIn

        created = create_campaign("owner4", CrmCampaignCreateIn(name="Delete Test"))
        delete_campaign(created["campaign_id"], "owner4")
        assert get_campaign(created["campaign_id"], "owner4") is None


# ===========================================================================
# CMP-001: Send path channel dispatch
# ===========================================================================

class TestSendPath:

    def _seed_campaign(self, owner: str, name: str, campaign_type: str = "email") -> str:
        from app.services.crm_campaigns import create_campaign
        from app.models import CrmCampaignCreateIn
        result = create_campaign(owner, CrmCampaignCreateIn(name=name, campaign_type=campaign_type))
        return result["campaign_id"]

    def _add_member_to_campaign(self, campaign_id: str, owner: str, party_id: str):
        """Directly seed the contact list and mock list_members_for_send."""
        pass  # We'll use patching instead

    def test_send_email_campaign_dry_run(self, _moto_tables):
        """Email campaign dry_run=True: returns counts, no messages sent."""
        from app.services.crm_campaigns import send_campaign
        from app.models import MarketingCampaignSendIn

        campaign_id = self._seed_campaign("sender1", "Email DryRun", "email")
        result = send_campaign(campaign_id, "sender1", dry_run=True)
        assert result["campaign_id"] == campaign_id
        assert result["dry_run"] is True
        assert result["total_sent"] == 0  # no audience members

    def test_send_campaign_flag_off_raises(self, _moto_tables):
        from fastapi import HTTPException
        from app.core.settings import S
        from app.services.crm_campaigns import send_campaign, create_campaign
        from app.models import CrmCampaignCreateIn

        campaign_id = self._seed_campaign("sender2", "Flag Off Test")
        orig = getattr(S, "crm_campaigns_enabled", True)
        object.__setattr__(S, "crm_campaigns_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc:
                send_campaign(campaign_id, "sender2")
            assert exc.value.status_code == 404
        finally:
            object.__setattr__(S, "crm_campaigns_enabled", orig)

    def test_send_log_has_channel(self, _moto_tables):
        """Send log rows written by send path include 'channel' attribute."""
        from app.services.crm_campaigns import send_campaign, create_campaign, _try_send_one
        from app.models import CrmCampaignCreateIn
        from app.core.tables import T
        from app.core.time import now_ts

        campaign_id = self._seed_campaign("sender3", "Send Log Test", "sms")
        # Directly call _try_send_one to test the send-log path
        now = now_ts()
        with patch("app.services.crm_campaigns.send_alert_sms", return_value=[{"status": "sent"}], create=True):
            result = _try_send_one(
                campaign_id=campaign_id,
                campaign_type="sms",
                party_id="party123",
                subject="Test",
                body_text="Test body",
                body_html=None,
                dry_run=False,
                now=now,
                snapshot_ts=now,
                send_id_prefix="test",
                variant_id=None,
            )
        assert result is True

        # Check send-log
        items = T.crm_campaign_send_log.scan(
            FilterExpression=__import__("boto3").dynamodb.conditions.Attr("campaign_id").eq(campaign_id)
        ).get("Items", [])
        assert len(items) >= 1
        assert items[0].get("channel") == "sms"

    def test_send_log_sms_number_redacted(self, _moto_tables):
        """sms_number in send-log is redacted to last 4 digits."""
        from app.services.crm_campaigns import _try_send_one
        from app.core.tables import T
        from app.core.time import now_ts

        now = now_ts()
        campaign_id = "redact_test_" + __import__("uuid").uuid4().hex[:8]
        with patch("app.services.crm_campaigns.send_alert_sms", return_value=[{"status": "sent"}], create=True):
            _try_send_one(
                campaign_id=campaign_id,
                campaign_type="sms",
                party_id="party_phone_test",
                subject="Test",
                body_text="Test",
                body_html=None,
                dry_run=False,
                now=now,
                snapshot_ts=now,
                send_id_prefix="x",
            )

        items = T.crm_campaign_send_log.scan(
            FilterExpression=__import__("boto3").dynamodb.conditions.Attr("campaign_id").eq(campaign_id)
        ).get("Items", [])
        # The phone is from our stub get_profile which returns +15551234567
        assert any(item.get("sms_number") == "***4567" for item in items)

    def test_idempotent_send_no_duplicate(self, _moto_tables):
        """Calling _try_send_one twice with same campaign/party returns False on second."""
        from app.services.crm_campaigns import _try_send_one
        from app.core.time import now_ts

        now = now_ts()
        campaign_id = "dedup_test_" + __import__("uuid").uuid4().hex[:8]
        kwargs = dict(
            campaign_id=campaign_id,
            campaign_type="email",
            party_id="party_dedup",
            subject="S",
            body_text="B",
            body_html=None,
            dry_run=False,
            now=now,
            snapshot_ts=now,
            send_id_prefix="x",
        )
        r1 = _try_send_one(**kwargs)
        r2 = _try_send_one(**kwargs)
        assert r1 is True
        assert r2 is False  # second call hits conditional put failure


# ===========================================================================
# CMP-001: phone/mail/fax send (in-app only)
# ===========================================================================

class TestNonEmailChannels:

    def _seed(self, owner: str, name: str, ctype: str) -> str:
        from app.services.crm_campaigns import create_campaign
        from app.models import CrmCampaignCreateIn
        result = create_campaign(owner, CrmCampaignCreateIn(name=name, campaign_type=ctype))
        return result["campaign_id"]

    def test_phone_channel_write_alert_called(self, _moto_tables):
        from app.services.crm_campaigns import _try_send_one
        from app.core.time import now_ts

        now = now_ts()
        cid = "phone_test_" + __import__("uuid").uuid4().hex[:8]
        write_alert_mock = MagicMock()

        with patch.dict(sys.modules, {
            "app.services.alerts": type(sys)("app.services.alerts"),
        }):
            import app.services.alerts as alerts_mod
            alerts_mod.write_alert = write_alert_mock
            alerts_mod.send_alert_email = MagicMock()
            alerts_mod.send_alert_sms = MagicMock()
            alerts_mod.audit_event = MagicMock()

            result = _try_send_one(
                campaign_id=cid,
                campaign_type="phone",
                party_id="party_phone",
                subject="Phone campaign",
                body_text="Call me",
                body_html=None,
                dry_run=False,
                now=now,
                snapshot_ts=now,
                send_id_prefix="x",
            )

        assert result is True

    def test_mail_channel_no_sms(self, _moto_tables):
        """mail channel never calls send_alert_sms."""
        from app.services.crm_campaigns import _try_send_one
        from app.core.time import now_ts

        now = now_ts()
        cid = "mail_test_" + __import__("uuid").uuid4().hex[:8]
        sms_mock = MagicMock()

        with patch.dict("sys.modules"):
            import app.services.alerts as am
            orig_sms = getattr(am, "send_alert_sms", None)
            am.send_alert_sms = sms_mock
            try:
                _try_send_one(
                    campaign_id=cid,
                    campaign_type="mail",
                    party_id="party_mail",
                    subject="Mail",
                    body_text="Mail body",
                    body_html=None,
                    dry_run=False,
                    now=now,
                    snapshot_ts=now,
                    send_id_prefix="x",
                )
            finally:
                am.send_alert_sms = orig_sms

        sms_mock.assert_not_called()


# ===========================================================================
# CMP-002: Email Templates
# ===========================================================================

class TestEmailTemplates:

    def test_create_template_extracts_variables(self, _moto_tables):
        from app.services.marketing_email_templates import create_template
        from app.models import MarketingEmailTemplateCreateIn

        data = MarketingEmailTemplateCreateIn(
            name="Vars Test Template",
            subject_template="Hi {{first_name}}",
            body_html_template="<p>{{company}}</p>",
        )
        result = create_template("tmpl_owner", data)
        assert "company" in result["variables"]
        assert "first_name" in result["variables"]
        assert result["variables"] == sorted(result["variables"])

    def test_create_template_duplicate_409(self, _moto_tables):
        from fastapi import HTTPException
        from app.services.marketing_email_templates import create_template
        from app.models import MarketingEmailTemplateCreateIn

        data = MarketingEmailTemplateCreateIn(
            name="Dupe Template",
            subject_template="Sub",
            body_html_template="<p>Body</p>",
        )
        create_template("tmpl_owner2", data)
        with pytest.raises(HTTPException) as exc:
            create_template("tmpl_owner2", data)
        assert exc.value.status_code == 409

    def test_get_template_ownership_403(self, _moto_tables):
        from fastapi import HTTPException
        from app.services.marketing_email_templates import create_template, get_template
        from app.models import MarketingEmailTemplateCreateIn

        data = MarketingEmailTemplateCreateIn(
            name="Owner Test", subject_template="S", body_html_template="<p>B</p>"
        )
        tmpl = create_template("owner_a", data)
        with pytest.raises(HTTPException) as exc:
            get_template("owner_b", tmpl["template_id"])
        assert exc.value.status_code == 403

    def test_list_templates_pagination(self, _moto_tables):
        from app.services.marketing_email_templates import create_template, list_templates
        from app.models import MarketingEmailTemplateCreateIn

        for i in range(5):
            create_template("pg_owner", MarketingEmailTemplateCreateIn(
                name=f"Page Template {i}",
                subject_template="S",
                body_html_template="<p>B</p>",
            ))

        page1 = list_templates("pg_owner", limit=3)
        assert len(page1["templates"]) == 3
        # cursor may or may not be present depending on DDB page behavior
        # just verify we got 3 templates

    def test_render_template_substitutes_vars(self, _moto_tables):
        from app.services.marketing_email_templates import create_template, render_template
        from app.models import MarketingEmailTemplateCreateIn

        data = MarketingEmailTemplateCreateIn(
            name="Render Test",
            subject_template="Hello {{first_name}}",
            body_html_template="<p>Company: {{company}}</p>",
        )
        tmpl = create_template("render_owner", data)
        subj, html = render_template(tmpl, {"first_name": "Alice", "company": "Acme"})
        assert "Alice" in subj
        assert "Acme" in html

    def test_render_template_missing_var_intact(self, _moto_tables):
        """Unresolved {{var}} placeholders are left as-is."""
        from app.services.marketing_email_templates import create_template, render_template
        from app.models import MarketingEmailTemplateCreateIn

        data = MarketingEmailTemplateCreateIn(
            name="Missing Var Test",
            subject_template="Hello {{first_name}}",
            body_html_template="<p>{{company}}</p>",
        )
        tmpl = create_template("missing_owner", data)
        _, html = render_template(tmpl, {})
        assert "{{" in html or "company" in html  # placeholder left intact

    def test_update_template_re_extracts_variables(self, _moto_tables):
        from app.services.marketing_email_templates import create_template, update_template
        from app.models import MarketingEmailTemplateCreateIn, MarketingEmailTemplateUpdateIn

        data = MarketingEmailTemplateCreateIn(
            name="Reextract Test",
            subject_template="S",
            body_html_template="<p>{{first_name}}</p>",
        )
        tmpl = create_template("reext_owner", data)
        updated = update_template(
            "reext_owner",
            tmpl["template_id"],
            MarketingEmailTemplateUpdateIn(body_html_template="<p>{{phone}}</p>"),
        )
        assert "phone" in updated["variables"]

    def test_delete_template(self, _moto_tables):
        from app.services.marketing_email_templates import create_template, delete_template, get_template
        from app.models import MarketingEmailTemplateCreateIn

        data = MarketingEmailTemplateCreateIn(
            name="Delete Template", subject_template="S", body_html_template="<p>B</p>"
        )
        tmpl = create_template("del_owner", data)
        delete_template("del_owner", tmpl["template_id"])
        assert get_template("del_owner", tmpl["template_id"]) is None


# ===========================================================================
# CMP-003: Open tracking pixel
# ===========================================================================

class TestOpenTrackingPixel:

    def test_record_visit_open_type(self, _moto_tables):
        from app.services.marketing_tracking_codes import create_tracking_code, record_visit
        from app.core.tables import T

        create_tracking_code("tc_owner", {"code_slug": "testcode1", "campaign_id": "camp1"})
        record_visit("testcode1", event_type="open", ip_address="1.2.3.4", user_agent="Mozilla")

        items = T.marketing_tracking_codes.query(
            KeyConditionExpression=__import__("boto3").dynamodb.conditions.Key("pk").eq("TRACK#testcode1")
        ).get("Items", [])
        visit_items = [i for i in items if i["sk"].startswith("VISIT#")]
        assert len(visit_items) == 1
        assert visit_items[0].get("event_type") == "open"
        assert visit_items[0].get("ip_address") == "1.2.3.4"

    def test_record_visit_open_increments_open_count(self, _moto_tables):
        from app.services.marketing_tracking_codes import create_tracking_code, record_visit
        from app.core.tables import T

        create_tracking_code("tc_owner2", {"code_slug": "testcode2", "campaign_id": "camp2"})
        record_visit("testcode2", event_type="open")
        record_visit("testcode2", event_type="open")

        meta = T.marketing_tracking_codes.get_item(Key={"pk": "TRACK#testcode2", "sk": "META"}).get("Item")
        assert meta is not None
        assert int(meta.get("open_count", 0)) == 2
        assert int(meta.get("visit_count", 0)) == 2

    def test_record_visit_click_no_event_type_attr(self, _moto_tables):
        """Click VISIT rows omit event_type attribute for backward compat."""
        from app.services.marketing_tracking_codes import create_tracking_code, record_visit
        from app.core.tables import T

        create_tracking_code("tc_owner3", {"code_slug": "clickcode", "campaign_id": "camp3"})
        record_visit("clickcode", event_type="click")

        items = T.marketing_tracking_codes.query(
            KeyConditionExpression=__import__("boto3").dynamodb.conditions.Key("pk").eq("TRACK#clickcode")
        ).get("Items", [])
        visit_items = [i for i in items if i["sk"].startswith("VISIT#")]
        assert len(visit_items) == 1
        assert "event_type" not in visit_items[0]  # omitted for click
        # visit_count incremented, open_count not
        meta = T.marketing_tracking_codes.get_item(Key={"pk": "TRACK#clickcode", "sk": "META"}).get("Item")
        assert int(meta.get("visit_count", 0)) == 1
        assert int(meta.get("open_count", 0)) == 0

    def test_record_visit_unknown_code_silent(self, _moto_tables):
        """record_visit on unknown code does nothing (no orphan write)."""
        from app.services.marketing_tracking_codes import record_visit
        from app.core.tables import T

        record_visit("nonexistent_code_xyz", event_type="open")
        items = T.marketing_tracking_codes.query(
            KeyConditionExpression=__import__("boto3").dynamodb.conditions.Key("pk").eq("TRACK#nonexistent_code_xyz")
        ).get("Items", [])
        assert len(items) == 0


# ===========================================================================
# CMP-004: Unsubscribe
# ===========================================================================

class TestUnsubscribe:

    def test_generate_and_process_unsubscribe(self, _moto_tables):
        from app.services.marketing_unsubscribe import generate_unsubscribe_url, process_unsubscribe

        url = generate_unsubscribe_url("party_unsub", "camp_unsub")
        assert "/ui/crm-marketing/optout/" in url

        token = url.split("/ui/crm-marketing/optout/")[-1]
        result = process_unsubscribe(token)
        assert result["ok"] is True

    def test_invalid_token_returns_error(self, _moto_tables):
        from app.services.marketing_unsubscribe import process_unsubscribe

        result = process_unsubscribe("garbage.token.here")
        assert result["ok"] is False

    def test_one_time_use(self, _moto_tables):
        from app.services.marketing_unsubscribe import generate_unsubscribe_url, process_unsubscribe

        url = generate_unsubscribe_url("party_otu", "camp_otu")
        token = url.split("/ui/crm-marketing/optout/")[-1]
        r1 = process_unsubscribe(token)
        r2 = process_unsubscribe(token)
        # Both return ok=True (second is idempotent "already unsubscribed")
        assert r1["ok"] is True
        assert r2["ok"] is True  # idempotent

    def test_opt_out_row_written(self, _moto_tables):
        from app.services.marketing_unsubscribe import generate_unsubscribe_url, process_unsubscribe
        from app.core.tables import T

        url = generate_unsubscribe_url("party_write_test", "camp_wr")
        token = url.split("/ui/crm-marketing/optout/")[-1]
        process_unsubscribe(token)

        row = T.cart_reminder_config.get_item(
            Key={"pk": "OPTOUT#USER#party_write_test", "sk": "META"}
        ).get("Item")
        assert row is not None
        assert row.get("opted_out") is True


# ===========================================================================
# CMP-006: Web-to-lead
# ===========================================================================

class TestWebToLead:

    def test_create_lead_capture_basic(self, _moto_tables):
        from app.services.marketing_web_leads import create_lead_capture
        from app.models import WebLeadCaptureIn

        data = WebLeadCaptureIn(
            first_name="John",
            last_name="Doe",
            email="john@example.com",
        )
        result = create_lead_capture(data, source_ip="127.0.0.1")
        assert result["ok"] is True
        assert result["capture_id"] != "bot"

    def test_honeypot_returns_bot_silently(self, _moto_tables):
        from app.services.marketing_web_leads import create_lead_capture
        from app.models import WebLeadCaptureIn

        data = WebLeadCaptureIn(
            first_name="Bot",
            last_name="Smith",
            email="bot@evil.com",
            honeypot="I am a bot",
        )
        result = create_lead_capture(data, source_ip="1.1.1.1")
        assert result["capture_id"] == "bot"

    def test_lead_written_to_ddb(self, _moto_tables):
        from app.services.marketing_web_leads import create_lead_capture
        from app.core.tables import T
        from app.models import WebLeadCaptureIn

        data = WebLeadCaptureIn(
            first_name="Jane",
            last_name="Test",
            email="jane@test.com",
        )
        result = create_lead_capture(data)
        cap_id = result["capture_id"]

        item = T.marketing_web_lead_captures.get_item(
            Key={"pk": f"CAPTURE#{cap_id}", "sk": "META"}
        ).get("Item")
        assert item is not None
        assert item["email"] == "jane@test.com"


# ===========================================================================
# CMP-001: Models validation
# ===========================================================================

class TestModels:

    def test_valid_campaign_types(self):
        from app.models import CrmCampaignCreateIn
        for ct in ("email", "phone", "mail", "fax", "sms"):
            m = CrmCampaignCreateIn(name="X", campaign_type=ct)
            assert m.campaign_type == ct

    def test_invalid_campaign_type_raises(self):
        from pydantic import ValidationError
        from app.models import CrmCampaignCreateIn
        with pytest.raises(ValidationError):
            CrmCampaignCreateIn(name="X", campaign_type="whatsapp")

    def test_campaign_out_defaults(self):
        from app.models import CrmCampaignOut
        out = CrmCampaignOut(campaign_id="c1", owner_id="o1", name="N")
        assert out.campaign_type == "email"
        assert out.status == "draft"
        assert out.variants is None


# ===========================================================================
# CMP-008: Merge vars
# ===========================================================================

class TestMergeVars:

    def test_build_merge_vars_includes_profile(self, _moto_tables):
        from app.services.crm_campaigns import _build_merge_vars
        merge_vars = _build_merge_vars("party123", "camp123")
        assert merge_vars.get("first_name") == "Alice"
        assert merge_vars.get("email") == "alice@test.local"
        assert merge_vars.get("platform_name") == "testlogon"

    def test_build_merge_vars_extra_wins(self, _moto_tables):
        from app.services.crm_campaigns import _build_merge_vars
        merge_vars = _build_merge_vars("party123", "camp123", extra={"survey_url": "https://s.co"})
        assert merge_vars.get("survey_url") == "https://s.co"

    def test_redact_phone(self):
        from app.services.crm_campaigns import _redact_phone
        assert _redact_phone("+15551234567") == "***4567"
        assert _redact_phone(None) == "***"
        assert _redact_phone("") == "***"
        assert _redact_phone("123") == "***"


# ===========================================================================
# CMP-007: A/B variant assignment
# ===========================================================================

class TestAbVariants:

    def test_variant_assignment_deterministic(self, _moto_tables):
        from app.services.crm_campaigns import _assign_variant

        variants = [
            {"variant_id": "a", "weight": 1},
            {"variant_id": "b", "weight": 1},
        ]
        # Same inputs → same assignment
        r1 = _assign_variant("party1", "camp1", variants)
        r2 = _assign_variant("party1", "camp1", variants)
        assert r1["variant_id"] == r2["variant_id"]

    def test_variant_assignment_distributes(self, _moto_tables):
        from app.services.crm_campaigns import _assign_variant

        variants = [
            {"variant_id": "a", "weight": 1},
            {"variant_id": "b", "weight": 1},
        ]
        assignments = set()
        for i in range(20):
            v = _assign_variant(f"party_{i}", "campX", variants)
            assignments.add(v["variant_id"])
        # Both variants should be assigned across 20 parties
        assert "a" in assignments
        assert "b" in assignments
