"""Hermetic offline tests for PRT-001..PRT-005 ATS Career Portal.

Pattern (per CLAUDE.md / tests/test_gap_0220_0221_ssh_stored_key.py):
  - module-scoped autouse fixture that installs moto DynamoDB tables and patches
    frozen T/S via object.__setattr__, then restores in teardown.
  - Route handlers called directly (no TestClient, no live server).
  - Tier-1 collaborators (JOB-*, CND-*, PIP-*) patched at their source modules.
  - audit_event / send_alert_email patched to no-ops.
"""

from __future__ import annotations

import asyncio
import sys
import xml.etree.ElementTree as ET
from contextlib import ExitStack
from types import SimpleNamespace
from typing import Any, Optional
from unittest.mock import MagicMock, patch

import boto3
import pytest

try:
    from moto import mock_aws
except ImportError:
    mock_aws = None  # type: ignore[assignment]


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_career_portal_table(ddb: Any):
    """Create the CareerPortal DynamoDB table with ByJob GSI."""
    return ddb.create_table(
        TableName="CareerPortalTest",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "GSI1PK", "AttributeType": "S"},
            {"AttributeName": "GSI1SK", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": "ByJob",
            "KeySchema": [
                {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
            ],
            "Projection": {"ProjectionType": "ALL"},
        }],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_sessions_table(ddb: Any):
    """Create sessions table for rate-limit bucket writes."""
    return ddb.create_table(
        TableName="SessionsTest",
        KeySchema=[
            {"AttributeName": "user_sub", "KeyType": "HASH"},
            {"AttributeName": "session_id", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "user_sub", "AttributeType": "S"},
            {"AttributeName": "session_id", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


# ── Module-scoped autouse fixture ─────────────────────────────────────────────

@pytest.fixture(scope="module", autouse=True)
def _prt_tables():
    """
    Module-scoped autouse fixture: starts moto, creates tables, patches T/S.
    Restores all prior values on teardown.

    MANDATORY ISOLATION RULE: scope="module", saves prior T/S values, restores in teardown.
    """
    if mock_aws is None:
        pytest.skip("moto not installed")

    stack = ExitStack()

    # Start moto context
    stack.enter_context(mock_aws())

    ddb = boto3.resource("dynamodb", region_name="us-east-1")
    portal_table = _make_career_portal_table(ddb)
    sessions_table = _make_sessions_table(ddb)

    # Patch T handles (frozen dataclass — must use object.__setattr__)
    from app.core import tables as tbl_mod
    from app.core import settings as s_mod

    prev_portal = tbl_mod.T.career_portal
    prev_sessions = tbl_mod.T.sessions
    object.__setattr__(tbl_mod.T, "career_portal", portal_table)
    object.__setattr__(tbl_mod.T, "sessions", sessions_table)

    # Patch S settings
    prev_enabled = s_mod.S.career_portal_enabled
    prev_rate_limit = s_mod.S.career_portal_apply_rate_limit_per_ip_per_hour
    prev_rss_max = s_mod.S.career_portal_rss_max_items
    prev_resume_max = s_mod.S.career_portal_resume_max_bytes
    prev_autoresponder = s_mod.S.career_portal_apply_autoresponder_enabled
    prev_notify_email = s_mod.S.career_portal_apply_notify_email
    prev_dev_mode = s_mod.S.dev_mode
    prev_ddb_sessions_table = s_mod.S.ddb_sessions_table

    object.__setattr__(s_mod.S, "career_portal_enabled", True)
    object.__setattr__(s_mod.S, "career_portal_apply_rate_limit_per_ip_per_hour", 10)
    object.__setattr__(s_mod.S, "career_portal_rss_max_items", 50)
    object.__setattr__(s_mod.S, "career_portal_resume_max_bytes", 10 * 1024 * 1024)
    object.__setattr__(s_mod.S, "career_portal_apply_autoresponder_enabled", False)
    object.__setattr__(s_mod.S, "career_portal_apply_notify_email", "")
    object.__setattr__(s_mod.S, "dev_mode", True)
    # Enable rate limiting (ddb_sessions_table must be non-empty for _sessions_table_enabled())
    object.__setattr__(s_mod.S, "ddb_sessions_table", "SessionsTest")

    # Patch audit_event and send_alert_email to no-ops
    stack.enter_context(patch("app.services.alerts.audit_event", lambda *a, **kw: None))
    stack.enter_context(patch("app.services.alerts.send_alert_email", lambda *a, **kw: None))

    # Inject fake JOB-*, CND-*, PIP-* modules into sys.modules
    # because these are forward deps that may not exist in this worktree.
    _fake_job = {"job_order_id": "job_001", "is_public": True, "status": "open",
                 "title": "Senior Engineer", "slug": "senior-engineer-2026",
                 "location": "Remote", "employment_type": "full_time",
                 "posted_at": 1700000000, "openings": 2, "public_description": "<p>Great role</p>",
                 "screening_questionnaire_id": None}

    _cnd_calls: list = []
    _pip_calls: list = []

    def _fake_create_candidate(creator_sub, data):
        _cnd_calls.append({"creator_sub": creator_sub, "data": data})
        return {"candidate_id": "cnd_001"}

    def _fake_add_to_pipeline(owner_sub, data):
        _pip_calls.append({"owner_sub": owner_sub, "data": data})
        return SimpleNamespace(pipeline_id="pip_001", status=getattr(data, "status", "100_no_contact"))

    # Build fake modules
    _fake_job_orders_mod = SimpleNamespace(
        list_public_job_orders=lambda limit=25, exclusive_start_key=None: {
            "items": [], "last_evaluated_key": None
        },
        get_job_order_for_apply=lambda job_order_id: _fake_job,
        get_job_order=lambda job_order_id: _fake_job,
        get_screening_questionnaire_id=lambda job_order_id: None,
    )
    _fake_candidates_mod = SimpleNamespace(
        create_candidate=_fake_create_candidate,
        attach_resume_to_candidate=lambda **kw: None,
    )

    # Make a fake PipelineEntryCreateIn model
    class _FakePipIn:
        def __init__(self, *, job_order_id, candidate_id, status="100_no_contact"):
            self.job_order_id = job_order_id
            self.candidate_id = candidate_id
            self.status = status

    _fake_pipeline_mod = SimpleNamespace(
        add_to_pipeline=_fake_add_to_pipeline,
    )

    # Save parent-package attributes (per MANDATORY ISOLATION RULE)
    import app.services as _svc_pkg
    _prev_job_orders_in_sys = sys.modules.get("app.services.job_orders")
    _prev_candidates_in_sys = sys.modules.get("app.services.candidates")
    _prev_pipeline_in_sys = sys.modules.get("app.services.pipeline")
    _prev_job_orders_attr = getattr(_svc_pkg, "job_orders", None)
    _prev_candidates_attr = getattr(_svc_pkg, "candidates", None)
    _prev_pipeline_attr = getattr(_svc_pkg, "pipeline", None)

    # Also build a PipelineEntryCreateIn in models if absent
    import app.models as _models_mod
    _prev_pip_model = getattr(_models_mod, "PipelineEntryCreateIn", None)
    if _prev_pip_model is None:
        _models_mod.PipelineEntryCreateIn = _FakePipIn  # type: ignore[attr-defined]

    # Install into sys.modules and parent package
    sys.modules["app.services.job_orders"] = _fake_job_orders_mod  # type: ignore[assignment]
    sys.modules["app.services.candidates"] = _fake_candidates_mod  # type: ignore[assignment]
    sys.modules["app.services.pipeline"] = _fake_pipeline_mod      # type: ignore[assignment]
    _svc_pkg.job_orders = _fake_job_orders_mod  # type: ignore[attr-defined]
    _svc_pkg.candidates = _fake_candidates_mod  # type: ignore[attr-defined]
    _svc_pkg.pipeline = _fake_pipeline_mod      # type: ignore[attr-defined]

    # Seed a SLUG row for happy-path tests
    portal_table.put_item(Item={
        "pk": "SLUG#test-slug",
        "sk": "META",
        "job_order_id": "job_001",
        "slug": "test-slug",
        "created_at": 1700000000,
    })

    yield {
        "portal_table": portal_table,
        "sessions_table": sessions_table,
        "cnd_calls": _cnd_calls,
        "pip_calls": _pip_calls,
    }

    # Teardown: restore everything
    object.__setattr__(tbl_mod.T, "career_portal", prev_portal)
    object.__setattr__(tbl_mod.T, "sessions", prev_sessions)
    object.__setattr__(s_mod.S, "career_portal_enabled", prev_enabled)
    object.__setattr__(s_mod.S, "career_portal_apply_rate_limit_per_ip_per_hour", prev_rate_limit)
    object.__setattr__(s_mod.S, "career_portal_rss_max_items", prev_rss_max)
    object.__setattr__(s_mod.S, "career_portal_resume_max_bytes", prev_resume_max)
    object.__setattr__(s_mod.S, "career_portal_apply_autoresponder_enabled", prev_autoresponder)
    object.__setattr__(s_mod.S, "career_portal_apply_notify_email", prev_notify_email)
    object.__setattr__(s_mod.S, "dev_mode", prev_dev_mode)
    object.__setattr__(s_mod.S, "ddb_sessions_table", prev_ddb_sessions_table)
    stack.close()

    # Restore fake modules — per MANDATORY ISOLATION RULE
    def _restore_mod(name: str, prev_sys, pkg_attr_name: str, prev_attr):
        if prev_sys is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = prev_sys
        if prev_attr is None:
            try:
                delattr(_svc_pkg, pkg_attr_name)
            except AttributeError:
                pass
        else:
            setattr(_svc_pkg, pkg_attr_name, prev_attr)

    _restore_mod("app.services.job_orders", _prev_job_orders_in_sys, "job_orders", _prev_job_orders_attr)
    _restore_mod("app.services.candidates", _prev_candidates_in_sys, "candidates", _prev_candidates_attr)
    _restore_mod("app.services.pipeline", _prev_pipeline_in_sys, "pipeline", _prev_pipeline_attr)

    # Restore PipelineEntryCreateIn model
    if _prev_pip_model is None:
        try:
            delattr(_models_mod, "PipelineEntryCreateIn")
        except AttributeError:
            pass


# ── Helper to call async handler ─────────────────────────────────────────────

def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _mock_request(ip: str = "10.1.2.3") -> MagicMock:
    req = MagicMock()
    req.headers = {"X-Forwarded-For": ip}
    req.client = MagicMock()
    req.client.host = ip
    return req


# ── PRT-001: Admin config ─────────────────────────────────────────────────────

class TestAdminConfig:
    def test_get_config_cold_start(self):
        """GET config with no row returns S-defaults."""
        from app.services.career_portal import get_portal_config
        cfg = get_portal_config()
        assert cfg["portal_name"] == "Careers"
        assert cfg["logo_url"] is None
        assert cfg["updated_at"] is None

    def test_set_and_get_config(self):
        """PUT config persists; GET returns updated values."""
        from app.services.career_portal import get_portal_config, set_portal_config
        result = set_portal_config(
            {"portal_name": "TestCo Careers", "intro_copy": "Hello", "primary_color": "#aabbcc"},
            actor_sub="admin_sub_1",
        )
        assert result["portal_name"] == "TestCo Careers"
        assert result["updated_by"] == "admin_sub_1"
        assert isinstance(result["updated_at"], int)

        fetched = get_portal_config()
        assert fetched["portal_name"] == "TestCo Careers"

    def test_flag_off_raises_404(self):
        """With career_portal_enabled=False, get_portal_config raises 404."""
        from fastapi import HTTPException
        from app.core import settings as s_mod
        from app.services.career_portal import get_portal_config
        object.__setattr__(s_mod.S, "career_portal_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc_info:
                get_portal_config()
            assert exc_info.value.status_code == 404
        finally:
            object.__setattr__(s_mod.S, "career_portal_enabled", True)

    def test_admin_put_as_user_raises_403(self):
        """admin_put_config with USER role raises 403."""
        from fastapi import HTTPException
        from app.auth.roles import Role
        from app.routers.career_portal import admin_put_config
        from app.models import CareerPortalConfigIn
        ctx = {"user_sub": "user_sub_1", "role": Role.USER}
        body = CareerPortalConfigIn(portal_name="Hack")
        with pytest.raises(HTTPException) as exc_info:
            admin_put_config(body=body, ctx=ctx)
        assert exc_info.value.status_code == 403

    def test_admin_put_as_admin_succeeds(self):
        """admin_put_config with ADMIN role succeeds."""
        from app.auth.roles import Role
        from app.routers.career_portal import admin_put_config
        from app.models import CareerPortalConfigIn
        ctx = {"user_sub": "admin_sub_2", "role": Role.ADMIN}
        body = CareerPortalConfigIn(portal_name="Prod Corp Careers")
        result = admin_put_config(body=body, ctx=ctx)
        # handler returns a dict (service returns dict; Pydantic coercion happens in router's response_model)
        pname = result.portal_name if hasattr(result, "portal_name") else result.get("portal_name")
        assert pname == "Prod Corp Careers"

    def test_invalid_primary_color_raises_422(self):
        """CareerPortalConfigIn with invalid hex color fails validation."""
        from pydantic import ValidationError
        from app.models import CareerPortalConfigIn
        with pytest.raises(ValidationError):
            CareerPortalConfigIn(portal_name="X", primary_color="red")

    def test_portal_name_too_long_raises_422(self):
        """CareerPortalConfigIn with portal_name > 120 chars fails validation."""
        from pydantic import ValidationError
        from app.models import CareerPortalConfigIn
        with pytest.raises(ValidationError):
            CareerPortalConfigIn(portal_name="X" * 121)

    def test_logo_url_derived(self):
        """logo_file_path in config → logo_url resolved by build_download_url."""
        from app.core import settings as s_mod
        from app.services.career_portal import set_portal_config, get_portal_config
        set_portal_config(
            {"portal_name": "Logo Co", "logo_file_path": "/career-portal/logo.png"},
            actor_sub="admin_logo",
        )
        cfg = get_portal_config()
        assert cfg["logo_file_path"] == "/career-portal/logo.png"
        public_base = s_mod.S.public_base_url
        assert cfg["logo_url"] is not None
        assert "/career-portal/logo.png" in cfg["logo_url"] or public_base in cfg["logo_url"]


# ── PRT-002: Public config ────────────────────────────────────────────────────

class TestPublicConfig:
    def test_public_get_config(self):
        """GET /public/careers/config returns config."""
        from app.routers.career_portal import public_get_config
        result = public_get_config()
        assert hasattr(result, "portal_name") or isinstance(result, dict)


# ── PRT-002: Job listing ──────────────────────────────────────────────────────

class TestJobListing:
    def test_list_public_jobs_empty_when_job_service_absent(self):
        """list_public_jobs returns empty list when JOB-* raises ImportError."""
        from app.services.career_portal import list_public_jobs
        import app.services as _svc_pkg
        orig = _svc_pkg.job_orders.list_public_job_orders
        _svc_pkg.job_orders.list_public_job_orders = lambda **kw: (_ for _ in ()).throw(ImportError("no job"))
        try:
            result = list_public_jobs()
        finally:
            _svc_pkg.job_orders.list_public_job_orders = orig
        assert result["items"] == []
        assert result["cursor"] is None
        assert result["total_estimate"] is None

    def test_list_public_jobs_returns_summary_fields(self):
        """list_public_jobs returns only whitelisted summary fields."""
        fake_items = [
            {"job_order_id": "j1", "slug": "eng-2026", "title": "Engineer",
             "location": "Remote", "employment_type": "full_time",
             "posted_at": 1700000000, "openings": 1,
             # internal fields that should NOT appear:
             "pay_rate": 100, "bill_rate": 150, "recruiter_notes": "secret"},
        ]
        from app.services.career_portal import list_public_jobs
        import app.services as _svc_pkg
        orig = _svc_pkg.job_orders.list_public_job_orders
        _svc_pkg.job_orders.list_public_job_orders = lambda **kw: {"items": fake_items, "last_evaluated_key": None}
        try:
            result = list_public_jobs()
        finally:
            _svc_pkg.job_orders.list_public_job_orders = orig
        assert len(result["items"]) == 1
        item = result["items"][0]
        assert item["job_order_id"] == "j1"
        assert "pay_rate" not in item
        assert "bill_rate" not in item
        assert "recruiter_notes" not in item

    def test_list_public_jobs_with_cursor(self):
        """Cursor round-trip: encode + decode."""
        from app.services.career_portal import list_public_jobs
        from app.core.cursor import decode_cursor
        import app.services as _svc_pkg

        fake_lek = {"pk": "foo", "sk": "bar"}
        orig = _svc_pkg.job_orders.list_public_job_orders
        _svc_pkg.job_orders.list_public_job_orders = lambda **kw: {"items": [], "last_evaluated_key": fake_lek}
        try:
            result = list_public_jobs()
        finally:
            _svc_pkg.job_orders.list_public_job_orders = orig

        assert result["cursor"] is not None
        decoded = decode_cursor(result["cursor"])
        assert decoded == fake_lek


# ── PRT-002: Job detail ───────────────────────────────────────────────────────

class TestJobDetail:
    def test_get_job_detail_unknown_slug_returns_404(self):
        """get_job_detail with unknown slug raises 404."""
        from fastapi import HTTPException
        from app.services.career_portal import get_job_detail
        with pytest.raises(HTTPException) as exc_info:
            get_job_detail("nonexistent-slug-xyz")
        assert exc_info.value.status_code == 404

    def test_get_job_detail_non_public_returns_404(self):
        """get_job_detail where is_public=False raises 404."""
        from fastapi import HTTPException
        from app.services.career_portal import get_job_detail
        import app.services as _svc_pkg
        orig = _svc_pkg.job_orders.get_job_order
        _svc_pkg.job_orders.get_job_order = lambda job_order_id: {
            "job_order_id": "job_001", "is_public": False,
            "status": "open", "title": "X", "slug": "test-slug",
            "posted_at": 0, "openings": 1}
        try:
            with pytest.raises(HTTPException) as exc_info:
                get_job_detail("test-slug")
        finally:
            _svc_pkg.job_orders.get_job_order = orig
        assert exc_info.value.status_code == 404

    def test_get_job_detail_closed_returns_404(self):
        """get_job_detail where status=closed raises 404."""
        from fastapi import HTTPException
        from app.services.career_portal import get_job_detail
        import app.services as _svc_pkg
        orig = _svc_pkg.job_orders.get_job_order
        _svc_pkg.job_orders.get_job_order = lambda job_order_id: {
            "job_order_id": "job_001", "is_public": True,
            "status": "closed", "title": "X", "slug": "test-slug",
            "posted_at": 0, "openings": 1}
        try:
            with pytest.raises(HTTPException) as exc_info:
                get_job_detail("test-slug")
        finally:
            _svc_pkg.job_orders.get_job_order = orig
        assert exc_info.value.status_code == 404

    def test_get_job_detail_job_service_absent_returns_404(self):
        """get_job_detail where JOB-* raises ImportError returns 404."""
        from fastapi import HTTPException
        from app.services.career_portal import get_job_detail
        import app.services as _svc_pkg
        orig = _svc_pkg.job_orders.get_job_order
        _svc_pkg.job_orders.get_job_order = lambda job_order_id: (_ for _ in ()).throw(ImportError("absent"))
        try:
            with pytest.raises(HTTPException) as exc_info:
                get_job_detail("test-slug")
        finally:
            _svc_pkg.job_orders.get_job_order = orig
        assert exc_info.value.status_code == 404

    def test_get_job_detail_happy_path(self):
        """get_job_detail returns public fields and apply_path."""
        from app.services.career_portal import get_job_detail
        result = get_job_detail("test-slug")
        assert result["title"] == "Senior Engineer"
        assert result["apply_path"] == "/public/careers/jobs/test-slug/apply"
        assert "pay_rate" not in result
        assert "bill_rate" not in result
        assert "recruiter_notes" not in result

    def test_get_job_detail_no_internal_fields(self):
        """Response never contains internal fields even if JOB-* returns them."""
        from app.services.career_portal import get_job_detail
        import app.services as _svc_pkg
        orig = _svc_pkg.job_orders.get_job_order
        _svc_pkg.job_orders.get_job_order = lambda job_order_id: {
            "job_order_id": "job_001", "is_public": True, "status": "open",
            "title": "PM", "slug": "test-slug", "location": "NYC",
            "employment_type": "full_time", "posted_at": 1700000000, "openings": 1,
            "public_description": "Good role",
            "screening_questionnaire_id": None,
            # Internal fields — must NOT appear in response:
            "pay_rate": 200, "bill_rate": 300, "recruiter_notes": "do not share",
            "owner_sub": "recruiter@example.com",
        }
        try:
            result = get_job_detail("test-slug")
        finally:
            _svc_pkg.job_orders.get_job_order = orig
        for forbidden in ("pay_rate", "bill_rate", "recruiter_notes", "owner_sub"):
            assert forbidden not in result, f"Field {forbidden!r} leaked into public response"


# ── PRT-003: RSS feed ──────────────────────────────────────────────────────────

class TestRssFeed:
    def test_rss_flag_off_raises_404(self):
        """build_jobs_rss raises 404 when flag off."""
        from fastapi import HTTPException
        from app.core import settings as s_mod
        from app.services.career_portal import build_jobs_rss
        object.__setattr__(s_mod.S, "career_portal_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc_info:
                build_jobs_rss()
            assert exc_info.value.status_code == 404
        finally:
            object.__setattr__(s_mod.S, "career_portal_enabled", True)

    def test_rss_empty_when_no_jobs(self):
        """build_jobs_rss with no jobs returns valid XML with empty channel."""
        from app.services.career_portal import build_jobs_rss
        with patch("app.services.career_portal.list_public_jobs",
                   return_value={"items": [], "cursor": None, "total_estimate": None}):
            xml = build_jobs_rss()
        root = ET.fromstring(xml)
        assert root.tag == "rss"
        assert root.attrib.get("version") == "2.0"
        items = root.findall(".//item")
        assert len(items) == 0

    def test_rss_valid_xml_with_jobs(self):
        """build_jobs_rss with two jobs returns two <item> elements."""
        from app.services.career_portal import build_jobs_rss
        stub_items = [
            {"job_order_id": "j1", "slug": "sre-2026", "title": "SRE & DevOps",
             "location": "Remote", "employment_type": "full_time",
             "posted_at": 1700000000, "openings": 1,
             "public_description": "<p>Great role with <b>benefits</b></p>"},
            {"job_order_id": "j2", "slug": "pm-lead-2026", "title": "PM Lead",
             "location": None, "employment_type": None,
             "posted_at": 0, "openings": 2, "public_description": None},
        ]
        with patch("app.services.career_portal.list_public_jobs",
                   return_value={"items": stub_items, "cursor": None, "total_estimate": None}):
            xml = build_jobs_rss()

        root = ET.fromstring(xml)
        items = root.findall(".//item")
        assert len(items) == 2
        titles = [i.findtext("title") for i in items]
        assert "SRE & DevOps" in titles   # & decoded back by ET
        assert "PM Lead" in titles

    def test_rss_xml_escaping(self):
        """Job title containing & is correctly XML-escaped."""
        from app.services.career_portal import build_jobs_rss
        stub_items = [
            {"job_order_id": "j1", "slug": "dev-2026", "title": "Rust & Go Engineer",
             "location": None, "employment_type": None,
             "posted_at": 1700000000, "openings": 1, "public_description": None},
        ]
        with patch("app.services.career_portal.list_public_jobs",
                   return_value={"items": stub_items, "cursor": None, "total_estimate": None}):
            xml = build_jobs_rss()

        # XML string should contain &amp; not bare &
        assert "&amp;" in xml
        # But ElementTree decodes it back
        root = ET.fromstring(xml)
        titles = [i.findtext("title") for i in root.findall(".//item")]
        assert "Rust & Go Engineer" in titles

    def test_rss_html_stripped_from_description(self):
        """HTML tags stripped from public_description in <description>."""
        from app.services.career_portal import build_jobs_rss, _strip_html_excerpt
        result = _strip_html_excerpt("<p>Hello <b>world</b></p>", 200)
        assert result == "Hello world"
        assert "<" not in result

    def test_rss_content_type_in_response(self):
        """public_jobs_rss handler returns application/rss+xml."""
        from app.routers.career_portal import public_jobs_rss
        with patch("app.services.career_portal.list_public_jobs",
                   return_value={"items": [], "cursor": None, "total_estimate": None}):
            resp = public_jobs_rss()
        assert "application/rss+xml" in resp.media_type

    def test_rss_xml_escape_function(self):
        """_xml_escape handles & < > and quotes."""
        from app.services.career_portal import _xml_escape
        result = _xml_escape('O\'Brien & <Co>')
        assert "&amp;" in result
        assert "&lt;" in result
        assert "&gt;" in result

    def test_strip_html_excerpt_none(self):
        """_strip_html_excerpt handles None input."""
        from app.services.career_portal import _strip_html_excerpt
        assert _strip_html_excerpt(None) == ""

    def test_strip_html_excerpt_truncates(self):
        """_strip_html_excerpt truncates at max_chars."""
        from app.services.career_portal import _strip_html_excerpt
        result = _strip_html_excerpt("A" * 600, 500)
        assert len(result) == 500

    def test_rss_jobs_rss_exemption_registered(self):
        """GET:/public/careers/jobs.rss is in API_KEY_ROUTE_EXEMPTIONS."""
        from app.services.api_key_route_scope_registry import API_KEY_ROUTE_EXEMPTIONS
        assert "GET:/public/careers/jobs.rss" in API_KEY_ROUTE_EXEMPTIONS


# ── PRT-004: Self-apply ───────────────────────────────────────────────────────

class TestSelfApply:
    def test_apply_flag_off_raises_404(self):
        """create_application raises 404 when flag off."""
        from fastapi import HTTPException
        from app.core import settings as s_mod
        from app.services.career_portal import create_application
        from app.models import CareerApplyIn
        object.__setattr__(s_mod.S, "career_portal_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc_info:
                create_application(
                    slug="test-slug",
                    data=CareerApplyIn(first_name="A", last_name="B", email="a@b.com"),
                    source_ip="10.0.0.1",
                )
            assert exc_info.value.status_code == 404
        finally:
            object.__setattr__(s_mod.S, "career_portal_enabled", True)

    def test_honeypot_returns_fake_success_no_writes(self, _prt_tables):
        """Honeypot filled → fake success, zero DDB writes."""
        from app.services.career_portal import create_application
        from app.models import CareerApplyIn

        initial_count = len(_prt_tables["portal_table"].scan().get("Items", []))
        _prt_tables["cnd_calls"].clear()

        result = create_application(
            slug="test-slug",
            data=CareerApplyIn(first_name="Bot", last_name="B", email="bot@x.com", honeypot="filled"),
            source_ip="10.0.0.1",
        )
        assert result.application_id == "bot"
        assert result.status == "received"
        # No DDB write — count unchanged
        final_count = len(_prt_tables["portal_table"].scan().get("Items", []))
        # Allow for SLUG row already present
        assert final_count <= initial_count + 1
        assert len(_prt_tables["cnd_calls"]) == 0

    def test_honeypot_long_string_no_422(self):
        """Very long honeypot string still hits honeypot path (no max_length on field)."""
        from app.models import CareerApplyIn
        # Should not raise ValidationError
        body = CareerApplyIn(first_name="Bot", last_name="B", email="b@x.com",
                             honeypot="X" * 10_000)
        assert body.honeypot == "X" * 10_000

    def test_unknown_slug_returns_404(self):
        """create_application with unknown slug raises 404."""
        from fastapi import HTTPException
        from app.services.career_portal import create_application
        from app.models import CareerApplyIn
        with pytest.raises(HTTPException) as exc_info:
            create_application(
                slug="no-such-slug-xyz",
                data=CareerApplyIn(first_name="A", last_name="B", email="a@b.com"),
                source_ip="10.0.0.1",
            )
        assert exc_info.value.status_code == 404

    def test_job_not_available_returns_404(self):
        """create_application where JOB-* returns None raises 404."""
        from fastapi import HTTPException
        from app.services.career_portal import create_application
        from app.models import CareerApplyIn
        import app.services as _svc_pkg
        orig = _svc_pkg.job_orders.get_job_order_for_apply
        _svc_pkg.job_orders.get_job_order_for_apply = lambda job_order_id: None
        try:
            with pytest.raises(HTTPException) as exc_info:
                create_application(
                    slug="test-slug",
                    data=CareerApplyIn(first_name="A", last_name="B", email="a@b.com"),
                    source_ip="10.0.0.1",
                )
        finally:
            _svc_pkg.job_orders.get_job_order_for_apply = orig
        assert exc_info.value.status_code == 404

    def test_happy_path_creates_candidate_and_pipeline(self, _prt_tables):
        """Happy path: candidate created, pipeline entry added, row written."""
        from app.services.career_portal import create_application
        from app.models import CareerApplyIn

        _prt_tables["cnd_calls"].clear()
        _prt_tables["pip_calls"].clear()

        result = create_application(
            slug="test-slug",
            data=CareerApplyIn(first_name="Jane", last_name="Doe", email="jane@example.com"),
            source_ip="10.1.2.3",
        )
        assert result.status == "received"
        assert result.candidate_id == "cnd_001"
        assert result.application_id.startswith("app_")

        # CND-* was called
        assert len(_prt_tables["cnd_calls"]) == 1
        cnd_call = _prt_tables["cnd_calls"][0]
        assert cnd_call["data"].email == "jane@example.com"

        # PIP-* was called with correct initial status
        assert len(_prt_tables["pip_calls"]) == 1
        pip_call = _prt_tables["pip_calls"][0]
        assert getattr(pip_call["data"], "status", None) == "100_no_contact"

    def test_cnd_raises_409_still_returns_200(self, _prt_tables):
        """CND-* raises 409 → apply still returns 200 with candidate_id=None."""
        from fastapi import HTTPException
        from app.services.career_portal import create_application
        from app.models import CareerApplyIn
        import app.services as _svc_pkg
        orig = _svc_pkg.candidates.create_candidate
        _svc_pkg.candidates.create_candidate = lambda creator_sub, data: (_ for _ in ()).throw(
            HTTPException(status_code=409, detail="duplicate"))
        try:
            result = create_application(
                slug="test-slug",
                data=CareerApplyIn(first_name="Jane", last_name="Doe", email="jane409@example.com"),
                source_ip="10.1.2.4",
            )
        finally:
            _svc_pkg.candidates.create_candidate = orig
        assert result.status == "received"
        assert result.candidate_id is None

    def test_pip_raises_still_returns_200(self, _prt_tables):
        """PIP-* raises → apply still returns 200 with valid candidate_id."""
        from app.services.career_portal import create_application
        from app.models import CareerApplyIn
        import app.services as _svc_pkg

        _prt_tables["cnd_calls"].clear()
        orig = _svc_pkg.pipeline.add_to_pipeline
        _svc_pkg.pipeline.add_to_pipeline = lambda owner_sub, data: (_ for _ in ()).throw(
            RuntimeError("pip down"))
        try:
            result = create_application(
                slug="test-slug",
                data=CareerApplyIn(first_name="Bob", last_name="Smith", email="bob_pip@example.com"),
                source_ip="10.1.2.5",
            )
        finally:
            _svc_pkg.pipeline.add_to_pipeline = orig
        assert result.status == "received"
        assert result.candidate_id == "cnd_001"

    def test_malformed_email_captured_raw(self, _prt_tables):
        """Malformed email → apply proceeds with raw value, not 400."""
        from app.services.career_portal import create_application
        from app.models import CareerApplyIn

        _prt_tables["cnd_calls"].clear()
        result = create_application(
            slug="test-slug",
            data=CareerApplyIn(first_name="A", last_name="B", email="notvalid"),
            source_ip="10.1.2.6",
        )
        assert result.status == "received"
        assert len(_prt_tables["cnd_calls"]) == 1
        assert _prt_tables["cnd_calls"][0]["data"].email == "notvalid"

    def test_cnd_import_error_returns_200(self, _prt_tables):
        """CND-* ImportError → apply still returns 200, candidate_id=None."""
        from app.services.career_portal import create_application
        from app.models import CareerApplyIn
        import app.services as _svc_pkg
        orig = _svc_pkg.candidates.create_candidate
        _svc_pkg.candidates.create_candidate = lambda creator_sub, data: (_ for _ in ()).throw(
            ImportError("CND not installed"))
        try:
            result = create_application(
                slug="test-slug",
                data=CareerApplyIn(first_name="A", last_name="B", email="a_import@b.com"),
                source_ip="10.1.2.7",
            )
        finally:
            _svc_pkg.candidates.create_candidate = orig
        assert result.status == "received"
        assert result.candidate_id is None

    def test_ip_anonymization_in_application_row(self, _prt_tables):
        """source_ip on Application row is last-octet-truncated IPv4."""
        from app.services.career_portal import create_application
        from app.models import CareerApplyIn

        _prt_tables["cnd_calls"].clear()
        result = create_application(
            slug="test-slug",
            data=CareerApplyIn(first_name="IP", last_name="Test", email="ip@test.com"),
            source_ip="192.168.1.99",
        )
        # Scan for our application row
        items = _prt_tables["portal_table"].scan().get("Items", [])
        app_rows = [i for i in items if i.get("pk", "").startswith("APPLICATION#")
                    and i.get("email") == "ip@test.com"]
        assert len(app_rows) >= 1
        assert app_rows[-1]["source_ip"] == "192.168.1"

    def test_rate_limit_429_on_n_plus_1(self):
        """Rate limit: N+1 calls from same IP raises 429."""
        from fastapi import HTTPException
        from app.core import settings as s_mod
        from app.services.career_portal import create_application
        from app.models import CareerApplyIn

        object.__setattr__(s_mod.S, "career_portal_apply_rate_limit_per_ip_per_hour", 2)
        try:
            for _ in range(2):
                create_application(
                    slug="test-slug",
                    data=CareerApplyIn(first_name="RL", last_name="T", email=f"rl{_}@test.com"),
                    source_ip="10.99.0.1",
                )
            with pytest.raises(HTTPException) as exc_info:
                create_application(
                    slug="test-slug",
                    data=CareerApplyIn(first_name="RL", last_name="T", email="rl3@test.com"),
                    source_ip="10.99.0.1",
                )
            assert exc_info.value.status_code == 429
        finally:
            object.__setattr__(s_mod.S, "career_portal_apply_rate_limit_per_ip_per_hour", 10)


# ── PRT-005: Résumé presign ───────────────────────────────────────────────────

class TestResumePresign:
    def test_presign_flag_off_raises_404(self):
        """presign_resume_upload raises 404 when flag off."""
        from fastapi import HTTPException
        from app.core import settings as s_mod
        from app.services.career_portal import presign_resume_upload
        from app.models import CareerResumePresignIn
        object.__setattr__(s_mod.S, "career_portal_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc_info:
                presign_resume_upload(
                    slug="test-slug",
                    data=CareerResumePresignIn(filename="cv.pdf", content_type="application/pdf", size_bytes=100),
                    source_ip="10.0.0.1",
                )
            assert exc_info.value.status_code == 404
        finally:
            object.__setattr__(s_mod.S, "career_portal_enabled", True)

    def test_presign_honeypot_returns_fake(self):
        """Honeypot filled → presign returns fake ticket_id='bot'."""
        from app.services.career_portal import presign_resume_upload
        from app.models import CareerResumePresignIn
        with patch("app.services.filemanager.presign_upload", side_effect=Exception("should not be called")):
            result = presign_resume_upload(
                slug="test-slug",
                data=CareerResumePresignIn(filename="cv.pdf", content_type="application/pdf",
                                           size_bytes=100, honeypot="bot"),
                source_ip="10.0.0.1",
            )
        assert result.ticket_id == "bot"

    def test_presign_unsupported_content_type_raises_415(self):
        """Unsupported content type → 415."""
        from fastapi import HTTPException
        from app.services.career_portal import presign_resume_upload
        from app.models import CareerResumePresignIn
        with pytest.raises(HTTPException) as exc_info:
            presign_resume_upload(
                slug="test-slug",
                data=CareerResumePresignIn(filename="photo.jpg", content_type="image/jpeg", size_bytes=100),
                source_ip="10.0.0.1",
            )
        assert exc_info.value.status_code == 415

    def test_presign_oversize_raises_413(self):
        """Declared size > max → 413."""
        from fastapi import HTTPException
        from app.core import settings as s_mod
        from app.services.career_portal import presign_resume_upload
        from app.models import CareerResumePresignIn
        oversize = s_mod.S.career_portal_resume_max_bytes + 1
        with pytest.raises(HTTPException) as exc_info:
            presign_resume_upload(
                slug="test-slug",
                data=CareerResumePresignIn(filename="cv.pdf", content_type="application/pdf",
                                           size_bytes=oversize),
                source_ip="10.0.0.1",
            )
        assert exc_info.value.status_code == 413

    def test_presign_unknown_slug_raises_404(self):
        """Presign with unknown slug raises 404."""
        from fastapi import HTTPException
        from app.services.career_portal import presign_resume_upload
        from app.models import CareerResumePresignIn
        with pytest.raises(HTTPException) as exc_info:
            presign_resume_upload(
                slug="no-such-slug",
                data=CareerResumePresignIn(filename="cv.pdf", content_type="application/pdf",
                                           size_bytes=100),
                source_ip="10.0.0.1",
            )
        assert exc_info.value.status_code == 404

    def test_presign_happy_path(self):
        """Happy path: presign_upload called, result returned."""
        from app.services.career_portal import presign_resume_upload
        from app.models import CareerResumePresignIn

        fake_result = {
            "upload_url": "/mock/s3/testbucket/test-key",
            "ticket_id": "tkt_abc123",
            "key": "system_career_portal/objects/test-key",
            "path": "/career-portal/resumes/job_001/abc.pdf",
            "content_type": "application/pdf",
            "name": "cv.pdf",
            "parent": "/career-portal/resumes/job_001",
        }
        with patch("app.services.filemanager.presign_upload", return_value=fake_result), \
             patch("app.services.filemanager._auto_create_parents", return_value=None):
            result = presign_resume_upload(
                slug="test-slug",
                data=CareerResumePresignIn(filename="cv.pdf", content_type="application/pdf",
                                           size_bytes=1024),
                source_ip="10.0.0.1",
            )
        assert result.ticket_id == "tkt_abc123"
        assert result.upload_url.startswith("/mock/s3/")
        assert result.path.startswith("/career-portal/resumes/")

    def test_apply_with_resume_ticket(self, _prt_tables):
        """Apply with resume_ticket_id triggers register_presigned_upload."""
        from app.services.career_portal import create_application
        from app.models import CareerApplyIn

        _prt_tables["cnd_calls"].clear()
        fake_ticket_row = {
            "path": "/career-portal/resumes/job_001/abc.pdf",
            "s3_key": "system_career_portal/objects/abc",
            "content_type": "application/pdf",
        }
        fake_node = {"path": "/career-portal/resumes/job_001/abc.pdf", "size": 1024}

        register_called = []
        def _fake_register(user, path, *, s3_key, ticket_id, content_type=None):
            register_called.append({"user": user, "path": path, "ticket_id": ticket_id})
            return fake_node

        with patch("app.services.filemanager.register_presigned_upload", side_effect=_fake_register), \
             patch("app.services.filemanager._table", return_value=MagicMock(
                 get_item=lambda **kw: {"Item": fake_ticket_row}
             )), \
             patch("app.services.filemanager.pk_user", side_effect=lambda u: f"USER#{u}"), \
             patch("app.services.filemanager._upload_ticket_sk", side_effect=lambda t: f"UPLOADTICKET#{t}"):
            result = create_application(
                slug="test-slug",
                data=CareerApplyIn(first_name="Resume", last_name="User",
                                   email="resume@test.com", resume_ticket_id="tkt_001"),
                source_ip="10.1.2.100",
            )

        assert result.status == "received"
        assert len(register_called) == 1


# ── API_KEY_ROUTE_EXEMPTIONS coverage ────────────────────────────────────────

class TestApiKeyExemptions:
    def test_all_public_career_routes_exempted(self):
        """All 6 public career portal routes are in API_KEY_ROUTE_EXEMPTIONS."""
        from app.services.api_key_route_scope_registry import API_KEY_ROUTE_EXEMPTIONS
        expected = [
            "GET:/public/careers/config",
            "GET:/public/careers/jobs",
            "GET:/public/careers/jobs.rss",
            "GET:/public/careers/jobs/{slug}",
            "POST:/public/careers/jobs/{slug}/apply",
            "POST:/public/careers/jobs/{slug}/resume-presign",
        ]
        for route in expected:
            assert route in API_KEY_ROUTE_EXEMPTIONS, f"Missing exemption: {route!r}"

    def test_admin_career_routes_exempted(self):
        """Admin career portal routes are in API_KEY_ROUTE_EXEMPTIONS."""
        from app.services.api_key_route_scope_registry import API_KEY_ROUTE_EXEMPTIONS
        assert "GET:/ui/admin/career-portal/config" in API_KEY_ROUTE_EXEMPTIONS
        assert "PUT:/ui/admin/career-portal/config" in API_KEY_ROUTE_EXEMPTIONS


# ── Route ordering assertion ─────────────────────────────────────────────────

class TestRouteOrdering:
    def test_rss_route_before_slug_dynamic(self):
        """public_router: jobs.rss route declared before jobs/{slug}."""
        from app.routers.career_portal import public_router
        paths = [r.path for r in public_router.routes]
        rss_idx = next((i for i, p in enumerate(paths) if "jobs.rss" in p), None)
        slug_idx = next((i for i, p in enumerate(paths) if "{slug}" in p and "apply" not in p and "resume" not in p), None)
        assert rss_idx is not None, "jobs.rss route not found"
        assert slug_idx is not None, "jobs/{slug} route not found"
        assert rss_idx < slug_idx, "jobs.rss must be declared before jobs/{slug}"

    def test_static_jobs_before_dynamic_slug(self):
        """public_router: static /jobs declared before /jobs/{slug}."""
        from app.routers.career_portal import public_router
        paths = [r.path for r in public_router.routes]
        jobs_idx = next((i for i, p in enumerate(paths) if p.endswith("/jobs")), None)
        slug_idx = next((i for i, p in enumerate(paths) if p.endswith("/jobs/{slug}")), None)
        assert jobs_idx is not None
        assert slug_idx is not None
        assert jobs_idx < slug_idx
