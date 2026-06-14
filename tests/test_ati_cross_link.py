"""Hermetic offline tests for the ATI (ATS Integration) cross-link bridge.

Covers the ATI-001..ATI-005 *core* deliverable that this stale-base worktree
can build: ``app/services/ats_integration.py`` — candidate<->contact sync and
job<->opportunity link, plus list/unlink and flag gating.

CRITICAL ENVIRONMENT NOTE: this worktree is a STALE base. None of the sibling
clusters (candidates / job_orders / opportunities / party / contacts /
crm_activity_timeline) exist here, and all sibling flags are OFF. Therefore
these tests deliberately exercise the GRACEFUL-DEGRADE path: every link is
created with ``degraded=True`` because the sibling validators/upserts are
absent. This is exactly the behaviour RULE-1/RULE-2 demand — the bridge is the
ATI-owned source of truth and never raises when a sibling is missing.

Isolation (RULE-4): a module-scope autouse fixture creates a moto in-memory
DynamoDB table and binds it onto the FROZEN ``T`` instance via
``object.__setattr__`` (so collaborators that did ``from app.core.tables import
T`` see the moto table), flips the ATI + CND flags on the frozen ``S``, and
restores BOTH on teardown. No TestClient; route handlers driven on a fresh
``asyncio.new_event_loop()``.
"""
from __future__ import annotations

import asyncio
import importlib

import boto3
import pytest

try:
    from moto import mock_aws
except Exception:  # pragma: no cover
    mock_aws = None

from app.core.settings import S
from app.core.tables import T

pytestmark = pytest.mark.skipif(mock_aws is None, reason="moto not installed")


def _make_links_table(ddb):
    return ddb.create_table(
        TableName="ats_integration_links_test",
        BillingMode="PAY_PER_REQUEST",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
    )


@pytest.fixture(scope="module", autouse=True)
def _ati_env():
    """Module-scope moto + frozen T/S binding, fully restored on teardown."""
    if mock_aws is None:  # pragma: no cover
        yield
        return
    ctx = mock_aws()
    ctx.start()
    try:
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        tbl = _make_links_table(ddb)

        # Save originals so we can restore the FROZEN dataclasses exactly.
        from app.core.tables import _FloatSafeTable

        orig_tbl = getattr(T, "ats_integration_links")
        orig_ati = getattr(S, "ats_integration_enabled", False)
        orig_cnd = getattr(S, "candidates_enabled", False)

        object.__setattr__(T, "ats_integration_links", _FloatSafeTable(tbl))
        object.__setattr__(S, "ats_integration_enabled", True)
        # candidates_enabled is the authoritative ATS gate (CND-001); AND-ed
        # with our flag. Set it True so the master gate is ON — but the
        # candidates SERVICE still doesn't exist, so we hit the degrade path.
        object.__setattr__(S, "candidates_enabled", True)

        yield {"table": tbl}

        object.__setattr__(T, "ats_integration_links", orig_tbl)
        object.__setattr__(S, "ats_integration_enabled", orig_ati)
        object.__setattr__(S, "candidates_enabled", orig_cnd)
    finally:
        ctx.stop()


@pytest.fixture()
def ati():
    """Fresh import of the service so it reads the patched frozen handles."""
    mod = importlib.import_module("app.services.ats_integration")
    return mod


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# --------------------------------------------------------------------------
# Service-layer: candidate <-> contact
# --------------------------------------------------------------------------

def test_link_candidate_degrades_when_siblings_absent(ati):
    row = ati.link_candidate_to_contact(owner_sub="rec1", candidate_id="cand_a")
    assert row["link_type"] == "candidate_contact"
    assert row["candidate_id"] == "cand_a"
    assert row["owner_sub"] == "rec1"
    # Siblings absent/flag-off on stale base -> degraded, not raised.
    assert row["degraded"] is True
    assert row["synced"] is False
    assert "candidates" in (row["degraded_reason"] or "")


def test_link_candidate_with_explicit_contact_id(ati):
    row = ati.link_candidate_to_contact(
        owner_sub="rec1", candidate_id="cand_b", contact_id="contact_x"
    )
    assert row["contact_id"] == "contact_x"
    # Candidate validator still absent -> still degraded, but no contact sync needed.
    assert row["degraded"] is True
    assert "candidate" in (row["degraded_reason"] or "")


def test_link_candidate_idempotent_upsert(ati):
    ati.link_candidate_to_contact(owner_sub="rec_idem", candidate_id="cand_same")
    ati.link_candidate_to_contact(owner_sub="rec_idem", candidate_id="cand_same")
    links = ati.list_links("rec_idem")
    cc = links["candidate_contact_links"]
    assert len([l for l in cc if l["candidate_id"] == "cand_same"]) == 1


# --------------------------------------------------------------------------
# Service-layer: job <-> opportunity
# --------------------------------------------------------------------------

def test_link_job_degrades_when_siblings_absent(ati):
    row = ati.link_job_to_opportunity(owner_sub="rec2", job_order_id="job_a")
    assert row["link_type"] == "job_opportunity"
    assert row["job_order_id"] == "job_a"
    assert row["degraded"] is True
    assert row["synced"] is False
    assert "job_orders" in (row["degraded_reason"] or "")


def test_link_job_with_explicit_opportunity_id(ati):
    row = ati.link_job_to_opportunity(
        owner_sub="rec2", job_order_id="job_b", opportunity_id="opp_y"
    )
    assert row["opportunity_id"] == "opp_y"
    assert row["degraded"] is True


# --------------------------------------------------------------------------
# list / unlink
# --------------------------------------------------------------------------

def test_list_links_splits_by_type(ati):
    ati.link_candidate_to_contact(owner_sub="rec3", candidate_id="c1")
    ati.link_job_to_opportunity(owner_sub="rec3", job_order_id="j1")
    out = ati.list_links("rec3")
    assert len(out["candidate_contact_links"]) == 1
    assert len(out["job_opportunity_links"]) == 1
    assert out["count"] == 2


def test_unlink_removes_row_idempotently(ati):
    r = ati.link_candidate_to_contact(owner_sub="rec4", candidate_id="cand_del")
    assert ati.unlink("rec4", "candidate_contact", r["link_id"]) is True
    out = ati.list_links("rec4")
    assert all(l["candidate_id"] != "cand_del" for l in out["candidate_contact_links"])
    # Second unlink is a no-op (delete of missing key) but still returns True.
    assert ati.unlink("rec4", "candidate_contact", r["link_id"]) is True


def test_unlink_rejects_bad_type(ati):
    assert ati.unlink("rec4", "not_a_type", "x") is False


def test_owner_isolation(ati):
    ati.link_candidate_to_contact(owner_sub="ownerA", candidate_id="iso_a")
    ati.link_candidate_to_contact(owner_sub="ownerB", candidate_id="iso_b")
    a = ati.list_links("ownerA")
    b = ati.list_links("ownerB")
    a_ids = {l["candidate_id"] for l in a["candidate_contact_links"]}
    b_ids = {l["candidate_id"] for l in b["candidate_contact_links"]}
    assert "iso_a" in a_ids and "iso_b" not in a_ids
    assert "iso_b" in b_ids and "iso_a" not in b_ids


# --------------------------------------------------------------------------
# Flag matrix (master gate off)
# --------------------------------------------------------------------------

def test_master_gate_off_raises_disabled(ati):
    # Flip OUR flag off; restore after.
    orig = getattr(S, "ats_integration_enabled", False)
    object.__setattr__(S, "ats_integration_enabled", False)
    try:
        assert ati.ats_integration_active() is False
        with pytest.raises(ati.AtsIntegrationDisabled):
            ati.link_candidate_to_contact(owner_sub="rec5", candidate_id="x")
    finally:
        object.__setattr__(S, "ats_integration_enabled", orig)


def test_master_gate_off_when_candidates_flag_off(ati):
    # CND-001 is the authoritative gate — if it's off the whole bridge is off,
    # even with our flag on.
    orig = getattr(S, "candidates_enabled", False)
    object.__setattr__(S, "candidates_enabled", False)
    try:
        assert ati.ats_integration_active() is False
        with pytest.raises(ati.AtsIntegrationDisabled):
            ati.link_job_to_opportunity(owner_sub="rec5", job_order_id="x")
    finally:
        object.__setattr__(S, "candidates_enabled", orig)


# --------------------------------------------------------------------------
# Router layer (direct handler invocation, no TestClient)
# --------------------------------------------------------------------------

def test_router_create_and_list(ati):
    from app.routers import ats_integration as r
    from app.models import AtsCandidateContactLinkIn

    ctx = {"user_sub": "router_user"}
    created = _run(
        r.create_candidate_contact_link(
            AtsCandidateContactLinkIn(candidate_id="rc1"), ctx=ctx
        )
    )
    assert created.candidate_id == "rc1"
    assert created.degraded is True

    listed = _run(r.list_integration_links(ctx=ctx))
    assert listed.count >= 1


def test_router_503_when_gate_off(ati):
    from fastapi import HTTPException
    from app.routers import ats_integration as r
    from app.models import AtsJobOpportunityLinkIn

    orig = getattr(S, "ats_integration_enabled", False)
    object.__setattr__(S, "ats_integration_enabled", False)
    try:
        with pytest.raises(HTTPException) as ei:
            _run(
                r.create_job_opportunity_link(
                    AtsJobOpportunityLinkIn(job_order_id="x"), ctx={"user_sub": "u"}
                )
            )
        assert ei.value.status_code == 503
    finally:
        object.__setattr__(S, "ats_integration_enabled", orig)
