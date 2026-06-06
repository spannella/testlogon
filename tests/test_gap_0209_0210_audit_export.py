"""Regression tests for GAP-0209 (PDF audit export format) and GAP-0210
(scheduled / recurring audit export reports). Both are FIN-016 extensions that
share ``app/routers/audit_export.py`` and ``app/services/audit_export_pipeline``.

GAP-0209 fails-before: ``POST /ui/admin/audit-exports`` rejects ``format=pdf``
(``app/routers/audit_export.py`` validated only ``("csv", "ndjson")``), and the
pipeline had no PDF branch, so no ``%PDF`` document could ever be produced.
Passes-after: ``pdf`` is accepted and the pipeline renders a valid multi-page
audit-grade PDF (cover page + sequential rows + per-page running SHA-256).

GAP-0210 fails-before: no ``audit_export_schedule`` service, no ``/schedules``
endpoints, no ``SCHEDULE#`` rows, no ``next_run_at`` index, no runner.
Passes-after: schedule CRUD works and ``run_due_schedules`` spawns export jobs
for due schedules.

Fully offline AND hermetic (mirrors ``tests/test_gap_0192_export_receipts_zip``).
We do NOT rely on global ``mock_aws`` interception — the app binds
``app.core.tables.T`` (a frozen dataclass of boto3 ``Table`` proxies) at import
time, so if any earlier test imported the app those handles were created outside
a mock context and moto can no longer intercept them (they would fall through to
REAL AWS). We instead create a moto-backed ``audit_exports`` table inside an
active ``mock_aws`` context and monkeypatch the *exact* handle the code path uses
(``T.audit_exports`` via ``object.__setattr__`` since ``T`` is frozen), restoring
it on teardown. ``S`` is also frozen → patched via ``object.__setattr__``. The
event source (``_merge_sorted_events``) is stubbed so the tests never touch any
other table.
"""
from __future__ import annotations

import base64

import boto3
import pytest

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto must be installed
    mock_aws = None

pytestmark = pytest.mark.skipif(mock_aws is None, reason="moto is not installed")

_REGION = "us-east-1"
_TABLE = "audit_exports_gap_0209_0210_test"
_ROOT = "root.admin@testdev.local"


def _create_table(ddb):
    ddb.create_table(
        TableName=_TABLE,
        KeySchema=[
            {"AttributeName": "export_id", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "export_id", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "created_by", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
            {"AttributeName": "GSI1PK", "AttributeType": "S"},
            {"AttributeName": "GSI1SK", "AttributeType": "N"},
        ],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[
            {
                "IndexName": "user-created-index",
                "KeySchema": [
                    {"AttributeName": "created_by", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "schedules-due-index",
                "KeySchema": [
                    {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
    )


def _make_events(n: int, *, with_amounts: bool = False):
    from app.services.audit_export import UnifiedAuditEvent

    events = []
    for i in range(n):
        events.append(
            UnifiedAuditEvent(
                event_id=f"evt_{i}",
                event_type="billing",
                event_action="charge.succeeded",
                timestamp="2026-01-01T00:00:00Z",
                timestamp_unix=1_700_000_000 + i,
                actor_user_id=f"user{i}@example.com",
                actor_role="user",
                outcome="success",
                metadata={"amount_cents": 100 + i} if with_amounts else {},
            )
        )
    return events


def _wire(monkeypatch, request, ddb, *, events):
    """Point the audit-export code path at the moto-backed table and stub the
    event source so the tests are deterministic and never touch other tables."""
    from app.core import tables as tables_mod
    from app.core.tables import _FloatSafeTable
    from app.services import audit_export_pipeline as pipe
    from app.services import audit_export_schedule as sch

    # Force dev mode (inline processing path) on the frozen settings singleton.
    object.__setattr__(pipe.S, "dev_mode", True)

    # Swap the frozen global T.audit_exports onto the moto table; restore after.
    T = tables_mod.T
    wrapped = _FloatSafeTable(ddb.Table(_TABLE))
    saved = T.audit_exports

    def _restore():
        object.__setattr__(T, "audit_exports", saved)

    object.__setattr__(T, "audit_exports", wrapped)
    request.addfinalizer(_restore)

    # Stub the event source so we control exactly which events are exported and
    # avoid querying the (unmocked) per-category source tables.
    def _fake_merge(categories, from_ts, to_ts, actor=None, target=None,
                    event_actions=None, limit=10_000_000):
        for ev in events[:limit]:
            yield ev

    monkeypatch.setattr(pipe, "_merge_sorted_events", _fake_merge)
    return pipe, sch


# ---------------------------------------------------------------------------
# GAP-0209: PDF export format
# ---------------------------------------------------------------------------

@mock_aws()
def test_router_accepts_pdf_format(monkeypatch, request):
    """Fails-before: router rejected ``format=pdf`` with HTTP 400.
    Passes-after: validation accepts it and a job is created + completed."""
    import asyncio

    ddb = boto3.resource("dynamodb", region_name=_REGION)
    _create_table(ddb)
    _wire(monkeypatch, request, ddb, events=_make_events(3, with_amounts=True))

    from app.routers import audit_export as router_mod
    from app.auth.roles import Role
    from app.core.time import now_ts

    ctx = {"user_sub": _ROOT, "role": Role.ROOT}
    ts = now_ts()
    out = asyncio.new_event_loop().run_until_complete(
        router_mod.create_audit_export(
            {"categories": ["billing"], "format": "pdf",
             "from_date": ts - 3600, "to_date": ts},
            ctx=ctx,
        )
    )
    assert out["format"] == "pdf"
    assert out["status"] == "completed"
    assert out["export_id"].startswith("exp_")


@mock_aws()
def test_router_rejects_unknown_format(monkeypatch, request):
    """Sanity: a bogus format is still rejected with 400 (not silently PDF)."""
    import asyncio
    from fastapi import HTTPException

    ddb = boto3.resource("dynamodb", region_name=_REGION)
    _create_table(ddb)
    _wire(monkeypatch, request, ddb, events=_make_events(1))

    from app.routers import audit_export as router_mod
    from app.auth.roles import Role
    from app.core.time import now_ts

    ctx = {"user_sub": _ROOT, "role": Role.ROOT}
    ts = now_ts()
    with pytest.raises(HTTPException) as ei:
        asyncio.new_event_loop().run_until_complete(
            router_mod.create_audit_export(
                {"categories": ["billing"], "format": "xlsx",
                 "from_date": ts - 3600, "to_date": ts},
                ctx=ctx,
            )
        )
    assert ei.value.status_code == 400


@mock_aws()
def test_pdf_download_returns_valid_pdf(monkeypatch, request):
    """Fails-before: no PDF could be produced or downloaded.
    Passes-after: the download endpoint serves application/pdf with %PDF magic
    bytes, multiple pages (cover + data), and a tamper-evident SHA-256 footer."""
    import asyncio

    ddb = boto3.resource("dynamodb", region_name=_REGION)
    _create_table(ddb)
    # Enough events to force more than one data page (cover + >=2 data pages).
    pipe, _ = _wire(monkeypatch, request, ddb, events=_make_events(40, with_amounts=True))

    from app.routers import audit_export as router_mod
    from app.auth.roles import Role
    from app.core.time import now_ts

    ctx = {"user_sub": _ROOT, "role": Role.ROOT}
    ts = now_ts()
    created = asyncio.new_event_loop().run_until_complete(
        router_mod.create_audit_export(
            {"categories": ["billing"], "format": "pdf",
             "from_date": ts - 3600, "to_date": ts},
            ctx=ctx,
        )
    )
    export_id = created["export_id"]

    resp = asyncio.new_event_loop().run_until_complete(
        router_mod.download_audit_export(export_id, ctx=ctx)
    )
    assert resp.media_type == "application/pdf"
    assert resp.body[:4] == b"%PDF"
    assert resp.body.strip().endswith(b"%%EOF")
    # Cover page + at least two data pages for 40 rows at 28/page.
    assert resp.body.count(b"/Type /Page ") >= 3
    # Tamper-evident running SHA-256 footer present.
    assert b"Cumulative row SHA-256" in resp.body
    # Page subtotals present for billing amounts.
    assert b"Page subtotal" in resp.body


@mock_aws()
def test_render_pdf_empty_events(monkeypatch, request):
    """An export with zero events still yields a structurally valid PDF."""
    ddb = boto3.resource("dynamodb", region_name=_REGION)
    _create_table(ddb)
    pipe, _ = _wire(monkeypatch, request, ddb, events=[])

    pdf = pipe._render_audit_pdf(
        [], "exp_empty",
        {"created_by": _ROOT, "from_date": 1, "to_date": 2, "categories": ["billing"]},
        "deadbeef",
    )
    assert pdf[:4] == b"%PDF"
    assert pdf.strip().endswith(b"%%EOF")
    # Parens are PDF-escaped in the content stream.
    assert b"no events in range" in pdf
    # Cover page + one empty data page.
    assert pdf.count(b"/Type /Page ") == 2


@mock_aws()
def test_csv_still_works_after_pdf_change(monkeypatch, request):
    """Regression guard: CSV format unaffected by the PDF branch addition."""
    import asyncio

    ddb = boto3.resource("dynamodb", region_name=_REGION)
    _create_table(ddb)
    _wire(monkeypatch, request, ddb, events=_make_events(2))

    from app.routers import audit_export as router_mod
    from app.auth.roles import Role
    from app.core.time import now_ts

    ctx = {"user_sub": _ROOT, "role": Role.ROOT}
    ts = now_ts()
    created = asyncio.new_event_loop().run_until_complete(
        router_mod.create_audit_export(
            {"categories": ["billing"], "format": "csv",
             "from_date": ts - 3600, "to_date": ts},
            ctx=ctx,
        )
    )
    resp = asyncio.new_event_loop().run_until_complete(
        router_mod.download_audit_export(created["export_id"], ctx=ctx)
    )
    assert resp.media_type == "text/csv"
    assert b"event_id" in resp.body  # CSV header present


# ---------------------------------------------------------------------------
# GAP-0210: scheduled (recurring) audit export reports
# ---------------------------------------------------------------------------

@mock_aws()
def test_schedule_crud(monkeypatch, request):
    """Fails-before: no schedule service / endpoints existed.
    Passes-after: create -> list -> patch -> delete round-trips."""
    import asyncio

    ddb = boto3.resource("dynamodb", region_name=_REGION)
    _create_table(ddb)
    _wire(monkeypatch, request, ddb, events=_make_events(1))

    from app.routers import audit_export as router_mod
    from app.auth.roles import Role

    ctx = {"user_sub": _ROOT, "role": Role.ROOT}
    loop = asyncio.new_event_loop()

    created = loop.run_until_complete(
        router_mod.create_audit_export_schedule(
            {"categories": ["billing"], "format": "pdf", "cadence": "daily",
             "recipients": ["compliance@example.com"]},
            ctx=ctx,
        )
    )
    assert created["schedule_id"].startswith("sched_")
    assert created["cadence"] == "daily"
    assert created["enabled"] is True
    assert created["next_run_at"] is not None
    sid = created["schedule_id"]

    listed = loop.run_until_complete(router_mod.list_audit_export_schedules(ctx=ctx))
    assert any(s["schedule_id"] == sid for s in listed["schedules"])

    patched = loop.run_until_complete(
        router_mod.update_audit_export_schedule(
            sid, {"cadence": "weekly", "recipients": ["legal@example.com"]}, ctx=ctx
        )
    )
    assert patched["cadence"] == "weekly"
    assert patched["recipients"] == ["legal@example.com"]

    resp = loop.run_until_complete(
        router_mod.delete_audit_export_schedule(sid, ctx=ctx)
    )
    assert resp.status_code == 204
    listed2 = loop.run_until_complete(router_mod.list_audit_export_schedules(ctx=ctx))
    assert not any(s["schedule_id"] == sid for s in listed2["schedules"])


@mock_aws()
def test_create_schedule_rejects_bad_cadence(monkeypatch, request):
    import asyncio
    from fastapi import HTTPException

    ddb = boto3.resource("dynamodb", region_name=_REGION)
    _create_table(ddb)
    _wire(monkeypatch, request, ddb, events=[])

    from app.routers import audit_export as router_mod
    from app.auth.roles import Role

    ctx = {"user_sub": _ROOT, "role": Role.ROOT}
    with pytest.raises(HTTPException) as ei:
        asyncio.new_event_loop().run_until_complete(
            router_mod.create_audit_export_schedule(
                {"categories": ["billing"], "format": "csv", "cadence": "hourly"},
                ctx=ctx,
            )
        )
    assert ei.value.status_code == 400


@mock_aws()
def test_run_due_schedules_spawns_jobs(monkeypatch, request):
    """Fails-before: no runner existed.
    Passes-after: a schedule whose next_run_at is in the past is selected by
    ``get_due_schedules`` and ``run_due_schedules`` spawns an export job and
    advances next_run_at."""
    ddb = boto3.resource("dynamodb", region_name=_REGION)
    _create_table(ddb)
    pipe, sch = _wire(monkeypatch, request, ddb, events=_make_events(2))

    notified = {}

    def _capture(s, j):
        notified["schedule_id"] = s.get("schedule_id")
        notified["export_id"] = j.get("export_id")

    monkeypatch.setattr(sch, "_notify_recipients", _capture)

    created = sch.create_schedule(
        created_by=_ROOT, categories=["billing"], format="csv",
        cadence="daily", recipients=["x@example.com"],
    )
    sid = created["schedule_id"]

    # Make it due by setting next_run_at (GSI1SK) far in the past.
    from app.core.tables import T
    T.audit_exports.update_item(
        Key={"export_id": f"SCHEDULE#{sid}", "sk": "META"},
        UpdateExpression="SET GSI1SK = :v, next_run_at = :v",
        ExpressionAttributeValues={":v": 1},
    )

    due = sch.get_due_schedules()
    assert any(s["schedule_id"] == sid for s in due)

    count = sch.run_due_schedules()
    assert count >= 1
    assert notified.get("schedule_id") == sid
    assert notified.get("export_id", "").startswith("exp_")

    # next_run_at advanced into the future; no longer due.
    refreshed = sch.get_schedule(sid)
    assert int(refreshed["next_run_at"]) > 1
    assert refreshed["last_export_id"] == notified["export_id"]


@mock_aws()
def test_disabled_schedule_not_run(monkeypatch, request):
    """A disabled schedule is removed from the active index and never runs."""
    ddb = boto3.resource("dynamodb", region_name=_REGION)
    _create_table(ddb)
    pipe, sch = _wire(monkeypatch, request, ddb, events=_make_events(1))

    created = sch.create_schedule(
        created_by=_ROOT, categories=["billing"], format="csv", cadence="daily",
    )
    sid = created["schedule_id"]
    sch.update_schedule(sid, enabled=False)

    from app.core.tables import T
    T.audit_exports.update_item(
        Key={"export_id": f"SCHEDULE#{sid}", "sk": "META"},
        UpdateExpression="SET next_run_at = :v",
        ExpressionAttributeValues={":v": 1},
    )

    due = sch.get_due_schedules()
    assert not any(s.get("schedule_id") == sid for s in due)
    assert sch.run_due_schedules() == 0
