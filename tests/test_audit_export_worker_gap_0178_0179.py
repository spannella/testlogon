"""Offline regression tests for GAP-0178 + GAP-0179 (ENTERPRISE-004 audit export).

GAP-0178: background async export worker not implemented.
  - ``app/services/audit_export_worker.py`` with ``run_audit_export_worker_loop``
    and ``start_audit_export_worker_task`` must exist.
  - The startup hook must be registered in ``app.main``.
  - The worker loop must claim pending jobs and call ``process_export_job``.

GAP-0179: S3 upload path dead in the pipeline.
  - ``process_export_job`` must dispatch to a real S3 upload in production mode
    and to the inline path (no S3) in dev mode.

Fully offline: a fake DynamoDB table and a mock S3 client are injected; no real
AWS access occurs. Settings ``S`` is frozen, so it is mutated via
``object.__setattr__`` and restored afterwards.

Fails-before: ``audit_export_worker`` module and ``process_export_job`` do not
exist -> ImportError. Passes-after: both exist and behave as specified.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

from app.core.settings import S


@dataclass
class _FakeAuditExportsTable:
    """Minimal in-memory stand-in for the AuditExports DynamoDB table."""

    items: dict[str, dict] = field(default_factory=dict)
    scan_items: list[dict] = field(default_factory=list)

    def _key(self, key: dict) -> str:
        return f"{key['export_id']}#{key['sk']}"

    def put_item(self, *, Item):
        self.items[self._key(Item)] = dict(Item)

    def get_item(self, *, Key):
        item = self.items.get(self._key(Key))
        return {"Item": dict(item)} if item else {}

    def scan(self, **kwargs):
        return {"Items": [dict(i) for i in self.scan_items]}

    def update_item(self, *, Key, UpdateExpression=None, ExpressionAttributeNames=None,
                    ExpressionAttributeValues=None, ConditionExpression=None):
        # Record the most recent update for assertions and apply :st transitions.
        self.last_update = {
            "Key": Key,
            "UpdateExpression": UpdateExpression,
            "ExpressionAttributeValues": ExpressionAttributeValues or {},
        }
        item = self.items.setdefault(self._key(Key), dict(Key))
        for placeholder, value in (ExpressionAttributeValues or {}).items():
            if placeholder == ":st":
                item["status"] = value
        return {}


def _set(attr: str, value: Any):
    orig = getattr(S, attr)
    object.__setattr__(S, attr, value)
    return attr, orig


def _restore(saved):
    for attr, orig in saved:
        object.__setattr__(S, attr, orig)


def _pending_job(export_id: str = "exp_test001") -> dict:
    return {
        "export_id": export_id,
        "sk": "META",
        "status": "pending",
        "categories": ["auth"],
        "format": "ndjson",
        "from_date": 1700000000,
        "to_date": 1700001000,
        "created_by": "root",
        "actor_filter": "",
        "target_filter": "",
        "event_actions_filter": [],
    }


# --------------------------------------------------------------------------- #
# GAP-0179: pipeline dispatch + S3 upload
# --------------------------------------------------------------------------- #

def test_process_export_job_uploads_to_s3_in_production():
    """In production mode, process_export_job must upload to S3 and mark completed."""
    import app.services.audit_export_pipeline as pipeline

    saved = [
        _set("dev_mode", False),
        _set("audit_export_s3_bucket", "test-exports-bucket"),
        _set("audit_export_signing_key", "test-key"),
        _set("audit_export_signing_key_id", "v1"),
    ]
    table = _FakeAuditExportsTable()
    mock_s3 = MagicMock()
    try:
        with (
            patch.object(pipeline, "T", SimpleNamespace(audit_exports=table)),
            patch("app.core.aws_clients.s3_client", return_value=mock_s3),
            patch.object(pipeline, "_merge_sorted_events", return_value=iter([])),
        ):
            pipeline.process_export_job("exp_test001", _pending_job())

        mock_s3.upload_fileobj.assert_called_once()
        call = mock_s3.upload_fileobj.call_args
        assert call.args[1] == "test-exports-bucket"  # bucket
        assert "exp_test001" in call.args[2]          # key contains export id

        assert table.last_update["ExpressionAttributeValues"][":st"] == "completed"
        assert ":s3k" in table.last_update["ExpressionAttributeValues"]
    finally:
        _restore(saved)


def test_process_export_job_uses_inline_in_dev_no_s3():
    """In dev mode, process_export_job must NOT call S3."""
    import app.services.audit_export_pipeline as pipeline

    saved = [_set("dev_mode", True)]
    table = _FakeAuditExportsTable()
    mock_s3 = MagicMock()
    try:
        with (
            patch.object(pipeline, "T", SimpleNamespace(audit_exports=table)),
            patch("app.core.aws_clients.s3_client", return_value=mock_s3),
            patch.object(pipeline, "_merge_sorted_events", return_value=iter([])),
        ):
            pipeline.process_export_job("exp_dev001", _pending_job("exp_dev001"))

        mock_s3.upload_fileobj.assert_not_called()
        # Inline path still completes the job.
        assert table.last_update["ExpressionAttributeValues"][":st"] == "completed"
    finally:
        _restore(saved)


# --------------------------------------------------------------------------- #
# GAP-0178: worker module + claim + startup registration
# --------------------------------------------------------------------------- #

def test_worker_claims_pending_job_and_calls_process():
    """The worker must find a pending job, claim it, and call process_export_job."""
    import app.services.audit_export_worker as worker

    table = _FakeAuditExportsTable(scan_items=[_pending_job()])
    table.items[table._key({"export_id": "exp_test001", "sk": "META"})] = _pending_job()

    processed: list[str] = []
    with (
        patch.object(worker, "T", SimpleNamespace(audit_exports=table)),
        patch.object(worker, "process_export_job",
                     side_effect=lambda eid, job: processed.append(eid)),
    ):
        jobs = worker._query_pending_jobs(limit=5)
        assert len(jobs) == 1
        assert worker._claim_job(jobs[0]["export_id"]) is True
        worker.process_export_job(jobs[0]["export_id"], jobs[0])

    assert processed == ["exp_test001"]
    # Claim transitioned the job out of pending.
    assert table.items[table._key({"export_id": "exp_test001", "sk": "META"})]["status"] == "processing"


def test_start_audit_export_worker_task_creates_task_when_enabled():
    """start_audit_export_worker_task schedules the loop coroutine when enabled."""
    import app.services.audit_export_worker as worker

    saved = [_set("audit_export_worker_enabled", True)]
    created: list[Any] = []
    try:
        with patch.object(worker.asyncio, "create_task",
                          side_effect=lambda coro: created.append(coro)):
            asyncio.get_event_loop().run_until_complete(
                worker.start_audit_export_worker_task()
            )
        assert len(created) == 1
    finally:
        # Close the un-awaited coroutine to avoid a RuntimeWarning.
        for coro in created:
            coro.close()
        _restore(saved)


def test_start_audit_export_worker_task_noop_when_disabled():
    """start_audit_export_worker_task must not schedule a task when disabled."""
    import app.services.audit_export_worker as worker

    saved = [_set("audit_export_worker_enabled", False)]
    created: list[Any] = []
    try:
        with patch.object(worker.asyncio, "create_task",
                          side_effect=lambda coro: created.append(coro)):
            asyncio.get_event_loop().run_until_complete(
                worker.start_audit_export_worker_task()
            )
        assert created == []
    finally:
        _restore(saved)


def test_audit_export_worker_startup_handler_registered():
    """The audit export worker startup handler must be wired into the app."""
    from app.main import create_app

    app = create_app()
    handler_names = [getattr(h, "__name__", repr(h)) for h in app.router.on_startup]
    assert "start_audit_export_worker_task" in handler_names, (
        "Audit export worker startup handler not found in app.on_startup"
    )
