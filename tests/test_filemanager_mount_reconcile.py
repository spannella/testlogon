from __future__ import annotations

from unittest.mock import Mock, patch

from app.services import filemanager_mount_reconcile as svc


class _Dispatcher:
    def __init__(self, rows):
        self._rows = rows

    def list(self, user: str, path: str):
        return list(self._rows)


def test_reconcile_mount_metadata_batch_dry_run_plans_without_writes():
    mounts_page = {
        "items": [
            {
                "mount_id": "m1",
                "owner_user_sub": "u1",
                "mount_path": "/icloud/",
                "reconcile_cursor": None,
            }
        ],
        "cursor": {"pk": "MOUNT#m1"},
    }
    local_rows = [{"path": "/icloud/stale.txt", "type": "file", "size": 1}]
    remote_rows = [{"path": "/icloud/new.txt", "type": "file", "size": 2, "name": "new.txt"}]

    with (
        patch.object(svc, "scan_mounts_page_for_reconcile", return_value=mounts_page),
        patch.object(svc.fm, "list_children_page", return_value=(local_rows, None)),
        patch.object(svc, "audit_event") as audit_event,
        patch.object(svc, "record_filemgr_mount_reconcile_drift") as record_drift,
        patch.object(svc, "record_filemgr_mount_reconcile_batch") as record_batch,
        patch.object(svc, "update_mount_reconcile_state") as update_state,
        patch.object(svc.fm, "put_node") as put_node,
    ):
        out = svc.reconcile_mount_metadata_batch(dry_run=True, dispatcher=_Dispatcher(remote_rows), mount_scan_limit=10, local_page_limit=50)

    assert out["dry_run"] is True
    assert out["checked_mounts"] == 1
    assert out["drifted_mounts"] == 1
    assert out["repairs_planned"] == 2
    assert out["repairs_applied"] == 0
    assert put_node.call_count == 0
    assert audit_event.called
    record_drift.assert_called_once_with(dry_run=True, missing_local=1, stale_local=1, mismatched=0)
    record_batch.assert_called_once()
    update_state.assert_called_once()


def test_reconcile_mount_metadata_batch_applies_repairs_and_persists_cursor():
    mounts_page = {
        "items": [
            {
                "mount_id": "m1",
                "owner_user_sub": "u1",
                "mount_path": "/icloud/",
                "reconcile_cursor": None,
            }
        ],
        "cursor": None,
    }
    local_rows = [{"path": "/icloud/keep.txt", "type": "file", "size": 1, "name": "keep.txt", "parent": "/icloud/"}]
    remote_rows = [{"path": "/icloud/keep.txt", "type": "file", "size": 9, "name": "keep.txt", "updated_at": "t2"}]

    with (
        patch.object(svc, "scan_mounts_page_for_reconcile", return_value=mounts_page),
        patch.object(svc.fm, "list_children_page", return_value=(local_rows, {"k": "next"})),
        patch.object(svc, "record_filemgr_mount_reconcile_batch") as record_batch,
        patch.object(svc, "update_mount_reconcile_state") as update_state,
        patch.object(svc.fm, "put_node") as put_node,
    ):
        out = svc.reconcile_mount_metadata_batch(dry_run=False, dispatcher=_Dispatcher(remote_rows))

    assert out["repairs_planned"] == 1
    assert out["repairs_applied"] == 1
    assert put_node.call_count == 1
    update_state.assert_called_once()
    kwargs = update_state.call_args.kwargs
    assert kwargs["cursor"] == {"k": "next"}
    assert kwargs["completed"] is False
    record_batch.assert_called_once()


def test_reconcile_mount_metadata_batch_records_error_metrics_and_audit():
    mounts_page = {
        "items": [
            {
                "mount_id": "m1",
                "owner_user_sub": "u1",
                "mount_path": "/icloud/",
                "reconcile_cursor": None,
            }
        ],
        "cursor": None,
    }

    with (
        patch.object(svc, "scan_mounts_page_for_reconcile", return_value=mounts_page),
        patch.object(svc.fm, "list_children_page", side_effect=RuntimeError("boom")),
        patch.object(svc, "audit_event") as audit_event,
        patch.object(svc, "record_filemgr_mount_reconcile_batch") as record_batch,
    ):
        out = svc.reconcile_mount_metadata_batch(dry_run=False, dispatcher=_Dispatcher([]))

    assert out["errors"] == 1
    audit_event.assert_called_once()
    assert audit_event.call_args.args[0] == "filemgr_mount_reconcile_failed"
    record_batch.assert_called_once()
    assert record_batch.call_args.kwargs["outcome"] == "error"


def test_start_task_respects_setting():
    with (
        patch.object(svc, "S", Mock(filemgr_mount_reconcile_enabled=False)),
        patch.object(svc.asyncio, "create_task") as create_task,
    ):
        svc.start_filemgr_mount_reconcile_task()
    create_task.assert_not_called()
