from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.core.settings import S
from app.metrics import record_filemgr_mount_reconcile_batch, record_filemgr_mount_reconcile_drift
from app.services.alerts import audit_event
from app.services import filemanager as fm
from app.services.filemanager_mounts import (
    scan_mounts_page_for_reconcile,
    update_mount_reconcile_state,
)
from app.services.filemanager_provider import FileStorageDispatcher, build_default_dispatcher

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _cached_item_from_remote(*, owner: str, parent: str, remote: Dict[str, Any]) -> Dict[str, Any]:
    path = str(remote.get("path") or "")
    name = str(remote.get("name") or (path.rstrip("/").rsplit("/", 1)[-1] if path else ""))
    item_type = "folder" if str(remote.get("type") or "file") == "folder" else "file"
    now = _now_iso()
    item = {
        "PK": fm.pk_user(owner),
        "SK": fm.sk_node(path),
        "type": item_type,
        "path": path,
        "name": name,
        "name_lc": name.lower(),
        "parent": parent,
        "created_at": now,
        "updated_at": str(remote.get("updated_at") or now),
        "size": remote.get("size"),
        "content_type": remote.get("content_type") or "application/octet-stream",
        "provider": "icloud",
        "provider_cached": True,
        "GSI1PK": fm.pk_user(owner),
        "GSI1SK": f"NAME#{name.lower()}#PATH#{path}",
        "GSI2PK": f"PARENT#{parent}",
        "GSI2SK": f"TYPE#{item_type}#NAME#{name.lower()}#PATH#{path}",
    }
    return item


def _decode_cursor(raw: Any) -> Optional[Dict[str, Any]]:
    if not raw:
        return None
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            out = json.loads(raw)
            return out if isinstance(out, dict) else None
        except Exception:
            return None
    return None


def reconcile_mount_metadata_batch(
    *,
    mount_scan_limit: Optional[int] = None,
    mount_cursor: Optional[Dict[str, Any]] = None,
    local_page_limit: Optional[int] = None,
    dry_run: Optional[bool] = None,
    dispatcher: Optional[FileStorageDispatcher] = None,
) -> Dict[str, Any]:
    started = time.perf_counter()
    scan_limit = int(mount_scan_limit or S.filemgr_mount_reconcile_scan_limit)
    page_limit = int(local_page_limit or S.filemgr_mount_reconcile_local_page_limit)
    run_dry = bool(S.filemgr_mount_reconcile_dry_run if dry_run is None else dry_run)
    dsp = dispatcher or build_default_dispatcher()

    page = scan_mounts_page_for_reconcile(limit=scan_limit, cursor=mount_cursor)
    mounts = page.get("items") or []

    report: Dict[str, Any] = {
        "dry_run": run_dry,
        "checked_mounts": 0,
        "repairs_planned": 0,
        "repairs_applied": 0,
        "drifted_mounts": 0,
        "errors": 0,
        "mount_reports": [],
        "cursor": page.get("cursor"),
    }

    for mount in mounts:
        owner = str(mount.get("owner_user_sub") or "")
        mount_id = str(mount.get("mount_id") or "")
        mount_path = str(mount.get("mount_path") or "")
        report["checked_mounts"] += 1
        mount_report: Dict[str, Any] = {
            "mount_id": mount_id,
            "owner_user_sub": owner,
            "mount_path": mount_path,
            "planned": 0,
            "applied": 0,
            "missing_local": 0,
            "stale_local": 0,
            "mismatched": 0,
            "status": "ok",
        }
        try:
            local_cursor = _decode_cursor(mount.get("reconcile_cursor"))
            local_items, next_local_cursor = fm.list_children_page(owner, mount_path, limit=page_limit, cursor=local_cursor)
            remote_items = dsp.list(owner, mount_path)

            local_map = {str(it.get("path") or ""): it for it in local_items if str(it.get("path") or "")}
            remote_map = {str(it.get("path") or ""): it for it in remote_items if str(it.get("path") or "")}

            missing_local = [p for p in remote_map.keys() if p not in local_map]
            stale_local = [p for p in local_map.keys() if p not in remote_map and not local_map[p].get("deleted_at")]
            mismatched = [
                p
                for p in remote_map.keys() & local_map.keys()
                if (str(remote_map[p].get("type") or "") != str(local_map[p].get("type") or ""))
                or (remote_map[p].get("size") != local_map[p].get("size"))
            ]

            mount_report["missing_local"] = len(missing_local)
            mount_report["stale_local"] = len(stale_local)
            mount_report["mismatched"] = len(mismatched)

            planned = len(missing_local) + len(stale_local) + len(mismatched)
            mount_report["planned"] = planned
            report["repairs_planned"] += planned

            if planned > 0:
                report["drifted_mounts"] += 1
                audit_event(
                    "filemgr_mount_reconcile_drift_detected",
                    owner,
                    None,
                    outcome="success",
                    mount_id=mount_id,
                    mount_path=mount_path,
                    missing_local=len(missing_local),
                    stale_local=len(stale_local),
                    mismatched=len(mismatched),
                    dry_run=run_dry,
                )
                record_filemgr_mount_reconcile_drift(
                    dry_run=run_dry,
                    missing_local=len(missing_local),
                    stale_local=len(stale_local),
                    mismatched=len(mismatched),
                )

            applied = 0
            if not run_dry:
                for p in missing_local:
                    fm.put_node(_cached_item_from_remote(owner=owner, parent=mount_path, remote=remote_map[p]))
                    applied += 1
                for p in stale_local:
                    stale = dict(local_map[p])
                    stale["deleted_at"] = _now_iso()
                    stale["updated_at"] = _now_iso()
                    stale["deleted_by"] = "filemgr_mount_reconcile"
                    fm.put_node(stale)
                    applied += 1
                for p in mismatched:
                    merged = dict(local_map[p])
                    merged["type"] = remote_map[p].get("type") or merged.get("type")
                    merged["size"] = remote_map[p].get("size")
                    merged["updated_at"] = str(remote_map[p].get("updated_at") or _now_iso())
                    fm.put_node(merged)
                    applied += 1
                report["repairs_applied"] += applied

            mount_report["applied"] = applied

            update_mount_reconcile_state(
                owner_user_sub=owner,
                mount_id=mount_id,
                cursor=next_local_cursor,
                dry_run=run_dry,
                completed=not bool(next_local_cursor),
                last_report=mount_report,
            )

            logger.info(
                "filemgr mount reconcile completed",
                extra={"mount_id": mount_id, "owner": owner, "mount_path": mount_path, **mount_report, "dry_run": run_dry},
            )

        except Exception as exc:  # noqa: BLE001
            report["errors"] += 1
            mount_report["status"] = "error"
            mount_report["error"] = str(exc)
            logger.exception("filemgr mount reconcile failed", extra={"mount_id": mount_id, "owner": owner, "mount_path": mount_path})
            audit_event(
                "filemgr_mount_reconcile_failed",
                owner,
                None,
                outcome="failure",
                mount_id=mount_id,
                mount_path=mount_path,
                error=str(exc),
                dry_run=run_dry,
            )

        report["mount_reports"].append(mount_report)

    record_filemgr_mount_reconcile_batch(
        dry_run=run_dry,
        elapsed_seconds=time.perf_counter() - started,
        outcome="error" if report["errors"] else "success",
    )
    return report


async def filemgr_mount_reconcile_loop() -> None:
    import time as _time
    from app.services.job_registry import register_task, report_error, report_poll

    interval = max(30, int(S.filemgr_mount_reconcile_interval_seconds))
    register_task("filemgr_mount_reconcile", interval, enabled=True,
                   description="Syncs file manager mount points with remote storage")

    cursor: Optional[Dict[str, Any]] = None
    while True:
        _start = _time.perf_counter()
        try:
            result = reconcile_mount_metadata_batch(mount_cursor=cursor)
            cursor = result.get("cursor")
            if not cursor:
                cursor = None
            _dur = (_time.perf_counter() - _start) * 1000
            report_poll("filemgr_mount_reconcile", duration_ms=_dur)
        except Exception as exc:
            report_error("filemgr_mount_reconcile", str(exc))
            logger.exception("file manager mount reconcile loop failed")
        await asyncio.sleep(interval)


def start_filemgr_mount_reconcile_task() -> None:
    from app.services.job_registry import register_task

    if not S.filemgr_mount_reconcile_enabled:
        register_task("filemgr_mount_reconcile", 30, enabled=False,
                       description="Syncs file manager mount points with remote storage")
        logger.info("File manager mount reconcile disabled")
        return
    asyncio.create_task(filemgr_mount_reconcile_loop())
