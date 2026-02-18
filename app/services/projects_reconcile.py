from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.settings import Settings
from app.core.tables import T
from app.metrics import (
    record_provider_failure_alert,
    record_provider_failure_streak,
    record_provider_latency,
    record_reconcile_failure,
)
from app.models import TrackedFileModel
from app.services.file_providers import ProviderRegistry, default_provider_registry
from app.services.projects_store import emit_project_event, now_iso, tracked_file_from_item, tracked_file_to_item

logger = logging.getLogger(__name__)
S = Settings()
_PROVIDER_FAILURE_STREAKS: Dict[str, int] = {}

_TRANSIENT_CLIENT_ERRORS = {
    "ProvisionedThroughputExceededException",
    "ThrottlingException",
    "RequestLimitExceeded",
    "InternalServerError",
    "ServiceUnavailable",
}


def _is_transient_error(exc: Exception) -> bool:
    if isinstance(exc, HTTPException):
        return exc.status_code in {429, 500, 502, 503, 504}
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "")
        return code in _TRANSIENT_CLIENT_ERRORS
    return isinstance(exc, (TimeoutError, ConnectionError, OSError))


def _with_retry(
    fn: Callable[[], Any],
    *,
    max_attempts: int,
    base_backoff_seconds: float,
    sleep_fn: Callable[[float], None],
) -> Any:
    attempts = max(1, max_attempts)
    for attempt in range(1, attempts + 1):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            if (not _is_transient_error(exc)) or attempt >= attempts:
                raise
            delay = base_backoff_seconds * (2 ** (attempt - 1))
            sleep_fn(delay)


def _scan_tracked_file_items(*, limit: int, cursor: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    kwargs: Dict[str, Any] = {"Limit": max(1, limit)}
    if cursor:
        kwargs["ExclusiveStartKey"] = cursor
    return T.projects.scan(**kwargs)


def _project_exists_for_owner(owner: str, project_id: str) -> bool:
    resp = T.projects.get_item(
        Key={"PK": f"OWNER#{owner}", "SK": f"PROJECT#{project_id}"},
        ConsistentRead=True,
    )
    item = resp.get("Item")
    if not item:
        return False
    if item.get("entity_type") != "project":
        return False
    return item.get("owner") == owner and item.get("id") == project_id


def reconcile_tracked_files_batch(
    *,
    limit: Optional[int] = None,
    cursor: Optional[Dict[str, Any]] = None,
    registry: Optional[ProviderRegistry] = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    max_attempts: Optional[int] = None,
    base_backoff_seconds: Optional[float] = None,
) -> Dict[str, Any]:
    scan_limit = int(limit or S.projects_reconcile_scan_limit)
    attempts = int(max_attempts or S.projects_reconcile_max_attempts)
    backoff = float(base_backoff_seconds or S.projects_reconcile_backoff_seconds)

    page = _scan_tracked_file_items(limit=scan_limit, cursor=cursor)
    provider_registry = registry or default_provider_registry()
    alert_threshold = max(1, int(S.projects_provider_failure_alert_threshold))

    checked = 0
    updated = 0
    missing = 0
    skipped = 0
    errors = 0

    for raw in page.get("Items", []):
        if raw.get("entity_type") != "tracked_file":
            continue

        checked += 1
        tracked = tracked_file_from_item(raw)

        if tracked.status == "archived":
            skipped += 1
            continue

        if not _project_exists_for_owner(tracked.owner, tracked.project_id):
            logger.warning(
                "Skipping tracked file reconcile due to project ownership mismatch",
                extra={"tracked_file_id": tracked.id, "project_id": tracked.project_id, "owner": tracked.owner},
            )
            skipped += 1
            continue

        provider = provider_registry.get(tracked.owner, tracked.provider)
        provider_name = (tracked.provider or "unknown").lower()

        def _probe() -> Tuple[bool, Dict[str, Any], str]:
            canonical_ref = provider.resolve(tracked.provider_ref)
            exists = provider.exists(canonical_ref)
            if not exists:
                return False, {}, canonical_ref
            metadata = provider.get_metadata(canonical_ref)
            return True, metadata, canonical_ref

        started = time.perf_counter()
        try:
            exists, fresh_metadata, canonical_ref = _with_retry(
                _probe,
                max_attempts=attempts,
                base_backoff_seconds=backoff,
                sleep_fn=sleep_fn,
            )
            record_provider_latency(provider_name, "reconcile", time.perf_counter() - started)
        except HTTPException as exc:
            record_provider_latency(provider_name, "reconcile", time.perf_counter() - started)
            if exc.status_code == 404:
                exists = False
                fresh_metadata = {}
                canonical_ref = tracked.provider_ref
            else:
                record_reconcile_failure(provider_name, "provider_http_error")
                streak = _PROVIDER_FAILURE_STREAKS.get(provider_name, 0) + 1
                _PROVIDER_FAILURE_STREAKS[provider_name] = streak
                record_provider_failure_streak(provider_name, streak)
                if streak >= alert_threshold and streak % alert_threshold == 0:
                    logger.warning("Provider repeated failures exceeded threshold", extra={"provider": provider_name, "streak": streak})
                    record_provider_failure_alert(provider_name)
                emit_project_event(
                    tracked.owner,
                    tracked.project_id,
                    "provider_error",
                    tracked_file_id=tracked.id,
                    provider=tracked.provider,
                    provider_ref=tracked.provider_ref,
                    message=str(exc.detail),
                )
                logger.exception("Tracked file reconcile failed", extra={"tracked_file_id": tracked.id})
                errors += 1
                continue
        except Exception as exc:  # noqa: BLE001
            record_provider_latency(provider_name, "reconcile", time.perf_counter() - started)
            record_reconcile_failure(provider_name, "provider_error")
            streak = _PROVIDER_FAILURE_STREAKS.get(provider_name, 0) + 1
            _PROVIDER_FAILURE_STREAKS[provider_name] = streak
            record_provider_failure_streak(provider_name, streak)
            if streak >= alert_threshold and streak % alert_threshold == 0:
                logger.warning("Provider repeated failures exceeded threshold", extra={"provider": provider_name, "streak": streak})
                record_provider_failure_alert(provider_name)
            emit_project_event(
                tracked.owner,
                tracked.project_id,
                "provider_error",
                tracked_file_id=tracked.id,
                provider=tracked.provider,
                provider_ref=tracked.provider_ref,
                message=str(exc),
            )
            logger.exception("Tracked file reconcile failed", extra={"tracked_file_id": tracked.id})
            errors += 1
            continue

        _PROVIDER_FAILURE_STREAKS[provider_name] = 0
        record_provider_failure_streak(provider_name, 0)

        ts = now_iso()
        if exists:
            merged = tracked.model_copy(
                update={
                    "provider_ref": canonical_ref,
                    "display_path": tracked.display_path or canonical_ref,
                    "status": "active",
                    "metadata": {**(tracked.metadata or {}), **fresh_metadata},
                    "updated_at": ts,
                    "last_seen_at": ts,
                }
            )
            updated += 1
        else:
            merged = tracked.model_copy(
                update={
                    "status": "missing",
                    "updated_at": ts,
                }
            )
            missing += 1

        T.projects.put_item(Item=tracked_file_to_item(merged))
        emit_project_event(
            tracked.owner,
            tracked.project_id,
            "sync_ran",
            tracked_file_id=tracked.id,
            provider=tracked.provider,
            provider_ref=canonical_ref if exists else tracked.provider_ref,
            metadata={"status": merged.status},
        )

    return {
        "checked": checked,
        "updated": updated,
        "missing": missing,
        "skipped": skipped,
        "errors": errors,
        "cursor": page.get("LastEvaluatedKey"),
    }


async def projects_reconcile_loop() -> None:
    interval = max(30, int(S.projects_reconcile_interval_seconds))
    while True:
        cursor: Optional[Dict[str, Any]] = None
        try:
            while True:
                result = reconcile_tracked_files_batch(cursor=cursor)
                cursor = result.get("cursor")
                if not cursor:
                    break
        except Exception:  # noqa: BLE001
            logger.exception("Projects reconciliation loop failed")
        await asyncio.sleep(interval)


def start_projects_reconcile_task() -> None:
    if not S.projects_reconcile_enabled:
        logger.info("Projects reconciliation disabled")
        return
    asyncio.create_task(projects_reconcile_loop())
