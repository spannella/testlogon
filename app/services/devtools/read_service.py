from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Hashable, Optional, Tuple

from app.models import (
    DevtoolsBillingLedgerOut,
    DevtoolsBillingLedgerSummaryOut,
    DevtoolsEmailMessagesOut,
    DevtoolsSmsConversationsOut,
)
from app.services.devtools.billing_log_parser import parse_billing_logs
from app.services.devtools.email_log_parser import parse_email_log
from app.services.devtools.sms_log_parser import parse_sms_log

_CACHE_TTL_SECONDS = 3.0


@dataclass(frozen=True)
class FileState:
    exists: bool
    mtime_ns: int
    size: int


@dataclass
class CacheEntry:
    created_at: float
    file_state: Tuple[FileState, ...]
    payload: Any


_CACHE: Dict[Hashable, CacheEntry] = {}


def _file_state(path: str) -> FileState:
    try:
        st = os.stat(path)
        return FileState(exists=True, mtime_ns=int(st.st_mtime_ns), size=int(st.st_size))
    except FileNotFoundError:
        return FileState(exists=False, mtime_ns=0, size=0)


def _is_fresh(entry: CacheEntry, current_state: Tuple[FileState, ...]) -> bool:
    now = time.monotonic()
    if now - entry.created_at > _CACHE_TTL_SECONDS:
        return False
    return entry.file_state == current_state


def clear_devtools_cache() -> None:
    _CACHE.clear()


def _get_or_build(key: Hashable, state_paths: Tuple[str, ...], builder) -> Any:
    current_state = tuple(_file_state(p) for p in state_paths)
    entry = _CACHE.get(key)
    if entry and _is_fresh(entry, current_state):
        return entry.payload

    payload = builder()
    _CACHE[key] = CacheEntry(created_at=time.monotonic(), file_state=current_state, payload=payload)
    return payload


def get_email_messages(
    log_path: str,
    *,
    mailbox: Optional[str],
    thread_id: Optional[str],
    q: Optional[str],
    state: str,
    limit: int,
    offset: int,
) -> DevtoolsEmailMessagesOut:
    key = (
        "email",
        log_path,
        mailbox or "",
        thread_id or "",
        q or "",
        state,
        int(limit),
        int(offset),
    )
    return _get_or_build(
        key,
        (log_path,),
        lambda: parse_email_log(
            log_path,
            mailbox=mailbox,
            thread_id=thread_id,
            q=q,
            state=state,
            limit=limit,
            offset=offset,
        ),
    )


def get_sms_conversations(
    log_path: str,
    *,
    participant: Optional[str],
    q: Optional[str],
    limit: int,
    offset: int,
) -> DevtoolsSmsConversationsOut:
    key = (
        "sms",
        log_path,
        participant or "",
        q or "",
        int(limit),
        int(offset),
    )
    return _get_or_build(
        key,
        (log_path,),
        lambda: parse_sms_log(
            log_path,
            participant=participant,
            q=q,
            limit=limit,
            offset=offset,
        ),
    )


def get_billing_ledger(
    stripe_log_path: str,
    backend_log_path: str,
    *,
    provider: Optional[str],
    status: Optional[str],
    from_ts: Optional[str],
    to_ts: Optional[str],
    limit: int,
    offset: int,
) -> DevtoolsBillingLedgerOut:
    key = (
        "billing_ledger",
        stripe_log_path,
        backend_log_path,
        provider or "",
        status or "",
        from_ts or "",
        to_ts or "",
        int(limit),
        int(offset),
    )
    return _get_or_build(
        key,
        (stripe_log_path, backend_log_path),
        lambda: parse_billing_logs(
            stripe_log_path,
            backend_log_path,
            provider=provider,  # type: ignore[arg-type]
            status=status,
            from_ts=from_ts,
            to_ts=to_ts,
            limit=limit,
            offset=offset,
        ),
    )


def get_billing_summary(
    stripe_log_path: str,
    backend_log_path: str,
    *,
    provider: Optional[str],
    status: Optional[str],
    from_ts: Optional[str],
    to_ts: Optional[str],
) -> DevtoolsBillingLedgerSummaryOut:
    key = (
        "billing_summary",
        stripe_log_path,
        backend_log_path,
        provider or "",
        status or "",
        from_ts or "",
        to_ts or "",
    )

    out: DevtoolsBillingLedgerOut = _get_or_build(
        key,
        (stripe_log_path, backend_log_path),
        lambda: parse_billing_logs(
            stripe_log_path,
            backend_log_path,
            provider=provider,  # type: ignore[arg-type]
            status=status,
            from_ts=from_ts,
            to_ts=to_ts,
            limit=1,
            offset=0,
        ),
    )
    summary = out.summary.model_copy(deep=True)
    summary.parse_warnings = out.parse_warnings
    return summary
