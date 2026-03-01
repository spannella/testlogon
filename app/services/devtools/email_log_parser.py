from __future__ import annotations

import heapq
import json
import os
import re
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Dict, Iterable, List, Optional, Tuple

from app.models import (
    DevtoolsEmailMailboxOut,
    DevtoolsEmailMessageOut,
    DevtoolsEmailMessagesOut,
    DevtoolsEmailThreadOut,
    DevtoolsParseWarningOut,
)

_HEADER_RE = re.compile(r"^\[(?P<ts>[^\]]+)\]\s+(?P<body>.*)$")
_TO_RE = re.compile(r"TO=([^\s]+)")
_PURPOSE_RE = re.compile(r"PURPOSE=([^\s]+)")


def _iso_utc(value: str) -> Optional[str]:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    except Exception:
        return None


def _stable_id(*parts: str, length: int = 20) -> str:
    joined = "|".join(parts)
    return sha256(joined.encode("utf-8")).hexdigest()[:length]


def _warning(code: str, message: str, *, line_number: Optional[int] = None, sample: Optional[str] = None) -> DevtoolsParseWarningOut:
    return DevtoolsParseWarningOut(source="email", code=code, message=message, line_number=line_number, sample=sample)


def _parse_json_line(raw: str, *, line_number: int) -> Tuple[Optional[Dict[str, Any]], Optional[DevtoolsParseWarningOut]]:
    try:
        payload = json.loads(raw)
    except Exception:
        return None, _warning("invalid_json", "line looked like JSON but could not be parsed", line_number=line_number, sample=raw[:300])

    if not isinstance(payload, dict):
        return None, _warning("json_not_object", "JSON log entry must be an object", line_number=line_number, sample=raw[:300])

    ts = payload.get("sent_at") or payload.get("timestamp") or payload.get("ts")
    sent_at = _iso_utc(str(ts)) if ts else None
    if not sent_at:
        return None, _warning("missing_timestamp", "JSON email entry is missing a valid timestamp", line_number=line_number, sample=raw[:300])

    to_emails: List[str] = []
    raw_to = payload.get("to") or payload.get("to_email") or payload.get("to_emails")
    if isinstance(raw_to, str) and raw_to.strip():
        to_emails = [raw_to.strip()]
    elif isinstance(raw_to, list):
        to_emails = [str(v).strip() for v in raw_to if str(v).strip()]

    mailbox = str(payload.get("mailbox") or (to_emails[0] if to_emails else "unknown@example.invalid")).strip().lower()
    subject = str(payload.get("subject") or "").strip() or None
    body_text = str(payload.get("body") or payload.get("body_text") or "").strip() or None
    code = str(payload.get("code") or "").strip() or None
    purpose = str(payload.get("purpose") or "").strip() or None
    event_kind = str(payload.get("event_kind") or ("mfa_email_code" if code else "unknown")).strip() or "unknown"
    status = str(payload.get("status") or "").strip() or None

    thread_seed = subject or body_text or "(no-subject)"
    thread_id = f"thread_{_stable_id(mailbox, thread_seed)}"
    message_id = f"email_{_stable_id(mailbox, sent_at, subject or '', body_text or '', code or '')}"

    return {
        "id": message_id,
        "id_strategy": "sha256(mailbox|sent_at|subject|body_text|code)",
        "thread_id": thread_id,
        "mailbox": mailbox,
        "sent_at": sent_at,
        "event_kind": event_kind if event_kind in {"mfa_email_code", "alert_email", "unknown"} else "unknown",
        "direction": "outbound",
        "from_email": str(payload.get("from") or payload.get("from_email") or "").strip() or None,
        "to_emails": to_emails or ([mailbox] if mailbox else []),
        "subject": subject,
        "body_text": body_text,
        "body_html": str(payload.get("body_html") or "").strip() or None,
        "code": code,
        "purpose": purpose,
        "status": status,
        "parse_warnings": [],
    }, None


def _parse_plain_block(lines: List[str], *, start_line: int) -> Tuple[Optional[Dict[str, Any]], Optional[DevtoolsParseWarningOut]]:
    if not lines:
        return None, None

    header = lines[0].strip()
    m = _HEADER_RE.match(header)
    if not m:
        return None, _warning("invalid_header", "plain-text email block is missing a valid header", line_number=start_line, sample=header[:300])

    ts = _iso_utc(m.group("ts").strip())
    if not ts:
        return None, _warning("invalid_timestamp", "plain-text email block has invalid timestamp", line_number=start_line, sample=header[:300])

    body = m.group("body").strip()
    to_match = _TO_RE.search(body)
    mailbox = (to_match.group(1).strip().lower() if to_match else "unknown@example.invalid")
    purpose_match = _PURPOSE_RE.search(body)
    purpose = purpose_match.group(1).strip() if purpose_match else None
    event_kind = "alert_email" if "ALERT_EMAIL" in body else "mfa_email_code"

    subject: Optional[str] = None
    code: Optional[str] = None
    body_text: Optional[str] = None

    for line in lines[1:]:
        stripped = line.strip()
        if stripped.startswith("Subject:"):
            subject = stripped.split("Subject:", 1)[1].strip() or None
        elif stripped.startswith("Code:"):
            code = stripped.split("Code:", 1)[1].strip() or None
        elif stripped.startswith("Body:"):
            body_text = stripped.split("Body:", 1)[1].strip() or None

    if not subject and not body_text and not code:
        return None, _warning("missing_content", "plain-text email block did not contain subject/body/code fields", line_number=start_line, sample=header[:300])

    thread_seed = subject or body_text or "(no-subject)"
    thread_id = f"thread_{_stable_id(mailbox, thread_seed)}"
    message_id = f"email_{_stable_id(mailbox, ts, subject or '', body_text or '', code or '')}"

    return {
        "id": message_id,
        "id_strategy": "sha256(mailbox|sent_at|subject|body_text|code)",
        "thread_id": thread_id,
        "mailbox": mailbox,
        "sent_at": ts,
        "event_kind": event_kind,
        "direction": "outbound",
        "from_email": None,
        "to_emails": [mailbox] if mailbox else [],
        "subject": subject,
        "body_text": body_text,
        "body_html": None,
        "code": code,
        "purpose": purpose,
        "status": None,
        "parse_warnings": [],
    }, None


def _iter_blocks(path: str) -> Iterable[Tuple[List[str], int]]:
    """Yield plain-text entry blocks while streaming file lines."""

    buf: List[str] = []
    block_start = 1
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for idx, raw in enumerate(fh, start=1):
            line = raw.rstrip("\n")

            if not buf:
                if not line.strip():
                    continue
                buf = [line]
                block_start = idx
                continue

            if line.strip() == "":
                yield buf, block_start
                buf = []
                continue

            if line.startswith("[") and _HEADER_RE.match(line):
                yield buf, block_start
                buf = [line]
                block_start = idx
                continue

            buf.append(line)

    if buf:
        yield buf, block_start


def parse_email_log(
    path: str,
    *,
    mailbox: Optional[str] = None,
    thread_id: Optional[str] = None,
    q: Optional[str] = None,
    state: str = "all",
    limit: int = 50,
    offset: int = 0,
    max_messages: int = 5000,
) -> DevtoolsEmailMessagesOut:
    """Parse email log into canonical email mailbox/thread/message read models.

    The parser streams file input and caps retained messages (`max_messages`) to
    keep memory bounded for large logs.
    """

    warnings: List[DevtoolsParseWarningOut] = []
    selected_mailbox = mailbox.strip().lower() if mailbox else None
    query = q.strip().lower() if q else None

    if not os.path.exists(path):
        warnings.append(_warning("missing_log_file", "email log file does not exist", sample=path))
        return DevtoolsEmailMessagesOut(parse_warnings=warnings)

    # keep newest N using min-heap of (timestamp, seq, item)
    heap: List[Tuple[float, int, Dict[str, Any]]] = []
    seq = 0

    for block, start_line in _iter_blocks(path):
        first = block[0].lstrip()
        if first.startswith("{"):
            item, warn = _parse_json_line("\n".join(block), line_number=start_line)
        else:
            item, warn = _parse_plain_block(block, start_line=start_line)

        if warn is not None:
            warnings.append(warn)
            continue
        if not item:
            continue

        if selected_mailbox and item["mailbox"] != selected_mailbox:
            continue
        if thread_id and item["thread_id"] != thread_id:
            continue

        if state == "unread":
            # dev logs are generated outbound and do not currently model unread state.
            continue
        if state == "sent" and item["direction"] != "outbound":
            continue

        if query:
            haystack = " ".join(
                [
                    item.get("subject") or "",
                    item.get("body_text") or "",
                    item.get("mailbox") or "",
                    " ".join(item.get("to_emails") or []),
                ]
            ).lower()
            if query not in haystack:
                continue

        ts_dt = datetime.fromisoformat(item["sent_at"].replace("Z", "+00:00"))
        ts_val = ts_dt.timestamp()
        seq += 1
        heapq.heappush(heap, (ts_val, seq, item))
        if len(heap) > max_messages:
            heapq.heappop(heap)

    if seq > max_messages:
        warnings.append(
            _warning(
                "message_cap_reached",
                f"retained most recent {max_messages} messages while streaming large log",
            )
        )

    retained = [heapq.heappop(heap)[2] for _ in range(len(heap))]
    retained.sort(key=lambda m: (m["sent_at"], m["id"]), reverse=True)

    paged = retained[offset : offset + limit]
    next_cursor = None
    if offset + limit < len(retained):
        cursor_payload = json.dumps({"offset": offset + limit}).encode("utf-8")
        import base64

        next_cursor = base64.urlsafe_b64encode(cursor_payload).decode("utf-8").rstrip("=")

    messages: List[DevtoolsEmailMessageOut] = []
    thread_map: Dict[Tuple[str, str], Dict[str, Any]] = {}
    mailbox_map: Dict[str, Dict[str, Any]] = {}

    for item in retained:
        mailbox_key = item["mailbox"]
        thread_key = (mailbox_key, item["thread_id"])

        mb = mailbox_map.setdefault(
            mailbox_key,
            {
                "id": f"mailbox_{_stable_id(mailbox_key)}",
                "id_strategy": "sha256(mailbox)",
                "mailbox": mailbox_key,
                "thread_ids": set(),
                "unread_count": 0,
            },
        )
        mb["thread_ids"].add(item["thread_id"])

        thread_entry = thread_map.setdefault(
            thread_key,
            {
                "id": item["thread_id"],
                "id_strategy": "sha256(mailbox|subject-or-body)",
                "mailbox": mailbox_key,
                "subject": item.get("subject"),
                "message_count": 0,
                "unread_count": 0,
                "participant_emails": set(item.get("to_emails") or []),
                "latest_message_at": item["sent_at"],
            },
        )
        thread_entry["message_count"] += 1
        thread_entry["participant_emails"].update(item.get("to_emails") or [])
        if item["sent_at"] > thread_entry["latest_message_at"]:
            thread_entry["latest_message_at"] = item["sent_at"]

    for item in paged:
        messages.append(DevtoolsEmailMessageOut(**item))

    threads = [
        DevtoolsEmailThreadOut(
            id=v["id"],
            id_strategy=v["id_strategy"],
            mailbox=v["mailbox"],
            subject=v["subject"],
            message_count=v["message_count"],
            unread_count=v["unread_count"],
            participant_emails=sorted(v["participant_emails"]),
            latest_message_at=v["latest_message_at"],
        )
        for _, v in sorted(thread_map.items(), key=lambda kv: (kv[1]["latest_message_at"], kv[1]["id"]), reverse=True)
    ]

    mailboxes = [
        DevtoolsEmailMailboxOut(
            id=v["id"],
            id_strategy=v["id_strategy"],
            mailbox=v["mailbox"],
            thread_count=len(v["thread_ids"]),
            unread_count=v["unread_count"],
        )
        for _, v in sorted(mailbox_map.items(), key=lambda kv: kv[0])
    ]

    return DevtoolsEmailMessagesOut(
        mailboxes=mailboxes,
        threads=threads,
        messages=messages,
        next_cursor=next_cursor,
        parse_warnings=warnings,
    )
