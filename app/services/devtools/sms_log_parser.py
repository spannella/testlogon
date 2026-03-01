from __future__ import annotations

import heapq
import json
import os
import re
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Dict, Iterable, List, Optional, Tuple

from app.models import (
    DevtoolsParseWarningOut,
    DevtoolsSmsConversationOut,
    DevtoolsSmsConversationsOut,
    DevtoolsSmsMessageOut,
)

_HEADER_RE = re.compile(r"^\[(?P<ts>[^\]]+)\]\s+(?P<body>.*)$")
_TO_RE = re.compile(r"TO=([^\s]+)")
_FROM_RE = re.compile(r"FROM=([^\s]+)")
_CODE_RE = re.compile(r"Code:\s*([^\s]+)")


def _iso_utc(value: str) -> Optional[str]:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    except Exception:
        return None


def _stable_id(*parts: str, length: int = 20) -> str:
    return sha256("|".join(parts).encode("utf-8")).hexdigest()[:length]


def _warning(code: str, message: str, *, line_number: Optional[int] = None, sample: Optional[str] = None) -> DevtoolsParseWarningOut:
    return DevtoolsParseWarningOut(source="sms", code=code, message=message, line_number=line_number, sample=sample)


def _normalize_phone(raw: Optional[str]) -> Optional[str]:
    if raw is None:
        return None
    cleaned = str(raw).strip()
    return cleaned or None


def _conversation_id(from_number: Optional[str], to_number: Optional[str]) -> str:
    participants = sorted([p for p in [from_number, to_number] if p])
    seed = ",".join(participants) or "unknown"
    return f"conv_{_stable_id(seed)}"


def _parse_json_line(raw: str, *, line_number: int) -> Tuple[Optional[Dict[str, Any]], Optional[DevtoolsParseWarningOut]]:
    try:
        payload = json.loads(raw)
    except Exception:
        return None, _warning("invalid_json", "line looked like JSON but could not be parsed", line_number=line_number, sample=raw[:300])

    if not isinstance(payload, dict):
        return None, _warning("json_not_object", "JSON sms entry must be an object", line_number=line_number, sample=raw[:300])

    ts = payload.get("sent_at") or payload.get("timestamp") or payload.get("ts")
    sent_at = _iso_utc(str(ts)) if ts else None
    if not sent_at:
        return None, _warning("missing_timestamp", "JSON SMS entry is missing a valid timestamp", line_number=line_number, sample=raw[:300])

    to_number = _normalize_phone(payload.get("to") or payload.get("to_number") or payload.get("recipient"))
    from_number = _normalize_phone(payload.get("from") or payload.get("from_number") or payload.get("sender"))
    body_text = str(payload.get("body") or payload.get("body_text") or "").strip() or None
    code = str(payload.get("code") or "").strip() or None
    status = str(payload.get("status") or "").strip() or None
    provider_message_id = str(payload.get("message_id") or payload.get("provider_message_id") or "").strip() or None

    event_kind = str(payload.get("event_kind") or ("mfa_sms_code" if code else "unknown")).strip() or "unknown"
    event_kind = event_kind if event_kind in {"mfa_sms_code", "alert_sms", "unknown"} else "unknown"

    conversation_id = str(payload.get("conversation_id") or _conversation_id(from_number, to_number))
    message_id = f"sms_{_stable_id(conversation_id, sent_at, from_number or '', to_number or '', body_text or '', code or '')}"

    return {
        "id": message_id,
        "id_strategy": "sha256(conversation_id|sent_at|from|to|body|code)",
        "conversation_id": conversation_id,
        "sent_at": sent_at,
        "from_number": from_number,
        "to_number": to_number,
        "direction": str(payload.get("direction") or "outbound") if str(payload.get("direction") or "outbound") in {"inbound", "outbound", "unknown"} else "unknown",
        "body_text": body_text,
        "code": code,
        "status": status,
        "provider_message_id": provider_message_id,
        "event_kind": event_kind,
        "parse_warnings": [],
    }, None


def _parse_plain_block(lines: List[str], *, start_line: int) -> Tuple[Optional[Dict[str, Any]], Optional[DevtoolsParseWarningOut]]:
    if not lines:
        return None, None

    m = _HEADER_RE.match(lines[0].strip())
    if not m:
        return None, _warning("invalid_header", "plain-text SMS block is missing a valid header", line_number=start_line, sample=lines[0][:300])

    sent_at = _iso_utc(m.group("ts").strip())
    if not sent_at:
        return None, _warning("invalid_timestamp", "plain-text SMS block has invalid timestamp", line_number=start_line, sample=lines[0][:300])

    header_body = m.group("body").strip()
    to_match = _TO_RE.search(header_body)
    from_match = _FROM_RE.search(header_body)
    code_match = _CODE_RE.search(header_body)

    to_number = _normalize_phone(to_match.group(1) if to_match else None)
    from_number = _normalize_phone(from_match.group(1) if from_match else None)
    code = _normalize_phone(code_match.group(1) if code_match else None)

    event_kind = "alert_sms" if "ALERT_SMS" in header_body else "mfa_sms_code"
    body_text: Optional[str] = None
    for line in lines[1:]:
        stripped = line.strip()
        if stripped.startswith("Body:"):
            body_text = stripped.split("Body:", 1)[1].strip() or None

    if not to_number and not from_number:
        return None, _warning("missing_participants", "plain-text SMS block missing TO/FROM metadata", line_number=start_line, sample=lines[0][:300])

    conversation_id = _conversation_id(from_number, to_number)
    message_id = f"sms_{_stable_id(conversation_id, sent_at, from_number or '', to_number or '', body_text or '', code or '')}"

    return {
        "id": message_id,
        "id_strategy": "sha256(conversation_id|sent_at|from|to|body|code)",
        "conversation_id": conversation_id,
        "sent_at": sent_at,
        "from_number": from_number,
        "to_number": to_number,
        "direction": "outbound",
        "body_text": body_text,
        "code": code,
        "status": None,
        "provider_message_id": None,
        "event_kind": event_kind,
        "parse_warnings": [],
    }, None


def _iter_blocks(path: str) -> Iterable[Tuple[List[str], int]]:
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
            if not line.strip():
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


def parse_sms_log(
    path: str,
    *,
    participant: Optional[str] = None,
    q: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    max_messages: int = 5000,
) -> DevtoolsSmsConversationsOut:
    warnings: List[DevtoolsParseWarningOut] = []
    participant_filter = participant.strip() if participant else None
    query = q.strip().lower() if q else None

    if not os.path.exists(path):
        warnings.append(_warning("missing_log_file", "sms log file does not exist", sample=path))
        return DevtoolsSmsConversationsOut(parse_warnings=warnings)

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

        participants = [p for p in [item.get("from_number"), item.get("to_number")] if p]
        if participant_filter and participant_filter not in participants:
            continue
        if query:
            haystack = " ".join([item.get("body_text") or "", item.get("from_number") or "", item.get("to_number") or ""]).lower()
            if query not in haystack:
                continue

        ts = datetime.fromisoformat(item["sent_at"].replace("Z", "+00:00")).timestamp()
        seq += 1
        heapq.heappush(heap, (ts, seq, item))
        if len(heap) > max_messages:
            heapq.heappop(heap)

    if seq > max_messages:
        warnings.append(_warning("message_cap_reached", f"retained most recent {max_messages} sms messages while streaming large log"))

    retained = [heapq.heappop(heap)[2] for _ in range(len(heap))]
    retained.sort(key=lambda m: (m["sent_at"], m["id"]), reverse=True)

    paged = retained[offset : offset + limit]
    next_cursor = None
    if offset + limit < len(retained):
        payload = json.dumps({"offset": offset + limit}).encode("utf-8")
        import base64

        next_cursor = base64.urlsafe_b64encode(payload).decode("utf-8").rstrip("=")

    conv_map: Dict[str, Dict[str, Any]] = {}
    for item in retained:
        cid = item["conversation_id"]
        participants = sorted({p for p in [item.get("from_number"), item.get("to_number")] if p})
        conv = conv_map.setdefault(
            cid,
            {
                "id": cid,
                "id_strategy": "sha256(sorted(participants))",
                "participant_numbers": participants,
                "message_count": 0,
                "latest_message_at": item["sent_at"],
                "latest_preview": item.get("body_text") or item.get("code"),
            },
        )
        conv["message_count"] += 1
        if item["sent_at"] > conv["latest_message_at"]:
            conv["latest_message_at"] = item["sent_at"]
            conv["latest_preview"] = item.get("body_text") or item.get("code")

    messages = [DevtoolsSmsMessageOut(**item) for item in paged]
    conversations = [
        DevtoolsSmsConversationOut(
            id=v["id"],
            id_strategy=v["id_strategy"],
            participant_numbers=v["participant_numbers"],
            message_count=v["message_count"],
            latest_message_at=v["latest_message_at"],
            latest_preview=v["latest_preview"],
        )
        for _, v in sorted(conv_map.items(), key=lambda kv: (kv[1]["latest_message_at"], kv[0]), reverse=True)
    ]

    return DevtoolsSmsConversationsOut(
        conversations=conversations,
        messages=messages,
        next_cursor=next_cursor,
        parse_warnings=warnings,
    )
