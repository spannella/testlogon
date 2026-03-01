from __future__ import annotations

import heapq
import json
import os
import re
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Dict, Iterable, List, Literal, Optional, Tuple

from app.models import (
    DevtoolsBillingLedgerEntryOut,
    DevtoolsBillingLedgerOut,
    DevtoolsParseWarningOut,
)
from app.services.devtools.billing_summary_service import build_billing_summary

Provider = Literal["stripe", "ccbill", "paypal"]

_ACCESS_RE = re.compile(r'"(?P<method>[A-Z]+)\s+(?P<path>/[^\s]+)\s+HTTP/[0-9.]+"\s+(?P<status>\d{3})')


def _warning(code: str, message: str, *, line_number: Optional[int] = None, sample: Optional[str] = None) -> DevtoolsParseWarningOut:
    return DevtoolsParseWarningOut(source="billing", code=code, message=message, line_number=line_number, sample=sample)


def _stable_id(*parts: str, length: int = 20) -> str:
    return sha256("|".join(parts).encode("utf-8")).hexdigest()[:length]


def _iso_utc(value: Any) -> Optional[str]:
    if value is None:
        return None
    try:
        if isinstance(value, (int, float)):
            dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
        else:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    except Exception:
        return None


def _parse_amount(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        if isinstance(value, int):
            # Stripe often stores minor units.
            return round(value / 100.0, 6)
        return float(value)
    except Exception:
        return None


def _detect_provider(payload: Dict[str, Any]) -> Optional[Provider]:
    explicit = str(payload.get("provider") or "").strip().lower()
    if explicit in {"stripe", "ccbill", "paypal"}:
        return explicit  # type: ignore[return-value]
    if payload.get("transactionId") or payload.get("paymentUniqueId"):
        return "ccbill"
    if payload.get("purchase_units") or str(payload.get("id") or "").startswith("CAP-"):
        return "paypal"
    if payload.get("type") and payload.get("data"):
        return "stripe"
    return None


def _stripe_entry(payload: Dict[str, Any], source_path: str) -> Optional[Dict[str, Any]]:
    obj = payload.get("data", {}).get("object", {}) if isinstance(payload.get("data"), dict) else {}
    event_type = str(payload.get("type") or "stripe.event")
    status = str(obj.get("status") or payload.get("status") or "unknown")
    created = _iso_utc(payload.get("created") or obj.get("created") or payload.get("timestamp"))
    amount = _parse_amount(obj.get("amount") or obj.get("amount_total") or payload.get("amount"))
    fee = _parse_amount(obj.get("fee") or payload.get("fee")) or 0.0
    currency = str(obj.get("currency") or payload.get("currency") or "usd").lower()
    external_id = str(obj.get("id") or payload.get("id") or "").strip() or None

    if not created or amount is None:
        return None

    return {
        "provider": "stripe",
        "event_type": event_type,
        "status": status,
        "occurred_at": created,
        "external_id": external_id,
        "amount": amount,
        "fee": fee,
        "net": amount - fee,
        "currency": currency,
        "source_path": source_path,
        "raw_payload": payload,
    }


def _ccbill_entry(payload: Dict[str, Any], source_path: str) -> Optional[Dict[str, Any]]:
    created = _iso_utc(payload.get("timestamp") or payload.get("created_at") or payload.get("time"))
    amount = _parse_amount(payload.get("amount") or payload.get("initialPrice") or payload.get("recurringPrice"))
    fee = _parse_amount(payload.get("fee")) or 0.0
    currency = str(payload.get("currency") or payload.get("currencyCode") or "usd").lower()
    status = str(payload.get("status") or ("completed" if payload.get("approved") else "failed"))
    event_type = str(payload.get("eventType") or payload.get("type") or "ccbill.charge")
    external_id = str(payload.get("transactionId") or payload.get("paymentUniqueId") or payload.get("subscriptionId") or "").strip() or None

    if not created or amount is None:
        return None

    return {
        "provider": "ccbill",
        "event_type": event_type,
        "status": status,
        "occurred_at": created,
        "external_id": external_id,
        "amount": amount,
        "fee": fee,
        "net": amount - fee,
        "currency": currency,
        "source_path": source_path,
        "raw_payload": payload,
    }


def _paypal_entry(payload: Dict[str, Any], source_path: str) -> Optional[Dict[str, Any]]:
    cap = None
    units = payload.get("purchase_units")
    if isinstance(units, list) and units:
        cap = (((units[0] or {}).get("payments") or {}).get("captures") or [None])[0]

    amount_obj = (cap or {}).get("amount") or payload.get("amount") or {}
    amount = _parse_amount((amount_obj or {}).get("value") if isinstance(amount_obj, dict) else amount_obj)
    currency = str((amount_obj or {}).get("currency_code") if isinstance(amount_obj, dict) else payload.get("currency") or "usd").lower()

    created = _iso_utc(payload.get("timestamp") or payload.get("create_time") or payload.get("update_time") or payload.get("created_at"))
    if not created:
        # Many mock payloads omit create_time; use deterministic epoch fallback only when explicitly absent.
        created = "1970-01-01T00:00:00Z"

    fee = _parse_amount(payload.get("fee")) or 0.0
    status = str((cap or {}).get("status") or payload.get("status") or "unknown")
    event_type = str(payload.get("event_type") or payload.get("type") or "paypal.capture")
    external_id = str((cap or {}).get("id") or payload.get("id") or "").strip() or None

    if amount is None:
        return None

    return {
        "provider": "paypal",
        "event_type": event_type,
        "status": status,
        "occurred_at": created,
        "external_id": external_id,
        "amount": amount,
        "fee": fee,
        "net": amount - fee,
        "currency": currency,
        "source_path": source_path,
        "raw_payload": payload,
    }


def _iter_file(path: str) -> Iterable[Tuple[int, str]]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for idx, raw in enumerate(fh, start=1):
            line = raw.strip()
            if line:
                yield idx, line


def _parse_access_line(line: str, *, line_number: int, source_path: str) -> Optional[DevtoolsParseWarningOut]:
    m = _ACCESS_RE.search(line)
    if not m:
        return _warning("unsupported_line", "unrecognized billing log line", line_number=line_number, sample=line[:300])
    path = m.group("path")
    if "/mock/ccbill/" in path or "/mock/paypal/" in path or "/mock/stripe" in path:
        return _warning(
            "access_log_without_payload",
            "provider access log line found without payload body; skipping",
            line_number=line_number,
            sample=line[:300],
        )
    return None


def _normalize_payload(provider: Provider, payload: Dict[str, Any], source_path: str) -> Optional[Dict[str, Any]]:
    if provider == "stripe":
        return _stripe_entry(payload, source_path)
    if provider == "ccbill":
        return _ccbill_entry(payload, source_path)
    return _paypal_entry(payload, source_path)


def parse_billing_logs(
    stripe_log_path: str,
    backend_log_path: str,
    *,
    provider: Optional[Provider] = None,
    status: Optional[str] = None,
    from_ts: Optional[str] = None,
    to_ts: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    max_entries: int = 5000,
) -> DevtoolsBillingLedgerOut:
    warnings: List[DevtoolsParseWarningOut] = []
    from_cutoff = _iso_utc(from_ts) if from_ts else None
    to_cutoff = _iso_utc(to_ts) if to_ts else None

    heap: List[Tuple[float, int, Dict[str, Any]]] = []
    seq = 0

    for source_path in [stripe_log_path, backend_log_path]:
        if not os.path.exists(source_path):
            warnings.append(_warning("missing_log_file", "billing log file does not exist", sample=source_path))
            continue

        for line_number, line in _iter_file(source_path):
            if line.startswith("{"):
                try:
                    payload = json.loads(line)
                except Exception:
                    warnings.append(_warning("invalid_json", "billing log JSON could not be parsed", line_number=line_number, sample=line[:300]))
                    continue
                if not isinstance(payload, dict):
                    warnings.append(_warning("json_not_object", "billing log JSON entry must be an object", line_number=line_number, sample=line[:300]))
                    continue
                detected = _detect_provider(payload)
                if not detected:
                    warnings.append(_warning("unknown_provider", "could not determine billing provider for payload", line_number=line_number, sample=line[:300]))
                    continue
                if provider and detected != provider:
                    continue

                normalized = _normalize_payload(detected, payload, source_path)
                if not normalized:
                    warnings.append(_warning("unsupported_event", "provider payload missing required amount/timestamp fields", line_number=line_number, sample=line[:300]))
                    continue

                if status and str(normalized["status"]).lower() != status.lower():
                    continue

                occurred = normalized["occurred_at"]
                if from_cutoff and occurred < from_cutoff:
                    continue
                if to_cutoff and occurred > to_cutoff:
                    continue

                normalized["id"] = f"ledger_{_stable_id(normalized['provider'], normalized.get('external_id') or '', normalized['occurred_at'], str(normalized['amount']))}"
                normalized["id_strategy"] = "sha256(provider|external_id|occurred_at|amount)"

                ts = datetime.fromisoformat(occurred.replace("Z", "+00:00")).timestamp()
                seq += 1
                heapq.heappush(heap, (ts, seq, normalized))
                if len(heap) > max_entries:
                    heapq.heappop(heap)
            else:
                warn = _parse_access_line(line, line_number=line_number, source_path=source_path)
                if warn:
                    warnings.append(warn)

    if seq > max_entries:
        warnings.append(_warning("entry_cap_reached", f"retained most recent {max_entries} billing entries while streaming large logs"))

    retained = [heapq.heappop(heap)[2] for _ in range(len(heap))]
    retained.sort(key=lambda e: (e["occurred_at"], e["id"]), reverse=True)

    paged = retained[offset : offset + limit]
    next_cursor = None
    if offset + limit < len(retained):
        payload = json.dumps({"offset": offset + limit}).encode("utf-8")
        import base64

        next_cursor = base64.urlsafe_b64encode(payload).decode("utf-8").rstrip("=")

    entries = [DevtoolsBillingLedgerEntryOut(**row) for row in paged]

    summary = build_billing_summary(retained)

    return DevtoolsBillingLedgerOut(
        entries=entries,
        summary=summary,
        next_cursor=next_cursor,
        parse_warnings=warnings,
    )
