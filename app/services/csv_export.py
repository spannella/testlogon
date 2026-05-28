"""Server-side CSV export service (PLATFORM-009).

Generates streaming CSV data from DynamoDB for various data sources.
Uses Python's csv.writer for proper RFC 4180 CSV formatting (handling
commas, quotes, newlines in field values).

Supports:
  - billing_ledger: Billing history for a user
  - contacts: Contact records for a user
  - questionnaire_responses: Response sessions for a questionnaire
"""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional

from app.core.tables import T
from app.services.billing_shared import user_pk

logger = logging.getLogger(__name__)

# Maximum rows per export (safety limit)
MAX_EXPORT_ROWS = 50_000


# --- Column Definitions ---

BILLING_COLUMNS = ["Date", "Type", "Amount", "Currency", "Status", "Reason", "Transaction ID"]
CONTACTS_COLUMNS = ["Name", "Email", "Phone", "Company", "Tags", "Is Favorite", "Is Blocked", "Created At"]
QUESTIONNAIRE_COLUMNS = ["Respondent ID", "Started At", "Submitted At", "Status", "Duration (s)", "Version", "Answers"]


# --- CSV Injection Sanitization ---

_DANGEROUS_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _sanitize_csv_field(value: str) -> str:
    """Prevent CSV formula injection by prefixing dangerous characters."""
    if value and value[0] in _DANGEROUS_PREFIXES:
        return f"'{value}"
    return value


# --- Data Source Iterators ---

def _iter_billing_entries(
    user_sub: str,
    *,
    from_date: Optional[int] = None,
    to_date: Optional[int] = None,
) -> Generator[Dict[str, Any], None, None]:
    """Iterate over billing ledger entries with optional date filtering.

    Uses DynamoDB query with SK prefix 'LEDGER#' and handles pagination
    via LastEvaluatedKey loop.
    """
    pk = user_pk(user_sub)
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": "pk = :pk AND begins_with(sk, :prefix)",
        "ExpressionAttributeValues": {":pk": pk, ":prefix": "LEDGER#"},
        "Limit": 500,
    }

    row_count = 0
    while row_count < MAX_EXPORT_ROWS:
        resp = T.billing.query(**kwargs)
        items = resp.get("Items", [])
        for item in items:
            ts = int(item.get("created_at", 0))
            if from_date and ts < from_date:
                continue
            if to_date and ts > to_date:
                continue
            yield item
            row_count += 1
            if row_count >= MAX_EXPORT_ROWS:
                break

        if "LastEvaluatedKey" not in resp or row_count >= MAX_EXPORT_ROWS:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def _iter_contacts(user_sub: str) -> Generator[Dict[str, Any], None, None]:
    """Iterate over contact records for a user."""
    from boto3.dynamodb.conditions import Key

    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("owner_id").eq(user_sub),
        "Limit": 500,
    }

    row_count = 0
    while row_count < MAX_EXPORT_ROWS:
        resp = T.contacts.query(**kwargs)
        for item in resp.get("Items", []):
            yield item
            row_count += 1
            if row_count >= MAX_EXPORT_ROWS:
                break

        if "LastEvaluatedKey" not in resp or row_count >= MAX_EXPORT_ROWS:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def _iter_questionnaire_responses(
    questionnaire_id: str,
) -> Generator[Dict[str, Any], None, None]:
    """Iterate over questionnaire response sessions."""
    from app.services.questionnaires_repository import DynamoQuestionnaireRepository
    repo = DynamoQuestionnaireRepository()
    sessions = repo.list_response_sessions(questionnaire_id=questionnaire_id)
    for session in sessions[:MAX_EXPORT_ROWS]:
        yield session


# --- Row Formatters ---

def _ts_to_iso(ts: Any) -> str:
    """Convert Unix timestamp to ISO 8601 string."""
    try:
        ts_int = int(ts)
    except (TypeError, ValueError):
        return ""
    if not ts_int:
        return ""
    return datetime.fromtimestamp(ts_int, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _format_billing_row(item: Dict[str, Any]) -> List[str]:
    ts = int(item.get("created_at", 0))
    amount_cents = int(item.get("amount_cents", 0))
    # Extract transaction ID from sort key (last segment after #)
    sk = item.get("sk", "")
    txn_id = sk.split("#")[-1] if sk else ""
    return [
        _sanitize_csv_field(_ts_to_iso(ts)),
        _sanitize_csv_field(str(item.get("entry_type", ""))),
        f"{amount_cents / 100:.2f}",
        str(item.get("currency", "USD")),
        str(item.get("state", "")),
        _sanitize_csv_field(str(item.get("reason", ""))),
        _sanitize_csv_field(txn_id),
    ]


def _format_contacts_row(item: Dict[str, Any]) -> List[str]:
    tags = item.get("tags", [])
    tag_str = "; ".join(tags) if isinstance(tags, list) else str(tags or "")
    return [
        _sanitize_csv_field(str(item.get("display_name", ""))),
        _sanitize_csv_field(str(item.get("email", ""))),
        _sanitize_csv_field(str(item.get("phone", ""))),
        _sanitize_csv_field(str(item.get("company", ""))),
        _sanitize_csv_field(tag_str),
        str(item.get("is_favorite", False)),
        str(item.get("is_blocked", False)),
        _sanitize_csv_field(str(item.get("added_at", ""))),
    ]


def _format_questionnaire_row(item: Dict[str, Any]) -> List[str]:
    started = item.get("started_at", 0)
    submitted = item.get("submitted_at", 0)
    try:
        started_int = int(started) if started else 0
        submitted_int = int(submitted) if submitted else 0
    except (TypeError, ValueError):
        started_int = 0
        submitted_int = 0
    duration = (submitted_int - started_int) if submitted_int and started_int and submitted_int >= started_int else ""
    answers = item.get("answers", {})
    # For sessions, answers might be stored separately; include what's in the item
    return [
        _sanitize_csv_field(str(item.get("respondent_id", item.get("user_sub", "anonymous")) or "anonymous")),
        _sanitize_csv_field(_ts_to_iso(started)),
        _sanitize_csv_field(_ts_to_iso(submitted)),
        str(item.get("status", "")),
        str(duration),
        _sanitize_csv_field(str(item.get("version_id", ""))),
        json.dumps(answers, default=str) if answers else "",
    ]


# --- Main Generator ---

def generate_csv_rows(
    source: str,
    user_sub: str,
    *,
    from_date: Optional[int] = None,
    to_date: Optional[int] = None,
    questionnaire_id: Optional[str] = None,
) -> Generator[str, None, None]:
    """Generate CSV rows as strings for streaming response.

    Yields the header row first, then one string per data row.
    Each string includes the trailing newline.

    Uses csv.writer to properly escape commas, quotes, and newlines
    per RFC 4180.
    """
    buf = io.StringIO()
    writer = csv.writer(buf)

    # Determine columns and iterator
    if source == "billing_ledger":
        columns = BILLING_COLUMNS
        iterator = _iter_billing_entries(user_sub, from_date=from_date, to_date=to_date)
        formatter = _format_billing_row
    elif source == "contacts":
        columns = CONTACTS_COLUMNS
        iterator = _iter_contacts(user_sub)
        formatter = _format_contacts_row
    elif source == "questionnaire_responses":
        if not questionnaire_id:
            raise ValueError("questionnaire_id is required for questionnaire_responses source")
        columns = QUESTIONNAIRE_COLUMNS
        iterator = _iter_questionnaire_responses(questionnaire_id)
        formatter = _format_questionnaire_row
    else:
        raise ValueError(f"Unknown source: {source}")

    # Write UTF-8 BOM for Excel compatibility
    yield "﻿"

    # Write header
    writer.writerow(columns)
    yield buf.getvalue()
    buf.truncate(0)
    buf.seek(0)

    # Write data rows
    for item in iterator:
        try:
            row = formatter(item)
            writer.writerow(row)
            yield buf.getvalue()
            buf.truncate(0)
            buf.seek(0)
        except Exception:
            logger.warning("csv_row_format_error", extra={"source": source})
            continue
