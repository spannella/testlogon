"""CRM Workflow Condition Evaluator — WFL-003.

Pure, stateless module. Accepts a list of condition dicts and a flat record
dict, and returns (matched: bool, details: list[dict]).

Zero DynamoDB calls. No I/O. Thread-safe.
"""
from __future__ import annotations

import logging
from datetime import datetime
from decimal import Decimal
from typing import Any

from app.core.settings import S

logger = logging.getLogger(__name__)

_SUPPORTED_OPERATORS = frozenset(
    {"eq", "neq", "contains", "gt", "lt", "is_empty", "is_not_empty"}
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def evaluate_conditions(
    conditions: list[dict],
    record: dict,
) -> tuple[bool, list[dict]]:
    """Evaluate a list of conditions against a record dict.

    Returns (matched, details). All conditions are ANDed; short-circuits on
    first failure. Empty conditions list → (True, []).

    When S.crm_workflow_enabled is False → (False, []) unconditionally.
    """
    if not S.crm_workflow_enabled:
        return (False, [])
    if not conditions:
        return (True, [])

    details: list[dict] = []
    for condition in conditions:
        passed, entry = _eval_one(condition, record)
        details.append(entry)
        if not passed:
            return (False, details)
    return (True, details)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _resolve_field(field: str, record: dict) -> Any:
    """Resolve one level of dot-notation field access on the record dict.

    Returns None if the key is absent or the parent is not a dict.
    """
    if "." in field:
        parts = field.split(".", 1)
        parent = record.get(parts[0])
        if not isinstance(parent, dict):
            return None
        return parent.get(parts[1])
    return record.get(field)


def _is_empty(value: Any) -> bool:
    """Return True for None, blank/whitespace strings, and empty collections."""
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() == ""
    if isinstance(value, (list, dict, set, tuple)):
        return len(value) == 0
    # Numeric zero (0, False) is NOT considered empty
    return False


def _to_float(value: Any) -> float:
    """Coerce a value to float for gt/lt comparisons.

    Handles int, float, Decimal (from DynamoDB), numeric strings, and
    ISO-8601 datetime strings. Raises ValueError on unconvertible input.
    """
    if isinstance(value, bool):
        # bool is a subclass of int; treat True/False as 1.0/0.0
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, str):
        stripped = value.strip()
        try:
            return float(stripped)
        except ValueError:
            pass
        # Try ISO-8601 datetime
        try:
            dt = datetime.fromisoformat(stripped.replace("Z", "+00:00"))
            return dt.timestamp()
        except ValueError:
            pass
        raise ValueError(f"Cannot coerce {value!r} to float")
    raise ValueError(f"Cannot coerce {type(value).__name__} to float")


def _apply_operator(operator: str, record_value: Any, condition_value: str | None) -> bool:
    """Apply a comparison operator. Raises on type errors (caught by _eval_one)."""
    cv: str = condition_value if condition_value is not None else ""

    if operator == "is_empty":
        return _is_empty(record_value)
    if operator == "is_not_empty":
        return not _is_empty(record_value)

    rv_str = str(record_value) if record_value is not None else ""

    if operator == "eq":
        return rv_str.lower() == cv.lower()
    if operator == "neq":
        return rv_str.lower() != cv.lower()
    if operator == "contains":
        return cv.lower() in rv_str.lower()
    if operator == "gt":
        return _to_float(record_value) > _to_float(cv)
    if operator == "lt":
        return _to_float(record_value) < _to_float(cv)
    raise ValueError(f"Unsupported operator: {operator!r}")


def _eval_one(condition: dict, record: dict) -> tuple[bool, dict]:
    """Evaluate one condition dict against the record.

    Never raises — exceptions are absorbed into entry["error"].
    Returns (passed, detail_entry).
    """
    field = condition.get("field", "")
    operator = condition.get("operator", "")
    condition_value = condition.get("value")

    record_value = _resolve_field(field, record)
    rv_str = str(record_value) if record_value is not None else ""
    cv_str = condition_value if condition_value is not None else ""

    entry: dict[str, Any] = {
        "field": field,
        "operator": operator,
        "value": cv_str,
        "record_value": rv_str,
        "passed": False,
    }

    if operator not in _SUPPORTED_OPERATORS:
        entry["error"] = "unknown_operator"
        return (False, entry)

    try:
        passed = _apply_operator(operator, record_value, condition_value)
        entry["passed"] = passed
        return (passed, entry)
    except Exception as exc:
        logger.debug(
            "crm_workflow condition eval error field=%s op=%s: %s",
            field,
            operator,
            exc,
        )
        entry["error"] = "type_error"
        return (False, entry)
