"""PLT-004: Sandbox JSON import service — bulk-seeds accounts/transactions/customers."""
from __future__ import annotations

import logging
import secrets
from typing import Any, Dict, List

from app.core.tables import T
from app.core.settings import S
from app.core.time import now_ts

logger = logging.getLogger(__name__)

_SECTION_CAP_ERROR_INDEX = -1


def _generate_user_sub() -> str:
    return f"customer_{secrets.token_hex(6)}"


def _write_customer(row: Any) -> str:
    """Write users + profile rows. Returns the resolved user_sub."""
    try:
        from app.core.normalize import normalize_email
    except ImportError:
        def normalize_email(s: str) -> str:  # type: ignore[misc]
            return (s or "").strip().lower()

    user_sub = (row.user_sub or "").strip() or _generate_user_sub()
    email = normalize_email(row.email)
    now = now_ts()
    user_item: Dict[str, Any] = {
        "user_sub": user_sub,
        "email": email,
        "created_at": now,
        "updated_at": now,
        "source": "sandbox_import",
    }
    if row.full_name:
        user_item["full_name"] = row.full_name

    # Guarded put — raises ConditionalCheckFailedException on duplicate
    from botocore.exceptions import ClientError
    T.users.put_item(
        Item=user_item,
        ConditionExpression="attribute_not_exists(user_sub)",
    )

    # Profile put — unconditional (always refresh profile on re-import success)
    profile_body: Dict[str, Any] = {}
    if row.display_name:
        profile_body["display_name"] = row.display_name
    if row.bio:
        profile_body["bio"] = row.bio
    T.profile.put_item(Item={
        "user_sub": user_sub,
        "profile": profile_body,
        "audit": [],
        "updated_at": now,
        "source": "sandbox_import",
    })
    return user_sub


def _write_account(row: Any) -> None:
    """Ensure wallet/balance row; apply initial balance delta."""
    try:
        from app.services.billing_shared import apply_wallet_delta
    except ImportError:
        logger.error("billing_shared unavailable in sandbox_import._write_account")
        raise

    pk = f"USER#{row.user_sub}"
    # apply_wallet_delta with delta=0 auto-creates the WALLET row
    apply_wallet_delta(T.billing, pk, row.initial_balance_cents, currency=row.currency)


def _write_transaction(row: Any) -> str:
    """Write one ledger row via new_ledger_entry. Returns the ledger sk."""
    try:
        from app.services.billing_shared import new_ledger_entry
    except ImportError:
        logger.error("billing_shared unavailable in sandbox_import._write_transaction")
        raise

    pk = f"USER#{row.user_sub}"
    sk, item = new_ledger_entry(
        key_name="pk",
        key_value=pk,
        entry_type=row.entry_type,
        amount_cents=row.amount_cents,
        state=row.state,
        reason=row.reason,
        extra={"source": "sandbox_import"},
    )
    T.billing.put_item(Item=item)
    return sk


def import_sandbox_payload(payload: Any, *, actor_sub: str) -> Any:
    """Process a SandboxImportIn payload. Returns a SandboxImportResult.

    Never raises on row-level errors; collects them and returns partial success.
    """
    try:
        from app.models import SandboxImportResult, SandboxRowError
    except ImportError:
        raise

    max_items = int(getattr(S, "sandbox_import_max_items", 500) or 500)
    errors: List[Any] = []
    customers_created = 0
    accounts_created = 0
    transactions_created = 0

    # -- Customers --
    customers = list(payload.customers or [])
    if len(customers) > max_items:
        customers = customers[:max_items]
        errors.append(SandboxRowError(
            section="customers",
            index=_SECTION_CAP_ERROR_INDEX,
            code="section_truncated",
            message=f"capped at {max_items}",
        ))
    for i, row in enumerate(customers):
        try:
            _write_customer(row)
            customers_created += 1
        except Exception as exc:
            code = "duplicate_user_sub" if "ConditionalCheckFailed" in type(exc).__name__ else "write_error"
            errors.append(SandboxRowError(
                section="customers",
                index=i,
                code=code,
                message=str(exc),
            ))

    # -- Accounts --
    accounts = list(payload.accounts or [])
    if len(accounts) > max_items:
        accounts = accounts[:max_items]
        errors.append(SandboxRowError(
            section="accounts",
            index=_SECTION_CAP_ERROR_INDEX,
            code="section_truncated",
            message=f"capped at {max_items}",
        ))
    for i, row in enumerate(accounts):
        try:
            _write_account(row)
            accounts_created += 1
        except Exception as exc:
            errors.append(SandboxRowError(
                section="accounts",
                index=i,
                code="write_error",
                message=str(exc),
            ))

    # -- Transactions --
    transactions = list(payload.transactions or [])
    if len(transactions) > max_items:
        transactions = transactions[:max_items]
        errors.append(SandboxRowError(
            section="transactions",
            index=_SECTION_CAP_ERROR_INDEX,
            code="section_truncated",
            message=f"capped at {max_items}",
        ))
    for i, row in enumerate(transactions):
        try:
            _write_transaction(row)
            transactions_created += 1
        except Exception as exc:
            errors.append(SandboxRowError(
                section="transactions",
                index=i,
                code="write_error",
                message=str(exc),
            ))

    return SandboxImportResult(
        customers_created=customers_created,
        accounts_created=accounts_created,
        transactions_created=transactions_created,
        errors=errors,
        ok=True,
    )
