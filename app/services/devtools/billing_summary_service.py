from __future__ import annotations

from collections import defaultdict
from typing import Iterable, Mapping, Any

from app.models import DevtoolsBillingLedgerSummaryOut, DevtoolsParseWarningOut


def _num(value: Any) -> float:
    try:
        return float(value)
    except Exception:
        return 0.0


def build_billing_summary(entries: Iterable[Mapping[str, Any]]) -> DevtoolsBillingLedgerSummaryOut:
    """Aggregate normalized ledger entries into a summary DTO.

    Sign/currency handling rules:
    - `gross_inflow`: sum of positive `amount` values only (inflow-oriented).
    - `fees`: sum of absolute positive fee values.
    - `net_total_balance`: signed sum of each row net (`net` if present else `amount - fee`).
    - Mixed currencies are tolerated; totals are numeric aggregates and a parse warning
      is emitted if more than one currency appears.
    """

    gross_inflow = 0.0
    fees = 0.0
    net_total_balance = 0.0
    transaction_count = 0
    provider_counts: dict[str, int] = defaultdict(int)
    status_counts: dict[str, int] = defaultdict(int)
    currency_counts: dict[str, int] = defaultdict(int)

    for row in entries:
        amount = _num(row.get("amount"))
        fee = _num(row.get("fee"))
        net = _num(row.get("net"))
        if row.get("net") is None:
            net = amount - fee

        if amount > 0:
            gross_inflow += amount
        if fee > 0:
            fees += fee
        else:
            fees += abs(fee)
        net_total_balance += net

        provider = str(row.get("provider") or "unknown")
        status = str(row.get("status") or "unknown")
        currency = str(row.get("currency") or "unknown").lower()

        provider_counts[provider] += 1
        status_counts[status] += 1
        currency_counts[currency] += 1
        transaction_count += 1

    warnings: list[DevtoolsParseWarningOut] = []
    if len(currency_counts) > 1:
        warnings.append(
            DevtoolsParseWarningOut(
                source="billing",
                code="mixed_currency_totals",
                message="summary totals include multiple currencies; amounts are aggregated numerically",
                sample=",".join(sorted(currency_counts.keys())),
            )
        )

    return DevtoolsBillingLedgerSummaryOut(
        gross_inflow=round(gross_inflow, 6),
        fees=round(fees, 6),
        net_total_balance=round(net_total_balance, 6),
        transaction_count=transaction_count,
        provider_counts=dict(provider_counts),
        status_counts=dict(status_counts),
        parse_warnings=warnings,
    )
