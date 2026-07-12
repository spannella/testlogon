"""hotel_tax_currency.py — HTL-036 tax + multi-currency wire-in.

Double-flag-gated helpers consumed by HTL-029/031 folio/invoice computation.
With all INV sub-flags off (their default) these functions are byte-for-byte
identical to the existing flat-bps / opaque-currency behaviour in invoices.py.
No if-S.dev_mode branch (SECOPS-007 parity).
"""
from __future__ import annotations

from app.core.settings import S


def resolve_tax_cents(
    amount_cents: int,
    *,
    tax_rate_id: str | None = None,
    tax_rate_name: str | None = None,
) -> int:
    """Resolve tax for a folio/invoice amount.

    Double-guarded (INV-005 §5.7): the registry accessor is consulted ONLY when
    both CRM_TAX_RATES_ENABLED and AOS_PER_LINE_TAX_ENABLED are on AND the lazy
    import + accessor call succeed. Any miss → flat-bps fallback (today's behaviour:
    app/services/invoices.py:306).
    """
    if (
        getattr(S, "crm_tax_rates_enabled", False)
        and getattr(S, "aos_per_line_tax_enabled", False)
    ):
        try:
            from app.services import crm_tax_rates  # lazy: registry may not exist
            if tax_rate_name:
                rate = crm_tax_rates.get_tax_rate_by_name(tax_rate_name)
            else:
                rate = crm_tax_rates.get_tax_rate(tax_rate_id)
            bps = int(rate["rate_bps"])
            return (amount_cents * max(0, bps)) // 10_000
        except Exception:
            pass
    # Fallback: exactly app/services/invoices.py:306
    return (amount_cents * max(0, int(getattr(S, "invoices_tax_bps", 0)))) // 10_000


def resolve_currency_amount(
    amount_cents: int,
    folio_currency: str,
    platform_currency: str = "usd",
) -> tuple[int, str, int]:
    """Returns (display_amount_cents, original_currency, usd_amount_cents).

    Convert ONLY when CRM_CURRENCIES_ENABLED + AOS_INVOICE_CURRENCY_CONVERSION_ENABLED
    are on and the folio currency differs from the platform default. Otherwise store the
    opaque currency string with no conversion (today's behaviour, invoices.py:334).
    Integer cents at the boundary; no float money.
    """
    iso = (folio_currency or platform_currency).lower()
    if (
        getattr(S, "crm_currencies_enabled", False)
        and getattr(S, "aos_invoice_currency_conversion_enabled", False)
        and iso != platform_currency
    ):
        try:
            from app.services import crm_currencies  # lazy: registry may not exist
            usd = crm_currencies.convert_amount(amount_cents, iso, platform_currency)
            return amount_cents, iso, int(usd)
        except Exception:
            pass
    # Fallback: opaque currency, no conversion (invoices.py:334)
    return amount_cents, "", amount_cents
