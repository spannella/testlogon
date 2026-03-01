from app.services.devtools.billing_summary_service import build_billing_summary


def test_summary_aggregates_totals_counts_and_sign_handling() -> None:
    entries = [
        {
            "provider": "stripe",
            "status": "completed",
            "amount": 10.0,
            "fee": 0.5,
            "net": 9.5,
            "currency": "usd",
        },
        {
            "provider": "paypal",
            "status": "refunded",
            "amount": -2.0,
            "fee": -0.2,
            "net": -1.8,
            "currency": "usd",
        },
        {
            "provider": "ccbill",
            "status": "completed",
            "amount": 5.0,
            "fee": 0.25,
            "net": 4.75,
            "currency": "usd",
        },
    ]

    out = build_billing_summary(entries)

    # inflow ignores negative amount
    assert out.gross_inflow == 15.0
    # fees accumulate absolute fee values
    assert out.fees == 0.95
    assert out.net_total_balance == 12.45
    assert out.transaction_count == 3
    assert out.provider_counts == {"stripe": 1, "paypal": 1, "ccbill": 1}
    assert out.status_counts == {"completed": 2, "refunded": 1}
    assert out.parse_warnings == []


def test_summary_empty_and_mixed_currency_warning() -> None:
    empty = build_billing_summary([])
    assert empty.gross_inflow == 0.0
    assert empty.fees == 0.0
    assert empty.net_total_balance == 0.0
    assert empty.transaction_count == 0
    assert empty.provider_counts == {}
    assert empty.status_counts == {}

    mixed = build_billing_summary(
        [
            {"provider": "stripe", "status": "completed", "amount": 1, "fee": 0, "net": 1, "currency": "usd"},
            {"provider": "paypal", "status": "completed", "amount": 1, "fee": 0, "net": 1, "currency": "eur"},
        ]
    )
    assert len(mixed.parse_warnings) == 1
    assert mixed.parse_warnings[0].code == "mixed_currency_totals"
