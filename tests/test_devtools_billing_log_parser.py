from __future__ import annotations

from pathlib import Path

from app.services.devtools.billing_log_parser import parse_billing_logs


def test_billing_parser_normalizes_stripe_ccbill_paypal_to_unified_schema(tmp_path: Path) -> None:
    stripe = tmp_path / "stripe.log"
    backend = tmp_path / "backend.log"

    stripe.write_text(
        "\n".join(
            [
                '{"provider":"stripe","type":"payment_intent.succeeded","created":1700000000,"data":{"object":{"id":"pi_1","status":"succeeded","amount":1500,"currency":"USD"}},"fee":50}',
            ]
        ),
        encoding="utf-8",
    )

    backend.write_text(
        "\n".join(
            [
                '{"transactionId":"txn_1","approved":true,"status":"completed","amount":"10.00","currencyCode":"USD","timestamp":"2026-03-01T10:00:00Z"}',
                '{"id":"MOCK-ORDER-1","status":"COMPLETED","purchase_units":[{"payments":{"captures":[{"id":"CAP-1","status":"COMPLETED","amount":{"currency_code":"USD","value":"9.99"}}]}}],"timestamp":"2026-03-01T11:00:00Z"}',
            ]
        ),
        encoding="utf-8",
    )

    out = parse_billing_logs(str(stripe), str(backend), limit=20)

    assert len(out.entries) == 3
    providers = {e.provider for e in out.entries}
    assert providers == {"stripe", "ccbill", "paypal"}

    for entry in out.entries:
        assert entry.event_type
        assert entry.currency == "usd"
        assert entry.occurred_at.endswith("Z")
        assert entry.id
        assert entry.id_strategy

    assert out.summary.transaction_count == 3
    assert out.summary.gross_inflow > 0
    assert out.summary.net_total_balance == round(sum(e.net for e in out.entries), 6)


def test_billing_parser_filters_deterministic_order_and_warnings(tmp_path: Path) -> None:
    stripe = tmp_path / "stripe.log"
    backend = tmp_path / "backend.log"
    stripe.write_text(
        "\n".join(
            [
                '{"provider":"stripe","type":"payment_intent.succeeded","created":1700000010,"data":{"object":{"id":"pi_a","status":"completed","amount":1000,"currency":"usd"}}}',
                '{"provider":"stripe","type":"payment_intent.failed","created":1700000020,"data":{"object":{"id":"pi_b","status":"failed","amount":2000,"currency":"usd"}}}',
                '{bad json}',
            ]
        ),
        encoding="utf-8",
    )
    backend.write_text('INFO: 127.0.0.1 - "POST /mock/paypal/v2/checkout/orders HTTP/1.1" 200 OK\n', encoding="utf-8")

    first = parse_billing_logs(str(stripe), str(backend), provider="stripe", status="completed", limit=10)
    second = parse_billing_logs(str(stripe), str(backend), provider="stripe", status="completed", limit=10)

    assert first.model_dump() == second.model_dump()
    assert len(first.entries) == 1
    assert first.entries[0].status == "completed"
    warning_codes = {w.code for w in first.parse_warnings}
    assert "invalid_json" in warning_codes
    assert "access_log_without_payload" in warning_codes


def test_billing_parser_tolerates_missing_logs_and_pagination(tmp_path: Path) -> None:
    stripe = tmp_path / "stripe.log"
    stripe.write_text(
        "\n".join(
            [
                '{"provider":"stripe","type":"payment_intent.succeeded","created":1700000000,"data":{"object":{"id":"pi_1","status":"succeeded","amount":1000,"currency":"usd"}}}',
                '{"provider":"stripe","type":"payment_intent.succeeded","created":1700000001,"data":{"object":{"id":"pi_2","status":"succeeded","amount":1100,"currency":"usd"}}}',
                '{"provider":"stripe","type":"payment_intent.succeeded","created":1700000002,"data":{"object":{"id":"pi_3","status":"succeeded","amount":1200,"currency":"usd"}}}',
            ]
        ),
        encoding="utf-8",
    )

    out = parse_billing_logs(str(stripe), str(tmp_path / "missing-backend.log"), limit=2, offset=0)
    assert len(out.entries) == 2
    assert out.next_cursor is not None
    assert any(w.code == "missing_log_file" for w in out.parse_warnings)
