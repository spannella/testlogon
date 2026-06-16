"""OBP PAY-004 — FX rate store + integer convert helper (offline/hermetic).

moto in-memory ``fx_rates`` table bound to the frozen ``T.fx_rates`` handle via
``object.__setattr__`` (restored on teardown). ``audit_event`` is a best-effort
no-op import in the service, so no patching needed. No real AWS / no TestClient.
"""
from __future__ import annotations

import boto3
import pytest

try:
    from moto import mock_aws
except Exception:  # pragma: no cover
    mock_aws = None

pytestmark = pytest.mark.skipif(mock_aws is None, reason="moto not installed")


def _make_table(ddb):
    return ddb.create_table(
        TableName="fx_rates",
        KeySchema=[
            {"AttributeName": "pair", "KeyType": "HASH"},
            {"AttributeName": "as_of", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pair", "AttributeType": "S"},
            {"AttributeName": "as_of", "AttributeType": "N"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@pytest.fixture(scope="module", autouse=True)
def _bind_fx_table():
    if mock_aws is None:
        yield
        return
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        table = _make_table(ddb)
        from app.core.tables import T

        original = getattr(T, "fx_rates", None)
        object.__setattr__(T, "fx_rates", table)
        try:
            yield
        finally:
            object.__setattr__(T, "fx_rates", original)


def test_admin_set_and_newest_read(monkeypatch):
    import app.services.fx_rates as svc

    clock = {"t": 1000}

    def _tick():
        clock["t"] += 1
        return clock["t"]

    monkeypatch.setattr(svc, "now_ts", _tick)
    svc.set_rate("EUR", "USD", 1.10, source="admin", set_by="root")
    svc.set_rate("EUR", "USD", 1.20, source="admin", set_by="root")  # newer as_of overrides
    rate = svc.get_rate("EUR", "USD")
    assert rate is not None
    assert rate["pair"] == "EUR_USD"
    assert abs(rate["rate"] - 1.20) < 1e-9  # newest-row-by-numeric-SK


def test_integer_convert_no_float_drift():
    from app.services import fx_rates as svc

    svc.set_rate("GBP", "USD", 1.25, set_by="root")
    conv = svc.convert(10000, "GBP", "USD")
    assert conv["target_amount_cents"] == 12500  # 10000 * 1.25 (integer scaled math)
    assert conv["source_amount_cents"] == 10000
    assert abs(conv["rate"] - 1.25) < 1e-9


def test_usd_usd_identity():
    from app.services import fx_rates as svc

    rate = svc.get_rate("USD", "USD")
    assert rate is not None and rate["rate"] == 1.0
    conv = svc.convert(777, "usd", "usd")
    assert conv["target_amount_cents"] == 777
    assert conv["rate"] == 1.0


def test_missing_pair_raises_lookup():
    from app.services import fx_rates as svc

    with pytest.raises(LookupError):
        svc.convert(100, "JPY", "USD")


def test_convert_writes_no_ledger_row():
    """convert must NOT write any ledger/wallet row (money-safety #5)."""
    import app.services.fx_rates as svc

    # billing_shared.new_ledger_entry must never be called by convert. Spy via import.
    called = {"n": 0}
    try:
        import app.services.billing_shared as bs

        orig = getattr(bs, "new_ledger_entry", None)
        if orig is not None:
            def _spy(*a, **k):
                called["n"] += 1
                return orig(*a, **k)

            bs.new_ledger_entry = _spy  # type: ignore
    except Exception:
        orig = None
    try:
        svc.set_rate("CAD", "USD", 0.75, set_by="root")
        svc.convert(20000, "CAD", "USD")
    finally:
        try:
            if orig is not None:
                import app.services.billing_shared as bs2

                bs2.new_ledger_entry = orig  # type: ignore
        except Exception:
            pass
    assert called["n"] == 0


def test_rate_history_is_append_only(monkeypatch):
    import app.services.fx_rates as svc
    from app.core.tables import T

    clock = {"t": 5000}

    def _tick():
        clock["t"] += 1
        return clock["t"]

    monkeypatch.setattr(svc, "now_ts", _tick)
    svc.set_rate("AUD", "USD", 0.60, set_by="root")
    svc.set_rate("AUD", "USD", 0.65, set_by="root")
    from boto3.dynamodb.conditions import Key

    resp = T.fx_rates.query(KeyConditionExpression=Key("pair").eq("AUD_USD"))
    assert len(resp["Items"]) == 2  # both as_of rows retained
