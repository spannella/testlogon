from __future__ import annotations

from copy import deepcopy
import json
from threading import Lock, Thread
from types import SimpleNamespace

from botocore.exceptions import ClientError
from fastapi import Request
import pytest

from app.main import create_app
from app.services import api_pricing_catalog, api_usage_metering

_APP = create_app()


class _KeyExpr:
    def __init__(self, attr: str, op: str, value: str):
        self.attr = attr
        self.op = op
        self.value = value
        self.right = None

    def __and__(self, other):
        self.right = other
        return self


class _FakeKey:
    def __init__(self, attr: str):
        self.attr = attr

    def eq(self, value: str):
        return _KeyExpr(self.attr, "eq", value)

    def begins_with(self, value: str):
        return _KeyExpr(self.attr, "begins", value)


class _FakeTable:
    def __init__(self) -> None:
        self.items: dict[tuple[str, str], dict] = {}
        self.fail_aggregate_once = False
        self._lock = Lock()

    def put_item(self, *, Item, ConditionExpression=None):
        with self._lock:
            key = (Item["PK"], Item["SK"])
            if ConditionExpression and key in self.items:
                raise ClientError({"Error": {"Code": "ConditionalCheckFailedException", "Message": "dup"}}, "PutItem")
            self.items[key] = deepcopy(Item)

    def get_item(self, *, Key):
        with self._lock:
            key = (Key["PK"], Key["SK"])
            return {"Item": deepcopy(self.items.get(key))} if key in self.items else {}

    def update_item(self, *, Key, UpdateExpression, ExpressionAttributeValues, ExpressionAttributeNames=None, **_kwargs):
        with self._lock:
            key = (Key["PK"], Key["SK"])
            item = deepcopy(self.items.get(key, {"PK": Key["PK"], "SK": Key["SK"]}))

            # Quota conditional path
            if ExpressionAttributeNames and "#f" in ExpressionAttributeNames and ":limit" in ExpressionAttributeValues:
                field = ExpressionAttributeNames["#f"]
                limit = int(ExpressionAttributeValues[":limit"])
                current = int(item.get(field, 0))
                if current >= limit:
                    raise ClientError({"Error": {"Code": "ConditionalCheckFailedException", "Message": "limit"}}, "UpdateItem")
                item[field] = current + int(ExpressionAttributeValues[":inc"])
                item["updated_at"] = ExpressionAttributeValues.get(":updated_at")
                item["ttl_epoch"] = int(ExpressionAttributeValues.get(":ttl", 0))
                for attr in ("entity_type", "user_sub", "bucket"):
                    token = f":{attr}"
                    if token in ExpressionAttributeValues:
                        item[attr] = item.get(attr, ExpressionAttributeValues[token])
                self.items[key] = item
                return

            if "ADD calls_total" in UpdateExpression:
                if self.fail_aggregate_once:
                    self.fail_aggregate_once = False
                    raise RuntimeError("simulated aggregate write failure")
                for field, vkey in {
                    "calls_total": ":calls_inc",
                    "billable_calls_total": ":billable_inc",
                    "request_units_total": ":units_inc",
                    "cost_subtotal_micros": ":cost_inc",
                }.items():
                    item[field] = int(item.get(field, 0)) + int(ExpressionAttributeValues[vkey])
                for attr in ("entity_type", "user_sub", "period_id", "api_key_id", "route_id", "product", "day_utc"):
                    token = f":{attr}"
                    if token in ExpressionAttributeValues:
                        item[attr] = item.get(attr, ExpressionAttributeValues[token])
                if ":unit_price_micros" in ExpressionAttributeValues:
                    item["unit_price_micros"] = int(ExpressionAttributeValues[":unit_price_micros"])
                if ":updated_at" in ExpressionAttributeValues:
                    item["updated_at"] = ExpressionAttributeValues[":updated_at"]
                self.items[key] = item
                return

            if UpdateExpression == "SET aggregates_applied = :t":
                item = deepcopy(self.items[key])
                item["aggregates_applied"] = bool(ExpressionAttributeValues[":t"])
                self.items[key] = item
                return

            raise AssertionError(UpdateExpression)

    def query(self, *, KeyConditionExpression, Limit, IndexName=None):
        left = KeyConditionExpression
        right = getattr(left, "right", None)

        def _match(it: dict, expr: _KeyExpr) -> bool:
            val = str(it.get(expr.attr) or "")
            if expr.op == "eq":
                return val == str(expr.value)
            if expr.op == "begins":
                return val.startswith(str(expr.value))
            raise AssertionError(expr.op)

        rows = []
        for it in self.items.values():
            if _match(it, left) and (right is None or _match(it, right)):
                rows.append(deepcopy(it))
        return {"Items": rows[:max(1, min(int(Limit), 5000))]}

    def scan(self, *, Limit=1000):
        return {"Items": deepcopy(list(self.items.values())[:max(1, min(int(Limit), 10000))])}


def _request(path: str, *, method: str = "GET", headers: dict[str, str] | None = None) -> Request:
    app = _APP
    route = next((r for r in app.routes if getattr(r, "path", None) == path and method in getattr(r, "methods", set())), None)
    if route is None:
        from fastapi.routing import APIRoute
        route = APIRoute(path=path, endpoint=lambda: None, methods=[method])
    hdrs = [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in (headers or {}).items()]
    return Request({"type": "http", "method": method, "path": path, "headers": hdrs, "query_string": b"", "route": route, "app": app})


def _mock_pricing(monkeypatch, unit_price: int = 100, version: str = "v1") -> None:
    monkeypatch.setattr(api_usage_metering, "resolve_route_pricing", lambda **_kwargs: SimpleNamespace(unit_price_micros=unit_price, pricing_catalog_version=version))


def test_recompute_repairs_and_daily_series(monkeypatch) -> None:
    monkeypatch.setattr(api_usage_metering, "Key", _FakeKey)
    table = _FakeTable()
    _mock_pricing(monkeypatch, unit_price=111)
    for i in range(8):
        status = 200 if i % 2 == 0 else 401
        e = api_usage_metering.build_api_usage_event(_request("/ui/api_keys", headers={"x-user-sub": "u2", "x-request-id": f"r{i}", "x-api-key": "ak_kx.s"}), status)
        assert e
        e["timestamp"] = f"2026-03-{1 + (i % 3):02d}T12:00:00+00:00"
        e["period_id"] = "2026-03"
        api_usage_metering.record_api_usage_event_and_aggregates(table, e)

    table.items[("USER#u2", "API_USAGE#PERIOD#2026-03")]["calls_total"] = 999
    report = api_usage_metering.recompute_api_usage_aggregates(table=table, scope="user", user_sub="u2", period_id="2026-03", apply=True)
    assert report["drift_report"]["period"] >= 1
    daily = api_usage_metering.query_api_usage_daily(table, user_sub="u2", from_day="2026-03-01", to_day="2026-03-31")
    assert len(daily["items"]) == 3


def test_quota_denial_contract_deterministic(monkeypatch) -> None:
    monkeypatch.setattr(api_usage_metering, "Key", _FakeKey)
    _mock_pricing(monkeypatch, unit_price=10)
    table = _FakeTable()
    monkeypatch.setattr(api_usage_metering, "_quota_table", lambda: table)
    monkeypatch.setattr(
        api_usage_metering,
        "S",
        SimpleNamespace(
            api_usage_account_rps_limit=1,
            api_usage_account_rpm_limit=0,
            api_usage_account_daily_calls_limit=0,
            api_usage_account_monthly_calls_limit=0,
            api_usage_account_monthly_spend_micros_limit=0,
        ),
    )
    req = _request("/ui/api_keys", headers={"x-user-sub": "u1", "x-request-id": "q1"})
    api_usage_metering.enforce_account_quota_pre_request(req)
    try:
        api_usage_metering.enforce_account_quota_pre_request(req)
        assert False
    except Exception as exc:
        detail = exc.detail
        assert exc.status_code == 429
        assert detail["code"] == "api_limit_exceeded"
        assert detail["scope"] == "account"
        assert detail["limit_type"] == "rps"


def test_quota_concurrency_overrun_is_bounded(monkeypatch) -> None:
    monkeypatch.setattr(api_usage_metering, "Key", _FakeKey)
    _mock_pricing(monkeypatch, unit_price=10)
    table = _FakeTable()
    monkeypatch.setattr(api_usage_metering, "_quota_table", lambda: table)
    monkeypatch.setattr(
        api_usage_metering,
        "S",
        SimpleNamespace(
            api_usage_account_rps_limit=20,
            api_usage_account_rpm_limit=0,
            api_usage_account_daily_calls_limit=0,
            api_usage_account_monthly_calls_limit=0,
            api_usage_account_monthly_spend_micros_limit=0,
        ),
    )

    ok = 0
    lock = Lock()

    def _run(i: int):
        nonlocal ok
        req = _request("/ui/api_keys", headers={"x-user-sub": "u-race", "x-request-id": f"r{i}"})
        try:
            api_usage_metering.enforce_account_quota_pre_request(req)
            with lock:
                ok += 1
        except Exception:
            pass

    threads = [Thread(target=_run, args=(i,)) for i in range(120)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert ok <= 22  # small bounded overrun tolerance under race


def test_monthly_spend_quota_denial(monkeypatch) -> None:
    monkeypatch.setattr(api_usage_metering, "Key", _FakeKey)
    _mock_pricing(monkeypatch, unit_price=250)
    table = _FakeTable()
    monkeypatch.setattr(api_usage_metering, "_quota_table", lambda: table)
    monkeypatch.setattr(
        api_usage_metering,
        "S",
        SimpleNamespace(
            api_usage_account_rps_limit=0,
            api_usage_account_rpm_limit=0,
            api_usage_account_daily_calls_limit=0,
            api_usage_account_monthly_calls_limit=0,
            api_usage_account_monthly_spend_micros_limit=500,
        ),
    )

    req = _request("/ui/api_keys", headers={"x-user-sub": "u-spend", "x-request-id": "m1"})
    api_usage_metering.enforce_account_quota_pre_request(req)
    api_usage_metering.enforce_account_quota_pre_request(req)
    with pytest.raises(Exception) as exc:
        api_usage_metering.enforce_account_quota_pre_request(req)

    assert exc.value.status_code == 429
    assert exc.value.detail["limit_type"] == "monthly_spend"
    assert exc.value.detail["scope"] == "account"


def test_api_key_monthly_calls_self_limit_denial(monkeypatch) -> None:
    monkeypatch.setattr(api_usage_metering, "Key", _FakeKey)
    _mock_pricing(monkeypatch, unit_price=10)
    table = _FakeTable()
    monkeypatch.setattr(api_usage_metering, "_quota_table", lambda: table)
    monkeypatch.setattr(
        api_usage_metering,
        "S",
        SimpleNamespace(
            api_usage_account_rps_limit=0,
            api_usage_account_rpm_limit=0,
            api_usage_account_daily_calls_limit=0,
            api_usage_account_monthly_calls_limit=0,
            api_usage_account_monthly_spend_micros_limit=0,
        ),
    )
    monkeypatch.setattr(
        api_usage_metering,
        "get_api_key_item",
        lambda key_id: {"key_id": key_id, "user_sub": "u-key", "monthly_calls_cap": 2, "monthly_spend_cap_micros": 0, "route_caps": {}},
    )

    req = _request("/ui/api_keys", headers={"x-user-sub": "u-key", "x-request-id": "k1", "x-api-key": "ak_k1.secret"})
    api_usage_metering.enforce_account_quota_pre_request(req)
    api_usage_metering.enforce_account_quota_pre_request(req)
    with pytest.raises(Exception) as exc:
        api_usage_metering.enforce_account_quota_pre_request(req)

    assert exc.value.status_code == 429
    assert exc.value.detail["scope"] == "api_key"
    assert exc.value.detail["limit_type"] == "api_key_monthly_calls"
    assert exc.value.detail["api_key_id"] == "k1"


def test_api_key_route_calls_self_limit_denial(monkeypatch) -> None:
    monkeypatch.setattr(api_usage_metering, "Key", _FakeKey)
    _mock_pricing(monkeypatch, unit_price=10)
    table = _FakeTable()
    monkeypatch.setattr(api_usage_metering, "_quota_table", lambda: table)
    monkeypatch.setattr(
        api_usage_metering,
        "S",
        SimpleNamespace(
            api_usage_account_rps_limit=0,
            api_usage_account_rpm_limit=0,
            api_usage_account_daily_calls_limit=0,
            api_usage_account_monthly_calls_limit=0,
            api_usage_account_monthly_spend_micros_limit=0,
        ),
    )
    monkeypatch.setattr(
        api_usage_metering,
        "get_api_key_item",
        lambda key_id: {
            "key_id": key_id,
            "user_sub": "u-key",
            "monthly_calls_cap": 0,
            "monthly_spend_cap_micros": 0,
            "route_caps": {"GET:/ui/api_keys": {"monthly_calls_cap": 1, "monthly_spend_cap_micros": 0}},
        },
    )

    req = _request("/ui/api_keys", headers={"x-user-sub": "u-key", "x-request-id": "k2", "x-api-key": "ak_k2.secret"})
    api_usage_metering.enforce_account_quota_pre_request(req)
    with pytest.raises(Exception) as exc:
        api_usage_metering.enforce_account_quota_pre_request(req)

    assert exc.value.status_code == 429
    assert exc.value.detail["scope"] == "api_key"
    assert exc.value.detail["limit_type"] == "api_key_route_monthly_calls"
    assert exc.value.detail["api_key_id"] == "k2"


def test_api_key_warning_threshold_headers_key_level(monkeypatch) -> None:
    monkeypatch.setattr(api_usage_metering, "Key", _FakeKey)
    _mock_pricing(monkeypatch, unit_price=10)
    table = _FakeTable()
    monkeypatch.setattr(api_usage_metering, "_quota_table", lambda: table)
    monkeypatch.setattr(
        api_usage_metering,
        "S",
        SimpleNamespace(
            api_usage_account_rps_limit=0,
            api_usage_account_rpm_limit=0,
            api_usage_account_daily_calls_limit=0,
            api_usage_account_monthly_calls_limit=0,
            api_usage_account_monthly_spend_micros_limit=0,
        ),
    )
    monkeypatch.setattr(
        api_usage_metering,
        "get_api_key_item",
        lambda key_id: {"key_id": key_id, "user_sub": "u-warn", "monthly_calls_cap": 10, "monthly_spend_cap_micros": 0, "route_caps": {}},
    )

    req = _request("/ui/api_keys", headers={"x-user-sub": "u-warn", "x-request-id": "wk", "x-api-key": "ak_wk.secret"})
    headers = {}
    for _ in range(7):
        headers = api_usage_metering.enforce_account_quota_pre_request(req)

    assert "api_key_monthly_calls:70" in headers.get("x-api-limit-warning", "")
    assert headers.get("x-api-limit-warning-max") == "70"


def test_api_key_warning_threshold_headers_route_level(monkeypatch) -> None:
    monkeypatch.setattr(api_usage_metering, "Key", _FakeKey)
    _mock_pricing(monkeypatch, unit_price=10)
    table = _FakeTable()
    monkeypatch.setattr(api_usage_metering, "_quota_table", lambda: table)
    monkeypatch.setattr(
        api_usage_metering,
        "S",
        SimpleNamespace(
            api_usage_account_rps_limit=0,
            api_usage_account_rpm_limit=0,
            api_usage_account_daily_calls_limit=0,
            api_usage_account_monthly_calls_limit=0,
            api_usage_account_monthly_spend_micros_limit=0,
        ),
    )
    monkeypatch.setattr(
        api_usage_metering,
        "get_api_key_item",
        lambda key_id: {
            "key_id": key_id,
            "user_sub": "u-warn-route",
            "monthly_calls_cap": 0,
            "monthly_spend_cap_micros": 0,
            "route_caps": {"GET:/ui/api_keys": {"monthly_calls_cap": 20, "monthly_spend_cap_micros": 0}},
        },
    )

    req = _request("/ui/api_keys", headers={"x-user-sub": "u-warn-route", "x-request-id": "wr", "x-api-key": "ak_wr.secret"})
    headers = {}
    for _ in range(17):
        headers = api_usage_metering.enforce_account_quota_pre_request(req)

    assert "api_key_route_monthly_calls:85" in headers.get("x-api-limit-warning", "")
    assert headers.get("x-api-limit-warning-max") == "85"


def test_get_api_usage_summary_for_period_includes_limits_remaining(monkeypatch) -> None:
    table = _FakeTable()
    monkeypatch.setattr(api_usage_metering, "S", SimpleNamespace(api_usage_account_monthly_calls_limit=100, api_usage_account_monthly_spend_micros_limit=1000))
    table.items[("USER#u3", "API_USAGE#PERIOD#2026-04")] = {
        "PK": "USER#u3",
        "SK": "API_USAGE#PERIOD#2026-04",
        "calls_total": 40,
        "billable_calls_total": 30,
        "request_units_total": 30,
        "cost_subtotal_micros": 250,
    }

    out = api_usage_metering.get_api_usage_summary_for_period(table, user_sub="u3", period_id="2026-04")
    assert out["period"] == "2026-04"
    assert out["totals"]["calls_total"] == 40
    assert out["totals"]["estimated_cost_micros"] == 250
    assert out["limits"]["monthly_calls_limit"] == 100
    assert out["remaining"]["monthly_calls_remaining"] == 60
    assert out["remaining"]["monthly_spend_micros_remaining"] == 750


def test_get_api_usage_summary_for_period_without_table(monkeypatch) -> None:
    monkeypatch.setattr(api_usage_metering, "S", SimpleNamespace(api_usage_account_monthly_calls_limit=0, api_usage_account_monthly_spend_micros_limit=0))
    out = api_usage_metering.get_api_usage_summary_for_period(None, user_sub="u0", period_id="2026-05")
    assert out["totals"]["calls_total"] == 0
    assert out["remaining"]["monthly_calls_remaining"] is None


def test_route_breakdown_pagination_and_sort(monkeypatch) -> None:
    monkeypatch.setattr(api_usage_metering, "Key", _FakeKey)
    table = _FakeTable()
    for i in range(6):
        table.items[("USER#u9", f"API_USAGE#ROUTE#GET:/r{i}#PERIOD#2026-04")] = {
            "PK": "USER#u9",
            "SK": f"API_USAGE#ROUTE#GET:/r{i}#PERIOD#2026-04",
            "period_id": "2026-04",
            "route_id": f"GET:/r{i}",
            "calls_total": i + 1,
            "billable_calls_total": i + 1,
            "request_units_total": i + 1,
            "cost_subtotal_micros": (i + 1) * 10,
            "unit_price_micros": 10,
        }

    page1 = api_usage_metering.list_api_usage_route_breakdown(table, user_sub="u9", period_id="2026-04", sort_by="calls_total", order="desc", limit=2)
    assert page1["count"] == 2
    assert page1["items"][0]["route_id"] == "GET:/r5"
    assert page1["next_cursor"] is not None

    page2 = api_usage_metering.list_api_usage_route_breakdown(table, user_sub="u9", period_id="2026-04", sort_by="calls_total", order="desc", limit=2, cursor=page1["next_cursor"])
    assert page2["count"] == 2
    assert page2["items"][0]["route_id"] == "GET:/r3"


def test_key_breakdown_filter_and_pagination(monkeypatch) -> None:
    monkeypatch.setattr(api_usage_metering, "Key", _FakeKey)
    table = _FakeTable()
    for i in range(5):
        table.items[("USER#u8", f"API_USAGE#KEY#k{i}#PERIOD#2026-04")] = {
            "PK": "USER#u8",
            "SK": f"API_USAGE#KEY#k{i}#PERIOD#2026-04",
            "period_id": "2026-04",
            "api_key_id": f"k{i}",
            "calls_total": i + 1,
            "billable_calls_total": i + 1,
            "request_units_total": i + 1,
            "cost_subtotal_micros": (i + 1) * 100,
        }

    out = api_usage_metering.list_api_usage_key_breakdown(table, user_sub="u8", period_id="2026-04", search="k1", limit=10)
    assert out["total"] == 1
    assert out["items"][0]["api_key_id"] == "k1"


def test_get_api_key_usage_period_totals_reads_aggregate_row(monkeypatch) -> None:
    table = _FakeTable()
    table.items[("USER#u10", "API_USAGE#KEY#k10#PERIOD#2026-06")] = {
        "PK": "USER#u10",
        "SK": "API_USAGE#KEY#k10#PERIOD#2026-06",
        "calls_total": 7,
        "billable_calls_total": 5,
        "request_units_total": 5,
        "cost_subtotal_micros": 777,
    }
    out = api_usage_metering.get_api_key_usage_period_totals(table, user_sub="u10", key_id="k10", period_id="2026-06")
    assert out["api_key_id"] == "k10"
    assert out["calls_total"] == 7
    assert out["cost_subtotal_micros"] == 777


def test_api_billing_snapshot_finalized_immutable_and_reproducible(monkeypatch) -> None:
    monkeypatch.setattr(api_usage_metering, "Key", _FakeKey)
    _mock_pricing(monkeypatch, unit_price=50)
    table = _FakeTable()

    for i in range(3):
        e = api_usage_metering.build_api_usage_event(_request("/ui/api_keys", headers={"x-user-sub": "u-snap", "x-request-id": f"s{i}", "x-api-key": "ak_k1.secret"}), 200)
        assert e
        e["period_id"] = "2026-07"
        e["timestamp"] = f"2026-07-0{i+1}T12:00:00+00:00"
        api_usage_metering.record_api_usage_event_and_aggregates(table, e)

    snap = api_usage_metering.finalize_api_billing_usage_snapshot(table, user_sub="u-snap", period_id="2026-07", version=1)
    assert snap["status"] == "finalized"
    assert snap["totals"]["calls_total"] == 3
    assert len(snap["by_route"]) >= 1
    assert len(snap["by_key"]) >= 1

    # finalized snapshot remains immutable and reproducible
    with pytest.raises(Exception):
        api_usage_metering.create_api_billing_usage_snapshot(table, user_sub="u-snap", period_id="2026-07", version=1, status="draft")

    finalized_again = api_usage_metering.finalize_api_billing_usage_snapshot(table, user_sub="u-snap", period_id="2026-07", version=1)
    assert finalized_again["totals"]["calls_total"] == snap["totals"]["calls_total"]


def test_api_billing_snapshot_contains_key_and_route_breakdowns(monkeypatch) -> None:
    monkeypatch.setattr(api_usage_metering, "Key", _FakeKey)
    _mock_pricing(monkeypatch, unit_price=25)
    table = _FakeTable()

    e1 = api_usage_metering.build_api_usage_event(_request("/ui/api_keys", headers={"x-user-sub": "u-br", "x-request-id": "b1", "x-api-key": "ak_a.secret"}), 200)
    e2 = api_usage_metering.build_api_usage_event(_request("/ui/api_keys", headers={"x-user-sub": "u-br", "x-request-id": "b2", "x-api-key": "ak_b.secret"}), 200)
    assert e1 and e2
    for e in (e1, e2):
        e["period_id"] = "2026-08"
        e["timestamp"] = "2026-08-01T12:00:00+00:00"
        api_usage_metering.record_api_usage_event_and_aggregates(table, e)

    snap = api_usage_metering.create_api_billing_usage_snapshot(table, user_sub="u-br", period_id="2026-08", status="draft")
    assert snap["status"] == "draft"
    assert snap["source_event_count"] == 2
    assert sum(int(i["calls_total"]) for i in snap["by_key"]) == 2
    assert sum(int(i["calls_total"]) for i in snap["by_route"]) == 2


def test_calculate_period_charges_tier_pricing_deterministic(monkeypatch) -> None:
    monkeypatch.setattr(
        api_usage_metering,
        "load_api_pricing_catalog",
        lambda: [
            api_pricing_catalog.PricingCatalogVersion(
                pricing_catalog_version="v1",
                effective_at=0,
                routes={
                    "GET:/ui/api_keys": api_pricing_catalog.RoutePrice(
                        price_per_call_micros=100,
                        tiers=[
                            api_pricing_catalog.RoutePriceTier(up_to_calls=2, price_per_call_micros=10),
                            api_pricing_catalog.RoutePriceTier(up_to_calls=4, price_per_call_micros=20),
                        ],
                    )
                },
                default_route=None,
            )
        ],
    )

    events = []
    for i in range(5):
        events.append({
            "event_id": f"e{i}",
            "user_sub": "u-charge",
            "route_id": "GET:/ui/api_keys",
            "pricing_catalog_version": "v1",
            "timestamp": f"2026-09-01T00:00:0{i}+00:00",
            "billable": True,
            "request_units": 1,
        })

    out1 = api_usage_metering.calculate_period_charges_from_events(period_id="2026-09", events=events)
    out2 = api_usage_metering.calculate_period_charges_from_events(period_id="2026-09", events=list(reversed(events)))
    assert out1["total_charge_micros"] == 160  # 10+10+20+20+100
    assert out1["total_charge_micros"] == out2["total_charge_micros"]
    assert out1["line_items"][0]["unit_prices_micros"] == [10, 10, 20, 20, 100]


def test_calculate_period_charges_version_split(monkeypatch) -> None:
    monkeypatch.setattr(
        api_usage_metering,
        "load_api_pricing_catalog",
        lambda: [
            api_pricing_catalog.PricingCatalogVersion(
                pricing_catalog_version="v1",
                effective_at=0,
                routes={"GET:/ui/api_keys": api_pricing_catalog.RoutePrice(price_per_call_micros=10, tiers=[])},
                default_route=None,
            ),
            api_pricing_catalog.PricingCatalogVersion(
                pricing_catalog_version="v2",
                effective_at=100,
                routes={"GET:/ui/api_keys": api_pricing_catalog.RoutePrice(price_per_call_micros=25, tiers=[])},
                default_route=None,
            ),
        ],
    )

    events = [
        {"event_id": "a", "user_sub": "u-v", "route_id": "GET:/ui/api_keys", "pricing_catalog_version": "v1", "timestamp": "2026-09-01T00:00:01+00:00", "billable": True, "request_units": 1},
        {"event_id": "b", "user_sub": "u-v", "route_id": "GET:/ui/api_keys", "pricing_catalog_version": "v2", "timestamp": "2026-09-01T00:00:02+00:00", "billable": True, "request_units": 1},
        {"event_id": "c", "user_sub": "u-v", "route_id": "GET:/ui/api_keys", "pricing_catalog_version": "v2", "timestamp": "2026-09-01T00:00:03+00:00", "billable": True, "request_units": 1},
    ]

    out = api_usage_metering.calculate_period_charges_from_events(period_id="2026-09", events=events)
    assert out["total_charge_micros"] == 60
    assert len(out["line_items"]) == 2
    by_ver = {li["pricing_catalog_version"]: li for li in out["line_items"]}
    assert by_ver["v1"]["subtotal_micros"] == 10
    assert by_ver["v2"]["subtotal_micros"] == 50


def test_generate_api_invoice_line_items_and_adjustment_linkage(monkeypatch) -> None:
    monkeypatch.setattr(api_usage_metering, "Key", _FakeKey)
    _mock_pricing(monkeypatch, unit_price=100)
    table = _FakeTable()

    for i in range(2):
        e = api_usage_metering.build_api_usage_event(_request("/ui/api_keys", headers={"x-user-sub": "u-bill", "x-request-id": f"i{i}", "x-api-key": "ak_kx.secret"}), 200)
        assert e
        e["period_id"] = "2026-10"
        e["timestamp"] = f"2026-10-01T00:00:0{i}+00:00"
        api_usage_metering.record_api_usage_event_and_aggregates(table, e)

    snap = api_usage_metering.finalize_api_billing_usage_snapshot(table, user_sub="u-bill", period_id="2026-10", version=1)
    inv = api_usage_metering.generate_api_invoice_line_items_for_snapshot(table, user_sub="u-bill", period_id="2026-10", snapshot_version=1, include_key_sublines=True)
    assert inv["snapshot_sk"].endswith("V0001")
    assert inv["total_amount_micros"] == int(snap["totals"]["cost_subtotal_micros"])
    assert len(inv["line_items"]) >= 1

    adj = api_usage_metering.create_api_billing_adjustment(
        table,
        user_sub="u-bill",
        period_id="2026-10",
        snapshot_version=1,
        adjustment_type="credit",
        amount_micros=50,
        reason="promo",
    )
    assert adj["snapshot_sk"] == inv["snapshot_sk"]
    report = api_usage_metering.export_api_billing_reconciliation_report(table, user_sub="u-bill", period_id="2026-10", snapshot_version=1)
    assert report["invoice_total_micros"] == inv["total_amount_micros"]
    assert report["adjustments_total_micros"] == -50
    assert report["variance_vs_snapshot_micros"] == -50


def test_generate_api_invoice_requires_finalized_snapshot(monkeypatch) -> None:
    monkeypatch.setattr(api_usage_metering, "Key", _FakeKey)
    table = _FakeTable()
    table.items[("USER#u-z", "API_USAGE#SNAPSHOT#2026-11#V0001")] = {
        "PK": "USER#u-z",
        "SK": "API_USAGE#SNAPSHOT#2026-11#V0001",
        "status": "draft",
        "by_route": [],
        "by_key": [],
    }
    with pytest.raises(Exception):
        api_usage_metering.generate_api_invoice_line_items_for_snapshot(table, user_sub="u-z", period_id="2026-11", snapshot_version=1)


def test_shadow_billing_validation_and_cutover_signoff(monkeypatch) -> None:
    monkeypatch.setattr(api_usage_metering, "Key", _FakeKey)
    _mock_pricing(monkeypatch, unit_price=50, version="vshadow")
    table = _FakeTable()

    for rid in ("s1", "s2", "s3"):
        e = api_usage_metering.build_api_usage_event(
            _request("/ui/api_keys", headers={"x-user-sub": "u-shadow", "x-request-id": rid}),
            200,
        )
        assert e
        e["timestamp"] = "2026-12-05T00:00:00+00:00"
        e["period_id"] = "2026-12"
        api_usage_metering.record_api_usage_event_and_aggregates(table, e)

    snap = api_usage_metering.finalize_api_billing_usage_snapshot(table, user_sub="u-shadow", period_id="2026-12", version=1)
    expected_total = int(snap["totals"]["cost_subtotal_micros"])
    shadow = api_usage_metering.run_api_billing_shadow_validation(
        table,
        user_sub="u-shadow",
        period_id="2026-12",
        snapshot_version=1,
        expected_total_micros=expected_total,
        variance_threshold_micros=0,
        cycle_id="cycle-1",
    )
    assert shadow["within_threshold"] is True
    assert shadow["variance_vs_expected_micros"] == 0
    assert shadow["variance_vs_snapshot_micros"] == 0

    signoff = api_usage_metering.record_api_billing_cutover_signoff(
        table,
        user_sub="u-shadow",
        period_id="2026-12",
        snapshot_version=1,
        shadow_report_sk=shadow["shadow_report_sk"],
        product_approved_by="prod.user",
        finance_approved_by="fin.user",
        engineering_approved_by="eng.user",
        cutover_criteria="shadow variance <= 0 micros for one full cycle",
        rollback_criteria="rollback if variance > 1% for 15m or finalize errors > 0",
    )
    assert signoff["ok"] is True
    assert signoff["approvals"]["product"] == "prod.user"


def test_cutover_signoff_rejects_out_of_threshold_shadow(monkeypatch) -> None:
    monkeypatch.setattr(api_usage_metering, "Key", _FakeKey)
    _mock_pricing(monkeypatch, unit_price=10, version="vshadow")
    table = _FakeTable()

    e = api_usage_metering.build_api_usage_event(
        _request("/ui/api_keys", headers={"x-user-sub": "u-shadow2", "x-request-id": "s1"}),
        200,
    )
    assert e
    e["timestamp"] = "2026-12-06T00:00:00+00:00"
    e["period_id"] = "2026-12"
    api_usage_metering.record_api_usage_event_and_aggregates(table, e)
    api_usage_metering.finalize_api_billing_usage_snapshot(table, user_sub="u-shadow2", period_id="2026-12", version=1)

    shadow = api_usage_metering.run_api_billing_shadow_validation(
        table,
        user_sub="u-shadow2",
        period_id="2026-12",
        snapshot_version=1,
        expected_total_micros=999,
        variance_threshold_micros=0,
        cycle_id="cycle-2",
    )
    assert shadow["within_threshold"] is False

    with pytest.raises(Exception) as ex:
        api_usage_metering.record_api_billing_cutover_signoff(
            table,
            user_sub="u-shadow2",
            period_id="2026-12",
            snapshot_version=1,
            shadow_report_sk=shadow["shadow_report_sk"],
            product_approved_by="prod.user",
            finance_approved_by="fin.user",
            engineering_approved_by="eng.user",
            cutover_criteria="none",
            rollback_criteria="none",
        )
    assert ex.value.status_code == 409


@pytest.mark.parametrize(
    "path,method,expected_product",
    [
        ("/v1/files", "GET", "filemanager"),
        ("/v1/newsfeed/posts", "POST", "newsfeed"),
        ("/v1/tickets", "GET", "tickets"),
        ("/v1/cart/checkout", "POST", "shopping"),
        ("/v1/messages/send", "POST", "messager"),
    ],
)
def test_build_api_usage_event_includes_product_dimension(path: str, method: str, expected_product: str) -> None:
    event = api_usage_metering.build_api_usage_event(
        _request(path, method=method, headers={"x-user-sub": "u-prod", "x-request-id": "p1", "x-api-key": "ak_prod.secret"}),
        200,
    )
    assert event is not None
    assert event["product"] == expected_product


def test_build_api_usage_event_never_includes_api_key_secret_material() -> None:
    event = api_usage_metering.build_api_usage_event(
        _request("/v1/files", headers={"x-user-sub": "u-secret", "x-request-id": "sec1", "x-api-key": "ak_abcd1234.super-secret-value"}),
        200,
    )
    assert event is not None
    blob = json.dumps(event)
    assert "super-secret-value" not in blob
    assert event["api_key_id"] == "abcd1234"
