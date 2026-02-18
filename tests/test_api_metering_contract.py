from __future__ import annotations

from fastapi import Request

from app.main import create_app
from app.services import api_metering_contract as contract


def _request_for_route(path: str, method: str = "GET") -> Request:
    app = create_app()
    route = next(r for r in app.routes if getattr(r, "path", None) == path and method in getattr(r, "methods", set()))
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": [],
        "query_string": b"",
        "route": route,
        "app": app,
    }
    return Request(scope)


def test_normalize_route_id_canonicalizes_method_and_path() -> None:
    assert contract.normalize_route_id("post", "v1/messages//send/") == "POST:/v1/messages/send"


def test_excluded_probe_paths() -> None:
    assert contract.is_excluded_probe_path("/metrics")
    assert contract.is_excluded_probe_path("/openapi.json")
    assert contract.is_excluded_probe_path("/v1/messaging/healthz")
    assert not contract.is_excluded_probe_path("/v1/messaging/send")


def test_build_route_catalog_contains_only_stable_non_probe_route_ids() -> None:
    app = create_app()
    catalog = contract.build_route_catalog(app)

    assert catalog
    route_ids = [row["route_id"] for row in catalog]
    assert route_ids == sorted(route_ids)
    assert len(route_ids) == len(set(route_ids))
    assert all(route_id.count(":") == 1 for route_id in route_ids)
    assert all(not route_id.startswith("GET:/metrics") for route_id in route_ids)
    assert all(not route_id.endswith("/health") for route_id in route_ids)
    assert all(not route_id.endswith("/healthz") for route_id in route_ids)


def test_all_in_scope_api_routes_have_stable_route_ids() -> None:
    app = create_app()
    for route in app.routes:
        if not hasattr(route, "path") or not hasattr(route, "methods"):
            continue
        if contract.is_excluded_probe_path(route.path):
            continue
        methods = contract._canonical_methods(route.methods)
        if not methods:
            continue
        for method in methods:
            route_id = contract.resolve_route_id(method, route)
            assert route_id == contract.normalize_route_id(method, route.path)
            assert route_id.startswith(f"{method}:/")


def test_route_id_from_request_uses_route_template() -> None:
    req = _request_for_route("/ui/api_keys")
    assert contract.route_id_from_request(req) == "GET:/ui/api_keys"
