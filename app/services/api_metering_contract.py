from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Set

from fastapi import FastAPI, Request
from fastapi.routing import APIRoute

# Internal and non-billable probe/ops surfaces excluded from API call billing.
_EXCLUDED_PATH_PREFIXES: tuple[str, ...] = (
    "/metrics",
    "/openapi.json",
    "/docs",
    "/redoc",
    "/static",
    "/mock",
)
_EXCLUDED_EXACT_PATHS: Set[str] = {
    "/",
}
_EXCLUDED_HEALTH_SEGMENTS: Set[str] = {"health", "healthz"}


def _normalize_path_template(path_template: str) -> str:
    raw = (path_template or "").strip()
    if not raw:
        return "/"
    if not raw.startswith("/"):
        raw = f"/{raw}"
    normalized = "/".join(part for part in raw.split("/") if part)
    return "/" if not normalized else f"/{normalized}"


def normalize_route_id(method: str, path_template: str) -> str:
    normalized_method = (method or "").strip().upper()
    if not normalized_method:
        raise ValueError("method is required")
    return f"{normalized_method}:{_normalize_path_template(path_template)}"


def resolve_route_id(method: str, route: APIRoute) -> str:
    return normalize_route_id(method, route.path)


def is_excluded_probe_path(path_template: str) -> bool:
    path = _normalize_path_template(path_template)
    if path in _EXCLUDED_EXACT_PATHS:
        return True
    if any(path == prefix or path.startswith(f"{prefix}/") for prefix in _EXCLUDED_PATH_PREFIXES):
        return True
    segments = [segment for segment in path.split("/") if segment]
    return bool(segments and segments[-1] in _EXCLUDED_HEALTH_SEGMENTS)


def _canonical_methods(methods: Iterable[str]) -> List[str]:
    allowed = {"GET", "POST", "PUT", "PATCH", "DELETE"}
    out = sorted({(method or "").upper() for method in methods if (method or "").upper() in allowed})
    return out


def build_route_catalog(app: FastAPI) -> List[Dict[str, Any]]:
    by_route_id: Dict[str, Dict[str, Any]] = {}
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        if is_excluded_probe_path(route.path):
            continue
        methods = _canonical_methods(route.methods)
        if not methods:
            continue
        for method in methods:
            route_id = resolve_route_id(method, route)
            current = by_route_id.get(route_id)
            if current is None:
                by_route_id[route_id] = {
                    "route_id": route_id,
                    "method": method,
                    "path_template": _normalize_path_template(route.path),
                    "name": route.name,
                    "aliases": [],
                }
                continue
            alias = route.name
            if alias and alias != current["name"] and alias not in current["aliases"]:
                current["aliases"].append(alias)
    catalog = list(by_route_id.values())
    catalog.sort(key=lambda row: row["route_id"])
    return catalog


def route_id_from_request(request: Request) -> Optional[str]:
    route = request.scope.get("route")
    if not isinstance(route, APIRoute):
        return None
    if is_excluded_probe_path(route.path):
        return None
    return resolve_route_id(request.method, route)
