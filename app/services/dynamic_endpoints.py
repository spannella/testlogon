"""Dynamic Endpoints service (CSN-004).

Allows ROOT to register custom {method, path} entries mapped to connector kinds:
  - static_response: returns stored JSON body + status code
  - dynamic_entity_proxy: proxies to CSN-003 dynamic entity CRUD

Flag-gated: S.dynamic_endpoints_enabled (DYNAMIC_ENDPOINTS_ENABLED, default OFF).
No money movement. No external dependency.
"""
from __future__ import annotations

import json
import re
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

_PATH_RE = re.compile(r"^/custom/[a-zA-Z0-9/_\-\.{}]{1,120}$")
_FORBIDDEN_PATH_PREFIXES = frozenset({"/ui/", "/internal/", "/mock/", "/telemetry/"})
_ALLOWED_METHODS = frozenset({"GET", "POST", "PUT", "DELETE"})
_CONNECTOR_KINDS = frozenset({"static_response", "dynamic_entity_proxy"})
_PROXY_OPS = frozenset({"list", "get", "create", "update", "delete"})

_METHOD_OP_COMPAT: Dict[str, frozenset] = {
    "GET": frozenset({"list", "get"}),
    "POST": frozenset({"create"}),
    "PUT": frozenset({"update"}),
    "DELETE": frozenset({"delete"}),
}

_MAX_BODY_BYTES = 64 * 1024  # 64 KB


def _item_to_dict(item: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(item)
    for f in ("created_at", "updated_at"):
        if f in out and out[f] is not None:
            try:
                out[f] = int(out[f])
            except (TypeError, ValueError):
                pass
    return out


def _validate_path(path: str) -> None:
    if not path.startswith("/custom/"):
        raise HTTPException(400, {"code": "invalid_path_prefix", "path": path})
    if not _PATH_RE.match(path):
        raise HTTPException(400, {"code": "invalid_path_format", "path": path})
    if len(path) > 128:
        raise HTTPException(400, {"code": "invalid_path_format", "reason": "path too long"})
    for prefix in _FORBIDDEN_PATH_PREFIXES:
        if path.startswith(prefix):
            raise HTTPException(400, {"code": "invalid_path_format", "reason": "shadows internal path"})


def _validate_connector_config(method: str, connector_kind: str, connector_config: dict) -> None:
    if connector_kind == "static_response":
        if "status" not in connector_config or "body" not in connector_config:
            raise HTTPException(400, {"code": "invalid_connector_config",
                                      "reason": "static_response requires status and body"})
        status = connector_config["status"]
        if not isinstance(status, int) or not (100 <= status <= 599):
            raise HTTPException(400, {"code": "invalid_connector_config",
                                      "reason": "status must be an integer 100-599"})
        body = connector_config.get("body", {})
        body_bytes = len(json.dumps(body, default=str).encode("utf-8"))
        if body_bytes > _MAX_BODY_BYTES:
            raise HTTPException(400, {"code": "body_too_large", "limit_bytes": _MAX_BODY_BYTES})
        headers = connector_config.get("headers", {})
        if not isinstance(headers, dict):
            raise HTTPException(400, {"code": "invalid_connector_config", "reason": "headers must be a dict"})
        if len(headers) > 10:
            raise HTTPException(400, {"code": "invalid_connector_config", "reason": "too many headers"})
        _bad_hdr_prefixes = ("x-internal-", "content-type", "set-cookie", "authorization", "www-authenticate")
        for hk in headers:
            lk = str(hk).lower()
            for bp in _bad_hdr_prefixes:
                if lk.startswith(bp):
                    raise HTTPException(400, {"code": "invalid_connector_config",
                                              "reason": f"header {hk} not allowed"})

    elif connector_kind == "dynamic_entity_proxy":
        entity_name = connector_config.get("entity_name")
        op = connector_config.get("op")
        if not entity_name or not op:
            raise HTTPException(400, {"code": "invalid_connector_config",
                                      "reason": "dynamic_entity_proxy requires entity_name and op"})
        if op not in _PROXY_OPS:
            raise HTTPException(400, {"code": "invalid_connector_config",
                                      "reason": f"unknown op: {op}; must be one of {sorted(_PROXY_OPS)}"})
        # Validate method/op compat
        allowed_ops = _METHOD_OP_COMPAT.get(method, frozenset())
        if op not in allowed_ops:
            raise HTTPException(400, {"code": "incompatible_method_op",
                                      "method": method, "op": op,
                                      "allowed_ops": sorted(allowed_ops)})
        # Validate entity exists (when entities flag is on)
        if getattr(S, "dynamic_entities_enabled", False):
            try:
                from app.services.dynamic_entities import get_entity_def
                if get_entity_def(entity_name) is None:
                    raise HTTPException(400, {"code": "entity_not_found", "entity_name": entity_name})
            except HTTPException:
                raise
            except Exception:
                pass
    else:
        raise HTTPException(400, {"code": "unknown_connector_kind", "connector_kind": connector_kind})


def register_endpoint(
    admin_sub: str,
    method: str,
    path: str,
    connector_kind: str,
    connector_config: dict,
    openapi_spec: Optional[dict] = None,
    req: Optional[Request] = None,
) -> Dict[str, Any]:
    """Validate and register a dynamic endpoint definition."""
    method = method.upper()
    if method not in _ALLOWED_METHODS:
        raise HTTPException(400, {"code": "invalid_method", "method": method})
    _validate_path(path)
    if connector_kind not in _CONNECTOR_KINDS:
        raise HTTPException(400, {"code": "unknown_connector_kind", "connector_kind": connector_kind})
    _validate_connector_config(method, connector_kind, connector_config)

    method_path = f"{method} {path}"
    # Uniqueness check via GSI
    try:
        existing = T.dynamic_endpoints.query(
            IndexName=S.dynamic_endpoints_method_path_index,
            KeyConditionExpression=Key("method_path").eq(method_path),
        )
        if existing.get("Items"):
            raise HTTPException(409, {"code": "endpoint_already_exists",
                                      "method": method, "path": path})
    except HTTPException:
        raise
    except Exception:
        pass

    if openapi_spec is None:
        openapi_spec = {"summary": f"{method} {path}", "responses": {"200": {"description": "OK"}}}

    now = now_ts()
    endpoint_id = "dye_" + uuid.uuid4().hex
    item: Dict[str, Any] = {
        "endpoint_id": endpoint_id,
        "sk": "DEF",
        "method": method,
        "path": path,
        "method_path": method_path,
        "connector_kind": connector_kind,
        "connector_config": connector_config,
        "openapi_spec": openapi_spec,
        "created_by": admin_sub,
        "created_at": now,
        "updated_at": now,
    }
    T.dynamic_endpoints.put_item(Item=item)

    try:
        from app.services.alerts import audit_event
        audit_event("dynamic_endpoint.registered", admin_sub, req,
                    endpoint_id=endpoint_id, method=method, path=path,
                    connector_kind=connector_kind)
    except Exception:
        pass

    return _item_to_dict(item)


def get_endpoint_by_id(endpoint_id: str) -> Optional[Dict[str, Any]]:
    resp = T.dynamic_endpoints.get_item(Key={"endpoint_id": endpoint_id, "sk": "DEF"})
    item = resp.get("Item")
    return _item_to_dict(item) if item else None


def get_endpoint(method: str, path: str) -> Optional[Dict[str, Any]]:
    """Look up by method+path via ByMethodPath GSI."""
    method_path = f"{method.upper()} {path}"
    try:
        resp = T.dynamic_endpoints.query(
            IndexName=S.dynamic_endpoints_method_path_index,
            KeyConditionExpression=Key("method_path").eq(method_path),
        )
        items = resp.get("Items", [])
        if not items:
            # Try template matching: registered path may have {param} segments
            items = _template_match(method.upper(), path)
        if not items:
            return None
        return _item_to_dict(items[0])
    except Exception:
        return None


def _template_match(method: str, incoming_path: str) -> List[Dict[str, Any]]:
    """Scan registered endpoints and find a template that matches incoming_path."""
    # Simple scan; only practical for small numbers of registered endpoints
    try:
        resp = T.dynamic_endpoints.scan(
            FilterExpression=Key("method").eq(method) if False else __import__("boto3").dynamodb.conditions.Attr("method").eq(method)
        )
    except Exception:
        return []
    results = []
    for item in resp.get("Items", []):
        if item.get("method", "").upper() != method:
            continue
        tmpl = item.get("path", "")
        if _path_template_matches(tmpl, incoming_path):
            results.append(item)
    # Prefer more-specific (fewer {param} segments) first
    results.sort(key=lambda it: it.get("path", "").count("{"))
    return results


def _path_template_matches(template: str, path: str) -> bool:
    """Return True if template matches path (simple {param} → any segment)."""
    t_parts = template.rstrip("/").split("/")
    p_parts = path.rstrip("/").split("/")
    if len(t_parts) != len(p_parts):
        return False
    for tp, pp in zip(t_parts, p_parts):
        if tp.startswith("{") and tp.endswith("}"):
            continue
        if tp != pp:
            return False
    return True


def _extract_row_id(template: str, incoming_path: str) -> Optional[str]:
    """Extract {row_id} value from the incoming path using the template."""
    t_parts = template.rstrip("/").split("/")
    p_parts = incoming_path.rstrip("/").split("/")
    for tp, pp in zip(t_parts, p_parts):
        if tp == "{row_id}":
            return pp
    return None


def list_endpoints(
    *,
    created_by: Optional[str] = None,
    cursor_token: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    from app.core.cursor import decode_cursor, encode_cursor

    kwargs: Dict[str, Any] = {"Limit": limit}
    if cursor_token:
        esk = decode_cursor(cursor_token)
        if esk:
            kwargs["ExclusiveStartKey"] = esk

    if created_by:
        kwargs["IndexName"] = S.dynamic_endpoints_created_by_index
        kwargs["KeyConditionExpression"] = Key("created_by").eq(created_by)
        resp = T.dynamic_endpoints.query(**kwargs)
    else:
        resp = T.dynamic_endpoints.scan(**kwargs)

    endpoints = [_item_to_dict(i) for i in resp.get("Items", [])]
    last_key = resp.get("LastEvaluatedKey")
    return {
        "endpoints": endpoints,
        "cursor": encode_cursor(last_key) if last_key else None,
    }


def delete_endpoint(admin_sub: str, endpoint_id: str, req: Optional[Request] = None) -> None:
    ep = get_endpoint_by_id(endpoint_id)
    T.dynamic_endpoints.delete_item(Key={"endpoint_id": endpoint_id, "sk": "DEF"})
    try:
        from app.services.alerts import audit_event
        method = ep.get("method", "") if ep else ""
        path = ep.get("path", "") if ep else ""
        audit_event("dynamic_endpoint.deleted", admin_sub, req,
                    endpoint_id=endpoint_id, method=method, path=path)
    except Exception:
        pass


def invoke_endpoint(
    endpoint: Dict[str, Any],
    method: str,
    path: str,
    caller_sub: str,
    request_body: Optional[dict],
    query_params: dict,
    req: Optional[Request] = None,
) -> JSONResponse:
    """Dispatch on connector_kind; returns a FastAPI JSONResponse."""
    # Rate limit
    try:
        from app.services.rate_limit import _bucket_limit
        cap = int(getattr(S, "dynamic_endpoints_invoke_rate_per_hour", 1000) or 1000)
        endpoint_id = endpoint.get("endpoint_id", "")
        key = f"dye:{endpoint_id}:{caller_sub}"
        if not _bucket_limit(key, "rl#dye_invoke", cap, 3600):
            raise HTTPException(
                status_code=429,
                detail={"code": "dynamic_endpoint_rate_limited",
                        "endpoint_id": endpoint_id, "limit": cap, "window_seconds": 3600},
                headers={"Retry-After": "3600"},
            )
    except HTTPException:
        raise
    except Exception:
        pass

    kind = endpoint.get("connector_kind")
    cfg = endpoint.get("connector_config", {})

    if kind == "static_response":
        return JSONResponse(
            content=cfg.get("body", {}),
            status_code=cfg.get("status", 200),
            headers={str(k): str(v) for k, v in (cfg.get("headers") or {}).items()},
        )

    elif kind == "dynamic_entity_proxy":
        entity_name = cfg.get("entity_name", "")
        op = cfg.get("op", "")
        try:
            from app.services.dynamic_entities import (
                create_row, delete_row, get_row, list_rows, update_row,
            )
        except ImportError as exc:
            raise HTTPException(503, {"code": "dynamic_entities_unavailable"}) from exc

        if op == "list":
            limit = int(query_params.get("limit", [50])[0] if isinstance(query_params.get("limit"), list) else query_params.get("limit", 50))
            cursor = (query_params.get("cursor", [None])[0] if isinstance(query_params.get("cursor"), list) else query_params.get("cursor"))
            result = list_rows(entity_name, owner_sub=caller_sub, cursor=cursor, limit=limit)
            return JSONResponse(content=result)

        elif op == "create":
            data = request_body or {}
            row = create_row(entity_name, caller_sub, data)
            return JSONResponse(content=row, status_code=201)

        elif op in ("get", "update", "delete"):
            tmpl = endpoint.get("path", "")
            row_id = _extract_row_id(tmpl, path)
            if not row_id:
                raise HTTPException(400, {"code": "missing_row_id"})
            if op == "get":
                row = get_row(entity_name, row_id, caller_sub)
                if row is None:
                    raise HTTPException(404, "not found")
                return JSONResponse(content=row)
            elif op == "update":
                data = request_body or {}
                row = update_row(entity_name, row_id, caller_sub, data)
                return JSONResponse(content=row)
            elif op == "delete":
                delete_row(entity_name, row_id, caller_sub)
                return JSONResponse(content={"ok": True})
        raise HTTPException(500, {"code": "internal_connector_error", "op": op})

    raise HTTPException(500, {"code": "internal_connector_error", "connector_kind": kind})
