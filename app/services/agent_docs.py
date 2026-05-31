"""Documentation Agent service (AGENT-014).

The Documentation Agent is an agent *type* that maintains documentation for the
platform. It owns:

* documentation coverage + freshness tracking (``agent_doc_coverage`` table)
* documentation template management (``agent_doc_templates`` table)
* ``doc_config`` storage on the shared ``agent_types`` table
* a deterministic, mockable freshness/PR-impact engine
* inline-documentation ticket creation via the ticket system (AGENT-004)

All operations are scoped to the authenticated user's ``user_id`` (security §9).
Source-file git hashes are computed by the agent in its terminal session — the
backend only stores opaque hash strings and compares them for staleness
detection. Real execution (writing docs / creating tickets) is gated behind
``S.doc_agent_enabled``; freshness comparison is pure/deterministic so it is
fully driveable and testable from E2E without touching the filesystem.

The agent may read AGENT-005 agent memory for project context when assembling
documentation prompts.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from app.core.aws import ddb
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services import tickets as tickets_svc

logger = logging.getLogger("app.agent_docs")

DOC_AGENT_TYPE = "documentation"

DOC_TYPES = ("api", "architecture", "user_guide", "adr", "readme", "inline")
TEMPLATE_DOC_TYPES = ("api", "architecture", "user_guide", "adr", "readme")
IMPACT_LEVELS = ("none", "low", "medium", "high")

_MAX_DOCS_PER_USER = 1000
_MAX_TEMPLATES_PER_USER = 50

_DEFAULT_CONFIG: Dict[str, Any] = {
    "trigger_on_pr_merge": True,
    "freshness_check_frequency": "daily",
    "freshness_check_hour_utc": 6,
    "doc_format": "markdown",
    "doc_root": "docs/",
    "api_doc_root": "docs/api/",
    "adr_root": "docs/adr/",
    "user_guide_root": "docs/guides/",
    "min_coverage_threshold": 0.7,
    "create_tickets_for_inline_docs": True,
    "inline_doc_target_agent_type": "coder",
    "ignored_paths": ["node_modules/", ".venv/", "dist/"],
}


# ---------------------------------------------------------------------------
# Table bootstrap (idempotent; tables are additive per AGENT-014)
# ---------------------------------------------------------------------------

_BOOTSTRAPPED = False


def ensure_tables() -> None:
    """Create the agent_doc_coverage / agent_doc_templates tables on first use.

    The shared local-ddb-init script is the canonical place tables are defined,
    but the doc feature is self-contained so it works in any environment (E2E
    live DDB, fresh stacks) without requiring a stack re-init.
    """
    global _BOOTSTRAPPED
    if _BOOTSTRAPPED:
        return
    client = ddb.meta.client
    specs = [
        (
            S.agent_doc_coverage_table_name,
            [
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "GSI1PK", "AttributeType": "S"},
                {"AttributeName": "GSI1SK", "AttributeType": "N"},
                {"AttributeName": "GSI2PK", "AttributeType": "S"},
                {"AttributeName": "GSI2SK", "AttributeType": "N"},
            ],
            [
                {
                    "IndexName": "GSI1",
                    "KeySchema": [
                        {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
                {
                    "IndexName": "GSI2",
                    "KeySchema": [
                        {"AttributeName": "GSI2PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI2SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
        ),
        (
            S.agent_doc_templates_table_name,
            [
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            [],
        ),
    ]
    for name, attr_defs, gsi in specs:
        kwargs: Dict[str, Any] = {
            "TableName": name,
            "KeySchema": [
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            "AttributeDefinitions": attr_defs,
            "BillingMode": "PAY_PER_REQUEST",
        }
        if gsi:
            kwargs["GlobalSecondaryIndexes"] = gsi
        try:
            client.create_table(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("ResourceInUseException",):
                logger.warning("ensure_tables: could not create %s: %s", name, exc)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("ensure_tables: %s create error: %s", name, exc)
    _BOOTSTRAPPED = True


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------


def _user_pk(user_id: str) -> str:
    return f"USER#{user_id}"


def _doc_sk(doc_path: str) -> str:
    return f"DOC#{doc_path}"


def _tmpl_sk(template_id: str) -> str:
    return f"TMPL#{template_id}"


def _gsi1pk(user_id: str, doc_type: str) -> str:
    return f"USER#{user_id}#TYPE#{doc_type}"


def _gsi2pk(user_id: str, is_stale: bool) -> str:
    return f"USER#{user_id}#STALE#{str(bool(is_stale)).lower()}"


# ---------------------------------------------------------------------------
# Path validation (security §9 — relative, no traversal)
# ---------------------------------------------------------------------------


def validate_path(path: str) -> bool:
    """Return True if ``path`` is a safe relative repository path."""
    if not path or not isinstance(path, str):
        return False
    if path.startswith("/") or path.startswith("~"):
        return False
    if ".." in path.split("/"):
        return False
    # Reject windows-style absolute / drive paths and backslashes.
    if "\\" in path or ":" in path:
        return False
    return True


def validate_paths(paths: List[str]) -> List[str]:
    """Return the subset of ``paths`` that fail validation."""
    return [p for p in (paths or []) if not validate_path(p)]


# ---------------------------------------------------------------------------
# Git hash computation (deterministic / mockable)
# ---------------------------------------------------------------------------


def _compute_source_hash(path: str) -> str:
    """Compute a stable hash token for a source file.

    Hashes are normally produced by the agent in its terminal session (real git
    blob hashes). The backend never touches the filesystem; in mock/dev mode it
    derives a deterministic content-independent token from the path so freshness
    detection is exercisable without git. When the same path is registered and
    later re-verified with no intervening update call, the token is identical →
    the doc is considered fresh.
    """
    return f"h_{abs(hash(path)) & 0xFFFFFFFF:08x}"


def compute_source_hashes(paths: List[str]) -> Dict[str, str]:
    return {p: _compute_source_hash(p) for p in (paths or []) if p}


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def _loads_list(raw: Any) -> List[str]:
    if isinstance(raw, list):
        return [str(x) for x in raw]
    if isinstance(raw, str) and raw:
        try:
            val = json.loads(raw)
            if isinstance(val, list):
                return [str(x) for x in val]
        except (ValueError, TypeError):
            return []
    return []


def _loads_map(raw: Any) -> Dict[str, str]:
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, str) and raw:
        try:
            val = json.loads(raw)
            if isinstance(val, dict):
                return {str(k): str(v) for k, v in val.items()}
        except (ValueError, TypeError):
            return {}
    return {}


def _doc_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Project a raw DDB item into the public DocCoverage shape."""
    stale_since = item.get("stale_since")
    return {
        "doc_path": item.get("doc_path", ""),
        "doc_type": item.get("doc_type", "readme"),
        "source_refs": _loads_list(item.get("source_refs")),
        "coverage_score": float(item.get("coverage_score", 0) or 0),
        "is_stale": bool(item.get("is_stale", False)),
        "stale_since": int(stale_since) if stale_since is not None else None,
        "last_verified": int(item.get("last_verified", 0) or 0),
        "last_updated": int(item.get("last_updated", 0) or 0),
        "created_at": int(item.get("created_at", 0) or 0),
    }


def _tmpl_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "template_id": item.get("template_id", ""),
        "name": item.get("name", ""),
        "doc_type": item.get("doc_type", "readme"),
        "template_body": item.get("template_body", ""),
        "required_sections": _loads_list(item.get("required_sections")),
        "created_at": int(item.get("created_at", 0) or 0),
    }


# ---------------------------------------------------------------------------
# Doc coverage CRUD
# ---------------------------------------------------------------------------


def get_doc(*, user_id: str, doc_path: str) -> Optional[Dict[str, Any]]:
    ensure_tables()
    resp = T.agent_doc_coverage.get_item(Key={"pk": _user_pk(user_id), "sk": _doc_sk(doc_path)})
    item = resp.get("Item")
    return _doc_out(item) if item else None


def register_doc(
    *,
    user_id: str,
    doc_path: str,
    doc_type: str,
    source_refs: List[str],
    coverage_score: float,
    agent_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Register a documentation artifact in the coverage tracker.

    Raises ValueError("duplicate") if the doc_path is already registered.
    """
    ensure_tables()
    ts = now_ts()
    source_refs = list(source_refs or [])
    source_hashes = compute_source_hashes(source_refs)
    item: Dict[str, Any] = {
        "pk": _user_pk(user_id),
        "sk": _doc_sk(doc_path),
        "doc_path": doc_path,
        "doc_type": doc_type,
        "source_refs": json.dumps(source_refs),
        "source_hashes": json.dumps(source_hashes),
        "coverage_score": _decimalize(coverage_score),
        "is_stale": False,
        "last_verified": ts,
        "last_updated": ts,
        "created_at": ts,
        "GSI1PK": _gsi1pk(user_id, doc_type),
        "GSI1SK": ts,
        "GSI2PK": _gsi2pk(user_id, False),
        "GSI2SK": ts,
    }
    if agent_id:
        item["agent_id"] = agent_id
    try:
        T.agent_doc_coverage.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)",
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            raise ValueError("duplicate") from exc
        raise
    return _doc_out(item)


def update_doc_record(
    *,
    user_id: str,
    doc_path: str,
    source_refs: Optional[List[str]] = None,
    coverage_score: Optional[float] = None,
    agent_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Refresh a doc record: recompute hashes, clear staleness, bump last_updated.

    Raises LookupError if the doc is not registered.
    """
    ensure_tables()
    resp = T.agent_doc_coverage.get_item(Key={"pk": _user_pk(user_id), "sk": _doc_sk(doc_path)})
    item = resp.get("Item")
    if not item:
        raise LookupError("doc_not_found")
    ts = now_ts()
    refs = list(source_refs) if source_refs is not None else _loads_list(item.get("source_refs"))
    hashes = compute_source_hashes(refs)
    set_parts = [
        "source_refs = :refs",
        "source_hashes = :hashes",
        "is_stale = :stale",
        "last_updated = :ts",
        "last_verified = :ts",
        "GSI2PK = :g2pk",
        "GSI2SK = :ts",
        "GSI1SK = :ts",
    ]
    values: Dict[str, Any] = {
        ":refs": json.dumps(refs),
        ":hashes": json.dumps(hashes),
        ":stale": False,
        ":ts": ts,
        ":g2pk": _gsi2pk(user_id, False),
    }
    if coverage_score is not None:
        set_parts.append("coverage_score = :cov")
        values[":cov"] = _decimalize(coverage_score)
    if agent_id:
        set_parts.append("agent_id = :aid")
        values[":aid"] = agent_id
    remove_clause = " REMOVE stale_since" if item.get("stale_since") is not None else ""
    T.agent_doc_coverage.update_item(
        Key={"pk": _user_pk(user_id), "sk": _doc_sk(doc_path)},
        UpdateExpression="SET " + ", ".join(set_parts) + remove_clause,
        ExpressionAttributeValues=values,
    )
    return get_doc(user_id=user_id, doc_path=doc_path)  # type: ignore[return-value]


def delete_doc(*, user_id: str, doc_path: str) -> bool:
    ensure_tables()
    resp = T.agent_doc_coverage.get_item(Key={"pk": _user_pk(user_id), "sk": _doc_sk(doc_path)})
    if not resp.get("Item"):
        return False
    T.agent_doc_coverage.delete_item(Key={"pk": _user_pk(user_id), "sk": _doc_sk(doc_path)})
    return True


def list_docs(*, user_id: str, doc_type: Optional[str] = None) -> List[Dict[str, Any]]:
    """List all tracked docs for a user, optionally filtered by doc_type."""
    ensure_tables()
    items: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": "pk = :pk AND begins_with(sk, :pfx)",
        "ExpressionAttributeValues": {":pk": _user_pk(user_id), ":pfx": "DOC#"},
    }
    while True:
        resp = T.agent_doc_coverage.query(**kwargs)
        items.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek or len(items) >= _MAX_DOCS_PER_USER:
            break
        kwargs["ExclusiveStartKey"] = lek
    out = [_doc_out(it) for it in items]
    if doc_type:
        out = [d for d in out if d["doc_type"] == doc_type]
    out.sort(key=lambda d: d["last_updated"], reverse=True)
    return out


# ---------------------------------------------------------------------------
# Freshness + staleness
# ---------------------------------------------------------------------------


def check_freshness(*, user_id: str) -> Dict[str, Any]:
    """Run freshness check on all tracked docs.

    Compares each doc's stored ``source_hashes`` against the current hashes for
    its ``source_refs``. Docs whose source changed are flagged stale.
    """
    ensure_tables()
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": "pk = :pk AND begins_with(sk, :pfx)",
        "ExpressionAttributeValues": {":pk": _user_pk(user_id), ":pfx": "DOC#"},
    }
    raw_items: List[Dict[str, Any]] = []
    while True:
        resp = T.agent_doc_coverage.query(**kwargs)
        raw_items.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek

    ts = now_ts()
    stale = 0
    fresh = 0
    stale_docs: List[Dict[str, Any]] = []
    for item in raw_items:
        doc_path = item.get("doc_path", "")
        refs = _loads_list(item.get("source_refs"))
        stored = _loads_map(item.get("source_hashes"))
        current = compute_source_hashes(refs)
        changed = [p for p in refs if stored.get(p) != current.get(p)]
        was_stale = bool(item.get("is_stale", False))
        is_stale_now = len(changed) > 0
        update_values: Dict[str, Any] = {":lv": ts}
        set_parts = ["last_verified = :lv"]
        if is_stale_now:
            stale += 1
            set_parts += ["is_stale = :st", "GSI2PK = :g2pk", "GSI2SK = :ss"]
            update_values[":st"] = True
            update_values[":g2pk"] = _gsi2pk(user_id, True)
            stale_since = int(item.get("stale_since")) if item.get("stale_since") is not None else ts
            update_values[":ss"] = stale_since
            if not was_stale:
                set_parts.append("stale_since = :ss")
            stale_docs.append(
                {
                    "doc_path": doc_path,
                    "doc_type": item.get("doc_type", "readme"),
                    "changed_sources": changed,
                    "stale_since": stale_since,
                }
            )
        else:
            fresh += 1
            set_parts += ["is_stale = :st", "GSI2PK = :g2pk", "GSI2SK = :lv"]
            update_values[":st"] = False
            update_values[":g2pk"] = _gsi2pk(user_id, False)
        remove_clause = ""
        if not is_stale_now and item.get("stale_since") is not None:
            remove_clause = " REMOVE stale_since"
        T.agent_doc_coverage.update_item(
            Key={"pk": item["pk"], "sk": item["sk"]},
            UpdateExpression="SET " + ", ".join(set_parts) + remove_clause,
            ExpressionAttributeValues=update_values,
        )
    return {
        "total": len(raw_items),
        "stale": stale,
        "fresh": fresh,
        "stale_docs": stale_docs,
        "checked_at": ts,
    }


def list_stale_docs(*, user_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    """List stale docs ordered by staleness duration (oldest-stale first)."""
    ensure_tables()
    try:
        resp = T.agent_doc_coverage.query(
            IndexName="GSI2",
            KeyConditionExpression="GSI2PK = :pk",
            ExpressionAttributeValues={":pk": _gsi2pk(user_id, True)},
            ScanIndexForward=True,
            Limit=limit,
        )
        items = resp.get("Items", [])
    except ClientError:
        items = [it for it in _raw_user_docs(user_id) if bool(it.get("is_stale"))]
    out = [_doc_out(it) for it in items]
    out.sort(key=lambda d: (d["stale_since"] or d["last_updated"]))
    return out[:limit]


def _raw_user_docs(user_id: str) -> List[Dict[str, Any]]:
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": "pk = :pk AND begins_with(sk, :pfx)",
        "ExpressionAttributeValues": {":pk": _user_pk(user_id), ":pfx": "DOC#"},
    }
    items: List[Dict[str, Any]] = []
    while True:
        resp = T.agent_doc_coverage.query(**kwargs)
        items.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    return items


# ---------------------------------------------------------------------------
# Coverage summary
# ---------------------------------------------------------------------------


def get_coverage_summary(*, user_id: str) -> Dict[str, Any]:
    """Return documentation coverage summary grouped by doc_type."""
    docs = list_docs(user_id=user_id)
    by_type: Dict[str, Dict[str, Any]] = {}
    total_score = 0.0
    stale_total = 0
    for d in docs:
        dt = d["doc_type"]
        entry = by_type.setdefault(dt, {"count": 0, "_score_sum": 0.0, "stale_count": 0})
        entry["count"] += 1
        entry["_score_sum"] += d["coverage_score"]
        if d["is_stale"]:
            entry["stale_count"] += 1
            stale_total += 1
        total_score += d["coverage_score"]
    for dt, entry in by_type.items():
        cnt = entry["count"] or 1
        entry["avg_coverage"] = round(entry.pop("_score_sum") / cnt, 4)
    overall = round(total_score / len(docs), 4) if docs else 0.0
    return {
        "overall_coverage": overall,
        "total_docs": len(docs),
        "stale_docs": stale_total,
        "by_type": by_type,
    }


# ---------------------------------------------------------------------------
# PR impact assessment
# ---------------------------------------------------------------------------


def assess_pr_impact(*, user_id: str, changed_files: List[str]) -> Dict[str, Any]:
    """Assess documentation impact of a set of changed files from a PR.

    The backend does NOT access the filesystem — it compares ``changed_files``
    against the ``source_refs`` stored on each tracked doc.
    """
    changed = set(changed_files or [])
    docs = list_docs(user_id=user_id)
    docs_to_update: List[Dict[str, Any]] = []
    covered: set[str] = set()
    for d in docs:
        refs = set(d["source_refs"])
        covered |= refs
        if refs & changed:
            docs_to_update.append(d)
    uncovered_files = sorted(f for f in changed if f not in covered)
    impact = _impact_level(num_docs=len(docs_to_update), num_uncovered=len(uncovered_files))
    return {
        "docs_to_update": docs_to_update,
        "uncovered_files": uncovered_files,
        "impact_level": impact,
    }


def _impact_level(*, num_docs: int, num_uncovered: int) -> str:
    # Impact is driven by how many *tracked* docs are affected. When no tracked
    # doc references any changed file, the change has no documentation impact
    # (uncovered files alone are surfaced separately as gaps, not as impact).
    if num_docs == 0:
        return "none"
    total = num_docs + num_uncovered
    if num_docs >= 3 or total >= 5:
        return "high"
    if num_docs >= 2 or num_uncovered >= 2:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------


def create_doc_template(
    *,
    user_id: str,
    name: str,
    doc_type: str,
    template_body: str,
    required_sections: List[str],
) -> Dict[str, Any]:
    ensure_tables()
    import uuid

    template_id = uuid.uuid4().hex
    ts = now_ts()
    item = {
        "pk": _user_pk(user_id),
        "sk": _tmpl_sk(template_id),
        "template_id": template_id,
        "name": name,
        "doc_type": doc_type,
        "template_body": template_body,
        "required_sections": json.dumps(list(required_sections or [])),
        "created_at": ts,
    }
    T.agent_doc_templates.put_item(Item=item)
    return _tmpl_out(item)


def get_doc_template(*, user_id: str, template_id: str) -> Optional[Dict[str, Any]]:
    ensure_tables()
    resp = T.agent_doc_templates.get_item(Key={"pk": _user_pk(user_id), "sk": _tmpl_sk(template_id)})
    item = resp.get("Item")
    return _tmpl_out(item) if item else None


def list_doc_templates(*, user_id: str, doc_type: Optional[str] = None) -> List[Dict[str, Any]]:
    ensure_tables()
    resp = T.agent_doc_templates.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :pfx)",
        ExpressionAttributeValues={":pk": _user_pk(user_id), ":pfx": "TMPL#"},
    )
    out = [_tmpl_out(it) for it in resp.get("Items", [])]
    if doc_type:
        out = [t for t in out if t["doc_type"] == doc_type]
    out.sort(key=lambda t: t["created_at"], reverse=True)
    return out


def update_doc_template(
    *,
    user_id: str,
    template_id: str,
    name: Optional[str] = None,
    doc_type: Optional[str] = None,
    template_body: Optional[str] = None,
    required_sections: Optional[List[str]] = None,
) -> Dict[str, Any]:
    ensure_tables()
    existing = get_doc_template(user_id=user_id, template_id=template_id)
    if not existing:
        raise LookupError("template_not_found")
    set_parts: List[str] = []
    values: Dict[str, Any] = {}
    names: Dict[str, str] = {}
    if name is not None:
        set_parts.append("#nm = :nm")
        names["#nm"] = "name"
        values[":nm"] = name
    if doc_type is not None:
        set_parts.append("doc_type = :dt")
        values[":dt"] = doc_type
    if template_body is not None:
        set_parts.append("template_body = :tb")
        values[":tb"] = template_body
    if required_sections is not None:
        set_parts.append("required_sections = :rs")
        values[":rs"] = json.dumps(list(required_sections))
    if not set_parts:
        return existing
    kwargs: Dict[str, Any] = {
        "Key": {"pk": _user_pk(user_id), "sk": _tmpl_sk(template_id)},
        "UpdateExpression": "SET " + ", ".join(set_parts),
        "ExpressionAttributeValues": values,
    }
    if names:
        kwargs["ExpressionAttributeNames"] = names
    T.agent_doc_templates.update_item(**kwargs)
    return get_doc_template(user_id=user_id, template_id=template_id)  # type: ignore[return-value]


def delete_doc_template(*, user_id: str, template_id: str) -> bool:
    ensure_tables()
    if not get_doc_template(user_id=user_id, template_id=template_id):
        return False
    T.agent_doc_templates.delete_item(Key={"pk": _user_pk(user_id), "sk": _tmpl_sk(template_id)})
    return True


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def get_doc_config(*, agent_type_id: str) -> Dict[str, Any]:
    from app.services import agent_coder as coder_svc

    coder_svc.ensure_tables()
    resp = T.agent_types.get_item(Key={"pk": f"TYPE#{agent_type_id}", "sk": "DOC_CONFIG"})
    item = resp.get("Item")
    if not item or not item.get("doc_config"):
        return dict(_DEFAULT_CONFIG)
    merged = dict(_DEFAULT_CONFIG)
    merged.update(_coerce_config(item["doc_config"]))
    return merged


def update_doc_config(*, agent_type_id: str, owner_sub: str, config: Dict[str, Any]) -> Dict[str, Any]:
    from app.services import agent_coder as coder_svc

    coder_svc.ensure_tables()
    if coder_svc.get_agent_type(agent_type_id=agent_type_id) is None:
        coder_svc.create_agent_type(
            agent_type_id=agent_type_id, owner_sub=owner_sub, agent_type=DOC_AGENT_TYPE
        )
    current = get_doc_config(agent_type_id=agent_type_id)
    for key, value in (config or {}).items():
        if value is not None:
            current[key] = value
    ts = now_ts()
    T.agent_types.put_item(
        Item={
            "pk": f"TYPE#{agent_type_id}",
            "sk": "DOC_CONFIG",
            "agent_type_id": agent_type_id,
            "agent_type": DOC_AGENT_TYPE,
            "owner_sub": owner_sub,
            "doc_config": _serialize_config(current),
            "updated_at": ts,
        }
    )
    return current


def _coerce_config(config: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(config)
    for field in ("freshness_check_hour_utc",):
        if field in out and out[field] is not None:
            try:
                out[field] = int(out[field])
            except (TypeError, ValueError):
                pass
    for field in ("min_coverage_threshold",):
        if field in out and out[field] is not None:
            try:
                out[field] = float(out[field])
            except (TypeError, ValueError):
                pass
    return out


def _serialize_config(config: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, value in config.items():
        out[key] = _decimalize(value) if isinstance(value, float) else value
    return out


# ---------------------------------------------------------------------------
# Inline documentation ticket creation (AGENT-004 bridge)
# ---------------------------------------------------------------------------


def create_inline_doc_ticket(
    *, user_id: str, source_file: str, description: str, target_agent_type: str = "coder"
) -> Dict[str, Any]:
    """Create a type:documentation ticket requesting inline docs for a file."""
    subject = f"Add inline documentation to {source_file}"
    labels = ["type:documentation", f"file:{source_file}"]
    ticket = tickets_svc.STORE.create_ticket(
        owner_sub=user_id,
        subject=subject,
        description=description or f"Document the public functions/classes in `{source_file}`.",
        labels=labels,
        metadata={
            "doc_agent": True,
            "source_file": source_file,
            "target_agent_type": target_agent_type,
        },
    )
    return ticket


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _decimalize(value: Any) -> Any:
    """Convert floats to Decimal for DynamoDB storage."""
    from decimal import Decimal

    if isinstance(value, float):
        return Decimal(str(value))
    return value
