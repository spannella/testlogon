from __future__ import annotations

import asyncio
import base64
import json
import binascii
import logging
import re
import shutil
import subprocess
import uuid
import tempfile
import time
import tarfile
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import zipstream

try:
    import rarfile
except ImportError:  # pragma: no cover - optional dependency
    rarfile = None
from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError
from fastapi import HTTPException, UploadFile

from app.core.aws import ddb
from app.core.aws_clients import s3_client
from app.core.settings import S
from app.metrics import (
    FILEMGR_PURGE_RESULTS,
    record_filemgr_bytes,
    record_filemgr_operation_latency,
    record_filemgr_purge_run,
    record_filemgr_search_path,
)
from app.services.usage_metering import (
    build_usage_event,
    build_billing_usage_snapshot_item,
    period_bounds_utc,
    period_id_for_datetime,
    record_usage_event_and_aggregates,
)

_s3 = s3_client()
logger = logging.getLogger(__name__)

ENCRYPTION_META_REQUIRED_KEYS = {
    "version",
    "alg",
    "kdf",
    "iterations",
    "salt_b64",
    "iv_b64",
    "orig_name",
    "orig_size",
    "mime",
}
ENCRYPTION_VERSION_SUPPORTED = {1}
ENCRYPTION_ITERATIONS_MIN = 100_000
ENCRYPTION_ITERATIONS_MAX = 2_000_000


def _table():
    if not S.filemgr_table_name:
        raise HTTPException(500, "file manager table not configured")
    return ddb.Table(S.filemgr_table_name)


def _bucket() -> str:
    if not S.filemgr_bucket:
        raise HTTPException(500, "file manager bucket not configured")
    return S.filemgr_bucket


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ttl_epoch_from_now(days: int) -> int:
    safe_days = max(1, int(days))
    return int((datetime.now(timezone.utc) + timedelta(days=safe_days)).timestamp())


def _record_usage_event_safe(event: Dict[str, Any]) -> None:
    try:
        record_usage_event_and_aggregates(_table(), event)
    except Exception:
        logger.exception("filemgr usage metering failed", extra={"event_type": event.get("event_type"), "source": event.get("source")})


def _record_usage_event_non_aggregating_safe(event: Dict[str, Any]) -> None:
    try:
        record_usage_event_and_aggregates(_table(), event, apply_aggregates=False)
    except Exception:
        logger.exception("filemgr usage metering (non-aggregate) failed", extra={"event_type": event.get("event_type"), "source": event.get("source")})


def record_download_usage(user: str, path: str, bytes_count: int, *, source: str, request_id: Optional[str] = None) -> None:
    if bytes_count <= 0:
        return
    p = norm_path(path, is_folder=False)
    event = build_usage_event(
        user_id=user,
        event_type="download",
        bytes_count=bytes_count,
        source=source,
        resource_path=p,
        request_id=request_id,
        idempotency_key=f"download|{source}|{user}|{p}|{request_id or ''}|{bytes_count}",
    )
    _record_usage_event_safe(event)


def record_storage_delta(
    user: str,
    path: str,
    delta_bytes: int,
    *,
    source: str,
    request_id: Optional[str] = None,
    aggregate: bool = True,
) -> None:
    p = norm_path(path, is_folder=False)
    event = build_usage_event(
        user_id=user,
        event_type="storage_delta",
        bytes_count=int(delta_bytes),
        source=source,
        resource_path=p,
        request_id=request_id,
        idempotency_key=f"storage_delta|{source}|{user}|{p}|{request_id or ''}|{int(delta_bytes)}",
    )
    if aggregate:
        _record_usage_event_safe(event)
    else:
        _record_usage_event_non_aggregating_safe(event)


def _parse_iso(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def _ttl_epoch(ts: datetime) -> int:
    return int(ts.timestamp())


def _normalize_encryption_meta(meta: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not meta:
        return None

    missing = [k for k in ENCRYPTION_META_REQUIRED_KEYS if k not in meta]
    if missing:
        raise HTTPException(400, f"invalid encryption metadata: missing {', '.join(sorted(missing))}")

    version = meta.get("version")
    if not isinstance(version, int) or version not in ENCRYPTION_VERSION_SUPPORTED:
        raise HTTPException(400, "invalid encryption metadata: unsupported version")

    iterations = meta.get("iterations")
    if not isinstance(iterations, int) or not (ENCRYPTION_ITERATIONS_MIN <= iterations <= ENCRYPTION_ITERATIONS_MAX):
        raise HTTPException(400, "invalid encryption metadata: iterations out of bounds")

    orig_size = meta.get("orig_size")
    if not isinstance(orig_size, int) or orig_size < 0:
        raise HTTPException(400, "invalid encryption metadata: invalid orig_size")

    for key in ("alg", "kdf", "orig_name", "mime"):
        value = meta.get(key)
        if not isinstance(value, str) or not value.strip():
            raise HTTPException(400, f"invalid encryption metadata: invalid {key}")

    for key in ("salt_b64", "iv_b64"):
        value = meta.get(key)
        if not isinstance(value, str) or not value.strip():
            raise HTTPException(400, f"invalid encryption metadata: invalid {key}")
        try:
            decoded = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise HTTPException(400, f"invalid encryption metadata: invalid {key}") from exc
        if len(decoded) == 0:
            raise HTTPException(400, f"invalid encryption metadata: invalid {key}")

    out: Dict[str, Any] = {key: meta[key] for key in ENCRYPTION_META_REQUIRED_KEYS}
    return out


def _flatten_encryption_meta(meta: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not meta:
        return {}
    return {
        "enc_version": meta.get("version"),
        "enc_alg": meta.get("alg"),
        "enc_kdf": meta.get("kdf"),
        "enc_kdf_iterations": meta.get("iterations"),
        "enc_salt_b64": meta.get("salt_b64"),
        "enc_iv_b64": meta.get("iv_b64"),
        "enc_orig_name": meta.get("orig_name"),
        "enc_orig_size": meta.get("orig_size"),
        "enc_orig_content_type": meta.get("mime"),
    }


def encryption_info_from_node(node: Dict[str, Any]) -> Dict[str, Any]:
    meta = node.get("enc_metadata")
    if not meta and node.get("enc_version") is not None:
        meta = {
            "version": node.get("enc_version"),
            "alg": node.get("enc_alg"),
            "kdf": node.get("enc_kdf"),
            "iterations": node.get("enc_kdf_iterations"),
            "salt_b64": node.get("enc_salt_b64"),
            "iv_b64": node.get("enc_iv_b64"),
            "orig_name": node.get("enc_orig_name"),
            "orig_size": node.get("enc_orig_size"),
            "mime": node.get("enc_orig_content_type"),
        }
    flat = _flatten_encryption_meta(meta)
    return {
        "is_encrypted": node.get("is_encrypted", False),
        "enc_metadata": meta,
        **flat,
    }


def norm_path(path: str, is_folder: Optional[bool] = None) -> str:
    """
    Normalize paths:
    - always starts with "/"
    - no ".."
    - folders end with "/"
    """
    if not path:
        raise HTTPException(400, "path required")
    if not path.startswith("/"):
        path = "/" + path
    path = re.sub(r"/+", "/", path)

    parts = []
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            raise HTTPException(400, "invalid path")
        parts.append(part)

    normalized = "/" + "/".join(parts)
    if is_folder is True and not normalized.endswith("/"):
        normalized += "/"
    if is_folder is False and normalized.endswith("/") and normalized != "/":
        normalized = normalized[:-1]
    if normalized == "":
        normalized = "/"
    return normalized


def split_parent_name(path: str) -> tuple[str, str]:
    if path == "/":
        return "/", ""
    path2 = path[:-1] if path.endswith("/") else path
    parent = path2.rsplit("/", 1)[0]
    name = path2.rsplit("/", 1)[1]
    if parent == "":
        parent = "/"
    else:
        parent = parent + "/"
    return parent, name


def pk_user(user: str) -> str:
    return f"USER#{user}"


def sk_node(path: str) -> str:
    return f"NODE#{path}"


def node_key(user: str, path: str) -> Dict[str, str]:
    return {"PK": pk_user(user), "SK": sk_node(path)}


def get_node(owner: str, path: str) -> Dict[str, Any]:
    tbl = _table()
    resp = tbl.get_item(Key=node_key(owner, path), ConsistentRead=True)
    if "Item" not in resp:
        raise HTTPException(404, "not found")
    if resp["Item"].get("deleted_at"):
        raise HTTPException(404, "not found")
    return resp["Item"]


def put_node(item: Dict[str, Any]) -> None:
    tbl = _table()
    tbl.put_item(Item=item)


def delete_node(owner: str, path: str) -> None:
    tbl = _table()
    tbl.delete_item(Key=node_key(owner, path))


def list_children_page(
    owner: str,
    folder_path: str,
    *,
    include_deleted: bool = False,
    limit: Optional[int] = None,
    cursor: Optional[Dict[str, Any]] = None,
    scan_forward: Optional[bool] = None,
) -> tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    started = time.perf_counter()
    tbl = _table()

    def _filter(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if include_deleted:
            return items
        return [it for it in items if not it.get("deleted_at")]

    def _query_kwargs() -> Dict[str, Any]:
        kwargs: Dict[str, Any] = {}
        if limit is not None:
            kwargs["Limit"] = limit
        if cursor:
            kwargs["ExclusiveStartKey"] = cursor
        if scan_forward is not None:
            kwargs["ScanIndexForward"] = scan_forward
        return kwargs

    try:
        resp = tbl.query(
            IndexName="GSI2",
            KeyConditionExpression=Key("GSI2PK").eq(f"PARENT#{folder_path}"),
            **_query_kwargs(),
        )
        out = (_filter(resp.get("Items", [])), resp.get("LastEvaluatedKey"))
        record_filemgr_operation_latency("list", time.perf_counter() - started)
        return out
    except ClientError:
        record_filemgr_search_path("list_children", "gsi2_fallback")
        prefix = f"NODE#{folder_path}"
        resp = tbl.query(
            KeyConditionExpression=Key("PK").eq(pk_user(owner)) & Key("SK").begins_with(prefix),
            **_query_kwargs(),
        )
        out = (_filter(resp.get("Items", [])), resp.get("LastEvaluatedKey"))
        record_filemgr_operation_latency("list", time.perf_counter() - started)
        return out


def list_children(owner: str, folder_path: str, *, include_deleted: bool = False) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    cursor: Optional[Dict[str, Any]] = None
    while True:
        batch, cursor = list_children_page(
            owner,
            folder_path,
            include_deleted=include_deleted,
            cursor=cursor,
        )
        items.extend(batch)
        if not cursor:
            break
    return items


def is_ancestor_path(folder_path: str, maybe_child_path: str) -> bool:
    return maybe_child_path.startswith(folder_path)


def ensure_folder_exists(owner: str, folder_path: str) -> None:
    folder_path = norm_path(folder_path, is_folder=True)
    if folder_path == "/":
        return
    try:
        node = get_node(owner, folder_path)
        if node.get("type") != "folder":
            raise HTTPException(400, "parent is not a folder")
    except HTTPException as exc:
        if exc.status_code == 404:
            raise HTTPException(400, "parent folder does not exist") from exc
        raise


def require_not_exists(owner: str, path: str) -> None:
    tbl = _table()
    resp = tbl.get_item(Key=node_key(owner, path), ConsistentRead=True)
    if "Item" in resp:
        raise HTTPException(409, "already exists")


def search_prefix(user: str, prefix: str, *, limit: int = 50) -> List[Dict[str, Any]]:
    started = time.perf_counter()
    tbl = _table()
    prefix_lc = prefix.lower()
    resp = tbl.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq(pk_user(user))
        & Key("GSI1SK").begins_with(f"NAME#{prefix_lc}"),
        Limit=limit,
    )
    items = [it for it in resp.get("Items", []) if not it.get("deleted_at")]
    out = [
        {"path": it["path"], "type": it["type"], "name": it["name"], "size": it.get("size")}
        for it in items
    ]
    record_filemgr_operation_latency("search", time.perf_counter() - started)
    return out


def _search_tokens(text: str) -> List[str]:
    return [t for t in re.findall(r"[a-z0-9@._-]+", (text or "").lower()) if t]


def _node_haystack(item: Dict[str, Any]) -> str:
    return " ".join(
        [
            str(item.get("name", "")),
            str(item.get("path", "")),
            str(item.get("type", "")),
        ]
    ).lower()


def _node_matches(tokens: List[str], item: Dict[str, Any]) -> bool:
    if not tokens:
        return False
    haystack = _node_haystack(item)
    return all(token in haystack for token in tokens)


def _maybe_probe_duration(bucket: str, s3_key: str, content_type: Optional[str]) -> Optional[int]:
    if not content_type or not (content_type.startswith("audio/") or content_type.startswith("video/")):
        return None
    if not shutil.which("ffprobe"):
        return None
    with tempfile.NamedTemporaryFile(suffix=".media") as tmp:
        try:
            _s3.download_fileobj(bucket, s3_key, tmp)
            tmp.flush()
            result = subprocess.run(
                [
                    "ffprobe",
                    "-v",
                    "error",
                    "-show_entries",
                    "format=duration",
                    "-of",
                    "default=noprint_wrappers=1:nokey=1",
                    tmp.name,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
        except ClientError:
            return None
        except OSError:
            return None
    if result.returncode != 0:
        return None
    try:
        return int(float(result.stdout.strip()))
    except (TypeError, ValueError):
        return None


def _maybe_generate_thumbnail(
    bucket: str,
    s3_key: str,
    content_type: Optional[str],
) -> Optional[Dict[str, Any]]:
    if not content_type or not content_type.startswith("video/"):
        return None
    if not shutil.which("ffmpeg"):
        return None
    with tempfile.TemporaryDirectory() as tmpdir:
        input_path = f"{tmpdir}/input"
        output_path = f"{tmpdir}/thumb.jpg"
        try:
            with open(input_path, "wb") as infile:
                _s3.download_fileobj(bucket, s3_key, infile)
            result = subprocess.run(
                [
                    "ffmpeg",
                    "-y",
                    "-i",
                    input_path,
                    "-ss",
                    "00:00:01",
                    "-frames:v",
                    "1",
                    "-vf",
                    "scale=320:-1",
                    output_path,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
        except ClientError:
            return None
        except OSError:
            return None
        if result.returncode != 0:
            return None
        thumb_key = f"{s3_key}_thumb.jpg"
        try:
            _s3.upload_file(
                Filename=output_path,
                Bucket=bucket,
                Key=thumb_key,
                ExtraArgs={"ContentType": "image/jpeg"},
            )
        except ClientError:
            return None
    return {"bucket": bucket, "key": thumb_key, "content_type": "image/jpeg"}


def _token_pk(user: str, token: str) -> str:
    return f"TOKEN#{token}#USER#{user}"


def _token_sk(path: str) -> str:
    return f"PATH#{path}"


def _upload_ticket_sk(ticket_id: str) -> str:
    return f"UPLOADTICKET#{ticket_id}"


def _token_entry(user: str, item: Dict[str, Any], token: str) -> Dict[str, Any]:
    return {
        "PK": _token_pk(user, token),
        "SK": _token_sk(item["path"]),
        "path": item["path"],
        "type": item.get("type"),
        "name": item.get("name"),
        "size": item.get("size"),
        "updated_at": item.get("updated_at"),
    }


def _node_tokens(item: Dict[str, Any]) -> List[str]:
    return _search_tokens(_node_haystack(item))


def _put_token_entries(user: str, item: Dict[str, Any]) -> None:
    if not S.filemgr_table_name:
        return
    if item.get("is_encrypted"):
        return
    tbl = _table()
    for token in _node_tokens(item):
        tbl.put_item(Item=_token_entry(user, item, token))


def _delete_token_entries(user: str, item: Dict[str, Any]) -> None:
    if not S.filemgr_table_name:
        return
    tbl = _table()
    for token in _node_tokens(item):
        tbl.delete_item(Key={"PK": _token_pk(user, token), "SK": _token_sk(item["path"])})


def _soft_delete_node(user: str, item: Dict[str, Any], deleted_by: str) -> None:
    if item.get("deleted_at"):
        return
    tbl = _table()
    deleted_at = now_iso()
    purge_after_dt = datetime.now(timezone.utc) + timedelta(days=S.filemgr_retention_days)
    purge_after = purge_after_dt.isoformat()
    ttl_attr = S.ddb_ttl_attr
    expression_names = {}
    expression_values = {
        ":t": deleted_at,
        ":u": deleted_by,
        ":p": purge_after,
        ":s": "pending",
        ":gpk": "PURGE#pending",
        ":gsk": f"{purge_after}#{user}#{item['path']}",
    }
    update_expr = (
        "SET deleted_at=:t, deleted_by=:u, updated_at=:t, "
        "purge_after=:p, purge_status=:s, GSI_PURGEPK=:gpk, GSI_PURGESK=:gsk"
    )
    if ttl_attr:
        expression_names["#ttl"] = ttl_attr
        expression_values[":ttl"] = _ttl_epoch(purge_after_dt)
        update_expr += ", #ttl=:ttl"
    update_kwargs: Dict[str, Any] = {
        "Key": node_key(user, item["path"]),
        "UpdateExpression": update_expr,
        "ExpressionAttributeValues": expression_values,
    }
    if expression_names:
        update_kwargs["ExpressionAttributeNames"] = expression_names
    tbl.update_item(**update_kwargs)
    if item.get("s3_bucket") and item.get("s3_key"):
        try:
            _s3.put_object_tagging(
                Bucket=item["s3_bucket"],
                Key=item["s3_key"],
                Tagging={
                    "TagSet": [
                        {"Key": "filemgr_deleted", "Value": "true"},
                        {"Key": "filemgr_purge_after", "Value": purge_after},
                    ]
                },
            )
        except ClientError:
            logger.exception("Failed to tag deleted file manager object")


def _search_text_scan(user: str, query: str, *, limit: int = 50) -> List[Dict[str, Any]]:
    tokens = _search_tokens(query)
    if not tokens:
        record_filemgr_operation_latency("search", time.perf_counter() - started)
        return []
    tbl = _table()
    out: List[Dict[str, Any]] = []
    start_key: Optional[Dict[str, Any]] = None
    while len(out) < limit:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("PK").eq(pk_user(user)) & Key("SK").begins_with("NODE#"),
            "Limit": max(50, min(200, limit * 4)),
        }
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = tbl.query(**kwargs)
        for item in resp.get("Items", []):
            if item.get("deleted_at"):
                continue
            if item.get("is_encrypted"):
                continue
            if _node_matches(tokens, item):
                out.append(
                    {
                        "path": item.get("path"),
                        "type": item.get("type"),
                        "name": item.get("name"),
                        "size": item.get("size"),
                        "updated_at": item.get("updated_at"),
                    }
                )
                if len(out) >= limit:
                    break
        start_key = resp.get("LastEvaluatedKey")
        if not start_key:
            break
    return out


def _query_token_items(user: str, token: str, *, limit: int) -> List[Dict[str, Any]]:
    tbl = _table()
    out: List[Dict[str, Any]] = []
    start_key: Optional[Dict[str, Any]] = None
    while len(out) < limit:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("PK").eq(_token_pk(user, token)) & Key("SK").begins_with("PATH#"),
            "Limit": max(50, min(200, limit)),
        }
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = tbl.query(**kwargs)
        out.extend(resp.get("Items", []))
        start_key = resp.get("LastEvaluatedKey")
        if not start_key:
            break
    return out[:limit]

def search_text(user: str, query: str, *, limit: int = 50) -> List[Dict[str, Any]]:
    started = time.perf_counter()
    tokens = _search_tokens(query)
    if not tokens:
        record_filemgr_operation_latency("search", time.perf_counter() - started)
        return []
    items = _query_token_items(user, tokens[0], limit=limit * 4)
    if not items:
        record_filemgr_search_path("search_text", "scan_fallback")
        out = _search_text_scan(user, query, limit=limit)
        record_filemgr_operation_latency("search", time.perf_counter() - started)
        return out
    record_filemgr_search_path("search_text", "token_index")
    by_path = {it["path"]: it for it in items}
    paths = set(by_path.keys())
    for token in tokens[1:]:
        token_items = _query_token_items(user, token, limit=limit * 4)
        if not token_items:
            record_filemgr_operation_latency("search", time.perf_counter() - started)
            return []
        token_paths = {it["path"] for it in token_items}
        paths &= token_paths
        if not paths:
            record_filemgr_operation_latency("search", time.perf_counter() - started)
            return []
    results = [by_path[p] for p in paths if p in by_path and not by_path[p].get("is_encrypted")]
    results.sort(key=lambda x: (x.get("type") != "folder", (x.get("name") or "").lower()))
    out = results[:limit]
    result = [
        {
            "path": it.get("path"),
            "type": it.get("type"),
            "name": it.get("name"),
            "size": it.get("size"),
            "updated_at": it.get("updated_at"),
        }
        for it in out
    ]
    record_filemgr_operation_latency("search", time.perf_counter() - started)
    return result


def create_empty_folder(user: str, path: str) -> str:
    folder = norm_path(path, is_folder=True)
    if folder == "/":
        return "/"
    parent, name = split_parent_name(folder)
    ensure_folder_exists(user, parent)
    require_not_exists(user, folder)
    item = {
        "PK": pk_user(user),
        "SK": sk_node(folder),
        "type": "folder",
        "path": folder,
        "name": name,
        "name_lc": name.lower(),
        "parent": parent,
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "GSI1PK": pk_user(user),
        "GSI1SK": f"NAME#{name.lower()}#PATH#{folder}",
        "GSI2PK": f"PARENT#{parent}",
        "GSI2SK": f"TYPE#folder#NAME#{name.lower()}#PATH#{folder}",
    }
    put_node(item)
    _put_token_entries(user, item)
    return folder


def upload_file(
    user: str,
    path: str,
    file: UploadFile,
    *,
    encryption_meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    started = time.perf_counter()
    bucket = _bucket()
    p = norm_path(path, is_folder=False)
    parent, name = split_parent_name(p)
    ensure_folder_exists(user, parent)
    require_not_exists(user, p)

    obj_id = str(uuid.uuid4())
    s3_key = f"{user}/objects/{obj_id}"

    try:
        _s3.upload_fileobj(
            Fileobj=file.file,
            Bucket=bucket,
            Key=s3_key,
            ExtraArgs={"ContentType": file.content_type or "application/octet-stream"},
        )
        head = _s3.head_object(Bucket=bucket, Key=s3_key)
        size = int(head.get("ContentLength", 0))
        etag = head.get("ETag")
    except ClientError as exc:
        raise HTTPException(500, f"s3 error: {exc}") from exc

    try:
        _enforce_upload_and_storage_quotas(user, incoming_bytes=size)
    except HTTPException:
        try:
            _s3.delete_object(Bucket=bucket, Key=s3_key)
        except Exception:
            logger.exception("failed to clean up over-quota direct upload", extra={"user": user, "path": p})
        raise

    enc_meta = _normalize_encryption_meta(encryption_meta)
    is_encrypted = enc_meta is not None

    duration_seconds = None if is_encrypted else _maybe_probe_duration(bucket, s3_key, file.content_type)
    thumbnail = None if is_encrypted else _maybe_generate_thumbnail(bucket, s3_key, file.content_type)

    item = {
        "PK": pk_user(user),
        "SK": sk_node(p),
        "type": "file",
        "path": p,
        "name": name,
        "name_lc": name.lower(),
        "parent": parent,
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "upload_at": now_iso(),
        "upload_by": user,
        "size": size,
        "content_type": file.content_type or "application/octet-stream",
        "duration_seconds": duration_seconds,
        "thumbnail": thumbnail,
        "s3_bucket": bucket,
        "s3_key": s3_key,
        "etag": etag,
        "is_encrypted": is_encrypted,
        "enc_metadata": enc_meta,
        **_flatten_encryption_meta(enc_meta),
        "GSI1PK": pk_user(user),
        "GSI1SK": f"NAME#{name.lower()}#PATH#{p}",
        "GSI2PK": f"PARENT#{parent}",
        "GSI2SK": f"TYPE#file#NAME#{name.lower()}#PATH#{p}",
    }
    put_node(item)
    _put_token_entries(user, item)
    usage_event = build_usage_event(
        user_id=user,
        event_type="upload",
        bytes_count=size,
        source="api_upload",
        resource_path=p,
        idempotency_key=f"upload|{user}|{p}|{s3_key}|{etag or ''}",
    )
    _record_usage_event_safe(usage_event)
    record_storage_delta(user, p, size, source="upload_create")
    record_filemgr_bytes("uploaded", "upload", size)
    record_filemgr_operation_latency("upload", time.perf_counter() - started)
    return {"path": p, "size": size}


def presign_upload(user: str, path: str, *, content_type: Optional[str]) -> Dict[str, Any]:
    bucket = _bucket()
    p = norm_path(path, is_folder=False)
    parent, name = split_parent_name(p)
    ensure_folder_exists(user, parent)
    require_not_exists(user, p)

    obj_id = str(uuid.uuid4())
    s3_key = f"{user}/objects/{obj_id}"
    ticket_id = str(uuid.uuid4())
    expires_at_dt = datetime.now(timezone.utc) + timedelta(minutes=15)
    expires_at = expires_at_dt.isoformat()
    resolved_content_type = content_type or "application/octet-stream"

    upload_url = _s3.generate_presigned_url(
        ClientMethod="put_object",
        Params={
            "Bucket": bucket,
            "Key": s3_key,
            "ContentType": resolved_content_type,
            "Metadata": {
                "filemgr-ticket": ticket_id,
                "filemgr-user": user,
            },
        },
        ExpiresIn=900,
    )
    _table().put_item(
        Item={
            "PK": pk_user(user),
            "SK": _upload_ticket_sk(ticket_id),
            "ticket_id": ticket_id,
            "path": p,
            "s3_key": s3_key,
            "content_type": resolved_content_type,
            "expires_at": expires_at,
            "created_at": now_iso(),
            "updated_at": now_iso(),
        }
    )
    return {
        "upload_url": upload_url,
        "bucket": bucket,
        "key": s3_key,
        "ticket_id": ticket_id,
        "path": p,
        "content_type": resolved_content_type,
        "name": name,
        "parent": parent,
    }


def register_presigned_upload(
    user: str,
    path: str,
    *,
    s3_key: str,
    ticket_id: str,
    content_type: Optional[str],
    encryption_meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    started = time.perf_counter()
    p = norm_path(path, is_folder=False)
    parent, name = split_parent_name(p)
    ensure_folder_exists(user, parent)
    require_not_exists(user, p)

    required_prefix = f"{user}/objects/"
    if not s3_key.startswith(required_prefix):
        raise HTTPException(403, "invalid upload key")

    bucket = _bucket()

    tbl = _table()
    ticket_resp = tbl.get_item(Key={"PK": pk_user(user), "SK": _upload_ticket_sk(ticket_id)}, ConsistentRead=True)
    ticket = ticket_resp.get("Item")
    if not ticket:
        raise HTTPException(403, "invalid upload ticket")
    if ticket.get("path") != p or ticket.get("s3_key") != s3_key:
        raise HTTPException(403, "upload ticket mismatch")
    ticket_expiry = _parse_iso(ticket.get("expires_at"))
    if not ticket_expiry or ticket_expiry <= datetime.now(timezone.utc):
        raise HTTPException(403, "upload ticket expired")

    try:
        head = _s3.head_object(Bucket=bucket, Key=s3_key)
        size = int(head.get("ContentLength", 0))
        etag = head.get("ETag")
        resolved_content_type = content_type or ticket.get("content_type") or head.get("ContentType") or "application/octet-stream"
        metadata = head.get("Metadata") or {}
        if metadata.get("filemgr-ticket") != ticket_id or metadata.get("filemgr-user") != user:
            raise HTTPException(403, "uploaded object metadata mismatch")
    except ClientError as exc:
        raise HTTPException(500, f"s3 error: {exc}") from exc

    try:
        _enforce_upload_and_storage_quotas(user, incoming_bytes=size)
    except HTTPException:
        try:
            _s3.delete_object(Bucket=bucket, Key=s3_key)
        except Exception:
            logger.exception("failed to clean up over-quota presigned upload", extra={"user": user, "path": p, "ticket_id": ticket_id})
        raise

    enc_meta = _normalize_encryption_meta(encryption_meta)
    is_encrypted = enc_meta is not None

    duration_seconds = None if is_encrypted else _maybe_probe_duration(bucket, s3_key, resolved_content_type)
    thumbnail = None if is_encrypted else _maybe_generate_thumbnail(bucket, s3_key, resolved_content_type)

    item = {
        "PK": pk_user(user),
        "SK": sk_node(p),
        "type": "file",
        "path": p,
        "name": name,
        "name_lc": name.lower(),
        "parent": parent,
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "upload_at": now_iso(),
        "upload_by": user,
        "size": size,
        "content_type": resolved_content_type,
        "duration_seconds": duration_seconds,
        "thumbnail": thumbnail,
        "s3_bucket": bucket,
        "s3_key": s3_key,
        "etag": etag,
        "is_encrypted": is_encrypted,
        "enc_metadata": enc_meta,
        **_flatten_encryption_meta(enc_meta),
        "GSI1PK": pk_user(user),
        "GSI1SK": f"NAME#{name.lower()}#PATH#{p}",
        "GSI2PK": f"PARENT#{parent}",
        "GSI2SK": f"TYPE#file#NAME#{name.lower()}#PATH#{p}",
    }
    put_node(item)
    _put_token_entries(user, item)
    usage_event = build_usage_event(
        user_id=user,
        event_type="upload",
        bytes_count=size,
        source="presign_complete",
        resource_path=p,
        idempotency_key=f"complete_upload|{user}|{ticket_id}|{s3_key}|{etag or ''}",
    )
    _record_usage_event_safe(usage_event)
    record_storage_delta(user, p, size, source="complete_upload_create")
    record_filemgr_bytes("uploaded", "complete_upload", size)
    tbl.delete_item(Key={"PK": pk_user(user), "SK": _upload_ticket_sk(ticket_id)})
    record_filemgr_operation_latency("upload", time.perf_counter() - started)
    return {"path": p, "size": size, "content_type": resolved_content_type, "duration_seconds": duration_seconds}


def build_download_url(path: str) -> str:
    return f"{S.public_base_url}/v1/fs/download?path={quote(path, safe='')}"


def upload_profile_photo(
    user: str,
    *,
    kind: str,
    file_name: str,
    content: bytes,
    content_type: Optional[str] = None,
) -> Dict[str, Any]:
    bucket = _bucket()
    safe_name = file_name.replace("/", "_")
    obj_id = str(uuid.uuid4())
    folder = norm_path(f"/profile/photos/{kind}/", is_folder=True)
    _auto_create_parents(user, folder)
    path = norm_path(f"{folder}{obj_id}_{safe_name}", is_folder=False)
    require_not_exists(user, path)

    extra_args = {"ContentType": content_type or "application/octet-stream"}
    resp = _s3.put_object(Bucket=bucket, Key=f"{user}/objects/{obj_id}", Body=content, **extra_args)
    etag = resp.get("ETag")
    size = len(content)

    parent, name = split_parent_name(path)
    item = {
        "PK": pk_user(user),
        "SK": sk_node(path),
        "type": "file",
        "path": path,
        "name": name,
        "name_lc": name.lower(),
        "parent": parent,
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "upload_at": now_iso(),
        "upload_by": user,
        "size": size,
        "content_type": content_type or "application/octet-stream",
        "s3_bucket": bucket,
        "s3_key": f"{user}/objects/{obj_id}",
        "etag": etag,
        **_flatten_encryption_meta(enc_meta),
        "GSI1PK": pk_user(user),
        "GSI1SK": f"NAME#{name.lower()}#PATH#{path}",
        "GSI2PK": f"PARENT#{parent}",
        "GSI2SK": f"TYPE#file#NAME#{name.lower()}#PATH#{path}",
    }
    put_node(item)
    _put_token_entries(user, item)
    return {"path": path, "size": size}


def upload_billing_receipt(
    user: str,
    *,
    txn_id: str,
    content: bytes,
) -> Dict[str, Any]:
    bucket = _bucket()
    obj_id = str(uuid.uuid4())
    folder = norm_path("/billing/receipts/", is_folder=True)
    _auto_create_parents(user, folder)
    path = norm_path(f"{folder}{txn_id}.pdf", is_folder=False)
    require_not_exists(user, path)

    resp = _s3.put_object(Bucket=bucket, Key=f"{user}/objects/{obj_id}", Body=content, ContentType="application/pdf")
    etag = resp.get("ETag")
    size = len(content)

    parent, name = split_parent_name(path)
    item = {
        "PK": pk_user(user),
        "SK": sk_node(path),
        "type": "file",
        "path": path,
        "name": name,
        "name_lc": name.lower(),
        "parent": parent,
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "upload_at": now_iso(),
        "upload_by": user,
        "size": size,
        "content_type": "application/pdf",
        "s3_bucket": bucket,
        "s3_key": f"{user}/objects/{obj_id}",
        "etag": etag,
        **_flatten_encryption_meta(enc_meta),
        "GSI1PK": pk_user(user),
        "GSI1SK": f"NAME#{name.lower()}#PATH#{path}",
        "GSI2PK": f"PARENT#{parent}",
        "GSI2SK": f"TYPE#file#NAME#{name.lower()}#PATH#{path}",
    }
    put_node(item)
    _put_token_entries(user, item)
    return {"path": path, "size": size}


def upload_catalog_image(
    item_id: str,
    *,
    file_name: str,
    content: bytes,
    content_type: Optional[str] = None,
) -> Dict[str, Any]:
    bucket = _bucket()
    owner = "catalog"
    safe_name = file_name.replace("/", "_")
    obj_id = str(uuid.uuid4())
    folder = norm_path(f"/catalog/items/{item_id}/", is_folder=True)
    _auto_create_parents(owner, folder)
    path = norm_path(f"{folder}{obj_id}_{safe_name}", is_folder=False)
    require_not_exists(owner, path)

    extra_args = {"ContentType": content_type or "application/octet-stream"}
    resp = _s3.put_object(Bucket=bucket, Key=f"{owner}/objects/{obj_id}", Body=content, **extra_args)
    etag = resp.get("ETag")
    size = len(content)

    parent, name = split_parent_name(path)
    item = {
        "PK": pk_user(owner),
        "SK": sk_node(path),
        "type": "file",
        "path": path,
        "name": name,
        "name_lc": name.lower(),
        "parent": parent,
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "upload_at": now_iso(),
        "upload_by": owner,
        "size": size,
        "content_type": content_type or "application/octet-stream",
        "s3_bucket": bucket,
        "s3_key": f"{owner}/objects/{obj_id}",
        "etag": etag,
        "GSI1PK": pk_user(owner),
        "GSI1SK": f"NAME#{name.lower()}#PATH#{path}",
        "GSI2PK": f"PARENT#{parent}",
        "GSI2SK": f"TYPE#file#NAME#{name.lower()}#PATH#{path}",
    }
    put_node(item)
    _put_token_entries(owner, item)
    return {"path": path, "size": size}


def download_file(user: str, path: str) -> Dict[str, Any]:
    started = time.perf_counter()
    p = norm_path(path, is_folder=False)
    node = get_node(user, p)
    if node.get("type") != "file":
        raise HTTPException(400, "not a file")

    try:
        obj = _s3.get_object(Bucket=node["s3_bucket"], Key=node["s3_key"])
    except ClientError as exc:
        raise HTTPException(500, f"s3 error: {exc}") from exc

    tbl = _table()
    try:
        tbl.update_item(
            Key=node_key(user, p),
            UpdateExpression="SET last_download_at=:t, last_download_by=:u, updated_at=:t",
            ExpressionAttributeValues={":t": now_iso(), ":u": user},
        )
    except ClientError:
        pass

    record_filemgr_bytes("downloaded", "download", int(node.get("size") or 0))
    record_filemgr_operation_latency("download", time.perf_counter() - started)
    return {"node": node, "object": obj}


def download_thumbnail(user: str, path: str) -> Dict[str, Any]:
    started = time.perf_counter()
    p = norm_path(path, is_folder=False)
    node = get_node(user, p)
    if node.get("type") != "file":
        raise HTTPException(400, "not a file")
    if node.get("is_encrypted"):
        raise HTTPException(415, "thumbnail not available for encrypted files")
    thumb = node.get("thumbnail")
    if not thumb:
        raise HTTPException(404, "thumbnail not available")
    try:
        obj = _s3.get_object(Bucket=thumb["bucket"], Key=thumb["key"])
    except ClientError as exc:
        raise HTTPException(500, f"s3 error: {exc}") from exc
    return {"node": node, "thumbnail": thumb, "object": obj}




def _detect_preview_kind(node: Dict[str, Any]) -> str:
    content_type = (node.get("content_type") or "").strip().lower()
    name = (node.get("name") or node.get("path") or "").strip().lower()

    ext = ""
    if "." in name:
        ext = name.rsplit(".", 1)[-1]

    ext_map = {
        "png": "image",
        "jpg": "image",
        "jpeg": "image",
        "gif": "image",
        "webp": "image",
        "bmp": "image",
        "svg": "image",
        "pdf": "pdf",
        "doc": "word",
        "docx": "word",
        "csv": "csv",
        "xls": "excel",
        "xlsx": "excel",
        "parquet": "parquet",
        "txt": "text",
        "md": "text",
        "json": "text",
        "xml": "text",
        "yaml": "text",
        "yml": "text",
        "log": "text",
        "py": "text",
        "js": "text",
        "ts": "text",
        "tsx": "text",
        "jsx": "text",
        "css": "text",
        "html": "text",
        "java": "text",
        "go": "text",
        "rs": "text",
        "sql": "text",
        "sh": "text",
    }
    if ext in ext_map:
        return ext_map[ext]

    content_type_map = {
        "application/pdf": "pdf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "word",
        "application/msword": "word",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "excel",
        "application/vnd.ms-excel": "excel",
        "text/csv": "csv",
        "application/csv": "csv",
        "application/vnd.ms-excel.sheet.macroenabled.12": "excel",
        "application/parquet": "parquet",
        "application/vnd.apache.parquet": "parquet",
    }
    if content_type in content_type_map:
        return content_type_map[content_type]

    if content_type.startswith("image/"):
        return "image"
    if content_type.startswith("text/") or content_type in {"application/json", "application/xml"}:
        return "text"

    return "none"


def preview_capability_from_node(node: Dict[str, Any]) -> Dict[str, Any]:
    if node.get("type") != "file":
        return {"preview_kind": "none", "preview_supported": False, "preview_reason": "not_file"}

    preview_kind = _detect_preview_kind(node)
    preview_supported = is_previewable(node)
    max_bytes = int(getattr(S, "filemgr_preview_max_bytes", 0) or 0)
    size = int(node.get("size") or 0)

    if max_bytes > 0 and size > max_bytes:
        preview_supported = False
        preview_reason = "too_large"
    elif preview_supported:
        preview_reason = None
    elif node.get("is_encrypted"):
        preview_reason = "encrypted"
    elif preview_kind == "none":
        preview_reason = "unsupported_type"
    else:
        preview_reason = "not_enabled"

    return {
        "preview_kind": preview_kind,
        "preview_supported": preview_supported,
        "preview_reason": preview_reason,
    }
def is_previewable(node: Dict[str, Any]) -> bool:
    if node.get("is_encrypted"):
        return False
    content_type = (node.get("content_type") or "").lower()
    if content_type.startswith("image/"):
        return True
    if content_type in {"application/pdf"}:
        return True
    if content_type in {
        "text/csv",
        "application/csv",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.ms-excel",
        "application/vnd.ms-excel.sheet.macroenabled.12",
        "application/parquet",
        "application/vnd.apache.parquet",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/msword",
    }:
        return True
    if content_type.startswith("text/"):
        return True
    if content_type in {"application/json", "application/xml"}:
        return True
    return False



def _usage_limit_percentage(used: int, limit: int) -> Optional[float]:
    if limit <= 0:
        return None
    return round((float(used) / float(limit)) * 100.0, 2)


def _parse_plan_limits_config() -> Dict[str, Dict[str, int]]:
    raw = str(getattr(S, "filemgr_usage_plan_limits", "") or "")
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except Exception:
        logger.exception("invalid FILEMGR_USAGE_PLAN_LIMITS json")
        return {}
    if not isinstance(data, dict):
        return {}
    out: Dict[str, Dict[str, int]] = {}
    for plan_id, limits in data.items():
        if not isinstance(limits, dict):
            continue
        out[str(plan_id)] = {
            "upload_limit_bytes": int(limits.get("upload_limit_bytes") or 0),
            "download_limit_bytes": int(limits.get("download_limit_bytes") or 0),
            "storage_limit_bytes": int(limits.get("storage_limit_bytes") or 0),
        }
    return out


def _parse_user_plan_overrides() -> Dict[str, str]:
    raw = str(getattr(S, "filemgr_usage_user_plan_overrides", "") or "")
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except Exception:
        logger.exception("invalid FILEMGR_USAGE_USER_PLAN_OVERRIDES json")
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items()}


def resolve_user_usage_plan(user: str) -> Dict[str, Any]:
    tbl = _table()
    default_plan_id = str(getattr(S, "filemgr_usage_default_plan", "default") or "default")
    plan_limits = _parse_plan_limits_config()
    user_overrides = _parse_user_plan_overrides()

    source = "default"
    plan_id = default_plan_id
    if user in user_overrides:
        plan_id = user_overrides[user]
        source = "env_override"
    else:
        usage_plan_item = tbl.get_item(Key={"PK": pk_user(user), "SK": "USAGE#PLAN"}).get("Item") or {}
        if usage_plan_item.get("plan_id"):
            plan_id = str(usage_plan_item["plan_id"])
            source = "db"

    selected_limits = plan_limits.get(plan_id, {})
    upload_limit = int(selected_limits.get("upload_limit_bytes") or getattr(S, "filemgr_usage_upload_limit_bytes", 0) or 0)
    download_limit = int(selected_limits.get("download_limit_bytes") or getattr(S, "filemgr_usage_download_limit_bytes", 0) or 0)
    storage_limit = int(selected_limits.get("storage_limit_bytes") or getattr(S, "filemgr_usage_storage_limit_bytes", 0) or 0)

    return {
        "plan_id": plan_id,
        "source": source,
        "upload_limit_bytes": upload_limit,
        "download_limit_bytes": download_limit,
        "storage_limit_bytes": storage_limit,
    }


def _quota_exception(*, code: str, message: str, quota_type: str, limit_bytes: int, used_bytes: int) -> HTTPException:
    remaining = max(0, int(limit_bytes) - int(used_bytes))
    return HTTPException(
        status_code=403,
        detail={
            "code": code,
            "message": message,
            "quota_type": quota_type,
            "limit_bytes": int(limit_bytes),
            "used_bytes": int(used_bytes),
            "remaining_bytes": remaining,
        },
    )


def _enforce_upload_and_storage_quotas(user: str, *, incoming_bytes: int, summary: Optional[Dict[str, Any]] = None) -> None:
    if incoming_bytes < 0:
        return
    if not S.filemgr_table_name:
        return
    usage = summary or get_usage_summary(user)
    upload = usage["upload"]
    storage = usage["storage"]
    upload_limit = int(upload.get("limit_bytes") or 0)
    storage_limit = int(storage.get("limit_bytes") or 0)
    upload_used = int(upload.get("used_bytes") or 0)
    storage_used = int(storage.get("used_bytes") or 0)

    if upload_limit > 0 and (upload_used + incoming_bytes) > upload_limit:
        raise _quota_exception(
            code="upload_quota_exceeded",
            message="upload quota exceeded",
            quota_type="upload",
            limit_bytes=upload_limit,
            used_bytes=upload_used,
        )
    if storage_limit > 0 and (storage_used + incoming_bytes) > storage_limit:
        raise _quota_exception(
            code="storage_quota_exceeded",
            message="storage quota exceeded",
            quota_type="storage",
            limit_bytes=storage_limit,
            used_bytes=storage_used,
        )


def assert_download_allowed(user: str, *, requested_bytes: int = 0) -> None:
    if not S.filemgr_table_name:
        return
    mode = str(getattr(S, "filemgr_download_policy_mode", "off") or "off").strip().lower()
    if mode not in {"monitor", "enforce"}:
        return

    summary = get_usage_summary(user)
    used = int(summary["download"].get("used_bytes") or 0)
    limit = int(summary["download"].get("limit_bytes") or 0)
    if mode == "enforce" and limit > 0 and requested_bytes > 0 and used + requested_bytes > limit:
        raise _quota_exception(
            code="download_quota_exceeded",
            message="download quota exceeded",
            quota_type="download",
            limit_bytes=limit,
            used_bytes=used,
        )


def get_usage_summary(user: str, *, period_id: Optional[str] = None) -> Dict[str, Any]:
    tbl = _table()
    resolved_period = period_id or period_id_for_datetime(datetime.now(timezone.utc))
    period_bounds_utc(resolved_period)
    item = tbl.get_item(Key={"PK": pk_user(user), "SK": f"USAGE#PERIOD#{resolved_period}"}).get("Item") or {}

    upload_used = int(item.get("upload_bytes_total") or 0)
    download_used = int(item.get("download_bytes_total") or 0)
    storage_used = int(item.get("storage_bytes_current") or 0)

    plan = resolve_user_usage_plan(user)
    upload_limit = int(plan["upload_limit_bytes"])
    download_limit = int(plan["download_limit_bytes"])
    storage_limit = int(plan["storage_limit_bytes"])

    return {
        "period_id": resolved_period,
        "plan_id": plan.get("plan_id"),
        "plan_source": plan.get("source"),
        "upload": {
            "used_bytes": upload_used,
            "limit_bytes": upload_limit,
            "percent_used": _usage_limit_percentage(upload_used, upload_limit),
        },
        "download": {
            "used_bytes": download_used,
            "limit_bytes": download_limit,
            "percent_used": _usage_limit_percentage(download_used, download_limit),
        },
        "storage": {
            "used_bytes": storage_used,
            "limit_bytes": storage_limit,
            "percent_used": _usage_limit_percentage(storage_used, storage_limit),
        },
        "updated_at": item.get("updated_at"),
    }


def get_usage_daily(user: str, *, from_day: Optional[str] = None, to_day: Optional[str] = None) -> Dict[str, Any]:
    tbl = _table()
    start = datetime.fromisoformat(f"{from_day}T00:00:00+00:00") if from_day else datetime.now(timezone.utc) - timedelta(days=29)
    end = datetime.fromisoformat(f"{to_day}T00:00:00+00:00") if to_day else datetime.now(timezone.utc)
    if end < start:
        raise HTTPException(400, "invalid daily usage range")

    resp = tbl.query(
        KeyConditionExpression=Key("PK").eq(pk_user(user)) & Key("SK").begins_with("USAGE#DAY#"),
    )
    rows = []
    for it in resp.get("Items", []):
        day = str(it.get("day_utc") or "")
        if not day:
            sk = str(it.get("SK") or "")
            if sk.startswith("USAGE#DAY#"):
                day = sk.replace("USAGE#DAY#", "", 1)
        if not day:
            continue
        try:
            day_dt = datetime.fromisoformat(f"{day}T00:00:00+00:00")
        except ValueError:
            continue
        if day_dt < start or day_dt > end:
            continue
        rows.append({
            "day_utc": day,
            "upload_bytes_total": int(it.get("upload_bytes_total") or 0),
            "download_bytes_total": int(it.get("download_bytes_total") or 0),
            "storage_bytes_end_of_day": int(it.get("storage_bytes_end_of_day") or 0),
        })

    rows.sort(key=lambda x: x["day_utc"])
    return {
        "from": start.date().isoformat(),
        "to": end.date().isoformat(),
        "items": rows,
    }


def get_usage_storage(user: str, *, top_n: int = 10) -> Dict[str, Any]:
    tbl = _table()
    cursor: Optional[Dict[str, Any]] = None
    files: List[Dict[str, Any]] = []
    total = 0

    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("PK").eq(pk_user(user)) & Key("SK").begins_with("NODE#"),
            "Limit": 200,
        }
        if cursor:
            kwargs["ExclusiveStartKey"] = cursor
        resp = tbl.query(**kwargs)
        for it in resp.get("Items", []):
            if it.get("type") != "file" or it.get("deleted_at"):
                continue
            size = int(it.get("size") or 0)
            total += size
            files.append({"path": it.get("path"), "size": size})
        cursor = resp.get("LastEvaluatedKey")
        if not cursor:
            break

    files.sort(key=lambda x: x["size"], reverse=True)
    return {
        "storage_bytes_current": total,
        "top_files": files[: max(1, min(top_n, 100))],
    }

def remove_file(user: str, path: str) -> None:
    p = norm_path(path, is_folder=False)
    node = get_node(user, p)
    if node["type"] != "file":
        raise HTTPException(400, "not a file")
    _soft_delete_node(user, node, deleted_by=user)
    record_storage_delta(user, p, -int(node.get("size") or 0), source="delete_soft")
    _delete_token_entries(user, node)
    _delete_shares_for_path(owner=user, path=p)


def remove_folder(user: str, path: str) -> int:
    folder = norm_path(path, is_folder=True)
    if folder == "/":
        raise HTTPException(400, "cannot delete root")
    node = get_node(user, folder)
    if node["type"] != "folder":
        raise HTTPException(400, "not a folder")

    items = list_children(user, folder, include_deleted=True)
    for child in items:
        if child["path"] == folder:
            continue
        _soft_delete_node(user, child, deleted_by=user)
        if child.get("type") == "file":
            record_storage_delta(user, child["path"], -int(child.get("size") or 0), source="delete_soft")
        _delete_token_entries(user, child)
        _delete_shares_for_path(owner=user, path=child["path"])

    _soft_delete_node(user, node, deleted_by=user)
    _delete_token_entries(user, node)
    _delete_shares_for_path(owner=user, path=folder)
    return len(items)


def _list_move_tree_items(user: str, root_path: str) -> List[Dict[str, Any]]:
    """Return root + descendants sorted parent-first for stable move planning."""
    tbl = _table()
    root = norm_path(root_path, is_folder=True)
    prefix = f"NODE#{root}"
    items: List[Dict[str, Any]] = []
    cursor: Optional[Dict[str, Any]] = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("PK").eq(pk_user(user)) & Key("SK").begins_with(prefix),
            "Limit": 200,
        }
        if cursor:
            kwargs["ExclusiveStartKey"] = cursor
        resp = tbl.query(**kwargs)
        for it in resp.get("Items", []):
            if it.get("deleted_at"):
                continue
            items.append(it)
        cursor = resp.get("LastEvaluatedKey")
        if not cursor:
            break
    items.sort(key=lambda x: (x.get("path", "").count("/"), x.get("path", "")))
    return items


def _transact_move_item(tbl, user: str, item: Dict[str, Any], new_path: str, *, allow_existing_dst: bool = False) -> str:
    old_path = item["path"]
    existing_old = tbl.get_item(Key=node_key(user, old_path), ConsistentRead=True).get("Item")
    existing_new = tbl.get_item(Key=node_key(user, new_path), ConsistentRead=True).get("Item")

    if existing_old and existing_old.get("deleted_at"):
        existing_old = None
    if existing_new and existing_new.get("deleted_at"):
        existing_new = None

    if existing_new and (existing_new.get("PK") != item.get("PK") or existing_new.get("type") != item.get("type")):
        if not allow_existing_dst:
            raise HTTPException(409, "destination exists")

    if not existing_old and existing_new and existing_new.get("path") == new_path:
        return "already_moved"
    if not existing_old and not existing_new:
        raise HTTPException(409, f"move state inconsistent for {old_path}")

    target = norm_path(new_path, is_folder=(item.get("type") == "folder"))
    new_parent, new_name = split_parent_name(target)
    new_item = dict(item)
    new_item["path"] = target
    new_item["parent"] = new_parent
    new_item["name"] = new_name
    new_item["name_lc"] = new_name.lower()
    new_item["updated_at"] = now_iso()
    new_item["SK"] = sk_node(target)
    new_item["GSI1SK"] = f"NAME#{new_item['name_lc']}#PATH#{target}"
    new_item["GSI2PK"] = f"PARENT#{new_parent}"
    new_item["GSI2SK"] = f"TYPE#{new_item['type']}#NAME#{new_item['name_lc']}#PATH#{target}"

    if existing_new and allow_existing_dst:
        return "already_moved"

    ddb.meta.client.transact_write_items(
        TransactItems=[
            {
                "ConditionCheck": {
                    "TableName": tbl.name,
                    "Key": node_key(user, target),
                    "ConditionExpression": "attribute_not_exists(PK)",
                }
            },
            {
                "Delete": {
                    "TableName": tbl.name,
                    "Key": node_key(user, old_path),
                }
            },
            {
                "Put": {
                    "TableName": tbl.name,
                    "Item": new_item,
                }
            },
        ]
    )
    _delete_token_entries(user, item)
    _put_token_entries(user, new_item)
    _move_shares(owner=user, old_path=old_path, new_path=target)
    return "moved"


def _execute_checkpoint_move(user: str, move_id: str, *, reverse: bool = False) -> Dict[str, Any]:
    tbl = _table()
    checkpoint_key = {"PK": pk_user(user), "SK": f"MOVE#{move_id}"}
    checkpoint = tbl.get_item(Key=checkpoint_key, ConsistentRead=True).get("Item")
    if not checkpoint:
        raise HTTPException(404, "move checkpoint not found")

    entries = checkpoint.get("entries") or []
    if not isinstance(entries, list) or not entries:
        raise HTTPException(409, "move checkpoint has no entries")

    direction = "rollback" if reverse else "resume"
    status = "rolling_back" if reverse else "resuming"
    tbl.update_item(
        Key=checkpoint_key,
        UpdateExpression="SET #st=:s, updated_at=:t",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":s": status, ":t": now_iso()},
    )

    moved_now = 0
    already_done = 0
    last_old = None
    last_new = None
    for entry in entries:
        old_path = entry.get("dst") if reverse else entry.get("src")
        new_path = entry.get("src") if reverse else entry.get("dst")
        if not old_path or not new_path:
            continue
        item_stub = {
            "PK": pk_user(user),
            "path": old_path,
            "type": entry.get("type", "file"),
            "name": split_parent_name(old_path if entry.get("type") == "file" else norm_path(old_path, is_folder=True))[1],
        }
        try:
            result = _transact_move_item(tbl, user, item_stub, new_path, allow_existing_dst=True)
        except Exception:
            tbl.update_item(
                Key=checkpoint_key,
                UpdateExpression="SET #st=:s, last_path=:p, updated_at=:t",
                ExpressionAttributeNames={"#st": "status"},
                ExpressionAttributeValues={":s": "interrupted", ":p": old_path, ":t": now_iso()},
            )
            raise
        last_old = old_path
        last_new = new_path
        if result == "moved":
            moved_now += 1
        else:
            already_done += 1
        tbl.update_item(
            Key=checkpoint_key,
            UpdateExpression="SET moved=:m, already_done=:a, last_path=:p, updated_at=:t",
            ExpressionAttributeValues={
                ":m": int(checkpoint.get("moved", 0)) + moved_now,
                ":a": int(checkpoint.get("already_done", 0)) + already_done,
                ":p": old_path,
                ":t": now_iso(),
            },
        )

    final_status = "rolled_back" if reverse else "completed"
    tbl.update_item(
        Key=checkpoint_key,
        UpdateExpression="SET #st=:s, completed_at=:t, updated_at=:t",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":s": final_status, ":t": now_iso()},
    )
    return {
        "move_id": move_id,
        "status": final_status,
        "direction": direction,
        "moved_now": moved_now,
        "already_done": already_done,
        "last_src": last_old,
        "last_dst": last_new,
    }


def resume_move(user: str, move_id: str) -> Dict[str, Any]:
    return _execute_checkpoint_move(user, move_id, reverse=False)


def rollback_move(user: str, move_id: str) -> Dict[str, Any]:
    return _execute_checkpoint_move(user, move_id, reverse=True)


def move_node(user: str, src: str, dst: str) -> Dict[str, Any]:
    started = time.perf_counter()
    src_p = norm_path(src, is_folder=None)
    node = get_node(user, src_p if src_p.endswith("/") else src_p)
    is_folder = node["type"] == "folder"
    dst_p = norm_path(dst, is_folder=is_folder)

    if is_folder and dst_p == "/":
        raise HTTPException(400, "invalid destination")

    dst_parent, _ = split_parent_name(dst_p)
    ensure_folder_exists(user, dst_parent)

    tbl = _table()
    resp = tbl.get_item(Key=node_key(user, dst_p), ConsistentRead=True)
    if "Item" in resp:
        raise HTTPException(409, "destination exists")

    if is_folder:
        if is_ancestor_path(src_p, dst_p):
            raise HTTPException(400, "cannot move folder into itself")

        tree_items = _list_move_tree_items(user, src_p)
        root_item = get_node(user, src_p)
        all_items = [root_item] + [it for it in tree_items if it.get("path") != root_item.get("path")]
        entries = []
        for it in all_items:
            old_path = it["path"]
            mapped = dst_p + old_path[len(src_p):]
            new_path = mapped if it.get("type") == "file" else norm_path(mapped, is_folder=True)
            entries.append({"src": old_path, "dst": new_path, "type": it.get("type", "file")})

        move_id = str(uuid.uuid4())
        checkpoint = {
            "PK": pk_user(user),
            "SK": f"MOVE#{move_id}",
            "move_id": move_id,
            "src": src_p,
            "dst": dst_p,
            "status": "in_progress",
            "entries": entries,
            "total": len(entries),
            "moved": 0,
            "already_done": 0,
            "updated_at": now_iso(),
            "created_at": now_iso(),
        }
        tbl.put_item(Item=checkpoint)
        try:
            result = _execute_checkpoint_move(user, move_id, reverse=False)
        except Exception as exc:
            raise HTTPException(500, f"move interrupted; checkpoint {move_id}") from exc
        record_storage_delta(user, dst_p, 0, source="move_folder", aggregate=False)
        record_filemgr_operation_latency("move", time.perf_counter() - started)
        return {
            "type": "folder",
            "src": src_p,
            "dst": dst_p,
            "count": len(entries),
            "move_id": move_id,
            "status": result.get("status"),
        }

    item_stub = {
        "PK": pk_user(user),
        "path": src_p,
        "type": "file",
        "name": split_parent_name(src_p)[1],
    }
    _transact_move_item(tbl, user, item_stub, dst_p)
    record_storage_delta(user, dst_p, 0, source="move_file", aggregate=False)
    record_filemgr_operation_latency("move", time.perf_counter() - started)
    return {"type": "file", "src": src_p, "dst": dst_p}


def download_zip(user: str, paths: List[str]) -> tuple[zipstream.ZipFile, int]:
    entries: List[tuple[Dict[str, Any], str]] = []
    entry_names: Dict[str, int] = {}

    def add_entry(node: Dict[str, Any], entry_name: str) -> None:
        normalized = entry_name.lstrip("/")
        if not normalized:
            return
        if normalized in entry_names:
            raise HTTPException(409, f"duplicate entry name in zip: {normalized}")
        entry_names[normalized] = 1
        entries.append((node, normalized))

    def walk_folder(folder_path: str, prefix: str) -> None:
        children = list_children(user, folder_path)
        for child in children:
            if child.get("parent") != folder_path:
                continue
            if child.get("type") == "folder":
                walk_folder(child["path"], prefix + child["name"] + "/")
            else:
                add_entry(child, prefix + child["name"])

    for path in paths:
        normalized = norm_path(path, is_folder=None)
        node = get_node(user, normalized if normalized.endswith("/") else normalized)
        if node["type"] == "folder":
            folder = norm_path(node["path"], is_folder=True)
            _, name = split_parent_name(folder)
            prefix = f"{name}/" if name else ""
            walk_folder(folder, prefix)
        else:
            add_entry(node, node["name"])

    zf = zipstream.ZipFile(mode="w", compression=zipstream.ZIP_DEFLATED)
    for node, entry_name in entries:
        obj = _s3.get_object(Bucket=node["s3_bucket"], Key=node["s3_key"])
        body = obj["Body"]
        zf.write_iter(entry_name, iter(lambda: body.read(1024 * 1024), b""))
    return zf, len(entries)


def _archive_format_from_filename(file_name: Optional[str]) -> str:
    name = (file_name or "").lower()
    if name.endswith(".tar.gz") or name.endswith(".tgz"):
        return "targz"
    if name.endswith(".tar"):
        return "tar"
    if name.endswith(".zip"):
        return "zip"
    if name.endswith(".rar"):
        return "rar"
    raise HTTPException(400, "unsupported archive format")


def _enforce_archive_guardrails(entries: List[Dict[str, Any]], *, deadline: float) -> None:
    if len(entries) > S.filemgr_zip_max_entries:
        raise HTTPException(413, "archive contains too many entries")
    total_uncompressed = 0
    for entry in entries:
        if time.monotonic() > deadline:
            raise HTTPException(413, "archive extraction timeout")
        if entry.get("is_dir"):
            continue
        file_size = int(entry.get("file_size") or 0)
        if file_size > S.filemgr_zip_max_entry_uncompressed_bytes:
            raise HTTPException(413, "archive entry exceeds size limit")
        total_uncompressed += file_size
        if total_uncompressed > S.filemgr_zip_max_total_uncompressed_bytes:
            raise HTTPException(413, "archive exceeds total uncompressed size limit")
        if file_size > 0:
            compressed_size = max(int(entry.get("compress_size") or 0), 1)
            ratio = float(file_size) / float(compressed_size)
            if ratio > S.filemgr_zip_max_compression_ratio:
                raise HTTPException(413, "archive entry compression ratio too high")


def _upload_archive_entries(
    user: str,
    dest_folder: str,
    archive_file: UploadFile,
    *,
    entries: List[Dict[str, Any]],
    open_entry,
    byte_op: str,
) -> List[str]:
    bucket = _bucket()
    folder = norm_path(dest_folder, is_folder=True)
    ensure_folder_exists(user, folder)

    deadline = time.monotonic() + max(1, int(S.filemgr_zip_extract_timeout_seconds))
    _enforce_archive_guardrails(entries, deadline=deadline)

    created: List[str] = []
    created_set = set()
    total_uploaded_bytes = 0
    for entry in entries:
        if time.monotonic() > deadline:
            raise HTTPException(413, "archive extraction timeout")
        name = entry["name"]
        if name.startswith("/") or ".." in [p for p in name.split("/") if p]:
            raise HTTPException(400, "invalid archive entry path")
        if entry.get("is_dir"):
            fpath = norm_path(folder + name, is_folder=True)
            try:
                parent, _ = split_parent_name(fpath)
                ensure_folder_exists(user, parent)
                tbl = _table()
                resp = tbl.get_item(Key=node_key(user, fpath), ConsistentRead=True)
                if "Item" not in resp:
                    item = {
                        "PK": pk_user(user),
                        "SK": sk_node(fpath),
                        "type": "folder",
                        "path": fpath,
                        "name": split_parent_name(fpath)[1],
                        "name_lc": split_parent_name(fpath)[1].lower(),
                        "parent": split_parent_name(fpath)[0],
                        "created_at": now_iso(),
                        "updated_at": now_iso(),
                        "GSI1PK": pk_user(user),
                        "GSI1SK": f"NAME#{split_parent_name(fpath)[1].lower()}#PATH#{fpath}",
                        "GSI2PK": f"PARENT#{split_parent_name(fpath)[0]}",
                        "GSI2SK": f"TYPE#folder#NAME#{split_parent_name(fpath)[1].lower()}#PATH#{fpath}",
                    }
                    put_node(item)
                    _put_token_entries(user, {
                        "path": fpath,
                        "type": "folder",
                        "name": split_parent_name(fpath)[1],
                        "size": None,
                        "updated_at": now_iso(),
                    })
            except HTTPException:
                pass
            continue

        out_path = norm_path(folder + name, is_folder=False)
        if out_path in created_set:
            raise HTTPException(409, f"already exists: {out_path}")
        require_not_exists(user, out_path)
        out_parent, _ = split_parent_name(out_path)
        _auto_create_parents(user, out_parent)

        obj_id = str(uuid.uuid4())
        s3_key = f"{user}/objects/{obj_id}"
        with open_entry(entry) as file_obj:
            if time.monotonic() > deadline:
                raise HTTPException(413, "archive extraction timeout")
            _s3.upload_fileobj(
                Fileobj=file_obj,
                Bucket=bucket,
                Key=s3_key,
                ExtraArgs={"ContentType": "application/octet-stream"},
            )
        try:
            uploaded_head = _s3.head_object(Bucket=bucket, Key=s3_key)
            uploaded_size = int(uploaded_head.get("ContentLength", int(entry.get("file_size") or 0)))
            uploaded_etag = uploaded_head.get("ETag")
        except ClientError:
            uploaded_size = int(entry.get("file_size") or 0)
            uploaded_etag = None

        item = {
            "PK": pk_user(user),
            "SK": sk_node(out_path),
            "type": "file",
            "path": out_path,
            "name": split_parent_name(out_path)[1],
            "name_lc": split_parent_name(out_path)[1].lower(),
            "parent": out_parent,
            "created_at": now_iso(),
            "updated_at": now_iso(),
            "upload_at": now_iso(),
            "upload_by": user,
            "size": uploaded_size,
            "content_type": "application/octet-stream",
            "s3_bucket": bucket,
            "s3_key": s3_key,
            "GSI1PK": pk_user(user),
            "GSI1SK": f"NAME#{split_parent_name(out_path)[1].lower()}#PATH#{out_path}",
            "GSI2PK": f"PARENT#{out_parent}",
            "GSI2SK": f"TYPE#file#NAME#{split_parent_name(out_path)[1].lower()}#PATH#{out_path}",
        }
        put_node(item)
        _put_token_entries(user, item)
        record_filemgr_bytes("uploaded", byte_op, uploaded_size)
        total_uploaded_bytes += uploaded_size
        per_entry_event = build_usage_event(
            user_id=user,
            event_type="upload",
            bytes_count=uploaded_size,
            source=f"{byte_op}_entry",
            resource_path=out_path,
            idempotency_key=f"archive_entry|{byte_op}|{user}|{out_path}|{s3_key}|{uploaded_etag or ''}",
        )
        _record_usage_event_safe(per_entry_event)
        record_storage_delta(user, out_path, uploaded_size, source=f"{byte_op}_create")
        created.append(out_path)
        created_set.add(out_path)

    if total_uploaded_bytes > 0:
        total_event = build_usage_event(
            user_id=user,
            event_type="upload",
            bytes_count=total_uploaded_bytes,
            source=f"{byte_op}_total",
            resource_path=folder,
            idempotency_key=f"archive_total|{byte_op}|{user}|{folder}|{archive_file.filename or ''}|{len(created)}|{total_uploaded_bytes}",
        )
        _record_usage_event_non_aggregating_safe(total_event)

    return created


def upload_archive(user: str, dest_folder: str, archive_file: UploadFile) -> List[str]:
    fmt = _archive_format_from_filename(archive_file.filename)
    archive_file.file.seek(0)

    if fmt == "zip":
        try:
            zf = zipfile.ZipFile(archive_file.file)
        except zipfile.BadZipFile as exc:
            raise HTTPException(400, "invalid zip") from exc
        entries = [
            {
                "name": info.filename,
                "is_dir": info.is_dir() or info.filename.endswith("/"),
                "file_size": info.file_size,
                "compress_size": info.compress_size,
                "info": info,
            }
            for info in zf.infolist()
        ]
        return _upload_archive_entries(
            user,
            dest_folder,
            archive_file,
            entries=entries,
            open_entry=lambda e: zf.open(e["info"]),
            byte_op="upload_zip",
        )

    if fmt in {"tar", "targz"}:
        mode = "r:gz" if fmt == "targz" else "r:"
        try:
            tf = tarfile.open(fileobj=archive_file.file, mode=mode)
        except tarfile.TarError as exc:
            raise HTTPException(400, "invalid tar archive") from exc
        members = tf.getmembers()
        entries = []
        for m in members:
            if m.islnk() or m.issym() or m.isdev():
                raise HTTPException(400, "unsupported tar entry type")
            entries.append(
                {
                    "name": m.name + ("/" if m.isdir() and not m.name.endswith("/") else ""),
                    "is_dir": m.isdir(),
                    "file_size": int(m.size or 0),
                    "compress_size": int(m.size or 0),
                    "member": m,
                }
            )
        return _upload_archive_entries(
            user,
            dest_folder,
            archive_file,
            entries=entries,
            open_entry=lambda e: tf.extractfile(e["member"]),
            byte_op="upload_tar",
        )

    if fmt == "rar":
        if rarfile is None:
            raise HTTPException(501, "rar support not available in this environment")
        try:
            rf = rarfile.RarFile(archive_file.file)
        except Exception as exc:
            raise HTTPException(400, "invalid rar archive") from exc
        entries = []
        for info in rf.infolist():
            entries.append(
                {
                    "name": info.filename,
                    "is_dir": info.isdir(),
                    "file_size": int(getattr(info, "file_size", 0) or 0),
                    "compress_size": int(getattr(info, "compress_size", 0) or 0),
                    "info": info,
                }
            )
        return _upload_archive_entries(
            user,
            dest_folder,
            archive_file,
            entries=entries,
            open_entry=lambda e: rf.open(e["info"]),
            byte_op="upload_rar",
        )

    raise HTTPException(400, "unsupported archive format")


def upload_zip(user: str, dest_folder: str, zip_file: UploadFile) -> List[str]:
    return upload_archive(user, dest_folder, zip_file)


def _auto_create_parents(user: str, folder_path: str) -> None:
    folder_path = norm_path(folder_path, is_folder=True)
    if folder_path == "/":
        return
    cur = "/"
    for seg in [seg for seg in folder_path.split("/") if seg]:
        cur = norm_path(cur + seg + "/", is_folder=True)
        tbl = _table()
        resp = tbl.get_item(Key=node_key(user, cur), ConsistentRead=True)
        if "Item" not in resp:
            parent, name = split_parent_name(cur)
            item = {
                "PK": pk_user(user),
                "SK": sk_node(cur),
                "type": "folder",
                "path": cur,
                "name": name,
                "name_lc": name.lower(),
                "parent": parent,
                "created_at": now_iso(),
                "updated_at": now_iso(),
                "GSI1PK": pk_user(user),
                "GSI1SK": f"NAME#{name.lower()}#PATH#{cur}",
                "GSI2PK": f"PARENT#{parent}",
                "GSI2SK": f"TYPE#folder#NAME#{name.lower()}#PATH#{cur}",
            }
            put_node(item)
            _put_token_entries(user, item)


def share_node(
    user: str,
    path: str,
    to_user: str,
    permission: str = "read",
    expires_at: Optional[str] = None,
) -> None:
    if permission not in {"read", "write"}:
        raise HTTPException(status_code=400, detail="permission must be read or write")
    tbl = _table()
    p = norm_path(path, is_folder=None)
    node = get_node(user, p if p.endswith("/") else p)

    share_sk = f"SHARE#{node['path']}#TO#{to_user}"
    owner_item = {
        "PK": pk_user(user),
        "SK": share_sk,
        "path": node["path"],
        "to_user": to_user,
        "shared_at": now_iso(),
        "permission": permission,
    }
    if expires_at:
        owner_item["expires_at"] = expires_at
    tbl.put_item(Item=owner_item)

    recipient_item = {
        "PK": pk_user(to_user),
        "SK": f"SHARED#FROM#{user}#PATH#{node['path']}",
        "owner": user,
        "path": node["path"],
        "shared_at": now_iso(),
        "permission": permission,
    }
    if expires_at:
        recipient_item["expires_at"] = expires_at
    tbl.put_item(Item=recipient_item)


def unshare_node(user: str, path: str, to_user: str) -> None:
    tbl = _table()
    p = norm_path(path, is_folder=None)
    node = get_node(user, p if p.endswith("/") else p)
    share_sk = f"SHARE#{node['path']}#TO#{to_user}"
    tbl.delete_item(Key={"PK": pk_user(user), "SK": share_sk})
    tbl.delete_item(Key={"PK": pk_user(to_user), "SK": f"SHARED#FROM#{user}#PATH#{node['path']}"})


def list_shared_with(user: str, path: str) -> List[Dict[str, Any]]:
    tbl = _table()
    p = norm_path(path, is_folder=None)
    prefix = f"SHARE#{p}#TO#"
    resp = tbl.query(
        KeyConditionExpression=Key("PK").eq(pk_user(user)) & Key("SK").begins_with(prefix)
    )
    items = []
    for it in resp.get("Items", []):
        items.append({
            "to_user": it["to_user"],
            "permission": it.get("permission", "read"),
            "expires_at": it.get("expires_at"),
            "shared_at": it.get("shared_at"),
        })
    items.sort(key=lambda x: x["to_user"].lower())
    return items


def list_shared_with_me(user: str) -> List[Dict[str, Any]]:
    tbl = _table()
    resp = tbl.query(
        KeyConditionExpression=Key("PK").eq(pk_user(user)) & Key("SK").begins_with("SHARED#FROM#")
    )
    items = []
    for it in resp.get("Items", []):
        owner = it["owner"]
        path = it["path"]
        item = {
            "owner": owner,
            "path": path,
            "shared_at": it.get("shared_at"),
            "permission": it.get("permission", "read"),
            "expires_at": it.get("expires_at"),
        }
        try:
            node = get_node(owner, path)
            item.update({
                "type": node.get("type"),
                "name": node.get("name"),
                "size": node.get("size"),
                "content_type": node.get("content_type"),
                **encryption_info_from_node(node),
            })
        except HTTPException:
            pass
        items.append(item)
    items.sort(key=lambda x: (x["owner"].lower(), x["path"]))
    return items


def list_shared_with_me_by_owner(user: str, owner: str) -> List[Dict[str, Any]]:
    tbl = _table()
    prefix = f"SHARED#FROM#{owner}#PATH#"
    resp = tbl.query(
        KeyConditionExpression=Key("PK").eq(pk_user(user)) & Key("SK").begins_with(prefix)
    )
    items = []
    for it in resp.get("Items", []):
        items.append({
            "owner": it["owner"],
            "path": it["path"],
            "shared_at": it.get("shared_at"),
            "permission": it.get("permission", "read"),
            "expires_at": it.get("expires_at"),
        })
    items.sort(key=lambda x: x["path"])
    return items


def require_shared_access(user: str, owner: str, path: str, *, permission: str = "read") -> Dict[str, Any]:
    if permission not in {"read", "write"}:
        raise HTTPException(status_code=400, detail="invalid permission")
    p = norm_path(path, is_folder=None)
    candidates = list_shared_with_me_by_owner(user, owner)
    best: Optional[Dict[str, Any]] = None
    for candidate in candidates:
        shared_path = norm_path(candidate["path"], is_folder=None)
        if shared_path.endswith("/"):
            if is_ancestor_path(shared_path, p):
                if not best or len(shared_path) > len(best["path"]):
                    best = candidate
        elif shared_path == p:
            best = candidate
    if not best:
        raise HTTPException(status_code=404, detail="not shared")
    expires_at = _parse_iso(best.get("expires_at"))
    if expires_at and expires_at <= datetime.now(timezone.utc):
        raise HTTPException(status_code=403, detail="share expired")
    shared_permission = best.get("permission", "read")
    if permission == "write" and shared_permission != "write":
        raise HTTPException(status_code=403, detail="permission denied")
    return best

def _delete_shares_for_path(owner: str, path: str) -> None:
    tbl = _table()
    prefix = f"SHARE#{path}#TO#"
    resp = tbl.query(KeyConditionExpression=Key("PK").eq(pk_user(owner)) & Key("SK").begins_with(prefix))
    for it in resp.get("Items", []):
        to_user = it["to_user"]
        tbl.delete_item(Key={"PK": pk_user(owner), "SK": it["SK"]})
        tbl.delete_item(Key={"PK": pk_user(to_user), "SK": f"SHARED#FROM#{owner}#PATH#{path}"})


def _move_shares(owner: str, old_path: str, new_path: str) -> None:
    tbl = _table()
    prefix = f"SHARE#{old_path}#TO#"
    resp = tbl.query(KeyConditionExpression=Key("PK").eq(pk_user(owner)) & Key("SK").begins_with(prefix))
    for it in resp.get("Items", []):
        to_user = it["to_user"]
        tbl.delete_item(Key={"PK": pk_user(owner), "SK": it["SK"]})
        tbl.delete_item(Key={"PK": pk_user(to_user), "SK": f"SHARED#FROM#{owner}#PATH#{old_path}"})

        new_sk = f"SHARE#{new_path}#TO#{to_user}"
        tbl.put_item(Item={
            "PK": pk_user(owner),
            "SK": new_sk,
            "path": new_path,
            "to_user": to_user,
            "shared_at": it.get("shared_at", now_iso()),
            "permission": it.get("permission", "read"),
            "expires_at": it.get("expires_at"),
        })
        tbl.put_item(Item={
            "PK": pk_user(to_user),
            "SK": f"SHARED#FROM#{owner}#PATH#{new_path}",
            "owner": owner,
            "path": new_path,
            "shared_at": it.get("shared_at", now_iso()),
            "permission": it.get("permission", "read"),
            "expires_at": it.get("expires_at"),
        })


def _purge_node_item(
    tbl,
    item: Dict[str, Any],
    now: datetime,
    *,
    key: Optional[Dict[str, Any]] = None,
) -> str:
    if not item.get("deleted_at"):
        return "skipped"
    if item.get("purge_status") == "purged":
        return "skipped"
    purge_after = _parse_iso(item.get("purge_after"))
    if purge_after and purge_after > now:
        return "skipped"
    key = key or {"PK": item.get("PK"), "SK": item.get("SK")}
    if not key.get("PK") or not key.get("SK"):
        return "error"

    if item.get("s3_bucket") and item.get("s3_key"):
        try:
            _s3.delete_object(Bucket=item["s3_bucket"], Key=item["s3_key"])
        except ClientError as exc:
            tbl.update_item(
                Key=key,
                UpdateExpression=(
                    "SET updated_at=:t, purge_status=:s, last_purge_error=:e, "
                    "GSI_PURGEPK=:gpk, GSI_PURGESK=:gsk ADD purge_attempts :inc"
                ),
                ExpressionAttributeValues={
                    ":t": now_iso(),
                    ":s": "pending",
                    ":e": str(exc),
                    ":gpk": "PURGE#pending",
                    ":gsk": f"{item.get('purge_after') or now.isoformat()}#{item.get('PK')}#{item.get('SK')}",
                    ":inc": 1,
                },
            )
            return "error"

    tbl.update_item(
        Key=key,
        UpdateExpression=(
            "SET purge_status=:s, purged_at=:t, updated_at=:t, "
            "GSI_PURGEPK=:gpk, GSI_PURGESK=:gsk REMOVE last_purge_error ADD purge_attempts :inc"
        ),
        ExpressionAttributeValues={
            ":s": "purged",
            ":t": now_iso(),
            ":gpk": "PURGE#purged",
            ":gsk": f"{now.isoformat()}#{item.get('PK')}#{item.get('SK')}",
            ":inc": 1,
        },
    )
    if item.get("type") == "file":
        try:
            path = item.get("path")
            if path:
                record_storage_delta(
                    str(item.get("PK", "")).replace("USER#", "", 1),
                    path,
                    0,
                    source="purge_finalize",
                    aggregate=False,
                )
        except Exception:
            logger.exception("filemgr storage delta purge_finalize metering failed")
    return "purged"


def purge_deleted_nodes(user: str, *, limit: Optional[int] = None) -> Dict[str, Any]:
    started = time.perf_counter()
    tbl = _table()
    purge_limit = limit or S.filemgr_purge_scan_limit
    purged = 0
    skipped = 0
    errors = 0
    now = datetime.now(timezone.utc)
    start_key: Optional[Dict[str, Any]] = None

    while purged + skipped + errors < purge_limit:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("PK").eq(pk_user(user)) & Key("SK").begins_with("NODE#"),
            "Limit": max(50, min(purge_limit, S.filemgr_purge_scan_limit)),
        }
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = tbl.query(**kwargs)
        items = resp.get("Items", [])
        for item in items:
            if purged + skipped + errors >= purge_limit:
                break
            result = _purge_node_item(tbl, item, now, key=node_key(user, item["path"]))
            if result == "purged":
                purged += 1
            elif result == "error":
                errors += 1
            else:
                skipped += 1
        start_key = resp.get("LastEvaluatedKey")
        if not start_key:
            break
    mode = "pk_query"
    _record_purge_metrics("user", mode=mode, purged=purged, skipped=skipped, errors=errors)
    elapsed = time.perf_counter() - started
    record_filemgr_purge_run("user", mode, purged=purged, skipped=skipped, errors=errors, elapsed_seconds=elapsed)
    logger.info("filemgr_purge_run", extra={"scope": "user", "mode": mode, "purged": purged, "skipped": skipped, "errors": errors, "elapsed_seconds": elapsed})
    return {"purged": purged, "skipped": skipped, "errors": errors, "mode": mode}


def _record_purge_metrics(scope: str, *, mode: str, purged: int, skipped: int, errors: int) -> None:
    if purged:
        FILEMGR_PURGE_RESULTS.labels(scope=scope, outcome="purged", mode=mode).inc(purged)
    if skipped:
        FILEMGR_PURGE_RESULTS.labels(scope=scope, outcome="skipped", mode=mode).inc(skipped)
    if errors:
        FILEMGR_PURGE_RESULTS.labels(scope=scope, outcome="error", mode=mode).inc(errors)


def purge_deleted_nodes_global(*, limit: Optional[int] = None) -> Dict[str, Any]:
    started = time.perf_counter()
    tbl = _table()
    purge_limit = limit or S.filemgr_purge_scan_limit
    purged = 0
    skipped = 0
    errors = 0
    now = datetime.now(timezone.utc)
    start_key: Optional[Dict[str, Any]] = None
    mode = "index"

    while purged + skipped + errors < purge_limit:
        remaining = purge_limit - (purged + skipped + errors)
        if remaining <= 0:
            break
        kwargs: Dict[str, Any] = {
            "IndexName": S.filemgr_purge_index_name,
            "KeyConditionExpression": Key("GSI_PURGEPK").eq("PURGE#pending")
            & Key("GSI_PURGESK").lte(f"{now.isoformat()}#~"),
            "Limit": min(200, remaining),
        }
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        try:
            resp = tbl.query(**kwargs)
        except ClientError:
            mode = "scan_fallback"
            filter_expr = Attr("SK").begins_with("NODE#") & Attr("deleted_at").exists()
            scan_kwargs: Dict[str, Any] = {"FilterExpression": filter_expr, "Limit": min(200, remaining)}
            if start_key:
                scan_kwargs["ExclusiveStartKey"] = start_key
            resp = tbl.scan(**scan_kwargs)
        items = resp.get("Items", [])
        for item in items:
            if purged + skipped + errors >= purge_limit:
                break
            result = _purge_node_item(tbl, item, now)
            if result == "purged":
                purged += 1
            elif result == "error":
                errors += 1
            else:
                skipped += 1
        start_key = resp.get("LastEvaluatedKey")
        if not start_key:
            break
    _record_purge_metrics("global", mode=mode, purged=purged, skipped=skipped, errors=errors)
    elapsed = time.perf_counter() - started
    record_filemgr_purge_run("global", mode, purged=purged, skipped=skipped, errors=errors, elapsed_seconds=elapsed)
    logger.info("filemgr_purge_run", extra={"scope": "global", "mode": mode, "purged": purged, "skipped": skipped, "errors": errors, "elapsed_seconds": elapsed})
    return {"purged": purged, "skipped": skipped, "errors": errors, "mode": mode}


async def filemgr_purge_loop() -> None:
    interval = max(60, int(S.filemgr_purge_interval_seconds))
    while True:
        try:
            purge_deleted_nodes_global()
        except Exception:
            logger.exception("File manager purge loop failed")
        await asyncio.sleep(interval)


def start_filemgr_purge_task() -> None:
    if not S.filemgr_purge_enabled:
        logger.info("File manager purge disabled")
        return
    if not S.filemgr_table_name:
        logger.info("File manager purge skipped: FILEMGR_TABLE not configured")
        return
    asyncio.create_task(filemgr_purge_loop())


def _scan_usage_events(*, user_id: Optional[str] = None, period_id: Optional[str] = None) -> List[Dict[str, Any]]:
    tbl = _table()
    events: List[Dict[str, Any]] = []

    if user_id:
        cursor: Optional[Dict[str, Any]] = None
        while True:
            kwargs: Dict[str, Any] = {
                "KeyConditionExpression": Key("PK").eq(pk_user(user_id)) & Key("SK").begins_with("USAGE#EVENT#"),
                "Limit": 250,
            }
            if cursor:
                kwargs["ExclusiveStartKey"] = cursor
            resp = tbl.query(**kwargs)
            for it in resp.get("Items", []):
                if period_id and str(it.get("period_id")) != period_id:
                    continue
                events.append(it)
            cursor = resp.get("LastEvaluatedKey")
            if not cursor:
                break
        return events

    cursor = None
    while True:
        kwargs = {"Limit": 250}
        if cursor:
            kwargs["ExclusiveStartKey"] = cursor
        resp = tbl.scan(**kwargs)
        for it in resp.get("Items", []):
            if it.get("entity_type") != "usage_event":
                continue
            if period_id and str(it.get("period_id")) != period_id:
                continue
            events.append(it)
        cursor = resp.get("LastEvaluatedKey")
        if not cursor:
            break
    return events


def recompute_usage_aggregates_admin(*, scope: str, period_id: Optional[str] = None, user_id: Optional[str] = None, apply: bool = True) -> Dict[str, Any]:
    if scope not in {"user", "all"}:
        raise HTTPException(400, "invalid recompute scope")
    if scope == "user" and not user_id:
        raise HTTPException(400, "user_id required for user scope")
    if period_id:
        period_bounds_utc(period_id)

    events = _scan_usage_events(user_id=user_id if scope == "user" else None, period_id=period_id)

    period_totals: Dict[tuple[str, str], Dict[str, int]] = {}
    daily_totals: Dict[tuple[str, str], Dict[str, int]] = {}
    for ev in events:
        uid = str(ev.get("user_id") or "")
        ts = str(ev.get("timestamp") or "")
        if not uid or not ts:
            continue
        try:
            dt = datetime.fromisoformat(ts)
        except ValueError:
            continue
        p = period_id_for_datetime(dt)
        d = ts[:10]
        if period_id and p != period_id:
            continue
        p_key = (uid, p)
        d_key = (uid, d)
        if p_key not in period_totals:
            period_totals[p_key] = {
                "upload_bytes_total": 0,
                "download_bytes_total": 0,
                "storage_bytes_current": 0,
                "storage_bytes_peak": 0,
                "storage_byte_seconds": 0,
            }
        if d_key not in daily_totals:
            daily_totals[d_key] = {
                "upload_bytes_total": 0,
                "download_bytes_total": 0,
                "storage_bytes_end_of_day": 0,
            }
        b = int(ev.get("bytes") or 0)
        typ = ev.get("event_type")
        if typ == "upload":
            period_totals[p_key]["upload_bytes_total"] += b
            daily_totals[d_key]["upload_bytes_total"] += b
        elif typ == "download":
            period_totals[p_key]["download_bytes_total"] += b
            daily_totals[d_key]["download_bytes_total"] += b
        elif typ == "storage_delta":
            period_totals[p_key]["storage_bytes_current"] += b
            daily_totals[d_key]["storage_bytes_end_of_day"] += b
            if period_totals[p_key]["storage_bytes_current"] > period_totals[p_key]["storage_bytes_peak"]:
                period_totals[p_key]["storage_bytes_peak"] = period_totals[p_key]["storage_bytes_current"]

    tbl = _table()
    mismatches = 0
    now = now_iso()
    for (uid, p), vals in period_totals.items():
        stored = tbl.get_item(Key={"PK": pk_user(uid), "SK": f"USAGE#PERIOD#{p}"}).get("Item") or {}
        if any(int(stored.get(k) or 0) != int(vals[k]) for k in ("upload_bytes_total", "download_bytes_total", "storage_bytes_current")):
            mismatches += 1
        if apply:
            tbl.put_item(Item={
                "PK": pk_user(uid),
                "SK": f"USAGE#PERIOD#{p}",
                "entity_type": "usage_period_totals",
                "user_id": uid,
                "period_id": p,
                **vals,
                "updated_at": now,
                "ttl_epoch": _ttl_epoch_from_now(getattr(S, "filemgr_usage_aggregate_retention_days", 1095)),
            })

    if apply:
        for (uid, d), vals in daily_totals.items():
            tbl.put_item(Item={
                "PK": pk_user(uid),
                "SK": f"USAGE#DAY#{d}",
                "entity_type": "usage_daily",
                "user_id": uid,
                "day_utc": d,
                "period_id": d[:7],
                **vals,
                "updated_at": now,
                "ttl_epoch": _ttl_epoch_from_now(getattr(S, "filemgr_usage_aggregate_retention_days", 1095)),
            })

    return {
        "scope": scope,
        "user_id": user_id,
        "period_id": period_id,
        "events_scanned": len(events),
        "period_rows": len(period_totals),
        "daily_rows": len(daily_totals),
        "mismatches": mismatches,
        "applied": apply,
    }


def finalize_billing_period_admin(*, period_id: str, user_id: Optional[str] = None) -> Dict[str, Any]:
    period_bounds_utc(period_id)
    tbl = _table()

    target_users: List[str] = []
    if user_id:
        target_users = [user_id]
    else:
        cursor = None
        seen = set()
        while True:
            kwargs = {"Limit": 250}
            if cursor:
                kwargs["ExclusiveStartKey"] = cursor
            resp = tbl.scan(**kwargs)
            for it in resp.get("Items", []):
                if str(it.get("SK")) != f"USAGE#PERIOD#{period_id}":
                    continue
                uid = str(it.get("user_id") or "")
                if not uid:
                    pk = str(it.get("PK") or "")
                    if pk.startswith("USER#"):
                        uid = pk.replace("USER#", "", 1)
                if uid and uid not in seen:
                    seen.add(uid)
                    target_users.append(uid)
            cursor = resp.get("LastEvaluatedKey")
            if not cursor:
                break

    finalized = 0
    snapshots: List[Dict[str, Any]] = []
    for uid in target_users:
        period_row = tbl.get_item(Key={"PK": pk_user(uid), "SK": f"USAGE#PERIOD#{period_id}"}).get("Item") or {}
        if not period_row:
            continue

        q = tbl.query(
            KeyConditionExpression=Key("PK").eq(pk_user(uid)) & Key("SK").begins_with(f"USAGE#SNAPSHOT#{period_id}#V"),
        )
        current_version = 0
        for it in q.get("Items", []):
            try:
                current_version = max(current_version, int(it.get("version") or 0))
            except Exception:
                continue
        next_version = current_version + 1

        snap = build_billing_usage_snapshot_item(user_id=uid, period_id=period_id, version=next_version, status="finalized")
        snap["upload_bytes_total"] = int(period_row.get("upload_bytes_total") or 0)
        snap["download_bytes_total"] = int(period_row.get("download_bytes_total") or 0)
        snap["storage_bytes_peak"] = int(period_row.get("storage_bytes_peak") or 0)
        snap["storage_byte_seconds"] = int(period_row.get("storage_byte_seconds") or 0)
        snap["finalized_at"] = now_iso()
        snap["ttl_epoch"] = _ttl_epoch_from_now(getattr(S, "filemgr_usage_snapshot_retention_days", 2555))
        tbl.put_item(Item=snap)
        snapshots.append({"user_id": uid, "version": next_version, "sk": snap["SK"]})
        finalized += 1

    return {
        "period_id": period_id,
        "user_count": len(target_users),
        "finalized_count": finalized,
        "snapshots": snapshots,
    }


def get_admin_user_usage_detail(user_id: str, *, period_id: Optional[str] = None, top_n: int = 10, include_resource_paths: bool = False) -> Dict[str, Any]:
    summary = get_usage_summary(user_id, period_id=period_id)
    if period_id:
        start, end = period_bounds_utc(period_id)
        from_day = start.date().isoformat()
        to_day = (end - timedelta(days=1)).date().isoformat()
    else:
        from_day = None
        to_day = None
    daily = get_usage_daily(user_id, from_day=from_day, to_day=to_day)
    storage = get_usage_storage(user_id, top_n=top_n)
    if not include_resource_paths:
        redacted = [{"size": int(it.get("size") or 0)} for it in storage.get("top_files", [])]
        storage = {**storage, "top_files": redacted, "paths_redacted": True}

    tbl = _table()
    snap_resp = tbl.query(
        KeyConditionExpression=Key("PK").eq(pk_user(user_id)) & Key("SK").begins_with("USAGE#SNAPSHOT#"),
        Limit=50,
    )
    snapshots = sorted(
        [
            {
                "period_id": it.get("period_id"),
                "version": int(it.get("version") or 0),
                "status": it.get("status"),
                "finalized_at": it.get("finalized_at"),
                "upload_bytes_total": int(it.get("upload_bytes_total") or 0),
                "download_bytes_total": int(it.get("download_bytes_total") or 0),
                "storage_bytes_peak": int(it.get("storage_bytes_peak") or 0),
            }
            for it in snap_resp.get("Items", [])
        ],
        key=lambda x: (str(x.get("period_id") or ""), int(x.get("version") or 0)),
        reverse=True,
    )

    return {
        "user_id": user_id,
        "summary": summary,
        "daily": daily,
        "storage": storage,
        "snapshots": snapshots,
    }


def _parse_pricing_catalog_config() -> Dict[str, Dict[str, Any]]:
    raw = str(getattr(S, "filemgr_usage_pricing_catalog", "") or "")
    if not raw.strip():
        return {
            str(getattr(S, "filemgr_usage_default_pricing_catalog_version", "v1") or "v1"): {
                "upload_included_bytes": 0,
                "download_included_bytes": 0,
                "storage_included_bytes": 0,
                "upload_overage_cents_per_gb": 0,
                "download_overage_cents_per_gb": 0,
                "storage_overage_cents_per_gb": 0,
            }
        }
    try:
        data = json.loads(raw)
    except Exception:
        logger.exception("invalid FILEMGR_USAGE_PRICING_CATALOG json")
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): (v if isinstance(v, dict) else {}) for k, v in data.items()}


def _resolve_pricing_catalog(version: Optional[str] = None) -> tuple[str, Dict[str, Any]]:
    catalog = _parse_pricing_catalog_config()
    desired = version or str(getattr(S, "filemgr_usage_default_pricing_catalog_version", "v1") or "v1")
    if desired in catalog:
        return desired, catalog[desired]
    if catalog:
        first_key = sorted(catalog.keys())[0]
        return first_key, catalog[first_key]
    return desired, {}


def _calc_metered_cost_cents(used_bytes: int, included_bytes: int, rate_per_gb_cents: int) -> tuple[int, int]:
    overage_bytes = max(0, int(used_bytes) - int(included_bytes))
    if overage_bytes <= 0 or int(rate_per_gb_cents) <= 0:
        return overage_bytes, 0
    gb = 1024 * 1024 * 1024
    cents = int(round((overage_bytes / gb) * int(rate_per_gb_cents)))
    return overage_bytes, cents


def generate_invoice_line_items_for_snapshot_admin(
    *,
    user_id: str,
    period_id: str,
    snapshot_version: int,
    pricing_catalog_version: Optional[str] = None,
) -> Dict[str, Any]:
    if snapshot_version < 1:
        raise HTTPException(400, "snapshot_version must be >= 1")
    period_bounds_utc(period_id)
    tbl = _table()

    snapshot_sk = f"USAGE#SNAPSHOT#{period_id}#V{snapshot_version:04d}"
    snapshot = tbl.get_item(Key={"PK": pk_user(user_id), "SK": snapshot_sk}).get("Item") or {}
    if not snapshot:
        raise HTTPException(404, "finalized usage snapshot not found")

    catalog_version, pricing = _resolve_pricing_catalog(pricing_catalog_version)

    upload_used = int(snapshot.get("upload_bytes_total") or 0)
    download_used = int(snapshot.get("download_bytes_total") or 0)
    storage_used = int(snapshot.get("storage_bytes_peak") or 0)

    upload_over_bytes, upload_over_cents = _calc_metered_cost_cents(
        upload_used,
        int(pricing.get("upload_included_bytes") or 0),
        int(pricing.get("upload_overage_cents_per_gb") or 0),
    )
    download_over_bytes, download_over_cents = _calc_metered_cost_cents(
        download_used,
        int(pricing.get("download_included_bytes") or 0),
        int(pricing.get("download_overage_cents_per_gb") or 0),
    )
    storage_over_bytes, storage_over_cents = _calc_metered_cost_cents(
        storage_used,
        int(pricing.get("storage_included_bytes") or 0),
        int(pricing.get("storage_overage_cents_per_gb") or 0),
    )

    lines = [
        {
            "line_type": "upload_usage",
            "quantity_bytes": upload_used,
            "included_bytes": int(pricing.get("upload_included_bytes") or 0),
            "overage_bytes": upload_over_bytes,
            "unit_price": int(pricing.get("upload_overage_cents_per_gb") or 0),
            "amount_cents": upload_over_cents,
            "pricing_unit": "GB",
        },
        {
            "line_type": "download_usage",
            "quantity_bytes": download_used,
            "included_bytes": int(pricing.get("download_included_bytes") or 0),
            "overage_bytes": download_over_bytes,
            "unit_price": int(pricing.get("download_overage_cents_per_gb") or 0),
            "amount_cents": download_over_cents,
            "pricing_unit": "GB",
        },
        {
            "line_type": "storage_usage",
            "quantity_bytes": storage_used,
            "included_bytes": int(pricing.get("storage_included_bytes") or 0),
            "overage_bytes": storage_over_bytes,
            "unit_price": int(pricing.get("storage_overage_cents_per_gb") or 0),
            "amount_cents": storage_over_cents,
            "pricing_unit": "GB",
        },
    ]

    total_cents = sum(int(x.get("amount_cents") or 0) for x in lines)
    invoice_sk = f"USAGE#INVOICE#{period_id}#V{snapshot_version:04d}"
    invoice_item = {
        "PK": pk_user(user_id),
        "SK": invoice_sk,
        "entity_type": "usage_invoice_lines",
        "user_id": user_id,
        "period_id": period_id,
        "snapshot_version": snapshot_version,
        "pricing_catalog_version": catalog_version,
        "snapshot_sk": snapshot_sk,
        "currency": "usd",
        "line_items": lines,
        "total_amount_cents": total_cents,
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "ttl_epoch": _ttl_epoch_from_now(getattr(S, "filemgr_usage_billing_record_retention_days", 2555)),
    }
    tbl.put_item(Item=invoice_item)

    return {
        "user_id": user_id,
        "period_id": period_id,
        "snapshot_version": snapshot_version,
        "pricing_catalog_version": catalog_version,
        "invoice_sk": invoice_sk,
        "line_items": lines,
        "total_amount_cents": total_cents,
    }


def create_billing_adjustment_admin(
    *,
    user_id: str,
    period_id: str,
    snapshot_version: int,
    adjustment_type: str,
    amount_cents: int,
    reason: str,
    reference_id: Optional[str] = None,
) -> Dict[str, Any]:
    if snapshot_version < 1:
        raise HTTPException(400, "snapshot_version must be >= 1")
    if adjustment_type not in {"credit", "debit"}:
        raise HTTPException(400, "adjustment_type must be credit or debit")
    if amount_cents <= 0:
        raise HTTPException(400, "amount_cents must be > 0")
    period_bounds_utc(period_id)

    tbl = _table()
    snapshot_sk = f"USAGE#SNAPSHOT#{period_id}#V{snapshot_version:04d}"
    snap = tbl.get_item(Key={"PK": pk_user(user_id), "SK": snapshot_sk}).get("Item") or {}
    if not snap:
        raise HTTPException(404, "snapshot not found")

    adj_id = str(uuid.uuid4())
    signed_amount = -amount_cents if adjustment_type == "credit" else amount_cents
    adj_sk = f"USAGE#ADJUSTMENT#{period_id}#V{snapshot_version:04d}#{adj_id}"
    item = {
        "PK": pk_user(user_id),
        "SK": adj_sk,
        "entity_type": "usage_billing_adjustment",
        "adjustment_id": adj_id,
        "user_id": user_id,
        "period_id": period_id,
        "snapshot_version": snapshot_version,
        "snapshot_sk": snapshot_sk,
        "adjustment_type": adjustment_type,
        "amount_cents": signed_amount,
        "abs_amount_cents": amount_cents,
        "reason": reason,
        "reference_id": reference_id,
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "ttl_epoch": _ttl_epoch_from_now(getattr(S, "filemgr_usage_billing_record_retention_days", 2555)),
    }
    tbl.put_item(Item=item)
    return {
        "ok": True,
        "adjustment_id": adj_id,
        "user_id": user_id,
        "period_id": period_id,
        "snapshot_version": snapshot_version,
        "amount_cents": signed_amount,
        "adjustment_type": adjustment_type,
        "adjustment_sk": adj_sk,
    }
