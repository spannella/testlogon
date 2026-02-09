from __future__ import annotations

import asyncio
import logging
import re
import shutil
import subprocess
import uuid
import tempfile
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import zipstream
from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError
from fastapi import HTTPException, UploadFile

from app.core.aws import ddb
from app.core.aws_clients import s3_client
from app.core.settings import S

_s3 = s3_client()
logger = logging.getLogger(__name__)


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


def _parse_iso(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def _ttl_epoch(ts: datetime) -> int:
    return int(ts.timestamp())


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
        return _filter(resp.get("Items", [])), resp.get("LastEvaluatedKey")
    except ClientError:
        prefix = f"NODE#{folder_path}"
        resp = tbl.query(
            KeyConditionExpression=Key("PK").eq(pk_user(owner)) & Key("SK").begins_with(prefix),
            **_query_kwargs(),
        )
        return _filter(resp.get("Items", [])), resp.get("LastEvaluatedKey")


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
    tbl = _table()
    prefix_lc = prefix.lower()
    resp = tbl.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq(pk_user(user))
        & Key("GSI1SK").begins_with(f"NAME#{prefix_lc}"),
        Limit=limit,
    )
    items = [it for it in resp.get("Items", []) if not it.get("deleted_at")]
    return [
        {"path": it["path"], "type": it["type"], "name": it["name"], "size": it.get("size")}
        for it in items
    ]


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
    expression_values = {":t": deleted_at, ":u": deleted_by, ":p": purge_after, ":s": "pending"}
    update_expr = (
        "SET deleted_at=:t, deleted_by=:u, updated_at=:t, "
        "purge_after=:p, purge_status=:s"
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
    tokens = _search_tokens(query)
    if not tokens:
        return []
    items = _query_token_items(user, tokens[0], limit=limit * 4)
    if not items:
        return _search_text_scan(user, query, limit=limit)
    by_path = {it["path"]: it for it in items}
    paths = set(by_path.keys())
    for token in tokens[1:]:
        token_items = _query_token_items(user, token, limit=limit * 4)
        if not token_items:
            return []
        token_paths = {it["path"] for it in token_items}
        paths &= token_paths
        if not paths:
            return []
    results = [by_path[p] for p in paths if p in by_path]
    results.sort(key=lambda x: (x.get("type") != "folder", (x.get("name") or "").lower()))
    out = results[:limit]
    return [
        {
            "path": it.get("path"),
            "type": it.get("type"),
            "name": it.get("name"),
            "size": it.get("size"),
            "updated_at": it.get("updated_at"),
        }
        for it in out
    ]


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


def upload_file(user: str, path: str, file: UploadFile) -> Dict[str, Any]:
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

    duration_seconds = _maybe_probe_duration(bucket, s3_key, file.content_type)
    thumbnail = _maybe_generate_thumbnail(bucket, s3_key, file.content_type)

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
        "GSI1PK": pk_user(user),
        "GSI1SK": f"NAME#{name.lower()}#PATH#{p}",
        "GSI2PK": f"PARENT#{parent}",
        "GSI2SK": f"TYPE#file#NAME#{name.lower()}#PATH#{p}",
    }
    put_node(item)
    _put_token_entries(user, item)
    return {"path": p, "size": size}


def presign_upload(user: str, path: str, *, content_type: Optional[str]) -> Dict[str, Any]:
    bucket = _bucket()
    p = norm_path(path, is_folder=False)
    parent, name = split_parent_name(p)
    ensure_folder_exists(user, parent)
    require_not_exists(user, p)

    obj_id = str(uuid.uuid4())
    s3_key = f"{user}/objects/{obj_id}"
    upload_url = _s3.generate_presigned_url(
        ClientMethod="put_object",
        Params={
            "Bucket": bucket,
            "Key": s3_key,
            "ContentType": content_type or "application/octet-stream",
        },
        ExpiresIn=900,
    )
    return {
        "upload_url": upload_url,
        "bucket": bucket,
        "key": s3_key,
        "path": p,
        "content_type": content_type or "application/octet-stream",
        "name": name,
        "parent": parent,
    }


def register_presigned_upload(
    user: str,
    path: str,
    *,
    s3_key: str,
    content_type: Optional[str],
) -> Dict[str, Any]:
    bucket = _bucket()
    p = norm_path(path, is_folder=False)
    parent, name = split_parent_name(p)
    ensure_folder_exists(user, parent)
    require_not_exists(user, p)

    try:
        head = _s3.head_object(Bucket=bucket, Key=s3_key)
        size = int(head.get("ContentLength", 0))
        etag = head.get("ETag")
        resolved_content_type = content_type or head.get("ContentType") or "application/octet-stream"
    except ClientError as exc:
        raise HTTPException(500, f"s3 error: {exc}") from exc

    duration_seconds = _maybe_probe_duration(bucket, s3_key, resolved_content_type)
    thumbnail = _maybe_generate_thumbnail(bucket, s3_key, resolved_content_type)

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
        "GSI1PK": pk_user(user),
        "GSI1SK": f"NAME#{name.lower()}#PATH#{p}",
        "GSI2PK": f"PARENT#{parent}",
        "GSI2SK": f"TYPE#file#NAME#{name.lower()}#PATH#{p}",
    }
    put_node(item)
    _put_token_entries(user, item)
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

    return {"node": node, "object": obj}


def download_thumbnail(user: str, path: str) -> Dict[str, Any]:
    p = norm_path(path, is_folder=False)
    node = get_node(user, p)
    if node.get("type") != "file":
        raise HTTPException(400, "not a file")
    thumb = node.get("thumbnail")
    if not thumb:
        raise HTTPException(404, "thumbnail not available")
    try:
        obj = _s3.get_object(Bucket=thumb["bucket"], Key=thumb["key"])
    except ClientError as exc:
        raise HTTPException(500, f"s3 error: {exc}") from exc
    return {"node": node, "thumbnail": thumb, "object": obj}


def is_previewable(node: Dict[str, Any]) -> bool:
    content_type = (node.get("content_type") or "").lower()
    if content_type.startswith("image/"):
        return True
    if content_type in {"application/pdf"}:
        return True
    if content_type.startswith("text/"):
        return True
    if content_type in {"application/json", "application/xml"}:
        return True
    return False


def remove_file(user: str, path: str) -> None:
    p = norm_path(path, is_folder=False)
    node = get_node(user, p)
    if node["type"] != "file":
        raise HTTPException(400, "not a file")
    _soft_delete_node(user, node, deleted_by=user)
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
        _delete_token_entries(user, child)
        _delete_shares_for_path(owner=user, path=child["path"])

    _soft_delete_node(user, node, deleted_by=user)
    _delete_token_entries(user, node)
    _delete_shares_for_path(owner=user, path=folder)
    return len(items)


def move_node(user: str, src: str, dst: str) -> Dict[str, Any]:
    src_p = norm_path(src, is_folder=None)
    node = get_node(user, src_p if src_p.endswith("/") else src_p)
    is_folder = node["type"] == "folder"
    dst_p = norm_path(dst, is_folder=is_folder)

    if is_folder and dst_p == "/":
        raise HTTPException(400, "invalid destination")

    dst_parent, dst_name = split_parent_name(dst_p)
    ensure_folder_exists(user, dst_parent)

    tbl = _table()
    resp = tbl.get_item(Key=node_key(user, dst_p), ConsistentRead=True)
    if "Item" in resp:
        raise HTTPException(409, "destination exists")

    def transact_move_item(item: Dict[str, Any], new_path: str, new_parent: str, new_name: str) -> None:
        new_item = dict(item)
        new_item["path"] = new_path
        new_item["parent"] = new_parent
        new_item["name"] = new_name
        new_item["name_lc"] = new_name.lower()
        new_item["updated_at"] = now_iso()
        new_item["SK"] = sk_node(new_path)
        new_item["GSI1SK"] = f"NAME#{new_item['name_lc']}#PATH#{new_path}"
        new_item["GSI2PK"] = f"PARENT#{new_parent}"
        new_item["GSI2SK"] = f"TYPE#{new_item['type']}#NAME#{new_item['name_lc']}#PATH#{new_path}"
        ddb.meta.client.transact_write_items(
            TransactItems=[
                {
                    "ConditionCheck": {
                        "TableName": tbl.name,
                        "Key": node_key(user, new_path),
                        "ConditionExpression": "attribute_not_exists(PK)",
                    }
                },
                {
                    "Delete": {
                        "TableName": tbl.name,
                        "Key": node_key(user, item["path"]),
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

    if is_folder:
        if is_ancestor_path(src_p, dst_p):
            raise HTTPException(400, "cannot move folder into itself")
        descendants = list_children(user, src_p)
        move_id = str(uuid.uuid4())
        checkpoint = {
            "PK": pk_user(user),
            "SK": f"MOVE#{move_id}",
            "src": src_p,
            "dst": dst_p,
            "status": "in_progress",
            "total": len(descendants),
            "moved": 0,
            "updated_at": now_iso(),
        }
        tbl.put_item(Item=checkpoint)
        for it in descendants:
            old_path = it["path"]
            if not old_path.startswith(src_p):
                continue
            new_path = dst_p + old_path[len(src_p):]
            new_parent, new_name = split_parent_name(
                new_path if it["type"] == "file" else norm_path(new_path, is_folder=True)
            )
            try:
                transact_move_item(it, new_path, new_parent, new_name)
                _move_shares(owner=user, old_path=old_path, new_path=new_path)
                tbl.update_item(
                    Key={"PK": pk_user(user), "SK": f"MOVE#{move_id}"},
                    UpdateExpression="SET moved=:m, last_path=:p, updated_at=:t",
                    ExpressionAttributeValues={
                        ":m": checkpoint["moved"] + 1,
                        ":p": old_path,
                        ":t": now_iso(),
                    },
                )
                checkpoint["moved"] += 1
            except ClientError as exc:
                raise HTTPException(500, f"move interrupted; checkpoint {move_id}") from exc
        tbl.delete_item(Key={"PK": pk_user(user), "SK": f"MOVE#{move_id}"})
        return {"type": "folder", "src": src_p, "dst": dst_p, "count": len(descendants)}

    old_path = src_p
    new_path = dst_p
    transact_move_item(node, new_path, dst_parent, dst_name)

    _move_shares(owner=user, old_path=old_path, new_path=new_path)
    return {"type": "file", "src": old_path, "dst": new_path}


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


def upload_zip(user: str, dest_folder: str, zip_file: UploadFile) -> List[str]:
    bucket = _bucket()
    folder = norm_path(dest_folder, is_folder=True)
    ensure_folder_exists(user, folder)

    zip_file.file.seek(0)
    try:
        zf = zipfile.ZipFile(zip_file.file)
    except zipfile.BadZipFile as exc:
        raise HTTPException(400, "invalid zip") from exc

    created: List[str] = []
    created_set = set()
    for info in zf.infolist():
        name = info.filename
        if name.endswith("/"):
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
        with zf.open(info) as file_obj:
            _s3.upload_fileobj(
                Fileobj=file_obj,
                Bucket=bucket,
                Key=s3_key,
                ExtraArgs={"ContentType": "application/octet-stream"},
            )

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
            "size": info.file_size,
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
        created.append(out_path)
        created_set.add(out_path)

    return created


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
        items.append({
            "owner": it["owner"],
            "path": it["path"],
            "shared_at": it.get("shared_at"),
            "permission": it.get("permission", "read"),
            "expires_at": it.get("expires_at"),
        })
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
    if item.get("s3_bucket") and item.get("s3_key"):
        try:
            _s3.delete_object(Bucket=item["s3_bucket"], Key=item["s3_key"])
        except ClientError:
            return "error"
    key = key or {"PK": item.get("PK"), "SK": item.get("SK")}
    if not key.get("PK") or not key.get("SK"):
        return "error"
    tbl.update_item(
        Key=key,
        UpdateExpression="SET purge_status=:s, purged_at=:t, updated_at=:t",
        ExpressionAttributeValues={":s": "purged", ":t": now_iso()},
    )
    return "purged"


def purge_deleted_nodes(user: str, *, limit: Optional[int] = None) -> Dict[str, Any]:
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
    return {"purged": purged, "skipped": skipped, "errors": errors}


def purge_deleted_nodes_global(*, limit: Optional[int] = None) -> Dict[str, Any]:
    tbl = _table()
    purge_limit = limit or S.filemgr_purge_scan_limit
    purged = 0
    skipped = 0
    errors = 0
    now = datetime.now(timezone.utc)
    start_key: Optional[Dict[str, Any]] = None
    filter_expr = Attr("SK").begins_with("NODE#") & Attr("deleted_at").exists()

    while purged + skipped + errors < purge_limit:
        remaining = purge_limit - (purged + skipped + errors)
        if remaining <= 0:
            break
        kwargs: Dict[str, Any] = {"FilterExpression": filter_expr, "Limit": min(200, remaining)}
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = tbl.scan(**kwargs)
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
    return {"purged": purged, "skipped": skipped, "errors": errors}


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
