from __future__ import annotations

import hashlib
import io
import logging
import posixpath
import time
from typing import Any, BinaryIO, Dict, List, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import HTTPException

from app.core.settings import S
from app.metrics import (
    record_filemgr_mount_bytes,
    record_filemgr_mount_error,
    record_filemgr_mount_operation_latency,
)
from app.models import FileMountModel
from app.services.provider_credentials import get_provider_auth_context

logger = logging.getLogger(__name__)


def _normalize_prefix(prefix: Optional[str]) -> str:
    cleaned = (prefix or "").strip().strip("/")
    return f"{cleaned}/" if cleaned else ""


def _safe_relative_from_virtual(mount: FileMountModel, virtual_path: str, *, expect_dir: bool) -> str:
    mount_root = mount.mount_path.rstrip("/") + "/"
    candidate = (virtual_path or "").strip()
    if not candidate.startswith("/"):
        raise HTTPException(status_code=400, detail="virtual path must be absolute")
    if not candidate.startswith(mount_root):
        raise HTTPException(status_code=400, detail="path is outside mount root")

    rel = candidate[len(mount_root) :]
    if expect_dir and rel.endswith("/"):
        rel = rel[:-1]

    normed = posixpath.normpath(rel) if rel else "."
    if normed in {".", ""}:
        return ""
    if normed.startswith("../") or normed == ".." or "/../" in f"/{normed}":
        raise HTTPException(status_code=400, detail="invalid mount-relative path")
    return normed.strip("/")


def _join_s3_key(prefix: str, relative: str, *, as_dir: bool = False) -> str:
    key = f"{prefix}{relative}" if relative else prefix
    key = key.strip("/")
    if as_dir and key:
        return key + "/"
    return key


def _build_s3_client_for_mount(mount: FileMountModel):
    auth = get_provider_auth_context(mount.owner, "s3", org=mount.auth_ref)
    access_key_id = str(auth.get("access_key_id") or "").strip()
    secret_access_key = str(auth.get("secret_access_key") or "").strip()
    session_token = auth.get("session_token")
    metadata = auth.get("metadata") or {}

    if not access_key_id or not secret_access_key:
        raise HTTPException(status_code=500, detail="stored s3 credential missing access key material")

    region = str(metadata.get("region") or "").strip() or None
    endpoint_url = str(metadata.get("endpoint_url") or "").strip() or None
    path_style = bool(metadata.get("path_style", False))

    cfg = Config(s3={"addressing_style": "path" if path_style else "auto"})
    return boto3.client(
        "s3",
        region_name=region,
        endpoint_url=endpoint_url,
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        aws_session_token=session_token,
        config=cfg,
    )




def _multipart_threshold_bytes() -> int:
    try:
        value = int(getattr(S, "filemgr_s3_mounts_multipart_threshold_bytes", 8 * 1024 * 1024) or 0)
    except Exception:
        value = 8 * 1024 * 1024
    return max(5 * 1024 * 1024, value)


def _multipart_chunk_bytes() -> int:
    try:
        value = int(getattr(S, "filemgr_s3_mounts_multipart_chunk_bytes", 8 * 1024 * 1024) or 0)
    except Exception:
        value = 8 * 1024 * 1024
    return max(5 * 1024 * 1024, value)


def _as_stream(data: Any) -> BinaryIO:
    if hasattr(data, "read"):
        return data
    if isinstance(data, (bytes, bytearray)):
        return io.BytesIO(bytes(data))
    raise HTTPException(status_code=400, detail="invalid upload body")


def _stream_length(stream: BinaryIO) -> Optional[int]:
    if not hasattr(stream, "tell") or not hasattr(stream, "seek"):
        return None
    try:
        cur = stream.tell()
        stream.seek(0, 2)
        end = stream.tell()
        stream.seek(cur)
        return max(0, end - cur)
    except Exception:
        return None



def _mount_labels(mount: FileMountModel, operation: str) -> Dict[str, str]:
    return {
        "provider": str(mount.provider or "unknown"),
        "mode": str(mount.mode or "unknown"),
        "operation": operation,
        "mount_id_hash": hashlib.sha256(str(mount.id).encode("utf-8")).hexdigest()[:12],
    }


def _record_mount_latency(labels: Dict[str, str], started: float) -> None:
    record_filemgr_mount_operation_latency(
        provider=labels["provider"],
        mode=labels["mode"],
        operation=labels["operation"],
        mount_id_hash=labels["mount_id_hash"],
        elapsed_seconds=time.perf_counter() - started,
    )


def _record_mount_error(labels: Dict[str, str], code: str) -> None:
    record_filemgr_mount_error(
        provider=labels["provider"],
        mode=labels["mode"],
        operation=labels["operation"],
        aws_error_code=code or "unknown",
        mount_id_hash=labels["mount_id_hash"],
    )


def _record_mount_bytes(labels: Dict[str, str], *, direction: str, nbytes: int) -> None:
    record_filemgr_mount_bytes(
        provider=labels["provider"],
        mode=labels["mode"],
        operation=labels["operation"],
        direction=direction,
        mount_id_hash=labels["mount_id_hash"],
        nbytes=nbytes,
    )


def _aws_error_code(exc: ClientError) -> str:
    return str(((exc.response or {}).get("Error") or {}).get("Code") or "unknown")


def _log_mount(level: str, event: str, labels: Dict[str, str], **kwargs: Any) -> None:
    payload = {"event": event, **labels, **kwargs}
    getattr(logger, level)("filemgr_mount", extra=payload)

def _map_s3_error(exc: ClientError) -> HTTPException:
    err = (exc.response or {}).get("Error", {})
    code = str(err.get("Code") or "").strip()
    message = str(err.get("Message") or "").strip() or "s3 adapter error"
    if code in {"NoSuchKey", "NoSuchBucket", "404", "NotFound"}:
        return HTTPException(status_code=404, detail=f"s3 path not found: {message}")
    if code in {"AccessDenied", "AllAccessDisabled"}:
        return HTTPException(status_code=403, detail=f"s3 access denied: {message}")
    return HTTPException(status_code=502, detail=f"s3 provider error ({code or 'unknown'}): {message}")


def list_dir(
    mount: FileMountModel,
    virtual_dir_path: str,
    *,
    limit: int = 100,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    started = time.perf_counter()
    labels = _mount_labels(mount, "list")
    client = _build_s3_client_for_mount(mount)
    rel = _safe_relative_from_virtual(mount, virtual_dir_path, expect_dir=True)
    prefix_root = _normalize_prefix(mount.prefix)
    list_prefix = _join_s3_key(prefix_root, rel, as_dir=bool(rel))

    kwargs: Dict[str, Any] = {
        "Bucket": mount.bucket,
        "Prefix": list_prefix,
        "Delimiter": "/",
        "MaxKeys": max(1, min(int(limit or 100), 1000)),
    }
    if cursor:
        kwargs["ContinuationToken"] = cursor

    try:
        resp = client.list_objects_v2(**kwargs)
    except ClientError as exc:
        _record_mount_error(labels, _aws_error_code(exc))
        _log_mount("warning", "list_error", labels, aws_error_code=_aws_error_code(exc))
        raise _map_s3_error(exc) from exc
    except BotoCoreError as exc:
        _record_mount_error(labels, "BotoCoreError")
        _log_mount("warning", "list_error", labels, aws_error_code="BotoCoreError")
        raise HTTPException(status_code=502, detail="s3 list operation failed") from exc
    finally:
        _record_mount_latency(labels, started)

    items: List[Dict[str, Any]] = []
    for cp in resp.get("CommonPrefixes", []) or []:
        pfx = str(cp.get("Prefix") or "")
        leaf = pfx[len(list_prefix) :].strip("/") if pfx.startswith(list_prefix) else pfx.strip("/")
        if not leaf:
            continue
        items.append({"type": "folder", "name": leaf, "key": pfx})

    for obj in resp.get("Contents", []) or []:
        key = str(obj.get("Key") or "")
        if not key or key == list_prefix:
            continue
        leaf = key[len(list_prefix) :].strip("/") if key.startswith(list_prefix) else key.strip("/")
        if not leaf or "/" in leaf:
            continue
        items.append(
            {
                "type": "file",
                "name": leaf,
                "key": key,
                "size": int(obj.get("Size") or 0),
                "updated_at": obj.get("LastModified").isoformat() if obj.get("LastModified") else None,
                "etag": str(obj.get("ETag") or "").strip('"'),
            }
        )

    bytes_out = sum(int(it.get("size") or 0) for it in items if it.get("type") == "file")
    _record_mount_bytes(labels, direction="out", nbytes=bytes_out)
    _log_mount("info", "list_ok", labels, bytes_out=bytes_out, item_count=len(items))
    return {
        "items": items,
        "cursor": resp.get("NextContinuationToken"),
        "truncated": bool(resp.get("IsTruncated", False)),
        "prefix": list_prefix,
    }


def stat(mount: FileMountModel, virtual_path: str) -> Dict[str, Any]:
    started = time.perf_counter()
    labels = _mount_labels(mount, "list")
    client = _build_s3_client_for_mount(mount)
    rel = _safe_relative_from_virtual(mount, virtual_path, expect_dir=False)
    prefix_root = _normalize_prefix(mount.prefix)

    if virtual_path.rstrip("/") == mount.mount_path.rstrip("/"):
        return {"type": "dir", "exists": True, "key": _join_s3_key(prefix_root, "", as_dir=True)}

    key = _join_s3_key(prefix_root, rel, as_dir=False)
    try:
        head = client.head_object(Bucket=mount.bucket, Key=key)
        return {
            "type": "file",
            "exists": True,
            "key": key,
            "size": int(head.get("ContentLength") or 0),
            "content_type": head.get("ContentType"),
            "etag": str(head.get("ETag") or "").strip('"'),
            "updated_at": head.get("LastModified").isoformat() if head.get("LastModified") else None,
        }
    except ClientError as exc:
        code = str((exc.response or {}).get("Error", {}).get("Code") or "").strip()
        if code not in {"404", "NoSuchKey", "NotFound"}:
            raise _map_s3_error(exc) from exc

    dir_key = _join_s3_key(prefix_root, rel, as_dir=True)
    try:
        probe = client.list_objects_v2(Bucket=mount.bucket, Prefix=dir_key, MaxKeys=1)
    except ClientError as exc:
        raise _map_s3_error(exc) from exc
    except BotoCoreError as exc:
        raise HTTPException(status_code=502, detail="s3 stat operation failed") from exc

    if int(probe.get("KeyCount") or 0) > 0:
        return {"type": "dir", "exists": True, "key": dir_key}
    raise HTTPException(status_code=404, detail="s3 path not found")


def read_file(mount: FileMountModel, virtual_file_path: str) -> Dict[str, Any]:
    started = time.perf_counter()
    labels = _mount_labels(mount, "read")
    client = _build_s3_client_for_mount(mount)
    rel = _safe_relative_from_virtual(mount, virtual_file_path, expect_dir=False)
    key = _join_s3_key(_normalize_prefix(mount.prefix), rel, as_dir=False)
    if not key:
        raise HTTPException(status_code=400, detail="cannot read mount root as file")

    try:
        obj = client.get_object(Bucket=mount.bucket, Key=key)
    except ClientError as exc:
        _record_mount_error(labels, _aws_error_code(exc))
        _log_mount("warning", "read_error", labels, aws_error_code=_aws_error_code(exc))
        raise _map_s3_error(exc) from exc
    except BotoCoreError as exc:
        _record_mount_error(labels, "BotoCoreError")
        _log_mount("warning", "read_error", labels, aws_error_code="BotoCoreError")
        raise HTTPException(status_code=502, detail="s3 read operation failed") from exc
    finally:
        _record_mount_latency(labels, started)

    content_length = int(obj.get("ContentLength") or 0)
    _record_mount_bytes(labels, direction="out", nbytes=content_length)
    _log_mount("info", "read_ok", labels, bytes_out=content_length)
    return {
        "bucket": mount.bucket,
        "key": key,
        "content_type": obj.get("ContentType") or "application/octet-stream",
        "content_length": content_length,
        "etag": str(obj.get("ETag") or "").strip('"'),
        "body": obj.get("Body"),  # streaming body; caller can stream without buffering entire content
    }


def write_file(
    mount: FileMountModel,
    virtual_file_path: str,
    *,
    body: Any,
    content_type: Optional[str] = None,
    metadata: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    started = time.perf_counter()
    labels = _mount_labels(mount, "write")
    if mount.mode != "read_write":
        _record_mount_error(labels, "mount_read_only")
        _record_mount_latency(labels, started)
        raise HTTPException(status_code=403, detail={"code": "mount_read_only", "message": "mount is read-only"})

    client = _build_s3_client_for_mount(mount)
    rel = _safe_relative_from_virtual(mount, virtual_file_path, expect_dir=False)
    key = _join_s3_key(_normalize_prefix(mount.prefix), rel, as_dir=False)
    if not key:
        _record_mount_error(labels, "invalid_path")
        _record_mount_latency(labels, started)
        raise HTTPException(status_code=400, detail="cannot write mount root")

    stream = _as_stream(body)
    ctype = content_type or "application/octet-stream"
    meta = {str(k): str(v) for k, v in (metadata or {}).items() if k and v is not None}
    threshold = _multipart_threshold_bytes()
    chunk_size = _multipart_chunk_bytes()
    size = _stream_length(stream)

    if size is not None and size <= threshold:
        try:
            kwargs: Dict[str, Any] = {"Bucket": mount.bucket, "Key": key, "Body": stream, "ContentType": ctype}
            if meta:
                kwargs["Metadata"] = meta
            resp = client.put_object(**kwargs)
        except ClientError as exc:
            _record_mount_error(labels, _aws_error_code(exc))
            _log_mount("warning", "write_error", labels, aws_error_code=_aws_error_code(exc))
            _record_mount_latency(labels, started)
            raise _map_s3_error(exc) from exc
        except BotoCoreError as exc:
            _record_mount_error(labels, "BotoCoreError")
            _log_mount("warning", "write_error", labels, aws_error_code="BotoCoreError")
            _record_mount_latency(labels, started)
            raise HTTPException(status_code=502, detail="s3 write operation failed") from exc
        _record_mount_bytes(labels, direction="in", nbytes=int(size or 0))
        _record_mount_latency(labels, started)
        _log_mount("info", "write_ok", labels, bytes_in=int(size or 0), multipart=False)
        return {
            "bucket": mount.bucket,
            "key": key,
            "etag": str(resp.get("ETag") or "").strip('"') or None,
            "content_type": ctype,
            "content_length": size,
        }

    upload_id: Optional[str] = None
    parts: List[Dict[str, Any]] = []
    total = 0
    try:
        create_kwargs: Dict[str, Any] = {"Bucket": mount.bucket, "Key": key, "ContentType": ctype}
        if meta:
            create_kwargs["Metadata"] = meta
        created = client.create_multipart_upload(**create_kwargs)
        upload_id = str(created.get("UploadId") or "")
        if not upload_id:
            raise HTTPException(status_code=502, detail="s3 multipart init failed")

        part_no = 1
        while True:
            chunk = stream.read(chunk_size)
            if not chunk:
                break
            total += len(chunk)
            up = client.upload_part(
                Bucket=mount.bucket,
                Key=key,
                UploadId=upload_id,
                PartNumber=part_no,
                Body=chunk,
            )
            etag = str(up.get("ETag") or "").strip('"')
            if not etag:
                raise HTTPException(status_code=502, detail="s3 multipart part missing etag")
            parts.append({"PartNumber": part_no, "ETag": etag})
            part_no += 1

        if not parts:
            # empty uploads: write empty object via put_object
            resp = client.put_object(Bucket=mount.bucket, Key=key, Body=b"", ContentType=ctype, **({"Metadata": meta} if meta else {}))
            if upload_id:
                client.abort_multipart_upload(Bucket=mount.bucket, Key=key, UploadId=upload_id)
            _record_mount_latency(labels, started)
            _log_mount("info", "write_ok", labels, bytes_in=0, multipart=False)
            return {"bucket": mount.bucket, "key": key, "etag": str(resp.get("ETag") or "").strip('"') or None, "content_type": ctype, "content_length": 0}

        comp = client.complete_multipart_upload(
            Bucket=mount.bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={"Parts": parts},
        )
    except HTTPException:
        _record_mount_error(labels, "http_error")
        _record_mount_latency(labels, started)
        if upload_id:
            try:
                client.abort_multipart_upload(Bucket=mount.bucket, Key=key, UploadId=upload_id)
            except Exception:
                pass
        raise
    except ClientError as exc:
        _record_mount_error(labels, _aws_error_code(exc))
        _log_mount("warning", "write_error", labels, aws_error_code=_aws_error_code(exc))
        _record_mount_latency(labels, started)
        if upload_id:
            try:
                client.abort_multipart_upload(Bucket=mount.bucket, Key=key, UploadId=upload_id)
            except Exception:
                pass
        raise _map_s3_error(exc) from exc
    except BotoCoreError as exc:
        _record_mount_error(labels, "BotoCoreError")
        _log_mount("warning", "write_error", labels, aws_error_code="BotoCoreError")
        _record_mount_latency(labels, started)
        if upload_id:
            try:
                client.abort_multipart_upload(Bucket=mount.bucket, Key=key, UploadId=upload_id)
            except Exception:
                pass
        raise HTTPException(status_code=502, detail="s3 multipart upload failed") from exc

    bytes_in = int(total if size is None else size or 0)
    _record_mount_bytes(labels, direction="in", nbytes=bytes_in)
    _record_mount_latency(labels, started)
    _log_mount("info", "write_ok", labels, bytes_in=bytes_in, multipart=True)
    return {
        "bucket": mount.bucket,
        "key": key,
        "etag": str(comp.get("ETag") or "").strip('"') or None,
        "content_type": ctype,
        "content_length": total if size is None else size,
    }


def delete_file(mount: FileMountModel, virtual_file_path: str) -> Dict[str, Any]:
    started = time.perf_counter()
    labels = _mount_labels(mount, "delete")
    if mount.mode != "read_write":
        _record_mount_error(labels, "mount_read_only")
        _record_mount_latency(labels, started)
        raise HTTPException(status_code=403, detail={"code": "mount_read_only", "message": "mount is read-only"})

    client = _build_s3_client_for_mount(mount)
    rel = _safe_relative_from_virtual(mount, virtual_file_path, expect_dir=False)
    key = _join_s3_key(_normalize_prefix(mount.prefix), rel, as_dir=False)
    if not key:
        _record_mount_error(labels, "invalid_path")
        _record_mount_latency(labels, started)
        raise HTTPException(status_code=400, detail="cannot delete mount root")

    try:
        client.delete_object(Bucket=mount.bucket, Key=key)
    except ClientError as exc:
        _record_mount_error(labels, _aws_error_code(exc))
        _log_mount("warning", "delete_error", labels, aws_error_code=_aws_error_code(exc))
        _record_mount_latency(labels, started)
        raise _map_s3_error(exc) from exc
    except BotoCoreError as exc:
        _record_mount_error(labels, "BotoCoreError")
        _log_mount("warning", "delete_error", labels, aws_error_code="BotoCoreError")
        _record_mount_latency(labels, started)
        raise HTTPException(status_code=502, detail="s3 delete operation failed") from exc

    _record_mount_latency(labels, started)
    _log_mount("info", "delete_ok", labels)
    return {"bucket": mount.bucket, "key": key, "deleted": True}


def check_mount_health(mount: FileMountModel) -> Dict[str, Any]:
    started = time.perf_counter()
    labels = _mount_labels(mount, "health")
    client = _build_s3_client_for_mount(mount)
    prefix = _normalize_prefix(mount.prefix)
    try:
        client.head_bucket(Bucket=mount.bucket)
        client.list_objects_v2(Bucket=mount.bucket, Prefix=prefix, MaxKeys=1)
    except ClientError as exc:
        code = _aws_error_code(exc)
        _record_mount_error(labels, code)
        _record_mount_latency(labels, started)
        _log_mount("warning", "health_error", labels, aws_error_code=code)
        mapped = _map_s3_error(exc)
        return {"ok": False, "status": "degraded", "error": str(mapped.detail), "aws_error_code": code}
    except BotoCoreError:
        _record_mount_error(labels, "BotoCoreError")
        _record_mount_latency(labels, started)
        _log_mount("warning", "health_error", labels, aws_error_code="BotoCoreError")
        return {"ok": False, "status": "degraded", "error": "s3 health probe failed", "aws_error_code": "BotoCoreError"}

    _record_mount_latency(labels, started)
    _log_mount("info", "health_ok", labels)
    return {"ok": True, "status": "active", "error": None, "aws_error_code": None}
