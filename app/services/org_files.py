"""Organization shared file space service (ENTERPRISE-003).

Wraps the existing filemanager functions using ``pk=ORG#{org_id}``
as the file-manager owner key.
"""
from __future__ import annotations

import io
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException, UploadFile

from app.core.aws import ddb
from app.core.aws_clients import s3_client
from app.core.settings import S
from app.core.tables import T
from app.services.org_service import assert_org_membership, get_org


_s3 = s3_client()


def _fm_table():
    if not S.filemgr_table_name:
        raise HTTPException(500, "file manager table not configured")
    return ddb.Table(S.filemgr_table_name)


def _bucket() -> str:
    if not S.filemgr_bucket:
        raise HTTPException(500, "file manager bucket not configured")
    return S.filemgr_bucket


def _org_pk(org_id: str) -> str:
    return f"ORG#{org_id}"


def org_upload_file(
    org_id: str,
    user_sub: str,
    filename: str,
    file: UploadFile,
) -> Dict[str, Any]:
    """Upload a file to the org's shared space."""
    assert_org_membership(org_id, user_sub, min_role="member")

    pk = _org_pk(org_id)
    tbl = _fm_table()
    bucket = _bucket()
    path = f"/{filename}"
    node_id = f"orgfile_{uuid.uuid4().hex[:16]}"
    s3_key = f"org/{org_id}/{node_id}"

    content = file.file.read()
    size = len(content)

    _s3.put_object(
        Bucket=bucket,
        Key=s3_key,
        Body=content,
        ContentType=file.content_type or "application/octet-stream",
    )

    now = datetime.now(timezone.utc).isoformat()
    item: Dict[str, Any] = {
        "PK": pk,
        "SK": f"NODE#{node_id}",
        "type": "file",
        "node_id": node_id,
        "path": path,
        "name": filename,
        "name_lc": filename.lower(),
        "parent": "/",
        "created_at": now,
        "updated_at": now,
        "size": size,
        "content_type": file.content_type or "application/octet-stream",
        "s3_key": s3_key,
        "s3_bucket": bucket,
        "uploaded_by": user_sub,
    }
    tbl.put_item(Item=item)
    return item


def org_list_children(
    org_id: str,
    user_sub: str,
    path: str = "/",
) -> List[Dict[str, Any]]:
    """List files in the org's shared space."""
    assert_org_membership(org_id, user_sub, min_role="viewer")
    pk = _org_pk(org_id)
    tbl = _fm_table()
    resp = tbl.query(
        KeyConditionExpression=Key("PK").eq(pk) & Key("SK").begins_with("NODE#"),
    )
    items = resp.get("Items", [])
    return [i for i in items if not i.get("deleted_at")]


def org_download_file(
    org_id: str,
    user_sub: str,
    node_id: str,
) -> Dict[str, Any]:
    """Download a file from the org's shared space."""
    assert_org_membership(org_id, user_sub, min_role="viewer")
    pk = _org_pk(org_id)
    tbl = _fm_table()
    resp = tbl.get_item(Key={"PK": pk, "SK": f"NODE#{node_id}"})
    item = resp.get("Item")
    if not item:
        raise HTTPException(404, "File not found")

    s3_key = item.get("s3_key", "")
    bucket = item.get("s3_bucket", _bucket())
    obj = _s3.get_object(Bucket=bucket, Key=s3_key)
    body = obj["Body"].read()
    return {
        "content": body,
        "content_type": item.get("content_type", "application/octet-stream"),
        "filename": item.get("name", "download"),
    }


def org_remove_file(
    org_id: str,
    user_sub: str,
    node_id: str,
) -> None:
    """Remove a file from the org's shared space."""
    membership = assert_org_membership(org_id, user_sub, min_role="member")
    pk = _org_pk(org_id)
    tbl = _fm_table()
    resp = tbl.get_item(Key={"PK": pk, "SK": f"NODE#{node_id}"})
    item = resp.get("Item")
    if not item:
        raise HTTPException(404, "File not found")

    if membership["org_role"] not in ("admin", "owner"):
        if item.get("uploaded_by") != user_sub:
            raise HTTPException(403, "Can only delete your own files")

    tbl.update_item(
        Key={"PK": pk, "SK": f"NODE#{node_id}"},
        UpdateExpression="SET deleted_at = :d",
        ExpressionAttributeValues={":d": datetime.now(timezone.utc).isoformat()},
    )
