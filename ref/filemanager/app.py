import os
import io
import re
import json
import uuid
import time
import zipfile
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Query, Body
from fastapi.responses import StreamingResponse

AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
TABLE = os.environ["FILEMGR_TABLE"]
BUCKET = os.environ["FILEMGR_BUCKET"]

ddb = boto3.resource("dynamodb", region_name=AWS_REGION)
tbl = ddb.Table(TABLE)
s3 = boto3.client("s3", region_name=AWS_REGION)

app = FastAPI(title="File Manager (FastAPI + DynamoDB + S3)")

# -----------------------------
# Auth placeholder
# -----------------------------
def get_current_user() -> str:
    # Replace with your auth integration (e.g., JWT / Cognito).
    # Must return username.
    return "alice"

# -----------------------------
# Helpers
# -----------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

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
    # collapse multiple slashes
    path = re.sub(r"/+", "/", path)

    parts = []
    for p in path.split("/"):
        if p in ("", "."):
            continue
        if p == "..":
            raise HTTPException(400, "invalid path")
        parts.append(p)

    normalized = "/" + "/".join(parts)
    if is_folder is True and not normalized.endswith("/"):
        normalized += "/"
    if is_folder is False and normalized.endswith("/") and normalized != "/":
        normalized = normalized[:-1]
    if normalized == "":
        normalized = "/"
    if normalized != "/" and is_folder is None:
        # keep as caller provided; don’t force trailing slash
        pass
    return normalized

def split_parent_name(path: str) -> (str, str):
    if path == "/":
        return "/", ""
    if path.endswith("/"):
        path2 = path[:-1]
    else:
        path2 = path
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
    r = tbl.get_item(Key=node_key(owner, path), ConsistentRead=True)
    if "Item" not in r:
        raise HTTPException(404, "not found")
    return r["Item"]

def put_node(item: Dict[str, Any]) -> None:
    tbl.put_item(Item=item)

def delete_node(owner: str, path: str) -> None:
    tbl.delete_item(Key=node_key(owner, path))

def list_children(owner: str, folder_path: str) -> List[Dict[str, Any]]:
    # Children are nodes whose path begins with folder_path but are not equal to folder_path.
    # We store all nodes under USER#owner, SK = NODE#<path>
    # Query by begins_with on SK.
    prefix = f"NODE#{folder_path}"
    resp = tbl.query(
        KeyConditionExpression=Key("PK").eq(pk_user(owner)) & Key("SK").begins_with(prefix),
    )
    items = resp.get("Items", [])
    return items

def is_ancestor_path(folder_path: str, maybe_child_path: str) -> bool:
    return maybe_child_path.startswith(folder_path)

def ensure_folder_exists(owner: str, folder_path: str) -> None:
    folder_path = norm_path(folder_path, is_folder=True)
    if folder_path == "/":
        # Root can be implicit; optionally create it.
        return
    try:
        n = get_node(owner, folder_path)
        if n.get("type") != "folder":
            raise HTTPException(400, "parent is not a folder")
    except HTTPException as e:
        if e.status_code == 404:
            raise HTTPException(400, "parent folder does not exist")
        raise

def require_not_exists(owner: str, path: str) -> None:
    r = tbl.get_item(Key=node_key(owner, path), ConsistentRead=True)
    if "Item" in r:
        raise HTTPException(409, "already exists")

# -----------------------------
# Core: view/list/info/search
# -----------------------------
@app.get("/v1/fs/list")
def list_files(
    path: str = Query("/", description="Folder path"),
    user: str = Depends(get_current_user),
):
    folder = norm_path(path, is_folder=True)
    # List direct children only (not recursive)
    # We'll query all descendants and filter to direct children by parent attr.
    items = list_children(user, folder)
    out = []
    for it in items:
        if it.get("parent") == folder:
            out.append({
                "path": it["path"],
                "type": it["type"],
                "name": it["name"],
                "size": it.get("size"),
                "updated_at": it.get("updated_at"),
            })
    out.sort(key=lambda x: (x["type"] != "folder", x["name"].lower()))
    return {"path": folder, "items": out}

@app.get("/v1/fs/info")
def file_info(
    path: str = Query(...),
    user: str = Depends(get_current_user),
):
    p = norm_path(path, is_folder=None)
    it = get_node(user, p if p.endswith("/") else p)
    return {
        "path": it["path"],
        "type": it["type"],
        "name": it["name"],
        "parent": it.get("parent"),
        "created_at": it.get("created_at"),
        "updated_at": it.get("updated_at"),
        "upload_at": it.get("upload_at"),
        "upload_by": it.get("upload_by"),
        "last_download_at": it.get("last_download_at"),
        "last_download_by": it.get("last_download_by"),
        "size": it.get("size"),
        "content_type": it.get("content_type"),
        "shared": it.get("shared", False),
    }

@app.get("/v1/fs/search")
def search_filenames(
    prefix: str = Query(..., description="Filename prefix"),
    user: str = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=200),
):
    prefix_lc = prefix.lower()
    resp = tbl.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq(pk_user(user)) & Key("GSI1SK").begins_with(f"NAME#{prefix_lc}"),
        Limit=limit,
    )
    items = resp.get("Items", [])
    return {
        "prefix": prefix,
        "results": [
            {"path": it["path"], "type": it["type"], "name": it["name"], "size": it.get("size")}
            for it in items
        ],
    }

# -----------------------------
# Create folder
# -----------------------------
@app.post("/v1/fs/folder")
def create_empty_folder(
    path: str = Body(..., embed=True),
    user: str = Depends(get_current_user),
):
    folder = norm_path(path, is_folder=True)
    if folder == "/":
        return {"ok": True, "path": "/"}
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
    }
    put_node(item)
    return {"ok": True, "path": folder}

# -----------------------------
# Upload / Download
# -----------------------------
@app.post("/v1/fs/upload")
def upload_file(
    path: str = Query(..., description="Full file path, e.g. /docs/a.txt"),
    file: UploadFile = File(...),
    user: str = Depends(get_current_user),
):
    p = norm_path(path, is_folder=False)
    parent, name = split_parent_name(p)
    ensure_folder_exists(user, parent)

    # Store content in S3 under immutable UUID key
    obj_id = str(uuid.uuid4())
    s3_key = f"{user}/objects/{obj_id}"

    try:
        s3.upload_fileobj(
            Fileobj=file.file,
            Bucket=BUCKET,
            Key=s3_key,
            ExtraArgs={"ContentType": file.content_type or "application/octet-stream"},
        )
        head = s3.head_object(Bucket=BUCKET, Key=s3_key)
        size = int(head.get("ContentLength", 0))
        etag = head.get("ETag")
    except ClientError as e:
        raise HTTPException(500, f"s3 error: {e}")

    # Upsert node metadata
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
        "s3_bucket": BUCKET,
        "s3_key": s3_key,
        "etag": etag,
        "GSI1PK": pk_user(user),
        "GSI1SK": f"NAME#{name.lower()}#PATH#{p}",
    }
    put_node(item)
    return {"ok": True, "path": p, "size": size}

@app.get("/v1/fs/download")
def download_file(
    path: str = Query(...),
    user: str = Depends(get_current_user),
):
    p = norm_path(path, is_folder=False)
    it = get_node(user, p)
    if it.get("type") != "file":
        raise HTTPException(400, "not a file")

    bucket = it["s3_bucket"]
    key = it["s3_key"]

    try:
        obj = s3.get_object(Bucket=bucket, Key=key)
    except ClientError as e:
        raise HTTPException(500, f"s3 error: {e}")

    # Update last download (best-effort)
    try:
        tbl.update_item(
            Key=node_key(user, p),
            UpdateExpression="SET last_download_at=:t, last_download_by=:u, updated_at=:t",
            ExpressionAttributeValues={":t": now_iso(), ":u": user},
        )
    except ClientError:
        pass

    def gen():
        body = obj["Body"]
        while True:
            chunk = body.read(1024 * 1024)
            if not chunk:
                break
            yield chunk

    return StreamingResponse(
        gen(),
        media_type=it.get("content_type", "application/octet-stream"),
        headers={"Content-Disposition": f'attachment; filename="{it["name"]}"'},
    )

# -----------------------------
# Remove file / folder
# -----------------------------
@app.delete("/v1/fs/file")
def remove_file(
    path: str = Query(...),
    user: str = Depends(get_current_user),
):
    p = norm_path(path, is_folder=False)
    it = get_node(user, p)
    if it["type"] != "file":
        raise HTTPException(400, "not a file")

    # delete S3 object
    try:
        s3.delete_object(Bucket=it["s3_bucket"], Key=it["s3_key"])
    except ClientError:
        pass

    delete_node(user, p)

    # also delete any shares for this path
    _delete_shares_for_path(owner=user, path=p)

    return {"ok": True}

@app.delete("/v1/fs/folder")
def remove_folder(
    path: str = Query(...),
    user: str = Depends(get_current_user),
):
    folder = norm_path(path, is_folder=True)
    if folder == "/":
        raise HTTPException(400, "cannot delete root")

    it = get_node(user, folder)
    if it["type"] != "folder":
        raise HTTPException(400, "not a folder")

    # Find all descendants
    items = list_children(user, folder)

    # Delete files' S3 objects and DDB nodes
    # NOTE: DynamoDB batch_write has limits; production code should chunk in 25 writes.
    # We'll do simple loop here.
    # Delete descendants first
    for child in items:
        if child["path"] == folder:
            continue
        if child["type"] == "file":
            try:
                s3.delete_object(Bucket=child["s3_bucket"], Key=child["s3_key"])
            except ClientError:
                pass
        delete_node(user, child["path"])
        _delete_shares_for_path(owner=user, path=child["path"])

    # Delete the folder itself
    delete_node(user, folder)
    _delete_shares_for_path(owner=user, path=folder)

    return {"ok": True, "deleted_count": len(items)}

# -----------------------------
# Move / Rename (metadata-only, since S3 keys are immutable UUIDs)
# -----------------------------
@app.post("/v1/fs/move")
def move_node(
    src: str = Body(..., embed=True),
    dst: str = Body(..., embed=True),
    user: str = Depends(get_current_user),
):
    src_p = norm_path(src, is_folder=None)
    node = get_node(user, src_p if src_p.endswith("/") else src_p)

    is_folder = (node["type"] == "folder")
    dst_p = norm_path(dst, is_folder=is_folder)

    if is_folder and dst_p == "/":
        raise HTTPException(400, "invalid destination")

    # ensure destination parent exists
    dst_parent, dst_name = split_parent_name(dst_p)
    ensure_folder_exists(user, dst_parent)

    # disallow overwriting
    r = tbl.get_item(Key=node_key(user, dst_p), ConsistentRead=True)
    if "Item" in r:
        raise HTTPException(409, "destination exists")

    # For folders: move all descendants by rewriting paths
    if is_folder:
        if is_ancestor_path(src_p, dst_p):
            raise HTTPException(400, "cannot move folder into itself")

        descendants = list_children(user, src_p)  # includes folder itself and below
        # rewrite each path
        for it in descendants:
            old_path = it["path"]
            if not old_path.startswith(src_p):
                continue
            new_path = dst_p + old_path[len(src_p):]
            # compute new parent/name
            new_parent, new_name = split_parent_name(new_path if it["type"] == "file" else norm_path(new_path, is_folder=True))

            # delete old
            delete_node(user, old_path)

            it["path"] = new_path
            it["parent"] = new_parent
            it["name"] = new_name
            it["name_lc"] = new_name.lower()
            it["updated_at"] = now_iso()
            it["SK"] = sk_node(new_path)
            it["GSI1SK"] = f"NAME#{it['name_lc']}#PATH#{new_path}"
            put_node(it)

            # update shares for each moved path
            _move_shares(owner=user, old_path=old_path, new_path=new_path)

        return {"ok": True, "type": "folder", "src": src_p, "dst": dst_p, "count": len(descendants)}

    # File move
    old_path = src_p
    new_path = dst_p
    delete_node(user, old_path)

    node["path"] = new_path
    node["parent"] = dst_parent
    node["name"] = dst_name
    node["name_lc"] = dst_name.lower()
    node["updated_at"] = now_iso()
    node["SK"] = sk_node(new_path)
    node["GSI1SK"] = f"NAME#{node['name_lc']}#PATH#{new_path}"
    put_node(node)

    _move_shares(owner=user, old_path=old_path, new_path=new_path)

    return {"ok": True, "type": "file", "src": old_path, "dst": new_path}

@app.post("/v1/fs/rename-file")
def rename_file(
    path: str = Body(..., embed=True),
    new_name: str = Body(..., embed=True),
    user: str = Depends(get_current_user),
):
    p = norm_path(path, is_folder=False)
    parent, _ = split_parent_name(p)
    dst = parent + new_name
    return move_node(src=p, dst=dst, user=user)  # reuse move

@app.post("/v1/fs/rename-folder")
def rename_folder(
    path: str = Body(..., embed=True),
    new_name: str = Body(..., embed=True),
    user: str = Depends(get_current_user),
):
    folder = norm_path(path, is_folder=True)
    parent, _ = split_parent_name(folder)
    dst = parent + new_name + "/"
    return move_node(src=folder, dst=dst, user=user)

# -----------------------------
# Zip: download multiple, upload zip
# -----------------------------
@app.post("/v1/fs/download-zip")
def download_multiple_as_zip(
    paths: List[str] = Body(...),
    user: str = Depends(get_current_user),
):
    # Validate and collect file nodes
    nodes = []
    for p in paths:
        pp = norm_path(p, is_folder=False)
        it = get_node(user, pp)
        if it["type"] != "file":
            raise HTTPException(400, f"not a file: {p}")
        nodes.append(it)

    def zip_stream():
        # Streaming zip is tricky; simplest is spooling to memory/disk.
        # Here we spool to an in-memory BytesIO. For huge zips, spool to tempfile.
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for it in nodes:
                obj = s3.get_object(Bucket=it["s3_bucket"], Key=it["s3_key"])
                data = obj["Body"].read()
                zf.writestr(it["name"], data)
        buf.seek(0)
        yield from iter(lambda: buf.read(1024 * 1024), b"")

    return StreamingResponse(
        zip_stream(),
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="download.zip"'},
    )

@app.post("/v1/fs/upload-zip")
def upload_zip_and_extract(
    dest_folder: str = Query("/", description="Folder to extract into"),
    zip_file: UploadFile = File(...),
    user: str = Depends(get_current_user),
):
    folder = norm_path(dest_folder, is_folder=True)
    ensure_folder_exists(user, folder)

    data = zip_file.file.read()
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise HTTPException(400, "invalid zip")

    created = []
    for info in z.infolist():
        # Skip directories; create folders explicitly
        name = info.filename
        if name.endswith("/"):
            # create folder
            fpath = norm_path(folder + name, is_folder=True)
            # best-effort create (ignore exists)
            try:
                parent, _ = split_parent_name(fpath)
                ensure_folder_exists(user, parent)
                r = tbl.get_item(Key=node_key(user, fpath), ConsistentRead=True)
                if "Item" not in r:
                    put_node({
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
                    })
            except HTTPException:
                pass
            continue

        # File
        file_bytes = z.read(info)
        out_path = norm_path(folder + name, is_folder=False)
        out_parent, _ = split_parent_name(out_path)

        # ensure parent folders exist? (optional: auto-create)
        # Here we auto-create missing intermediate folders.
        _auto_create_parents(user, out_parent)

        # upload bytes as new object
        obj_id = str(uuid.uuid4())
        s3_key = f"{user}/objects/{obj_id}"
        s3.put_object(Bucket=BUCKET, Key=s3_key, Body=file_bytes, ContentType="application/octet-stream")

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
            "size": len(file_bytes),
            "content_type": "application/octet-stream",
            "s3_bucket": BUCKET,
            "s3_key": s3_key,
            "GSI1PK": pk_user(user),
            "GSI1SK": f"NAME#{split_parent_name(out_path)[1].lower()}#PATH#{out_path}",
        }
        put_node(item)
        created.append(out_path)

    return {"ok": True, "created": created, "count": len(created)}

def _auto_create_parents(user: str, folder_path: str) -> None:
    folder_path = norm_path(folder_path, is_folder=True)
    if folder_path == "/":
        return
    # create each segment if missing
    cur = "/"
    for seg in [s for s in folder_path.split("/") if s]:
        cur = norm_path(cur + seg + "/", is_folder=True)
        r = tbl.get_item(Key=node_key(user, cur), ConsistentRead=True)
        if "Item" not in r:
            parent, name = split_parent_name(cur)
            if parent != "/":
                # ensure its parent exists first
                pass
            put_node({
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
            })

# -----------------------------
# Sharing
# -----------------------------
@app.post("/v1/fs/share")
def share_node(
    path: str = Body(..., embed=True),
    to_user: str = Body(..., embed=True),
    user: str = Depends(get_current_user),
):
    p = norm_path(path, is_folder=None)
    node = get_node(user, p if p.endswith("/") else p)

    # Write "shared with" entry under owner
    share_sk = f"SHARE#{node['path']}#TO#{to_user}"
    tbl.put_item(Item={
        "PK": pk_user(user),
        "SK": share_sk,
        "path": node["path"],
        "to_user": to_user,
        "shared_at": now_iso(),
    })

    # Write "shared with me" entry under recipient
    tbl.put_item(Item={
        "PK": pk_user(to_user),
        "SK": f"SHARED#FROM#{user}#PATH#{node['path']}",
        "owner": user,
        "path": node["path"],
        "shared_at": now_iso(),
    })

    return {"ok": True}

@app.get("/v1/fs/shared-with")
def list_shared_with(
    path: str = Query(...),
    user: str = Depends(get_current_user),
):
    p = norm_path(path, is_folder=None)
    # Query owner partition for share entries with prefix
    prefix = f"SHARE#{p}#TO#"
    resp = tbl.query(
        KeyConditionExpression=Key("PK").eq(pk_user(user)) & Key("SK").begins_with(prefix)
    )
    tos = [it["to_user"] for it in resp.get("Items", [])]
    tos.sort(key=lambda x: x.lower())
    return {"path": p, "shared_with": tos}

@app.get("/v1/fs/shared-with-me")
def list_shared_with_me(
    user: str = Depends(get_current_user),
):
    resp = tbl.query(
        KeyConditionExpression=Key("PK").eq(pk_user(user)) & Key("SK").begins_with("SHARED#FROM#")
    )
    items = []
    for it in resp.get("Items", []):
        items.append({"owner": it["owner"], "path": it["path"], "shared_at": it.get("shared_at")})
    items.sort(key=lambda x: (x["owner"].lower(), x["path"]))
    return {"items": items}

def _delete_shares_for_path(owner: str, path: str) -> None:
    # Remove all SHARE#<path>#TO#* entries and corresponding recipient entries.
    prefix = f"SHARE#{path}#TO#"
    resp = tbl.query(KeyConditionExpression=Key("PK").eq(pk_user(owner)) & Key("SK").begins_with(prefix))
    for it in resp.get("Items", []):
        to_user = it["to_user"]
        tbl.delete_item(Key={"PK": pk_user(owner), "SK": it["SK"]})
        tbl.delete_item(Key={"PK": pk_user(to_user), "SK": f"SHARED#FROM#{owner}#PATH#{path}"})

def _move_shares(owner: str, old_path: str, new_path: str) -> None:
    # For every SHARE entry on old_path, rewrite it to new_path (and update recipient entry)
    prefix = f"SHARE#{old_path}#TO#"
    resp = tbl.query(KeyConditionExpression=Key("PK").eq(pk_user(owner)) & Key("SK").begins_with(prefix))
    for it in resp.get("Items", []):
        to_user = it["to_user"]

        # delete old
        tbl.delete_item(Key={"PK": pk_user(owner), "SK": it["SK"]})
        tbl.delete_item(Key={"PK": pk_user(to_user), "SK": f"SHARED#FROM#{owner}#PATH#{old_path}"})

        # create new
        new_sk = f"SHARE#{new_path}#TO#{to_user}"
        tbl.put_item(Item={
            "PK": pk_user(owner),
            "SK": new_sk,
            "path": new_path,
            "to_user": to_user,
            "shared_at": it.get("shared_at", now_iso()),
        })
        tbl.put_item(Item={
            "PK": pk_user(to_user),
            "SK": f"SHARED#FROM#{owner}#PATH#{new_path}",
            "owner": owner,
            "path": new_path,
            "shared_at": it.get("shared_at", now_iso()),
        })
