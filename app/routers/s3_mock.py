"""FastAPI proxy routes for the moto in-process S3 mock.

These routes expose /mock/s3/{bucket}/{key} so that browsers and HTTP clients
can reach objects stored in moto's in-memory S3 store.  All data access goes
through boto3, which moto intercepts at the botocore HTTP layer.

boto3 client operations (put_object, get_object, …) called elsewhere in the
app bypass HTTP entirely — moto handles them in-process.  Only browser-facing
presigned download/upload URLs actually reach these routes.

Only active in DEV_MODE=1.
"""
from __future__ import annotations

from fastapi import APIRouter, Request, Response
from botocore.exceptions import ClientError

from app.core.aws_clients import s3_client

router = APIRouter(tags=["s3_mock"])

# Module-level client.  moto patches botocore's HTTP layer globally, so even
# though this client is created before mock_aws().start() runs, all subsequent
# calls through it are intercepted by moto once the startup handler fires.
_s3 = s3_client()


# ── Service root: list buckets ────────────────────────────────────────────────

async def list_buckets() -> Response:  # also registered at GET /mock/s3 in main.py
    resp = _s3.list_buckets()
    bucket_xml = "".join(
        f"<Bucket>"
        f"<Name>{b['Name']}</Name>"
        f"<CreationDate>{b['CreationDate'].strftime('%Y-%m-%dT%H:%M:%S.000Z')}</CreationDate>"
        f"</Bucket>"
        for b in resp.get("Buckets", [])
    )
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        "<Owner><ID>mock</ID><DisplayName>mock</DisplayName></Owner>"
        f"<Buckets>{bucket_xml}</Buckets>"
        "</ListAllMyBucketsResult>"
    )
    return Response(content=body, media_type="application/xml")


@router.get("/")
async def list_buckets_slash() -> Response:
    return await list_buckets()


# ── Bucket-level operations ───────────────────────────────────────────────────

@router.put("/{bucket}")
async def create_bucket(bucket: str) -> Response:
    try:
        _s3.create_bucket(Bucket=bucket)
    except ClientError:
        pass
    return Response(status_code=200, headers={"Location": f"/{bucket}"})


@router.get("/{bucket}")
async def list_objects(bucket: str) -> Response:
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        f"<Name>{bucket}</Name><Prefix></Prefix>"
        "<MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>"
        "</ListBucketResult>"
    )
    return Response(content=body, media_type="application/xml")


# ── Object-level operations ───────────────────────────────────────────────────

@router.put("/{bucket}/{key:path}")
async def put_object(bucket: str, key: str, request: Request) -> Response:
    # Tagging sub-resource: just acknowledge.
    if "tagging" in (request.url.query or ""):
        return Response(status_code=200)

    body = await request.body()
    ct = request.headers.get("content-type", "application/octet-stream")
    resp = _s3.put_object(Bucket=bucket, Key=key, Body=body, ContentType=ct)
    etag = resp.get("ETag", "")
    return Response(status_code=200, headers={"ETag": etag} if etag else {})


@router.get("/{bucket}/{key:path}")
async def get_object(bucket: str, key: str) -> Response:
    try:
        obj = _s3.get_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("NoSuchKey", "404", "NoSuchBucket"):
            return Response(status_code=404)
        raise
    body = obj["Body"].read()
    ct = obj.get("ContentType", "application/octet-stream")
    return Response(content=body, media_type=ct)


@router.head("/{bucket}/{key:path}")
async def head_object(bucket: str, key: str) -> Response:
    try:
        meta = _s3.head_object(Bucket=bucket, Key=key)
    except ClientError:
        return Response(status_code=404)
    return Response(
        status_code=200,
        headers={
            "Content-Length": str(meta.get("ContentLength", 0)),
            "Content-Type": meta.get("ContentType", "application/octet-stream"),
            "ETag": meta.get("ETag", ""),
        },
    )


@router.delete("/{bucket}/{key:path}")
async def delete_object(bucket: str, key: str) -> Response:
    try:
        _s3.delete_object(Bucket=bucket, Key=key)
    except ClientError:
        pass
    return Response(status_code=204)
