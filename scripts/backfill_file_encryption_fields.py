#!/usr/bin/env python3
from __future__ import annotations

from typing import Any, Dict, Optional

from boto3.dynamodb.conditions import Attr

from app.core.aws import ddb
from app.core.settings import S


def _flatten(meta: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(meta, dict):
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


def _needs_backfill(item: Dict[str, Any]) -> bool:
    if not item.get("is_encrypted"):
        return False
    if not isinstance(item.get("enc_metadata"), dict):
        return False
    return item.get("enc_version") is None


def main() -> None:
    if not S.filemgr_table_name:
        raise RuntimeError("FILEMGR_TABLE_NAME is not configured")

    table = ddb.Table(S.filemgr_table_name)
    last_key = None
    scanned = 0
    updated = 0

    while True:
        kwargs = {
            "FilterExpression": Attr("SK").begins_with("NODE#") & Attr("is_encrypted").eq(True),
        }
        if last_key is not None:
            kwargs["ExclusiveStartKey"] = last_key
        resp = table.scan(**kwargs)
        items = resp.get("Items", [])
        scanned += len(items)

        for item in items:
            if not _needs_backfill(item):
                continue
            flat = _flatten(item.get("enc_metadata"))
            table.update_item(
                Key={"PK": item["PK"], "SK": item["SK"]},
                UpdateExpression=(
                    "SET enc_version=:v, enc_alg=:a, enc_kdf=:k, "
                    "enc_kdf_iterations=:i, enc_salt_b64=:s, enc_iv_b64=:iv, "
                    "enc_orig_name=:n, enc_orig_size=:os, enc_orig_content_type=:ct"
                ),
                ExpressionAttributeValues={
                    ":v": flat.get("enc_version"),
                    ":a": flat.get("enc_alg"),
                    ":k": flat.get("enc_kdf"),
                    ":i": flat.get("enc_kdf_iterations"),
                    ":s": flat.get("enc_salt_b64"),
                    ":iv": flat.get("enc_iv_b64"),
                    ":n": flat.get("enc_orig_name"),
                    ":os": flat.get("enc_orig_size"),
                    ":ct": flat.get("enc_orig_content_type"),
                },
            )
            updated += 1

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    print(f"scanned={scanned} updated={updated}")


if __name__ == "__main__":
    main()
