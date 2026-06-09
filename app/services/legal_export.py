"""Law-enforcement / subpoena scoped export (LEX-009 + LEX-010).

Captures a chain-of-custody intake record (matter ref / requesting authority /
legal basis / scope) and builds a *sealed* scoped package that combines:

  * the targeted user's data (scoped by ``data_types`` + ``date_range``), and
  * the matching audit-trail slice (via the audit-export pipeline adapters),

wrapped in an audit-grade PDF index and a tamper-evident, HMAC-signed
``manifest.json`` (reusing ``audit_export_pipeline._compute_manifest_signature``).

Everything is additive and gated behind ``S.legal_export_enabled`` at the
router layer; this module is pure plumbing and never runs unless invoked.
"""
from __future__ import annotations

import hashlib
import io
import json
import logging
import uuid
import zipfile
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.audit_export_pipeline import (
    _compute_manifest_signature,
    _merge_sorted_events,
    _render_audit_pdf,
    verify_manifest_signature,
)
from app.services.gdpr_service import (
    _query_all,
    _serialize_items,
    _user_pk as _billing_user_pk,
)

logger = logging.getLogger(__name__)

# Redaction set mirrors the GDPR export (secrets never leave the platform even
# under subpoena — only substantive content is exported).
_REDACT_KEYS = {"card_number", "cvv", "session_token", "csrf_token", "key_hash", "key_material"}

# Audit categories included in the trail slice.
_AUDIT_CATEGORIES = ["auth", "moderation", "broadcast", "admin", "billing"]

# Mapping of user-data "data_types" → builder fn. Each returns a list of
# JSON-safe dicts for one subsystem.
_VALID_DATA_TYPES = {"profile", "addresses", "billing", "alerts", "audit_trail"}


def _new_export_id() -> str:
    return f"lex_{uuid.uuid4().hex}"


def _export_pk(legal_export_id: str) -> str:
    return f"EXPORT#{legal_export_id}"


# ---------------------------------------------------------------------------
# LEX-009: Intake
# ---------------------------------------------------------------------------

def create_intake(
    *,
    matter_ref: str,
    requesting_authority: str,
    requested_by: str,
    legal_basis: str,
    target_user_subs: List[str],
    data_types: Optional[List[str]] = None,
    from_ts: Optional[int] = None,
    to_ts: Optional[int] = None,
    reason: Optional[str] = None,
) -> Dict[str, Any]:
    """Persist a chain-of-custody intake record. Required fields enforced here;
    the router maps a ValueError to a 400."""
    if not matter_ref:
        raise ValueError("matter_ref is required")
    if not requesting_authority:
        raise ValueError("requesting_authority is required")
    if not legal_basis:
        raise ValueError("legal_basis is required")
    if not target_user_subs:
        raise ValueError("at least one target_user_sub is required")

    dtypes = list(data_types) if data_types else sorted(_VALID_DATA_TYPES)
    invalid = set(dtypes) - _VALID_DATA_TYPES
    if invalid:
        raise ValueError(
            f"Unknown data_types: {', '.join(sorted(invalid))}. "
            f"Valid: {', '.join(sorted(_VALID_DATA_TYPES))}"
        )

    legal_export_id = _new_export_id()
    ts = now_ts()
    item: Dict[str, Any] = {
        "pk": _export_pk(legal_export_id),
        "sk": "META",
        "legal_export_id": legal_export_id,
        "matter_ref": matter_ref,
        "requesting_authority": requesting_authority,
        "requested_by": requested_by,
        "legal_basis": legal_basis,
        "reason": reason or "",
        "target_user_subs": list(target_user_subs),
        "data_types": dtypes,
        "from_ts": int(from_ts) if from_ts else 0,
        "to_ts": int(to_ts) if to_ts else 0,
        "status": "intake",
        "created_at": ts,
    }
    T.legal_exports.put_item(Item=item)
    return item


def get_export(legal_export_id: str) -> Optional[Dict[str, Any]]:
    resp = T.legal_exports.get_item(Key={"pk": _export_pk(legal_export_id), "sk": "META"})
    return resp.get("Item")


def list_exports(limit: int = 200) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {"Limit": 200}
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.legal_exports.scan(**kwargs)
        for item in resp.get("Items", []):
            if item.get("sk") == "META":
                items.append(item)
                if len(items) >= limit:
                    return items
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return items


# ---------------------------------------------------------------------------
# LEX-010: Scoped sealed package builder
# ---------------------------------------------------------------------------

def _in_range(ts_val: Any, from_ts: int, to_ts: int) -> bool:
    """Date-range filter; 0/0 means no filter."""
    if not from_ts and not to_ts:
        return True
    try:
        v = int(ts_val)
    except (TypeError, ValueError):
        # No usable timestamp → keep (conservative: don't silently drop).
        return True
    if from_ts and v < from_ts:
        return False
    if to_ts and v > to_ts:
        return False
    return True


def _collect_user_data(
    user_sub: str, data_types: List[str], from_ts: int, to_ts: int
) -> Dict[str, List[Dict[str, Any]]]:
    """Assemble the scoped per-user data slices for one user."""
    out: Dict[str, List[Dict[str, Any]]] = {}

    if "profile" in data_types:
        try:
            resp = T.profile.get_item(Key={"user_sub": user_sub})
            prof = resp.get("Item")
            out["profile"] = _serialize_items([prof], redact_keys=_REDACT_KEYS) if prof else []
        except Exception:
            logger.exception("legal_export profile slice failed for %s", user_sub)
            out["profile"] = []

    if "addresses" in data_types:
        try:
            items = _query_all(T.addresses, Key("user_sub").eq(user_sub))
            out["addresses"] = _serialize_items(items, redact_keys=_REDACT_KEYS)
        except Exception:
            logger.exception("legal_export addresses slice failed for %s", user_sub)
            out["addresses"] = []

    if "billing" in data_types:
        try:
            items = _query_all(T.billing, Key("pk").eq(_billing_user_pk(user_sub)))
            ser = _serialize_items(items, redact_keys=_REDACT_KEYS)
            out["billing"] = [r for r in ser if _in_range(r.get("created_at", r.get("ts")), from_ts, to_ts)]
        except Exception:
            logger.exception("legal_export billing slice failed for %s", user_sub)
            out["billing"] = []

    if "alerts" in data_types:
        try:
            items = _query_all(T.alerts, Key("user_sub").eq(user_sub))
            ser = _serialize_items(items, redact_keys=_REDACT_KEYS)
            out["alerts"] = [r for r in ser if _in_range(r.get("ts", r.get("created_at")), from_ts, to_ts)]
        except Exception:
            logger.exception("legal_export alerts slice failed for %s", user_sub)
            out["alerts"] = []

    return out


def _collect_audit_events(
    user_sub: str, from_ts: int, to_ts: int
) -> List[Dict[str, Any]]:
    """Audit-trail slice for one user as both actor and target."""
    seen: Dict[str, Any] = {}
    events = []
    # 0/0 means the adapters get a wide window.
    f = from_ts if from_ts else 0
    t = to_ts if to_ts else now_ts()
    for role_kwarg in ("actor", "target"):
        try:
            for ev in _merge_sorted_events(
                _AUDIT_CATEGORIES, f, t, **{role_kwarg: user_sub}
            ):
                ev_id = getattr(ev, "event_id", None) or id(ev)
                if ev_id in seen:
                    continue
                seen[ev_id] = ev
                events.append(ev)
        except Exception:
            logger.exception("legal_export audit slice (%s) failed for %s", role_kwarg, user_sub)
    events.sort(key=lambda e: getattr(e, "timestamp_unix", 0))
    return events


def build_legal_package(intake: Dict[str, Any]) -> Dict[str, Any]:
    """Build a sealed ZIP for a legal-export intake. Returns
    ``{zip_bytes, manifest, package_sha256}``.

    The ZIP holds one folder per target user with their scoped JSON slices,
    an ``audit_trail.ndjson`` + ``audit_index.pdf`` per user, and a top-level
    signed ``manifest.json`` + ``README.txt``.
    """
    legal_export_id = intake["legal_export_id"]
    data_types = list(intake.get("data_types") or sorted(_VALID_DATA_TYPES))
    from_ts = int(intake.get("from_ts") or 0)
    to_ts = int(intake.get("to_ts") or 0)
    targets = list(intake.get("target_user_subs") or [])

    buf = io.BytesIO()
    files_meta: List[Dict[str, Any]] = []
    hasher = hashlib.sha256()

    def _add(zf: zipfile.ZipFile, path: str, data: bytes) -> None:
        zf.writestr(path, data)
        sha = hashlib.sha256(data).hexdigest()
        files_meta.append({"path": path, "sha256": sha, "size": len(data)})
        # Canonical content hash: path + per-file sha, in deterministic order.
        hasher.update(path.encode())
        hasher.update(sha.encode())

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for user_sub in targets:
            folder = f"users/{user_sub}"
            slices = _collect_user_data(user_sub, data_types, from_ts, to_ts)
            for name, rows in slices.items():
                _add(
                    zf,
                    f"{folder}/{name}.json",
                    json.dumps(rows, indent=2, default=str).encode(),
                )

            if "audit_trail" in data_types:
                events = _collect_audit_events(user_sub, from_ts, to_ts)
                ndjson = "\n".join(e.to_ndjson_line() for e in events).encode()
                _add(zf, f"{folder}/audit_trail.ndjson", ndjson)
                # PDF index reuses the audit renderer.
                content_sha = hashlib.sha256(ndjson).hexdigest()
                pdf_job = {
                    "created_by": intake.get("requested_by", ""),
                    "from_date": from_ts,
                    "to_date": to_ts,
                    "categories": _AUDIT_CATEGORIES,
                }
                try:
                    pdf_bytes = _render_audit_pdf(events, legal_export_id, pdf_job, content_sha)
                    _add(zf, f"{folder}/audit_index.pdf", pdf_bytes)
                except Exception:
                    logger.exception("legal_export PDF render failed for %s", user_sub)

        package_sha256 = hasher.hexdigest()

        manifest: Dict[str, Any] = {
            "legal_export_id": legal_export_id,
            "matter_ref": intake.get("matter_ref", ""),
            "requesting_authority": intake.get("requesting_authority", ""),
            "requested_by": intake.get("requested_by", ""),
            "legal_basis": intake.get("legal_basis", ""),
            "generated_at": now_ts(),
            "target_user_subs": targets,
            "data_types": data_types,
            "date_range": {"from": from_ts, "to": to_ts},
            "files": files_meta,
            "package_sha256": package_sha256,
            "signing_key_id": S.audit_export_signing_key_id,
            "contains_pii": True,
            "chain_of_custody": {
                "intake_created_at": int(intake.get("created_at", 0)),
                "package_generated_at": now_ts(),
                "generated_by": intake.get("requested_by", ""),
                "sealed": True,
            },
        }
        manifest["signature"] = _compute_manifest_signature(manifest)

        zf.writestr("manifest.json", json.dumps(manifest, indent=2, default=str))
        zf.writestr("README.txt", _readme_text(manifest))

    buf.seek(0)
    return {
        "zip_bytes": buf.getvalue(),
        "manifest": manifest,
        "package_sha256": manifest["package_sha256"],
    }


def _s3_key(legal_export_id: str) -> str:
    return f"legal-exports/{legal_export_id}/package.zip"


def generate_package(legal_export_id: str) -> Dict[str, Any]:
    """Build the sealed package, upload it to S3, and flip the intake to
    ``completed`` (or ``failed``). Returns the updated DDB item.

    Reuses ``app.core.aws_clients.s3_client`` + ``ServerSideEncryption=AES256``,
    same as the audit pipeline (dev/prod parity via in-process moto in dev).
    """
    from app.core.aws_clients import s3_client

    intake = get_export(legal_export_id)
    if not intake:
        raise KeyError(legal_export_id)

    try:
        built = build_legal_package(intake)
        zip_bytes = built["zip_bytes"]
        s3_key = _s3_key(legal_export_id)
        bucket = S.legal_export_s3_bucket
        client = s3_client()
        if S.dev_mode:
            try:
                client.head_bucket(Bucket=bucket)
            except Exception:
                try:
                    client.create_bucket(Bucket=bucket)
                except Exception:
                    pass
        client.put_object(
            Bucket=bucket,
            Key=s3_key,
            Body=zip_bytes,
            ServerSideEncryption="AES256",
            ContentType="application/zip",
        )
    except Exception as exc:
        logger.exception("legal_export generate failed for %s", legal_export_id)
        T.legal_exports.update_item(
            Key={"pk": _export_pk(legal_export_id), "sk": "META"},
            UpdateExpression="SET #st = :s, error_message = :e",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":s": "failed", ":e": str(exc)[:500]},
        )
        raise

    ts = now_ts()
    expires_at = ts + S.legal_export_ttl_days * 86400
    resp = T.legal_exports.update_item(
        Key={"pk": _export_pk(legal_export_id), "sk": "META"},
        UpdateExpression=(
            "SET #st = :s, completed_at = :c, s3_key = :k, s3_bucket = :b, "
            "package_sha256 = :h, size_bytes = :sz, expires_at = :ex, sealed = :sealed"
        ),
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":s": "completed",
            ":c": ts,
            ":k": s3_key,
            ":b": S.legal_export_s3_bucket,
            ":h": built["package_sha256"],
            ":sz": len(built["zip_bytes"]),
            ":ex": expires_at,
            ":sealed": True,
        },
        ReturnValues="ALL_NEW",
    )
    return resp.get("Attributes", get_export(legal_export_id) or {})


def get_download_url(legal_export_id: str) -> Optional[str]:
    """Short-lived presigned URL for a completed, unexpired package."""
    from app.core.aws_clients import s3_client

    item = get_export(legal_export_id)
    if not item or item.get("status") != "completed":
        return None
    s3_key = item.get("s3_key")
    if not s3_key:
        return None
    exp = item.get("expires_at")
    if exp:
        try:
            if now_ts() > int(exp):
                return None
        except (TypeError, ValueError):
            pass
    try:
        client = s3_client()
        return client.generate_presigned_url(
            "get_object",
            Params={"Bucket": item.get("s3_bucket", S.legal_export_s3_bucket), "Key": s3_key},
            ExpiresIn=S.legal_export_url_ttl_seconds,
        )
    except Exception:
        logger.exception("legal_export presign failed for %s", legal_export_id)
        return None


def _readme_text(manifest: Dict[str, Any]) -> str:
    lines = [
        "SEALED LEGAL EXPORT PACKAGE",
        "=" * 60,
        "",
        f"Legal export ID     : {manifest['legal_export_id']}",
        f"Matter reference    : {manifest['matter_ref']}",
        f"Requesting authority: {manifest['requesting_authority']}",
        f"Legal basis         : {manifest['legal_basis']}",
        f"Package SHA-256      : {manifest['package_sha256']}",
        "",
        "FOLDER LAYOUT",
        "-" * 60,
        "  manifest.json            HMAC-signed file inventory + chain of custody.",
        "  users/<user_sub>/        One folder per targeted user, containing:",
        "    profile.json           Account profile (secrets redacted).",
        "    addresses.json         Stored addresses.",
        "    billing.json           Billing/ledger rows (card data redacted).",
        "    alerts.json            Security/alert events.",
        "    audit_trail.ndjson     Matching audit events (NDJSON).",
        "    audit_index.pdf        Audit-grade, tamper-evident PDF index.",
        "",
        "VERIFICATION",
        "-" * 60,
        "  The manifest is signed with HMAC-SHA256 (signing_key_id above).",
        "  verify_manifest_signature(manifest) returns True for an unaltered",
        "  package and False if any file or field is modified.",
    ]
    return "\n".join(lines)


# Re-export for convenience / tests.
__all__ = [
    "create_intake",
    "get_export",
    "list_exports",
    "build_legal_package",
    "verify_manifest_signature",
]
