"""W-9 / Tax-info collection service (GAP-0020 / FIN-008).

TINs (SSNs and EINs) are KMS-encrypted before storage. The raw TIN is NEVER
logged, returned in API responses, or stored in plaintext.

Storage (``tax_info`` table, single-table):
  - pk = USER#{user_sub}
  - sk = "TAX_INFO"

Dev/Prod parity (SECOPS-007): ``kms_encrypt`` / ``kms_decrypt`` route to the
mock KMS server in dev (``S.dev_mode``) and to real AWS KMS in prod via the same
code path; only the resolved KMS endpoint differs.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from app.core.crypto import kms_decrypt, kms_encrypt
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

_SK = "TAX_INFO"

# Fields safe to return in API responses. Crucially excludes ``tin_encrypted``.
_SAFE_FIELDS = (
    "legal_name",
    "tin_last4",
    "tin_type",
    "address_line1",
    "city",
    "state",
    "zip_code",
    "certified",
    "certified_at",
    "updated_at",
)


def _pk(user_sub: str) -> str:
    return f"USER#{user_sub}"


def _safe_view(item: Dict[str, Any]) -> Dict[str, Any]:
    """Return only display-safe fields — never ``tin_encrypted``."""
    return {k: item.get(k) for k in _SAFE_FIELDS}


def submit_tax_info(
    *,
    user_sub: str,
    legal_name: str,
    tin: str,
    tin_type: str,
    address_line1: str,
    city: str,
    state: str,
    zip_code: str,
    certified: bool,
) -> Dict[str, Any]:
    """Store the KMS-encrypted TIN and W-9 data for a user.

    Returns a safe dict with ``tin_last4`` only — never ``tin_encrypted`` nor the
    raw TIN. Raises ``ValueError("invalid_tin")`` when the TIN is not 9 digits.
    """
    tin_digits = tin.replace("-", "").replace(" ", "")
    if not tin_digits.isdigit() or len(tin_digits) != 9:
        raise ValueError("invalid_tin: TIN must be 9 digits (SSN or EIN).")

    tin_encrypted = kms_encrypt(tin_digits)  # ciphertext only — never plaintext

    ts = now_ts()
    item: Dict[str, Any] = {
        "pk": _pk(user_sub),
        "sk": _SK,
        "user_sub": user_sub,
        "legal_name": legal_name,
        "tin_encrypted": tin_encrypted,
        "tin_last4": tin_digits[-4:],
        "tin_type": tin_type,
        "address_line1": address_line1,
        "city": city,
        "state": state,
        "zip_code": zip_code,
        "certified": bool(certified),
        "certified_at": ts if certified else None,
        "updated_at": ts,
    }
    T.tax_info.put_item(Item=item)

    # NOTE: raw TIN is never logged — only tin_type and certified.
    logger.info(
        "tax_info_submitted",
        extra={"user_sub": user_sub, "tin_type": tin_type, "certified": bool(certified)},
    )
    return _safe_view(item)


def get_tax_info(user_sub: str) -> Optional[Dict[str, Any]]:
    """Retrieve stored tax info WITHOUT the TIN ciphertext.

    Use ``get_decrypted_tin`` (audited at the call site) for the raw TIN.
    """
    item = T.tax_info.get_item(Key={"pk": _pk(user_sub), "sk": _SK}).get("Item")
    if not item:
        return None
    return _safe_view(item)


def get_decrypted_tin(user_sub: str) -> Optional[str]:
    """Decrypt and return the raw TIN for PDF generation.

    Must only be called from PDF-generation paths, never from HTTP response
    handlers. The call site is responsible for emitting an audit event.
    """
    item = T.tax_info.get_item(Key={"pk": _pk(user_sub), "sk": _SK}).get("Item")
    if not item or not item.get("tin_encrypted"):
        return None
    return kms_decrypt(item["tin_encrypted"]).decode()


# ---------------------------------------------------------------------------
# Admin TIN reveal + audit trail (GAP-0194 / SEC-004)
# ---------------------------------------------------------------------------

def _audit_pk(target_user_sub: str) -> str:
    return f"TAX_AUDIT#{target_user_sub}"


def write_tax_audit(*, action: str, actor: str, target: str, ip: str) -> None:
    """Append a queryable TAX_AUDIT entry for a TIN-related operation.

    Stored in the same ``tax_info`` table (no schema change):
      - pk = TAX_AUDIT#{target}
      - sk = AUDIT#{ts}#{id}

    SEC-004 / GAP-0194 require a dedicated, queryable trail (not just a log line)
    recording who viewed whose TIN, from which IP, and when.
    """
    from app.services.billing_shared import ulidish

    ts = now_ts()
    T.tax_info.put_item(
        Item={
            "pk": _audit_pk(target),
            "sk": f"AUDIT#{ts}#{ulidish()}",
            "action": action,
            "actor": actor,
            "target": target,
            "ip": ip,
            "ts": ts,
        }
    )


def get_tax_info_admin(
    *,
    user_sub: str,
    actor_sub: str,
    ip_address: str,
) -> Dict[str, Any]:
    """Return the full decrypted TIN for admin compliance review.

    Every successful call writes a ``TAX_AUDIT`` record (``action="tin_viewed"``)
    with the actor, target, IP, and timestamp (SEC-004 / GAP-0194).

    Raises ``LookupError("no_tax_info: ...")`` when the target has no W-9 on file.
    """
    item = T.tax_info.get_item(Key={"pk": _pk(user_sub), "sk": _SK}).get("Item")
    if not item:
        raise LookupError("no_tax_info: No W-9 on file for this user.")

    tin_ct = item.get("tin_encrypted") or ""
    tin_full = kms_decrypt(tin_ct).decode() if tin_ct else ""

    write_tax_audit(
        action="tin_viewed",
        actor=actor_sub,
        target=user_sub,
        ip=ip_address,
    )
    # NOTE: the raw TIN is never logged — only the audit record (which omits it).
    logger.info(
        "tin_viewed",
        extra={"actor_sub": actor_sub, "target_user_sub": user_sub, "context": "admin_reveal"},
    )

    out = _safe_view(item)
    out["tin_full"] = tin_full  # only ever returned to ADMIN/ROOT callers
    return out


def list_tax_audit(*, target_user_sub: str, limit: int = 50) -> Dict[str, Any]:
    """List TAX_AUDIT entries for a user, most-recent first."""
    from boto3.dynamodb.conditions import Key as _Key

    resp = T.tax_info.query(
        KeyConditionExpression=_Key("pk").eq(_audit_pk(target_user_sub)),
        ScanIndexForward=False,
        Limit=limit,
    )
    items = resp.get("Items", [])
    return {"entries": items, "count": len(items)}
