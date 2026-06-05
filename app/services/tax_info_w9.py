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
