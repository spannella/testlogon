"""KYC-023: Field-level encryption, masking, and audited decryption for PII.

This service implements envelope encryption for sensitive PII fields stored on
KYC cases:

    Master key (KMS)  --wraps-->  per-user Data Encryption Key (DEK)
                                       --encrypts-->  PII field values

The per-user DEK is generated via KMS ``GenerateDataKey`` and stored *wrapped*
(KMS-encrypted) in the ``kyc_cases`` table under ``pk=USER_DEK#{sub}``. The
plaintext DEK is NEVER persisted; it is unwrapped via KMS ``Decrypt`` on each
encrypt/decrypt operation and held only in memory for the duration of the call.

Every decrypt access is recorded in a PII access audit log
(``pk=PII_AUDIT#{case_id}``) for compliance review.

All numeric timestamps are integer Unix seconds (``now_ts``) — DynamoDB rejects
Python floats. Reserved-keyword attributes are avoided in this table partition.
"""
from __future__ import annotations

import base64
import os
import uuid
from dataclasses import asdict, dataclass
from typing import Any

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.aws import kms
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

ALGORITHM = "AES-256-GCM"

# ── PII field masking rules ─────────────────────────────────────────────
# Each rule maps a plaintext value -> masked string. Used by mask_fields,
# which never calls KMS (it relies on stored hint values, not decryption).

def _mask_last4(prefix: str, v: str) -> str:
    return prefix + v[-4:] if len(v) >= 4 else "****"


MASKING_RULES: dict[str, Any] = {
    "document_number": lambda v: _mask_last4("****", v),
    "date_of_birth": lambda v: v[:4] + "-**-**" if len(v) >= 4 else "****",
    "tax_id": lambda v: _mask_last4("***-**-", v),
    "bank_account_number": lambda v: _mask_last4("****", v),
    "bank_routing_number": lambda _v: "*********",
    "full_ssn": lambda v: _mask_last4("***-**-", v),
    "passport_mrz": lambda _v: "***...***",
    "eid_subject_id": lambda _v: "********",
}

_DEFAULT_MASK = lambda v: _mask_last4("****", v)  # noqa: E731


def _make_hint(field_name: str, plaintext: str) -> str:
    """Compute the unencrypted masked hint stored alongside ciphertext.

    The hint is derived from the plaintext at write time so masked views never
    need to call KMS. It contains only the masked representation (never the full
    value).
    """
    rule = MASKING_RULES.get(field_name, _DEFAULT_MASK)
    try:
        return str(rule(plaintext))
    except Exception:  # pragma: no cover - defensive
        return "****"


@dataclass
class EncryptedField:
    ciphertext_b64: str  # base64(nonce || ciphertext) under the DEK
    key_id: str          # KMS key id used to wrap the DEK
    algorithm: str       # "AES-256-GCM"
    encrypted_at: int    # Unix timestamp (int)
    field_name: str      # original field name (for audit + mask selection)


class KycEncryptionError(RuntimeError):
    """Raised on KMS/crypto failures during encrypt/decrypt."""


class KycKeysDestroyedError(RuntimeError):
    """Raised when attempting to decrypt PII whose DEK has been destroyed."""


def _dek_pk(user_sub: str) -> str:
    return f"USER_DEK#{user_sub}"


def _audit_pk(case_id: str) -> str:
    return f"PII_AUDIT#{case_id}"


def _audit_sk(ts: int, event_id: str) -> str:
    return f"{ts:013d}#{event_id}"


@dataclass
class KycEncryptionService:
    _table: Any = None

    def __post_init__(self) -> None:
        if self._table is None:
            self._table = T.kyc_cases

    # ── DEK management (envelope encryption) ────────────────────────────

    def _get_active_dek_record(self, user_sub: str) -> dict[str, Any] | None:
        resp = self._table.get_item(Key={"pk": _dek_pk(user_sub), "sk": "ACTIVE"})
        return resp.get("Item")

    def _unwrap_dek(self, wrapped_dek_b64: str) -> bytes:
        """Unwrap (KMS-decrypt) a wrapped DEK. Returns plaintext DEK bytes.

        The plaintext DEK is held only by the caller and never persisted.
        """
        try:
            ct = base64.b64decode(wrapped_dek_b64)
            r = kms.decrypt(CiphertextBlob=ct)
            return r["Plaintext"]
        except ClientError as exc:  # pragma: no cover - depends on KMS
            raise KycEncryptionError("kms_decrypt_failed") from exc

    def generate_user_dek(self, user_sub: str) -> dict[str, Any]:
        """Generate a per-user DEK wrapped by the KMS master key, store ACTIVE.

        Idempotent-ish: callers should check for an existing ACTIVE record first
        via ``_get_active_dek_record``. Returns the stored DEK record (minus the
        plaintext key, which is never stored).
        """
        if not S.kms_key_id:
            raise KycEncryptionError("kms_key_id_not_set")
        try:
            r = kms.generate_data_key(KeyId=S.kms_key_id, KeySpec="AES_256")
        except ClientError as exc:  # pragma: no cover
            raise KycEncryptionError("kms_generate_data_key_failed") from exc
        wrapped_dek_b64 = base64.b64encode(r["CiphertextBlob"]).decode("ascii")
        ts = now_ts()
        item = {
            "pk": _dek_pk(user_sub),
            "sk": "ACTIVE",
            "entity_type": "kyc_user_dek",
            "user_sub": user_sub,
            "wrapped_dek": wrapped_dek_b64,
            "key_id": S.kms_key_id,
            "algorithm": ALGORITHM,
            "created_at": ts,
            "version": 1,
        }
        self._table.put_item(Item=item)
        return item

    def _ensure_active_dek(self, user_sub: str) -> tuple[bytes, str, int]:
        """Return (plaintext_dek_bytes, key_id, version), creating one if absent."""
        rec = self._get_active_dek_record(user_sub)
        if not rec:
            rec = self.generate_user_dek(user_sub)
        plaintext_dek = self._unwrap_dek(str(rec["wrapped_dek"]))
        return plaintext_dek, str(rec.get("key_id") or S.kms_key_id), int(rec.get("version") or 1)

    # ── Field encryption / decryption ───────────────────────────────────

    @staticmethod
    def _encrypt_value(dek: bytes, plaintext: str) -> str:
        nonce = os.urandom(12)
        aesgcm = AESGCM(dek)
        ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return base64.b64encode(nonce + ct).decode("ascii")

    @staticmethod
    def _decrypt_value(dek: bytes, ciphertext_b64: str) -> str:
        raw = base64.b64decode(ciphertext_b64)
        nonce, ct = raw[:12], raw[12:]
        aesgcm = AESGCM(dek)
        return aesgcm.decrypt(nonce, ct, None).decode("utf-8")

    def encrypt_fields(
        self, *, data: dict[str, str], user_sub: str
    ) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
        """Encrypt multiple PII fields using the user's DEK.

        Returns ``(encrypted_pii, pii_hints)`` where ``encrypted_pii`` maps
        field_name -> EncryptedField dict (DDB-storable) and ``pii_hints`` maps
        field_name -> masked hint (unencrypted, for masked display).
        """
        clean = {k: v for k, v in (data or {}).items() if v is not None and str(v) != ""}
        if not clean:
            return {}, {}
        dek, key_id, _version = self._ensure_active_dek(user_sub)
        ts = now_ts()
        encrypted: dict[str, dict[str, Any]] = {}
        hints: dict[str, str] = {}
        for field_name, value in clean.items():
            value_str = str(value)
            ef = EncryptedField(
                ciphertext_b64=self._encrypt_value(dek, value_str),
                key_id=key_id,
                algorithm=ALGORITHM,
                encrypted_at=ts,
                field_name=field_name,
            )
            encrypted[field_name] = asdict(ef)
            hints[field_name] = _make_hint(field_name, value_str)
        return encrypted, hints

    def decrypt_fields(
        self,
        *,
        encrypted_data: dict[str, dict[str, Any]],
        accessor_sub: str,
        access_reason: str,
        case_id: str,
        user_sub: str,
        fields: list[str] | None = None,
        ip_address: str = "",
        audit: bool = True,
    ) -> dict[str, str]:
        """Decrypt PII fields and (by default) write an audit log entry.

        ``fields`` optionally restricts which fields are decrypted; if None all
        encrypted fields are decrypted. Raises KycKeysDestroyedError if the
        user's DEK no longer exists.
        """
        if not encrypted_data:
            return {}
        rec = self._get_active_dek_record(user_sub)
        if not rec:
            raise KycKeysDestroyedError("pii_keys_destroyed")
        dek = self._unwrap_dek(str(rec["wrapped_dek"]))

        target = list(fields) if fields else list(encrypted_data.keys())
        out: dict[str, str] = {}
        for field_name in target:
            ef = encrypted_data.get(field_name)
            if not ef:
                continue
            try:
                out[field_name] = self._decrypt_value(dek, str(ef["ciphertext_b64"]))
            except Exception as exc:  # pragma: no cover - corrupt ciphertext
                raise KycEncryptionError("pii_decrypt_error") from exc

        if audit and out and S.kyc_encryption_audit_enabled:
            self.log_access(
                accessor_sub=accessor_sub,
                case_id=case_id,
                fields_accessed=list(out.keys()),
                reason=access_reason,
                action="decrypt",
                ip_address=ip_address,
            )
        return out

    def mask_fields(
        self,
        *,
        encrypted_data: dict[str, dict[str, Any]],
        hints: dict[str, str] | None = None,
    ) -> dict[str, str]:
        """Return masked representations without decrypting (no KMS call).

        Prefers the stored unencrypted ``hints`` (computed at write time). If a
        hint is missing for a field, falls back to a fully-masked placeholder
        based on the field name's masking rule.
        """
        hints = hints or {}
        masked: dict[str, str] = {}
        for field_name in encrypted_data.keys():
            if field_name in hints:
                masked[field_name] = str(hints[field_name])
            else:
                rule = MASKING_RULES.get(field_name, _DEFAULT_MASK)
                # No plaintext available — produce a generic mask.
                try:
                    masked[field_name] = str(rule(""))
                except Exception:  # pragma: no cover
                    masked[field_name] = "****"
        return masked

    # ── Key rotation ────────────────────────────────────────────────────

    def rotate_user_dek(self, user_sub: str) -> dict[str, Any]:
        """Generate a new DEK and re-encrypt all of the user's case PII with it.

        The old DEK is archived under ``sk=ROTATED#{version}`` with a 30-day TTL
        for rollback. Returns ``{new_version, fields_re_encrypted}``.
        """
        if not S.kms_key_id:
            raise KycEncryptionError("kms_key_id_not_set")
        old_rec = self._get_active_dek_record(user_sub)
        old_version = int(old_rec.get("version") or 1) if old_rec else 0

        # New DEK material
        try:
            r = kms.generate_data_key(KeyId=S.kms_key_id, KeySpec="AES_256")
        except ClientError as exc:  # pragma: no cover
            raise KycEncryptionError("kms_generate_data_key_failed") from exc
        new_dek = r["Plaintext"]
        new_wrapped_b64 = base64.b64encode(r["CiphertextBlob"]).decode("ascii")
        new_version = old_version + 1
        ts = now_ts()

        # Archive the old DEK (if any) with a 30-day TTL.
        if old_rec:
            old_dek = self._unwrap_dek(str(old_rec["wrapped_dek"]))
            self._table.put_item(
                Item={
                    "pk": _dek_pk(user_sub),
                    "sk": f"ROTATED#{old_version:06d}",
                    "entity_type": "kyc_user_dek_rotated",
                    "user_sub": user_sub,
                    "wrapped_dek": str(old_rec["wrapped_dek"]),
                    "key_id": str(old_rec.get("key_id") or S.kms_key_id),
                    "rotated_at": ts,
                    "version": old_version,
                    "ttl_epoch": ts + 30 * 86400,
                }
            )
        else:
            old_dek = None

        # Re-encrypt all of this user's case PII.
        fields_re_encrypted = 0
        for case in self._iter_user_cases(user_sub):
            encrypted_pii = case.get("encrypted_pii") or {}
            if not encrypted_pii or old_dek is None:
                continue
            new_encrypted: dict[str, dict[str, Any]] = {}
            for field_name, ef in encrypted_pii.items():
                try:
                    plaintext = self._decrypt_value(old_dek, str(ef["ciphertext_b64"]))
                except Exception:  # pragma: no cover - skip corrupt
                    continue
                new_encrypted[field_name] = asdict(
                    EncryptedField(
                        ciphertext_b64=self._encrypt_value(new_dek, plaintext),
                        key_id=S.kms_key_id,
                        algorithm=ALGORITHM,
                        encrypted_at=ts,
                        field_name=field_name,
                    )
                )
                fields_re_encrypted += 1
            if new_encrypted:
                self._table.update_item(
                    Key={"pk": case["pk"], "sk": case["sk"]},
                    UpdateExpression="SET encrypted_pii=:e",
                    ExpressionAttributeValues={":e": new_encrypted},
                )

        # Install the new ACTIVE DEK.
        self._table.put_item(
            Item={
                "pk": _dek_pk(user_sub),
                "sk": "ACTIVE",
                "entity_type": "kyc_user_dek",
                "user_sub": user_sub,
                "wrapped_dek": new_wrapped_b64,
                "key_id": S.kms_key_id,
                "algorithm": ALGORITHM,
                "created_at": ts,
                "version": new_version,
            }
        )
        return {"new_version": new_version, "fields_re_encrypted": fields_re_encrypted}

    # ── GDPR erasure: destroy keys ──────────────────────────────────────

    def destroy_user_keys(self, user_sub: str) -> dict[str, Any]:
        """Permanently delete all DEKs for a user (GDPR right-to-be-forgotten).

        After this, all ``encrypted_pii`` ciphertext on the user's cases becomes
        permanently unrecoverable. Idempotent: a second call returns 0 keys.
        Returns ``{keys_destroyed, fields_affected}``.
        """
        keys_destroyed = 0
        last_key: dict[str, Any] | None = None
        dek_records: list[dict[str, Any]] = []
        while True:
            kw: dict[str, Any] = {"KeyConditionExpression": Key("pk").eq(_dek_pk(user_sub))}
            if last_key:
                kw["ExclusiveStartKey"] = last_key
            resp = self._table.query(**kw)
            dek_records.extend(resp.get("Items") or [])
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
        for rec in dek_records:
            self._table.delete_item(Key={"pk": rec["pk"], "sk": rec["sk"]})
            keys_destroyed += 1

        # Count affected case fields for the report (ciphertext remains but is
        # now permanently unrecoverable — the DEK is gone).
        fields_affected = 0
        for case in self._iter_user_cases(user_sub):
            encrypted_pii = case.get("encrypted_pii") or {}
            if encrypted_pii:
                fields_affected += len(encrypted_pii)
        return {"keys_destroyed": keys_destroyed, "fields_affected": fields_affected}

    # ── Audit log ───────────────────────────────────────────────────────

    def log_access(
        self,
        *,
        accessor_sub: str,
        case_id: str,
        fields_accessed: list[str],
        reason: str,
        action: str,
        ip_address: str = "",
    ) -> dict[str, Any]:
        """Write a single PII-access audit entry. Never raises on best-effort."""
        ts = now_ts()
        event_id = f"evt_{uuid.uuid4().hex[:16]}"
        item = {
            "pk": _audit_pk(case_id),
            "sk": _audit_sk(ts, event_id),
            "entity_type": "kyc_pii_audit",
            "event_id": event_id,
            "case_id": case_id,
            # GSI keys for accessor-scoped queries (declared in local-ddb-init).
            "gsi_pii_accessor_pk": accessor_sub or "unknown",
            "gsi_pii_accessor_sk": ts,
            "accessor_sub": accessor_sub,
            "action": action,
            "fields": list(fields_accessed),
            "reason": reason,
            "ip_address": ip_address or "",
            "created_at": ts,
        }
        try:
            self._table.put_item(Item=item)
        except Exception:  # pragma: no cover - audit must not break flow
            pass
        return item

    def get_access_log(
        self,
        *,
        case_id: str | None = None,
        accessor_sub: str | None = None,
        limit: int = 100,
        cursor: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Query the PII access audit log by case or by accessor.

        Returns ``{"events": [...], "next_key": LastEvaluatedKey|None}``,
        newest-first.
        """
        limit = max(1, min(int(limit or 100), 200))
        if accessor_sub:
            kw: dict[str, Any] = {
                "IndexName": S.kyc_pii_audit_accessor_index_name,
                "KeyConditionExpression": Key("gsi_pii_accessor_pk").eq(accessor_sub),
                "ScanIndexForward": False,
                "Limit": limit,
            }
        elif case_id:
            kw = {
                "KeyConditionExpression": Key("pk").eq(_audit_pk(case_id)),
                "ScanIndexForward": False,
                "Limit": limit,
            }
        else:
            return {"events": [], "next_key": None}
        if cursor:
            kw["ExclusiveStartKey"] = cursor
        resp = self._table.query(**kw)
        events = [self._audit_item_to_event(it) for it in (resp.get("Items") or [])]
        return {"events": events, "next_key": resp.get("LastEvaluatedKey")}

    @staticmethod
    def _audit_item_to_event(item: dict[str, Any]) -> dict[str, Any]:
        return {
            "event_id": str(item.get("event_id") or ""),
            "accessor_sub": str(item.get("accessor_sub") or ""),
            "accessor_display_name": str(item.get("accessor_display_name") or ""),
            "action": str(item.get("action") or ""),
            "fields": list(item.get("fields") or []),
            "reason": str(item.get("reason") or ""),
            "ip_address": str(item.get("ip_address") or ""),
            "created_at": int(item.get("created_at") or 0),
        }

    # ── Helpers ─────────────────────────────────────────────────────────

    def _iter_user_cases(self, user_sub: str):
        """Yield all KYC case META items owned by a user (via owner GSI)."""
        last_key: dict[str, Any] | None = None
        while True:
            kw: dict[str, Any] = {
                "IndexName": S.kyc_cases_owner_index_name,
                "KeyConditionExpression": Key("gsi_owner_pk").eq(f"OWNER#{user_sub}"),
            }
            if last_key:
                kw["ExclusiveStartKey"] = last_key
            resp = self._table.query(**kw)
            for it in resp.get("Items") or []:
                if it.get("sk") == "META":
                    yield it
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break


# Module-level singleton (mirrors STORE pattern in kyc_cases.py).
ENCRYPTION = KycEncryptionService()
