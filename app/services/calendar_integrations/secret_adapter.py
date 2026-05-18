from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from app.core.settings import S
from app.services.calendar_integrations.logging_safety import redacted_log_payload

logger = logging.getLogger(__name__)


class CalendarSecretAdapter:
    def put_secret(
        self,
        *,
        provider: str,
        secret_payload: dict[str, Any],
        credential_ref: str | None = None,
        tags: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        raise NotImplementedError

    def get_secret(self, *, credential_ref: str) -> dict[str, Any] | None:
        raise NotImplementedError

    def delete_secret(self, *, credential_ref: str) -> bool:
        raise NotImplementedError


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _encrypt(value: str) -> str:
    from app.core.crypto import kms_encrypt

    return kms_encrypt(value)


def _decrypt(value: str) -> bytes:
    from app.core.crypto import kms_decrypt

    return kms_decrypt(value)


def _secrets_table():
    from app.core.aws import ddb

    return ddb.Table(S.calendar_connection_secrets_table_name)


class DynamoCalendarSecretAdapter(CalendarSecretAdapter):
    def put_secret(
        self,
        *,
        provider: str,
        secret_payload: dict[str, Any],
        credential_ref: str | None = None,
        tags: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        ref = (credential_ref or "").strip() or f"cred_{uuid.uuid4().hex}"
        now = _now_iso()
        table = _secrets_table()

        existing = table.get_item(Key={"credential_ref": ref}).get("Item")
        created_at = now if not existing else str(existing.get("created_at") or now)
        version = int(existing.get("version", 0)) + 1 if existing else 1

        encrypted = _encrypt(json.dumps(secret_payload, separators=(",", ":")))
        item = {
            "credential_ref": ref,
            "provider": (provider or "apple_caldav").strip().lower(),
            "secret_ct_b64": encrypted,
            "tags": dict(tags or {}),
            "version": version,
            "created_at": created_at,
            "updated_at": now,
        }
        table.put_item(Item=item)
        logger.info(
            "calendar secret upserted",
            extra={
                "calendar": redacted_log_payload(
                    credential_ref=ref,
                    provider=item["provider"],
                    tags=item["tags"],
                    secret_payload=secret_payload,
                )
            },
        )
        return {
            "credential_ref": ref,
            "version": version,
            "created_at": created_at,
            "updated_at": now,
        }

    def get_secret(self, *, credential_ref: str) -> dict[str, Any] | None:
        ref = (credential_ref or "").strip()
        if not ref:
            return None

        item = _secrets_table().get_item(Key={"credential_ref": ref}).get("Item")
        if not item:
            return None

        payload = json.loads(_decrypt(str(item.get("secret_ct_b64") or "")).decode("utf-8"))
        logger.info(
            "calendar secret fetched",
            extra={
                "calendar": redacted_log_payload(
                    credential_ref=ref,
                    provider=item.get("provider"),
                    secret_payload=payload,
                )
            },
        )
        return {
            "credential_ref": ref,
            "provider": str(item.get("provider") or "apple_caldav"),
            "tags": dict(item.get("tags") or {}),
            "version": int(item.get("version") or 1),
            "created_at": item.get("created_at"),
            "updated_at": item.get("updated_at"),
            "secret_payload": payload,
        }

    def delete_secret(self, *, credential_ref: str) -> bool:
        ref = (credential_ref or "").strip()
        if not ref:
            return False

        table = _secrets_table()
        existing = table.get_item(Key={"credential_ref": ref}).get("Item")
        if not existing:
            return False

        table.delete_item(Key={"credential_ref": ref})
        logger.info(
            "calendar secret deleted",
            extra={"calendar": redacted_log_payload(credential_ref=ref, token="deleted")},
        )
        return True


_default_adapter = DynamoCalendarSecretAdapter()


def get_calendar_secret_adapter() -> CalendarSecretAdapter:
    return _default_adapter
