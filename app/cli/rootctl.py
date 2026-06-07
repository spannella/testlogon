from __future__ import annotations

import argparse
import getpass
import hmac
import json
import os
import re
import secrets
import sys
import uuid
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Dict, Optional

from boto3.dynamodb.conditions import Key

from app.auth.roles import Role, normalize_role
from app.auth.root_invariant import validate_root_user_sub_config
from app.core.cursor import decode_cursor, encode_cursor
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import audit_event
from app.services.api_keys import revoke_all_api_keys
from app.services.breach_check import check_password_breach
from app.services.registration import _hash_password
from app.services.sessions import revoke_all_sessions


class ExitCode(IntEnum):
    SUCCESS = 0
    VALIDATION_ERROR = 2
    AUTHZ_ERROR = 3
    BACKEND_ERROR = 4


@dataclass(frozen=True)
class SharedOptions:
    output: str
    dry_run: bool
    request_id: str
    correlation_id: str


class CliPolicyError(Exception):
    def __init__(self, message: str, *, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.details = details or {}


ADMIN_CAPABILITY_FEATURE_FLAG = "ROOTCTL_ADMIN_CAPABILITIES_ENABLED"
ADMIN_CAPABILITIES = {
    "billing_ops",
    "billing_read",
    "file_metadata",
    "file_content",
    "user_support",
    "impersonation",
}


def _admin_capabilities_enabled() -> bool:
    raw = (os.getenv(ADMIN_CAPABILITY_FEATURE_FLAG, "") or "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _parse_capabilities(values: list[str]) -> list[str]:
    normalized: list[str] = []
    for v in values:
        item = (v or "").strip().lower()
        if not item:
            continue
        if item not in ADMIN_CAPABILITIES:
            raise ValueError(
                "capability must be one of: " + ", ".join(sorted(ADMIN_CAPABILITIES))
            )
        if item not in normalized:
            normalized.append(item)
    return sorted(normalized)


def _emit(payload: Dict[str, Any], *, output: str) -> None:
    if output == "json":
        sys.stdout.write(json.dumps(payload, separators=(",", ":")) + "\n")
        return
    for key, value in payload.items():
        sys.stdout.write(f"{key}: {value}\n")


def _emit_error(message: str, *, code: ExitCode, output: str, details: Optional[Dict[str, Any]] = None) -> None:
    payload: Dict[str, Any] = {
        "ok": False,
        "error": message,
        "exit_code": int(code),
    }
    if details:
        payload.update(details)
    if output == "json":
        sys.stderr.write(json.dumps(payload, separators=(",", ":")) + "\n")
    else:
        sys.stderr.write(f"error: {message}\n")


def _shared_opts(args: argparse.Namespace) -> SharedOptions:
    return SharedOptions(
        output=str(getattr(args, "output", "table") or "table"),
        dry_run=bool(getattr(args, "dry_run", False)),
        request_id=str(getattr(args, "request_id", "") or ""),
        correlation_id=str(getattr(args, "correlation_id", "") or ""),
    )


def _status_command(args: argparse.Namespace) -> Dict[str, Any]:
    shared = _shared_opts(args)
    return {
        "ok": True,
        "group": str(args.group),
        "command": str(args.command),
        "dry_run": shared.dry_run,
        "request_id": shared.request_id,
        "correlation_id": shared.correlation_id,
        "message": f"{args.group} command framework is ready",
    }


def _resolve_password_input(args: argparse.Namespace) -> str:
    direct = str(getattr(args, "new_password", "") or "")
    if direct:
        return direct

    if bool(getattr(args, "password_stdin", False)):
        value = sys.stdin.readline().rstrip("\r\n")
        if not value:
            raise ValueError("new password is required from stdin")
        return value

    first = getpass.getpass("New password: ")
    second = getpass.getpass("Confirm new password: ")
    if not first:
        raise ValueError("new password is required")
    if first != second:
        raise ValueError("password confirmation mismatch")
    return first


def _root_reset_password_command(args: argparse.Namespace) -> Dict[str, Any]:
    shared = _shared_opts(args)
    root_sub = str(getattr(args, "root_sub", "") or "").strip()
    actor_sub = str(getattr(args, "actor_sub", "") or "").strip()
    reason = str(getattr(args, "reason", "") or "").strip()
    ticket = str(getattr(args, "ticket", "") or "").strip()

    target_user_sub = str(getattr(args, "target_user_sub", "") or "").strip() or root_sub
    if target_user_sub != root_sub:
        raise CliPolicyError(
            "root password reset is allowed only for immutable root principal",
            details={"code": "root_immutable", "target_user_sub": target_user_sub},
        )

    if bool(shared.dry_run):
        return {
            "ok": True,
            "group": str(args.group),
            "command": str(args.command),
            "dry_run": True,
            "actor_sub": actor_sub,
            "target_user_sub": root_sub,
            "reason": reason,
            "ticket": ticket,
            "request_id": shared.request_id,
            "correlation_id": shared.correlation_id,
            "message": "dry-run: root password would be reset and sessions/api keys revoked",
        }

    user_item = T.users.get_item(Key={"user_sub": root_sub}).get("Item") or {}
    if not user_item:
        raise ValueError("configured root user record not found")

    new_password = _resolve_password_input(args)
    breach_count = check_password_breach(new_password)
    if breach_count:
        raise ValueError("new password found in breach corpus")

    password_hash = _hash_password(new_password)
    ts = now_ts()
    T.users.update_item(
        Key={"user_sub": root_sub},
        UpdateExpression=(
            "SET password_hash=:ph, password_updated_at=:ts, "
            "password_updated_by=:actor, password_reason=:reason, password_ticket=:ticket"
        ),
        ExpressionAttributeValues={
            ":ph": password_hash,
            ":ts": ts,
            ":actor": actor_sub,
            ":reason": reason,
            ":ticket": ticket,
        },
    )

    try:
        revoke_all_sessions(root_sub)
    except Exception:
        pass
    try:
        revoke_all_api_keys(root_sub)
    except Exception:
        pass

    audit_event(
        "root_password_reset",
        root_sub,
        None,
        outcome="success",
        actor_sub=actor_sub,
        target_user_sub=root_sub,
        reason=reason,
        ticket_id=ticket,
        request_id=shared.request_id,
        correlation_id=shared.correlation_id,
        cli=True,
    )

    return {
        "ok": True,
        "group": str(args.group),
        "command": str(args.command),
        "dry_run": False,
        "actor_sub": actor_sub,
        "target_user_sub": root_sub,
        "reason": reason,
        "ticket": ticket,
        "request_id": shared.request_id,
        "correlation_id": shared.correlation_id,
        "sessions_revoked": True,
        "api_keys_revoked": True,
        "audit_event": "root_password_reset",
        "ts": ts,
    }


def _delete_items_by_user(table: Any, user_sub: str, *, key_field: str) -> int:
    items = table.query(KeyConditionExpression=Key("user_sub").eq(user_sub)).get("Items", [])
    count = 0
    for item in items:
        key_value = item.get(key_field)
        if not key_value:
            continue
        table.delete_item(Key={"user_sub": user_sub, key_field: key_value})
        count += 1
    return count


def _root_reset_mfa_command(args: argparse.Namespace) -> Dict[str, Any]:
    shared = _shared_opts(args)
    root_sub = str(getattr(args, "root_sub", "") or "").strip()
    actor_sub = str(getattr(args, "actor_sub", "") or "").strip()
    reason = str(getattr(args, "reason", "") or "").strip()
    ticket = str(getattr(args, "ticket", "") or "").strip()
    factor = str(getattr(args, "factor", "all") or "all").strip().lower()

    target_user_sub = str(getattr(args, "target_user_sub", "") or "").strip() or root_sub
    if target_user_sub != root_sub:
        raise CliPolicyError(
            "root MFA reset is allowed only for immutable root principal",
            details={"code": "root_immutable", "target_user_sub": target_user_sub},
        )

    if factor not in {"all", "totp", "sms", "email"}:
        raise ValueError("factor must be one of: all, totp, sms, email")

    if bool(shared.dry_run):
        return {
            "ok": True,
            "group": str(args.group),
            "command": str(args.command),
            "dry_run": True,
            "actor_sub": actor_sub,
            "target_user_sub": root_sub,
            "factor": factor,
            "reason": reason,
            "ticket": ticket,
            "request_id": shared.request_id,
            "correlation_id": shared.correlation_id,
            "message": "dry-run: root MFA devices/recovery codes would be reset and sessions revoked",
        }

    deleted: Dict[str, int] = {"totp": 0, "sms": 0, "email": 0, "recovery": 0}
    if factor in {"all", "totp"}:
        deleted["totp"] = _delete_items_by_user(T.totp, root_sub, key_field="device_id")
    if factor in {"all", "sms"}:
        deleted["sms"] = _delete_items_by_user(T.sms, root_sub, key_field="sms_device_id")
    if factor in {"all", "email"}:
        deleted["email"] = _delete_items_by_user(T.email, root_sub, key_field="email_device_id")

    recovery_items = T.recovery.query(KeyConditionExpression=Key("user_sub").eq(root_sub)).get("Items", [])
    for item in recovery_items:
        item_factor = str(item.get("factor") or "")
        if factor != "all" and item_factor != factor:
            continue
        code_hash = item.get("code_hash")
        if not code_hash:
            continue
        T.recovery.delete_item(Key={"user_sub": root_sub, "code_hash": code_hash})
        deleted["recovery"] += 1

    try:
        revoke_all_sessions(root_sub)
    except Exception:
        pass

    audit_event(
        "root_mfa_reset",
        root_sub,
        None,
        outcome="success",
        actor_sub=actor_sub,
        target_user_sub=root_sub,
        factor=factor,
        reason=reason,
        ticket_id=ticket,
        request_id=shared.request_id,
        correlation_id=shared.correlation_id,
        deleted=deleted,
        cli=True,
    )

    return {
        "ok": True,
        "group": str(args.group),
        "command": str(args.command),
        "dry_run": False,
        "actor_sub": actor_sub,
        "target_user_sub": root_sub,
        "factor": factor,
        "reason": reason,
        "ticket": ticket,
        "request_id": shared.request_id,
        "correlation_id": shared.correlation_id,
        "deleted": deleted,
        "sessions_revoked": True,
        "audit_event": "root_mfa_reset",
    }


def _parse_verified_flag(value: str, *, field_name: str) -> bool:
    normalized = value.strip().lower()
    if normalized == "verified":
        return True
    if normalized == "unverified":
        return False
    raise ValueError(f"{field_name} must be one of: verified, unverified")


def _parse_bool_flag(value: str, *, field_name: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"true", "1", "yes", "y"}:
        return True
    if normalized in {"false", "0", "no", "n"}:
        return False
    raise ValueError(f"{field_name} must be a boolean: true|false")


def _validate_email(value: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) > 254:
        raise ValueError("email must be <= 254 characters")
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", normalized):
        raise ValueError("email must be a valid address")
    return normalized


def _root_set_verification_command(args: argparse.Namespace) -> Dict[str, Any]:
    shared = _shared_opts(args)
    root_sub = str(getattr(args, "root_sub", "") or "").strip()
    actor_sub = str(getattr(args, "actor_sub", "") or "").strip()
    reason = str(getattr(args, "reason", "") or "").strip()
    ticket = str(getattr(args, "ticket", "") or "").strip()

    target_user_sub = str(getattr(args, "target_user_sub", "") or "").strip() or root_sub
    if target_user_sub != root_sub:
        raise CliPolicyError(
            "root verification updates are allowed only for immutable root principal",
            details={"code": "root_immutable", "target_user_sub": target_user_sub},
        )

    email_state = str(getattr(args, "email", "") or "").strip()
    phone_state = str(getattr(args, "phone", "") or "").strip()
    if not email_state and not phone_state:
        raise ValueError("at least one verification flag must be provided: --email and/or --phone")

    updates: Dict[str, Any] = {}
    if email_state:
        updates["email_verified"] = _parse_verified_flag(email_state, field_name="email")
    if phone_state:
        updates["phone_verified"] = _parse_verified_flag(phone_state, field_name="phone")

    if bool(shared.dry_run):
        return {
            "ok": True,
            "group": str(args.group),
            "command": str(args.command),
            "dry_run": True,
            "actor_sub": actor_sub,
            "target_user_sub": root_sub,
            "reason": reason,
            "ticket": ticket,
            "updates": updates,
            "request_id": shared.request_id,
            "correlation_id": shared.correlation_id,
            "message": "dry-run: root verification state would be updated",
        }

    ts = now_ts()
    expr_parts = ["verification_updated_at=:ts", "verification_updated_by=:actor", "verification_reason=:reason", "verification_ticket=:ticket"]
    values: Dict[str, Any] = {":ts": ts, ":actor": actor_sub, ":reason": reason, ":ticket": ticket}
    for field, val in updates.items():
        key = f":{field}"
        expr_parts.append(f"{field}={key}")
        values[key] = val

    T.users.update_item(
        Key={"user_sub": root_sub},
        UpdateExpression="SET " + ", ".join(expr_parts),
        ExpressionAttributeValues=values,
    )

    audit_event(
        "root_verification_state_updated",
        root_sub,
        None,
        outcome="success",
        actor_sub=actor_sub,
        target_user_sub=root_sub,
        reason=reason,
        ticket_id=ticket,
        request_id=shared.request_id,
        correlation_id=shared.correlation_id,
        updates=updates,
        cli=True,
    )

    return {
        "ok": True,
        "group": str(args.group),
        "command": str(args.command),
        "dry_run": False,
        "actor_sub": actor_sub,
        "target_user_sub": root_sub,
        "reason": reason,
        "ticket": ticket,
        "updates": updates,
        "request_id": shared.request_id,
        "correlation_id": shared.correlation_id,
        "audit_event": "root_verification_state_updated",
    }


def _root_set_email_command(args: argparse.Namespace) -> Dict[str, Any]:
    shared = _shared_opts(args)
    root_sub = str(getattr(args, "root_sub", "") or "").strip()
    actor_sub = str(getattr(args, "actor_sub", "") or "").strip()
    reason = str(getattr(args, "reason", "") or "").strip()
    ticket = str(getattr(args, "ticket", "") or "").strip()

    target_user_sub = str(getattr(args, "target_user_sub", "") or "").strip() or root_sub
    if target_user_sub != root_sub:
        raise CliPolicyError(
            "root email updates are allowed only for immutable root principal",
            details={"code": "root_immutable", "target_user_sub": target_user_sub},
        )

    email = _validate_email(str(getattr(args, "email", "") or ""))
    verify_email = bool(getattr(args, "verify", False))
    updates: Dict[str, Any] = {"email": email, "displayed_email": email}
    if verify_email:
        updates["email_verified"] = True

    if bool(shared.dry_run):
        return {
            "ok": True,
            "group": str(args.group),
            "command": str(args.command),
            "dry_run": True,
            "actor_sub": actor_sub,
            "target_user_sub": root_sub,
            "reason": reason,
            "ticket": ticket,
            "updates": updates,
            "request_id": shared.request_id,
            "correlation_id": shared.correlation_id,
            "message": "dry-run: root email/security profile would be updated",
        }

    user_item = T.users.get_item(Key={"user_sub": root_sub}).get("Item") or {}
    if not user_item:
        raise ValueError("configured root user record not found")

    ts = now_ts()
    expr_parts = ["email_updated_at=:ts", "email_updated_by=:actor", "email_reason=:reason", "email_ticket=:ticket"]
    values: Dict[str, Any] = {":ts": ts, ":actor": actor_sub, ":reason": reason, ":ticket": ticket}
    for field, val in updates.items():
        key = f":{field}"
        expr_parts.append(f"{field}={key}")
        values[key] = val

    T.users.update_item(
        Key={"user_sub": root_sub},
        UpdateExpression="SET " + ", ".join(expr_parts),
        ExpressionAttributeValues=values,
    )

    audit_event(
        "root_email_updated",
        root_sub,
        None,
        outcome="success",
        severity="high",
        actor_sub=actor_sub,
        target_user_sub=root_sub,
        reason=reason,
        ticket_id=ticket,
        request_id=shared.request_id,
        correlation_id=shared.correlation_id,
        updates=updates,
        cli=True,
    )

    return {
        "ok": True,
        "group": str(args.group),
        "command": str(args.command),
        "dry_run": False,
        "actor_sub": actor_sub,
        "target_user_sub": root_sub,
        "reason": reason,
        "ticket": ticket,
        "updates": updates,
        "request_id": shared.request_id,
        "correlation_id": shared.correlation_id,
        "audit_event": "root_email_updated",
    }


def _root_set_security_profile_command(args: argparse.Namespace) -> Dict[str, Any]:
    shared = _shared_opts(args)
    root_sub = str(getattr(args, "root_sub", "") or "").strip()
    actor_sub = str(getattr(args, "actor_sub", "") or "").strip()
    reason = str(getattr(args, "reason", "") or "").strip()
    ticket = str(getattr(args, "ticket", "") or "").strip()

    target_user_sub = str(getattr(args, "target_user_sub", "") or "").strip() or root_sub
    if target_user_sub != root_sub:
        raise CliPolicyError(
            "root security profile updates are allowed only for immutable root principal",
            details={"code": "root_immutable", "target_user_sub": target_user_sub},
        )

    updates: Dict[str, Any] = {}
    if str(getattr(args, "force_password_rotate", "") or "").strip():
        updates["force_password_rotate"] = _parse_bool_flag(
            str(getattr(args, "force_password_rotate", "")), field_name="force-password-rotate"
        )
    if str(getattr(args, "recovery_lockdown", "") or "").strip():
        updates["recovery_lockdown"] = _parse_bool_flag(
            str(getattr(args, "recovery_lockdown", "")), field_name="recovery-lockdown"
        )

    security_note = str(getattr(args, "security_note", "") or "").strip()
    if security_note:
        updates["security_note"] = security_note[:512]

    if not updates:
        raise ValueError("at least one security metadata update is required")

    if bool(shared.dry_run):
        return {
            "ok": True,
            "group": str(args.group),
            "command": str(args.command),
            "dry_run": True,
            "actor_sub": actor_sub,
            "target_user_sub": root_sub,
            "reason": reason,
            "ticket": ticket,
            "updates": updates,
            "request_id": shared.request_id,
            "correlation_id": shared.correlation_id,
            "message": "dry-run: root security profile would be updated",
        }

    ts = now_ts()
    expr_parts = ["security_profile_updated_at=:ts", "security_profile_updated_by=:actor", "security_reason=:reason", "security_ticket=:ticket"]
    values: Dict[str, Any] = {":ts": ts, ":actor": actor_sub, ":reason": reason, ":ticket": ticket}
    for field, val in updates.items():
        key = f":{field}"
        expr_parts.append(f"{field}={key}")
        values[key] = val

    T.users.update_item(
        Key={"user_sub": root_sub},
        UpdateExpression="SET " + ", ".join(expr_parts),
        ExpressionAttributeValues=values,
    )

    audit_event(
        "root_security_profile_updated",
        root_sub,
        None,
        outcome="success",
        severity="high",
        actor_sub=actor_sub,
        target_user_sub=root_sub,
        reason=reason,
        ticket_id=ticket,
        request_id=shared.request_id,
        correlation_id=shared.correlation_id,
        updates=updates,
        cli=True,
    )

    return {
        "ok": True,
        "group": str(args.group),
        "command": str(args.command),
        "dry_run": False,
        "actor_sub": actor_sub,
        "target_user_sub": root_sub,
        "reason": reason,
        "ticket": ticket,
        "updates": updates,
        "request_id": shared.request_id,
        "correlation_id": shared.correlation_id,
        "audit_event": "root_security_profile_updated",
    }


def _normalize_role(value: str) -> str:
    role = (value or "").strip().lower()
    if role not in {"root", "admin", "user"}:
        return "user"
    return role


def _normalize_status(value: str) -> str:
    status = (value or "").strip().lower()
    if not status:
        return "active"
    return status


def _user_create_command(args: argparse.Namespace) -> Dict[str, Any]:
    shared = _shared_opts(args)
    root_sub = str(getattr(args, "root_sub", "") or "").strip()
    actor_sub = str(getattr(args, "actor_sub", "") or "").strip()
    reason = str(getattr(args, "reason", "") or "").strip()
    ticket = str(getattr(args, "ticket", "") or "").strip()

    email = _validate_email(str(getattr(args, "email", "") or ""))
    target_user_sub = email
    if target_user_sub == root_sub:
        raise CliPolicyError(
            "root identity cannot be created/modified through user command paths",
            details={"code": "root_immutable", "target_user_sub": target_user_sub},
        )

    requested_role = _normalize_role(str(getattr(args, "role", "user") or "user"))
    if requested_role == "root":
        raise CliPolicyError(
            "root role is immutable and cannot be assigned via CLI mutation command",
            details={"code": "root_immutable", "requested_role": "root"},
        )

    full_name = str(getattr(args, "full_name", "") or "").strip()
    if len(full_name) > 200:
        raise ValueError("full-name must be <= 200 characters")

    status = _normalize_status(str(getattr(args, "status", "active") or "active"))
    if status not in {"active", "pending_verification", "deactivated", "deleted"}:
        raise ValueError("status must be one of: active, pending_verification, deactivated, deleted")

    password = str(getattr(args, "password", "") or "")
    generated_password = ""
    if not password:
        generated_password = secrets.token_urlsafe(18)
        password = generated_password
    if len(password) < 8:
        raise ValueError("password must be at least 8 characters")

    created_at = now_ts()
    item = {
        "user_sub": target_user_sub,
        "email": target_user_sub,
        "full_name": full_name,
        "password_hash": _hash_password(password),
        "role": requested_role,
        "created_at": created_at,
    }

    if bool(shared.dry_run):
        return {
            "ok": True,
            "group": str(args.group),
            "command": str(args.command),
            "dry_run": True,
            "actor_sub": actor_sub,
            "target_user_sub": target_user_sub,
            "role": requested_role,
            "status": status,
            "reason": reason,
            "ticket": ticket,
            "request_id": shared.request_id,
            "correlation_id": shared.correlation_id,
            "message": "dry-run: user would be created",
        }

    try:
        T.users.put_item(Item=item, ConditionExpression="attribute_not_exists(user_sub)")
    except Exception as exc:
        raise ValueError("user already exists") from exc

    T.account_state.put_item(
        Item={
            "user_sub": target_user_sub,
            "status": status,
            "updated_at": created_at,
            "reason": "rootctl_user_create",
            "requested_by": actor_sub,
        }
    )

    audit_event(
        "user_created_cli",
        target_user_sub,
        None,
        outcome="success",
        severity="high",
        actor_sub=actor_sub,
        target_user_sub=target_user_sub,
        role=requested_role,
        status=status,
        reason=reason,
        ticket_id=ticket,
        request_id=shared.request_id,
        correlation_id=shared.correlation_id,
        cli=True,
    )

    payload: Dict[str, Any] = {
        "ok": True,
        "group": str(args.group),
        "command": str(args.command),
        "dry_run": False,
        "actor_sub": actor_sub,
        "target_user_sub": target_user_sub,
        "role": requested_role,
        "status": status,
        "reason": reason,
        "ticket": ticket,
        "request_id": shared.request_id,
        "correlation_id": shared.correlation_id,
        "audit_event": "user_created_cli",
    }
    if generated_password:
        payload["generated_password"] = generated_password
    return payload


def _user_list_command(args: argparse.Namespace) -> Dict[str, Any]:
    limit = int(getattr(args, "limit", 50) or 50)
    if limit < 1 or limit > 200:
        raise ValueError("limit must be between 1 and 200")

    role_filter = str(getattr(args, "role", "") or "").strip().lower()
    if role_filter and role_filter not in {"root", "admin", "user"}:
        raise ValueError("role must be one of: root, admin, user")

    status_filter = str(getattr(args, "status", "") or "").strip().lower()
    if status_filter and status_filter not in {"active", "pending_verification", "deactivated", "deleted"}:
        raise ValueError("status must be one of: active, pending_verification, deactivated, deleted")

    raw_cursor = str(getattr(args, "cursor", "") or "").strip()
    eks = decode_cursor(raw_cursor) if raw_cursor else None
    if raw_cursor and not eks:
        raise ValueError("invalid cursor")

    out = []
    next_key = eks
    while len(out) < limit:
        page = T.users.scan(ExclusiveStartKey=next_key, Limit=max(limit * 2, 25)) if next_key else T.users.scan(Limit=max(limit * 2, 25))
        items = page.get("Items", [])
        for item in items:
            user_sub = str(item.get("user_sub") or "").strip()
            if not user_sub:
                continue
            role = _normalize_role(str(item.get("role") or "user"))
            if role_filter and role != role_filter:
                continue
            state = T.account_state.get_item(Key={"user_sub": user_sub}).get("Item") or {}
            status = _normalize_status(str(state.get("status") or "active"))
            if status_filter and status != status_filter:
                continue
            out.append({
                "user_sub": user_sub,
                "email": str(item.get("email") or user_sub),
                "full_name": str(item.get("full_name") or ""),
                "role": role,
                "status": status,
                "created_at": int(item.get("created_at") or 0),
            })
            if len(out) >= limit:
                break

        next_key = page.get("LastEvaluatedKey")
        if len(out) >= limit or not next_key:
            break

    return {
        "ok": True,
        "group": str(args.group),
        "command": str(args.command),
        "items": out,
        "count": len(out),
        "cursor": encode_cursor(next_key),
        "role": role_filter or None,
        "status": status_filter or None,
        "limit": limit,
    }


def _require_existing_non_root_user(target_user_sub: str, *, root_sub: str) -> Dict[str, Any]:
    if target_user_sub == root_sub:
        raise CliPolicyError(
            "root identity cannot be mutated through user/admin command paths",
            details={"code": "root_immutable", "target_user_sub": target_user_sub},
        )
    user_item = T.users.get_item(Key={"user_sub": target_user_sub}).get("Item") or {}
    if not user_item:
        raise ValueError("target user not found")
    return user_item


def _require_mutable_account_state(target_user_sub: str) -> str:
    state = T.account_state.get_item(Key={"user_sub": target_user_sub}).get("Item") or {}
    status = _normalize_status(str(state.get("status") or "active"))
    if status in {"deactivated", "deleted"}:
        raise CliPolicyError(
            "target user state does not permit this operation",
            details={"code": "account_state_forbidden", "status": status, "target_user_sub": target_user_sub},
        )
    return status


def _user_verify_command(args: argparse.Namespace) -> Dict[str, Any]:
    shared = _shared_opts(args)
    root_sub = str(getattr(args, "root_sub", "") or "").strip()
    actor_sub = str(getattr(args, "actor_sub", "") or "").strip()
    reason = str(getattr(args, "reason", "") or "").strip()
    ticket = str(getattr(args, "ticket", "") or "").strip()
    target_user_sub = str(getattr(args, "target_user_sub", "") or "").strip()

    _require_existing_non_root_user(target_user_sub, root_sub=root_sub)
    status = _require_mutable_account_state(target_user_sub)

    email_state = str(getattr(args, "email", "") or "").strip()
    phone_state = str(getattr(args, "phone", "") or "").strip()
    if not email_state and not phone_state:
        raise ValueError("at least one verification flag must be provided: --email and/or --phone")

    updates: Dict[str, Any] = {}
    if email_state:
        updates["email_verified"] = _parse_verified_flag(email_state, field_name="email")
    if phone_state:
        updates["phone_verified"] = _parse_verified_flag(phone_state, field_name="phone")

    if bool(shared.dry_run):
        return {
            "ok": True,
            "group": str(args.group),
            "command": str(args.command),
            "dry_run": True,
            "actor_sub": actor_sub,
            "target_user_sub": target_user_sub,
            "status": status,
            "updates": updates,
            "reason": reason,
            "ticket": ticket,
            "request_id": shared.request_id,
            "correlation_id": shared.correlation_id,
            "message": "dry-run: user verification state would be updated",
        }

    ts = now_ts()
    expr_parts = ["verification_updated_at=:ts", "verification_updated_by=:actor", "verification_reason=:reason", "verification_ticket=:ticket"]
    values: Dict[str, Any] = {":ts": ts, ":actor": actor_sub, ":reason": reason, ":ticket": ticket}
    for field, val in updates.items():
        key = f":{field}"
        expr_parts.append(f"{field}={key}")
        values[key] = val

    T.users.update_item(
        Key={"user_sub": target_user_sub},
        UpdateExpression="SET " + ", ".join(expr_parts),
        ExpressionAttributeValues=values,
    )

    audit_event(
        "user_verification_updated_cli",
        target_user_sub,
        None,
        outcome="success",
        actor_sub=actor_sub,
        target_user_sub=target_user_sub,
        reason=reason,
        ticket_id=ticket,
        request_id=shared.request_id,
        correlation_id=shared.correlation_id,
        status=status,
        updates=updates,
        cli=True,
    )

    return {
        "ok": True,
        "group": str(args.group),
        "command": str(args.command),
        "dry_run": False,
        "actor_sub": actor_sub,
        "target_user_sub": target_user_sub,
        "status": status,
        "updates": updates,
        "reason": reason,
        "ticket": ticket,
        "request_id": shared.request_id,
        "correlation_id": shared.correlation_id,
        "audit_event": "user_verification_updated_cli",
    }


def _user_set_password_command(args: argparse.Namespace) -> Dict[str, Any]:
    shared = _shared_opts(args)
    root_sub = str(getattr(args, "root_sub", "") or "").strip()
    actor_sub = str(getattr(args, "actor_sub", "") or "").strip()
    reason = str(getattr(args, "reason", "") or "").strip()
    ticket = str(getattr(args, "ticket", "") or "").strip()
    target_user_sub = str(getattr(args, "target_user_sub", "") or "").strip()

    _require_existing_non_root_user(target_user_sub, root_sub=root_sub)
    status = _require_mutable_account_state(target_user_sub)

    if bool(shared.dry_run):
        return {
            "ok": True,
            "group": str(args.group),
            "command": str(args.command),
            "dry_run": True,
            "actor_sub": actor_sub,
            "target_user_sub": target_user_sub,
            "status": status,
            "reason": reason,
            "ticket": ticket,
            "request_id": shared.request_id,
            "correlation_id": shared.correlation_id,
            "message": "dry-run: user password would be updated and sessions revoked",
        }

    new_password = _resolve_password_input(args)
    if len(new_password) < 8:
        raise ValueError("new password must be at least 8 characters")
    breach_count = check_password_breach(new_password)
    if breach_count:
        raise ValueError("new password found in breach corpus")

    password_hash = _hash_password(new_password)
    ts = now_ts()
    T.users.update_item(
        Key={"user_sub": target_user_sub},
        UpdateExpression=(
            "SET password_hash=:ph, password_updated_at=:ts, "
            "password_updated_by=:actor, password_reason=:reason, password_ticket=:ticket"
        ),
        ExpressionAttributeValues={
            ":ph": password_hash,
            ":ts": ts,
            ":actor": actor_sub,
            ":reason": reason,
            ":ticket": ticket,
        },
    )

    revoke_all_sessions(target_user_sub)

    audit_event(
        "user_password_reset_cli",
        target_user_sub,
        None,
        outcome="success",
        actor_sub=actor_sub,
        target_user_sub=target_user_sub,
        reason=reason,
        ticket_id=ticket,
        request_id=shared.request_id,
        correlation_id=shared.correlation_id,
        status=status,
        cli=True,
    )

    return {
        "ok": True,
        "group": str(args.group),
        "command": str(args.command),
        "dry_run": False,
        "actor_sub": actor_sub,
        "target_user_sub": target_user_sub,
        "status": status,
        "reason": reason,
        "ticket": ticket,
        "request_id": shared.request_id,
        "correlation_id": shared.correlation_id,
        "sessions_revoked": True,
        "audit_event": "user_password_reset_cli",
    }


def _user_deactivate_command(args: argparse.Namespace) -> Dict[str, Any]:
    shared = _shared_opts(args)
    root_sub = str(getattr(args, "root_sub", "") or "").strip()
    actor_sub = str(getattr(args, "actor_sub", "") or "").strip()
    reason = str(getattr(args, "reason", "") or "").strip()
    ticket = str(getattr(args, "ticket", "") or "").strip()
    target_user_sub = str(getattr(args, "target_user_sub", "") or "").strip()

    _require_existing_non_root_user(target_user_sub, root_sub=root_sub)
    status = _require_mutable_account_state(target_user_sub)

    if bool(shared.dry_run):
        return {
            "ok": True,
            "group": str(args.group),
            "command": str(args.command),
            "dry_run": True,
            "actor_sub": actor_sub,
            "target_user_sub": target_user_sub,
            "previous_status": status,
            "new_status": "deactivated",
            "reason": reason,
            "ticket": ticket,
            "request_id": shared.request_id,
            "correlation_id": shared.correlation_id,
            "message": "dry-run: user would be deactivated and sessions/api keys revoked",
        }

    ts = now_ts()
    T.account_state.put_item(
        Item={
            "user_sub": target_user_sub,
            "status": "deactivated",
            "updated_at": ts,
            "reason": reason,
            "requested_by": actor_sub,
        }
    )
    T.users.update_item(
        Key={"user_sub": target_user_sub},
        UpdateExpression=(
            "SET deactivated_at=:ts, deactivated_by=:actor, "
            "deactivation_reason=:reason, deactivation_ticket=:ticket"
        ),
        ExpressionAttributeValues={
            ":ts": ts,
            ":actor": actor_sub,
            ":reason": reason,
            ":ticket": ticket,
        },
    )

    revoke_all_sessions(target_user_sub)
    revoke_all_api_keys(target_user_sub)

    audit_event(
        "user_deactivated_cli",
        target_user_sub,
        None,
        outcome="success",
        actor_sub=actor_sub,
        target_user_sub=target_user_sub,
        previous_status=status,
        new_status="deactivated",
        reason=reason,
        ticket_id=ticket,
        request_id=shared.request_id,
        correlation_id=shared.correlation_id,
        cli=True,
    )

    return {
        "ok": True,
        "group": str(args.group),
        "command": str(args.command),
        "dry_run": False,
        "actor_sub": actor_sub,
        "target_user_sub": target_user_sub,
        "previous_status": status,
        "new_status": "deactivated",
        "reason": reason,
        "ticket": ticket,
        "request_id": shared.request_id,
        "correlation_id": shared.correlation_id,
        "sessions_revoked": True,
        "api_keys_revoked": True,
        "audit_event": "user_deactivated_cli",
    }


def _user_deactivate_bulk_command(args: argparse.Namespace) -> Dict[str, Any]:
    shared = _shared_opts(args)
    root_sub = str(getattr(args, "root_sub", "") or "").strip()
    actor_sub = str(getattr(args, "actor_sub", "") or "").strip()
    reason = str(getattr(args, "reason", "") or "").strip()
    ticket = str(getattr(args, "ticket", "") or "").strip()
    targets = [str(value or "").strip() for value in list(getattr(args, "target_user_sub", []) or [])]
    targets = [value for value in targets if value]
    if not targets:
        raise ValueError("at least one --target-user-sub is required")

    correlation_id = shared.correlation_id or str(uuid.uuid4())
    bulk_results: list[Dict[str, Any]] = []
    success = 0

    for target_user_sub in targets:
        per_target = argparse.Namespace(**vars(args))
        setattr(per_target, "target_user_sub", target_user_sub)
        setattr(per_target, "command", "deactivate")
        setattr(per_target, "correlation_id", correlation_id)
        try:
            result = _user_deactivate_command(per_target)
            bulk_results.append(
                {
                    "target_user_sub": target_user_sub,
                    "ok": True,
                    "result": result,
                }
            )
            success += 1
        except Exception as exc:  # bulk flow should continue through target failures
            bulk_results.append(
                {
                    "target_user_sub": target_user_sub,
                    "ok": False,
                    "error": str(exc),
                }
            )

    failed = len(targets) - success
    return {
        "ok": failed == 0,
        "group": str(args.group),
        "command": str(args.command),
        "dry_run": shared.dry_run,
        "actor_sub": actor_sub,
        "reason": reason,
        "ticket": ticket,
        "request_id": shared.request_id,
        "correlation_id": correlation_id,
        "summary": {
            "total_targets": len(targets),
            "success_count": success,
            "failure_count": failed,
        },
        "results": bulk_results,
    }


def _user_delete_command(args: argparse.Namespace) -> Dict[str, Any]:
    shared = _shared_opts(args)
    root_sub = str(getattr(args, "root_sub", "") or "").strip()
    actor_sub = str(getattr(args, "actor_sub", "") or "").strip()
    reason = str(getattr(args, "reason", "") or "").strip()
    ticket = str(getattr(args, "ticket", "") or "").strip()
    target_user_sub = str(getattr(args, "target_user_sub", "") or "").strip()
    hard_delete = bool(getattr(args, "hard_delete", False))

    _require_existing_non_root_user(target_user_sub, root_sub=root_sub)
    status = _normalize_status(
        str((T.account_state.get_item(Key={"user_sub": target_user_sub}).get("Item") or {}).get("status") or "active")
    )

    if bool(shared.dry_run):
        return {
            "ok": True,
            "group": str(args.group),
            "command": str(args.command),
            "dry_run": True,
            "actor_sub": actor_sub,
            "target_user_sub": target_user_sub,
            "hard_delete": hard_delete,
            "previous_status": status,
            "reason": reason,
            "ticket": ticket,
            "request_id": shared.request_id,
            "correlation_id": shared.correlation_id,
            "message": "dry-run: user would be deleted",
        }

    ts = now_ts()
    if hard_delete:
        T.users.delete_item(Key={"user_sub": target_user_sub})
        T.account_state.delete_item(Key={"user_sub": target_user_sub})
    else:
        T.account_state.put_item(
            Item={
                "user_sub": target_user_sub,
                "status": "deleted",
                "updated_at": ts,
                "reason": reason,
                "requested_by": actor_sub,
            }
        )
        T.users.update_item(
            Key={"user_sub": target_user_sub},
            UpdateExpression=(
                "SET deleted_at=:ts, deleted_by=:actor, "
                "deletion_reason=:reason, deletion_ticket=:ticket"
            ),
            ExpressionAttributeValues={
                ":ts": ts,
                ":actor": actor_sub,
                ":reason": reason,
                ":ticket": ticket,
            },
        )

    revoke_all_sessions(target_user_sub)
    revoke_all_api_keys(target_user_sub)

    audit_event(
        "user_deleted_cli",
        target_user_sub,
        None,
        outcome="success",
        actor_sub=actor_sub,
        target_user_sub=target_user_sub,
        previous_status=status,
        deletion_mode="hard" if hard_delete else "soft",
        reason=reason,
        ticket_id=ticket,
        request_id=shared.request_id,
        correlation_id=shared.correlation_id,
        cli=True,
    )

    return {
        "ok": True,
        "group": str(args.group),
        "command": str(args.command),
        "dry_run": False,
        "actor_sub": actor_sub,
        "target_user_sub": target_user_sub,
        "hard_delete": hard_delete,
        "previous_status": status,
        "reason": reason,
        "ticket": ticket,
        "request_id": shared.request_id,
        "correlation_id": shared.correlation_id,
        "sessions_revoked": True,
        "api_keys_revoked": True,
        "audit_event": "user_deleted_cli",
    }


def _persist_role_assignment_event_cli(
    *,
    actor_sub: str,
    target_user_sub: str,
    action: str,
    previous_role: Role,
    new_role: Role,
    reason: str,
    request_id: str,
    correlation_id: str,
) -> Dict[str, Any]:
    ts = now_ts()
    event_id = str(uuid.uuid4())
    item = {
        "pk": f"ACTOR#{actor_sub}",
        "sk": f"TS#{ts:013d}#{event_id}",
        "event_id": event_id,
        "event_type": "role_assignment",
        "action": action,
        "actor_sub": actor_sub,
        "target_user_sub": target_user_sub,
        "previous_role": previous_role.value,
        "new_role": new_role.value,
        "reason": reason,
        "request_id": request_id,
        "correlation_id": correlation_id,
        "source": "rootctl",
        "ts": ts,
    }
    T.role_audit.put_item(Item=item, ConditionExpression="attribute_not_exists(event_id)")
    return item


def _admin_grant_command(args: argparse.Namespace) -> Dict[str, Any]:
    shared = _shared_opts(args)
    root_sub = str(getattr(args, "root_sub", "") or "").strip()
    actor_sub = str(getattr(args, "actor_sub", "") or "").strip()
    reason = str(getattr(args, "reason", "") or "").strip()
    target_user_sub = str(getattr(args, "target_user_sub", "") or "").strip()
    requested_role = str(getattr(args, "role", "admin") or "admin").strip().lower()

    _require_existing_non_root_user(target_user_sub, root_sub=root_sub)
    if requested_role != Role.ADMIN.value:
        raise CliPolicyError(
            "only admin role is assignable via this command",
            details={"code": "invalid_role_transition", "requested_role": requested_role},
        )

    user = T.users.get_item(Key={"user_sub": target_user_sub}).get("Item") or {}
    current_role = normalize_role(user.get("role"))
    if current_role is Role.ADMIN:
        raise CliPolicyError(
            "target user is already admin",
            details={"code": "invalid_role_transition", "reason": "already_admin", "target_user_sub": target_user_sub},
        )
    if current_role is Role.ROOT:
        raise CliPolicyError(
            "cannot modify root role through admin grant command",
            details={"code": "root_immutable", "target_user_sub": target_user_sub},
        )

    new_caps = _parse_capabilities(list(getattr(args, "capability", []) or []))

    if bool(shared.dry_run):
        return {
            "ok": True,
            "group": str(args.group),
            "command": str(args.command),
            "dry_run": True,
            "actor_sub": actor_sub,
            "target_user_sub": target_user_sub,
            "previous_role": current_role.value,
            "new_role": Role.ADMIN.value,
            "reason": reason,
            "new_capabilities": new_caps,
            "request_id": shared.request_id,
            "correlation_id": shared.correlation_id,
            "message": (
                "dry-run: user would be granted admin role (general)"
                if not new_caps
                else f"dry-run: user would be granted admin role (scoped: {new_caps})"
            ),
        }

    ts = now_ts()
    if new_caps:
        # Scoped admin: persist the capability list so the token-minting layer
        # (GAP-0037 bridge) can build a restricted admin_profile.
        T.users.update_item(
            Key={"user_sub": target_user_sub},
            UpdateExpression=(
                "SET #role=:role, role_updated_at=:ts, role_updated_by=:by, "
                "role_reason=:reason, admin_capabilities=:caps"
            ),
            ExpressionAttributeNames={"#role": "role"},
            ExpressionAttributeValues={
                ":role": Role.ADMIN.value,
                ":ts": ts,
                ":by": actor_sub,
                ":reason": reason,
                ":caps": new_caps,
            },
        )
    else:
        # General admin: write role only (no admin_capabilities = GENERAL profile).
        T.users.update_item(
            Key={"user_sub": target_user_sub},
            UpdateExpression="SET #role=:role, role_updated_at=:ts, role_updated_by=:by, role_reason=:reason",
            ExpressionAttributeNames={"#role": "role"},
            ExpressionAttributeValues={
                ":role": Role.ADMIN.value,
                ":ts": ts,
                ":by": actor_sub,
                ":reason": reason,
            },
        )
    event = _persist_role_assignment_event_cli(
        actor_sub=actor_sub,
        target_user_sub=target_user_sub,
        action="grant",
        previous_role=current_role,
        new_role=Role.ADMIN,
        reason=reason,
        request_id=shared.request_id,
        correlation_id=shared.correlation_id,
    )
    audit_event(
        "admin_role_granted",
        actor_sub,
        None,
        outcome="success",
        actor_sub=actor_sub,
        target_user_sub=target_user_sub,
        role=Role.ADMIN.value,
        previous_role=current_role.value,
        reason=reason,
        new_capabilities=new_caps,
        role_audit_event_id=event["event_id"],
        request_id=shared.request_id,
        correlation_id=shared.correlation_id,
        cli=True,
    )
    return {
        "ok": True,
        "group": str(args.group),
        "command": str(args.command),
        "dry_run": False,
        "actor_sub": actor_sub,
        "target_user_sub": target_user_sub,
        "previous_role": current_role.value,
        "new_role": Role.ADMIN.value,
        "reason": reason,
        "new_capabilities": new_caps,
        "event_id": event["event_id"],
        "request_id": shared.request_id,
        "correlation_id": shared.correlation_id,
        "audit_event": "admin_role_granted",
    }


def _admin_revoke_command(args: argparse.Namespace) -> Dict[str, Any]:
    shared = _shared_opts(args)
    root_sub = str(getattr(args, "root_sub", "") or "").strip()
    actor_sub = str(getattr(args, "actor_sub", "") or "").strip()
    reason = str(getattr(args, "reason", "") or "").strip()
    target_user_sub = str(getattr(args, "target_user_sub", "") or "").strip()
    requested_role = str(getattr(args, "role", "admin") or "admin").strip().lower()

    _require_existing_non_root_user(target_user_sub, root_sub=root_sub)
    if requested_role != Role.ADMIN.value:
        raise CliPolicyError(
            "only admin role is revocable via this command",
            details={"code": "invalid_role_transition", "requested_role": requested_role},
        )

    user = T.users.get_item(Key={"user_sub": target_user_sub}).get("Item") or {}
    current_role = normalize_role(user.get("role"))
    if current_role is Role.USER:
        raise CliPolicyError(
            "target user is not admin",
            details={"code": "invalid_role_transition", "reason": "not_admin", "target_user_sub": target_user_sub},
        )
    if current_role is Role.ROOT:
        raise CliPolicyError(
            "cannot modify root role through admin revoke command",
            details={"code": "root_immutable", "target_user_sub": target_user_sub},
        )

    if bool(shared.dry_run):
        return {
            "ok": True,
            "group": str(args.group),
            "command": str(args.command),
            "dry_run": True,
            "actor_sub": actor_sub,
            "target_user_sub": target_user_sub,
            "previous_role": current_role.value,
            "new_role": Role.USER.value,
            "reason": reason,
            "request_id": shared.request_id,
            "correlation_id": shared.correlation_id,
            "message": "dry-run: user admin role would be revoked",
        }

    ts = now_ts()
    T.users.update_item(
        Key={"user_sub": target_user_sub},
        UpdateExpression=(
            "SET #role=:role, role_updated_at=:ts, role_updated_by=:by, role_reason=:reason "
            "REMOVE admin_capabilities"
        ),
        ExpressionAttributeNames={"#role": "role"},
        ExpressionAttributeValues={
            ":role": Role.USER.value,
            ":ts": ts,
            ":by": actor_sub,
            ":reason": reason,
        },
    )
    event = _persist_role_assignment_event_cli(
        actor_sub=actor_sub,
        target_user_sub=target_user_sub,
        action="revoke",
        previous_role=current_role,
        new_role=Role.USER,
        reason=reason,
        request_id=shared.request_id,
        correlation_id=shared.correlation_id,
    )
    audit_event(
        "admin_role_revoked",
        actor_sub,
        None,
        outcome="success",
        actor_sub=actor_sub,
        target_user_sub=target_user_sub,
        role=Role.ADMIN.value,
        previous_role=current_role.value,
        reason=reason,
        role_audit_event_id=event["event_id"],
        request_id=shared.request_id,
        correlation_id=shared.correlation_id,
        cli=True,
    )
    return {
        "ok": True,
        "group": str(args.group),
        "command": str(args.command),
        "dry_run": False,
        "actor_sub": actor_sub,
        "target_user_sub": target_user_sub,
        "previous_role": current_role.value,
        "new_role": Role.USER.value,
        "reason": reason,
        "event_id": event["event_id"],
        "request_id": shared.request_id,
        "correlation_id": shared.correlation_id,
        "audit_event": "admin_role_revoked",
    }


def _admin_create_command(args: argparse.Namespace) -> Dict[str, Any]:
    shared = _shared_opts(args)
    root_sub = str(getattr(args, "root_sub", "") or "").strip()
    actor_sub = str(getattr(args, "actor_sub", "") or "").strip()
    reason = str(getattr(args, "reason", "") or "").strip()
    ticket = str(getattr(args, "ticket", "") or "").strip()
    email = _validate_email(str(getattr(args, "email", "") or ""))
    full_name = str(getattr(args, "full_name", "") or "").strip()
    status = _normalize_status(str(getattr(args, "status", "active") or "active"))

    if status not in {"active", "pending_verification", "deactivated", "deleted"}:
        raise ValueError("status must be one of: active, pending_verification, deactivated, deleted")
    if email == root_sub:
        raise CliPolicyError(
            "root identity cannot be created/modified through admin command paths",
            details={"code": "root_immutable", "target_user_sub": email},
        )

    existing = T.users.get_item(Key={"user_sub": email}).get("Item") or {}
    if existing:
        raise ValueError("target user already exists")

    raw_password = str(getattr(args, "password", "") or "")
    generated_password = ""
    if not raw_password:
        generated_password = secrets.token_urlsafe(18)
        raw_password = generated_password
    if len(raw_password) < 8:
        raise ValueError("password must be at least 8 characters")

    if bool(shared.dry_run):
        return {
            "ok": True,
            "group": str(args.group),
            "command": str(args.command),
            "dry_run": True,
            "actor_sub": actor_sub,
            "target_user_sub": email,
            "role": Role.ADMIN.value,
            "status": status,
            "reason": reason,
            "ticket": ticket,
            "request_id": shared.request_id,
            "correlation_id": shared.correlation_id,
            "message": "dry-run: admin user would be created and admin role granted",
        }

    created_at = now_ts()
    created_user = False
    try:
        T.users.put_item(
            Item={
                "user_sub": email,
                "email": email,
                "full_name": full_name,
                "password_hash": _hash_password(raw_password),
                "role": Role.USER.value,
                "created_at": created_at,
                "created_by": actor_sub,
                "created_reason": reason,
            },
            ConditionExpression="attribute_not_exists(user_sub)",
        )
        created_user = True
        T.account_state.put_item(
            Item={
                "user_sub": email,
                "status": status,
                "updated_at": created_at,
                "reason": "rootctl_admin_create",
                "requested_by": actor_sub,
            }
        )

        T.users.update_item(
            Key={"user_sub": email},
            UpdateExpression="SET #role=:role, role_updated_at=:ts, role_updated_by=:by, role_reason=:reason",
            ExpressionAttributeNames={"#role": "role"},
            ExpressionAttributeValues={
                ":role": Role.ADMIN.value,
                ":ts": now_ts(),
                ":by": actor_sub,
                ":reason": reason,
            },
        )
        event = _persist_role_assignment_event_cli(
            actor_sub=actor_sub,
            target_user_sub=email,
            action="grant",
            previous_role=Role.USER,
            new_role=Role.ADMIN,
            reason=reason,
            request_id=shared.request_id,
            correlation_id=shared.correlation_id,
        )
    except Exception as exc:
        rollback_performed = False
        if created_user:
            try:
                T.users.delete_item(Key={"user_sub": email})
                T.account_state.delete_item(Key={"user_sub": email})
                rollback_performed = True
            except Exception:
                rollback_performed = False

        audit_event(
            "admin_create_failed",
            actor_sub,
            None,
            outcome="error",
            actor_sub=actor_sub,
            target_user_sub=email,
            reason=reason,
            ticket_id=ticket,
            request_id=shared.request_id,
            correlation_id=shared.correlation_id,
            rollback_performed=rollback_performed,
            cli=True,
        )
        raise RuntimeError("admin create failed; rollback attempted") from exc

    audit_event(
        "admin_created_cli",
        actor_sub,
        None,
        outcome="success",
        actor_sub=actor_sub,
        target_user_sub=email,
        role=Role.ADMIN.value,
        reason=reason,
        ticket_id=ticket,
        role_audit_event_id=event["event_id"],
        request_id=shared.request_id,
        correlation_id=shared.correlation_id,
        cli=True,
    )

    payload = {
        "ok": True,
        "group": str(args.group),
        "command": str(args.command),
        "dry_run": False,
        "actor_sub": actor_sub,
        "target_user_sub": email,
        "role": Role.ADMIN.value,
        "status": status,
        "reason": reason,
        "ticket": ticket,
        "event_id": event["event_id"],
        "request_id": shared.request_id,
        "correlation_id": shared.correlation_id,
        "audit_event": "admin_created_cli",
    }
    if generated_password:
        payload["generated_password"] = generated_password
    return payload


def _admin_permissions_set_command(args: argparse.Namespace) -> Dict[str, Any]:
    if not _admin_capabilities_enabled():
        raise CliPolicyError(
            "admin capability commands are disabled",
            details={"code": "feature_disabled", "feature_flag": ADMIN_CAPABILITY_FEATURE_FLAG},
        )

    shared = _shared_opts(args)
    root_sub = str(getattr(args, "root_sub", "") or "").strip()
    actor_sub = str(getattr(args, "actor_sub", "") or "").strip()
    reason = str(getattr(args, "reason", "") or "").strip()
    ticket = str(getattr(args, "ticket", "") or "").strip()
    target_user_sub = str(getattr(args, "target_user_sub", "") or "").strip()

    target = _require_existing_non_root_user(target_user_sub, root_sub=root_sub)
    target_role = normalize_role(target.get("role"))
    if target_role is not Role.ADMIN:
        raise CliPolicyError(
            "capabilities can be set only for admin users",
            details={"code": "invalid_role_transition", "target_role": target_role.value, "target_user_sub": target_user_sub},
        )

    new_caps = _parse_capabilities(list(getattr(args, "capability", []) or []))
    old_caps = _parse_capabilities(list(target.get("admin_capabilities", []) or []))

    if bool(shared.dry_run):
        return {
            "ok": True,
            "group": str(args.group),
            "command": str(args.command),
            "permissions_command": str(getattr(args, "permissions_command", "")),
            "dry_run": True,
            "actor_sub": actor_sub,
            "target_user_sub": target_user_sub,
            "old_capabilities": old_caps,
            "new_capabilities": new_caps,
            "reason": reason,
            "ticket": ticket,
            "request_id": shared.request_id,
            "correlation_id": shared.correlation_id,
            "message": "dry-run: admin capabilities would be updated",
        }

    ts = now_ts()
    T.users.update_item(
        Key={"user_sub": target_user_sub},
        UpdateExpression="SET admin_capabilities=:caps, admin_caps_updated_at=:ts, admin_caps_updated_by=:by, admin_caps_reason=:reason, admin_caps_ticket=:ticket",
        ExpressionAttributeValues={
            ":caps": new_caps,
            ":ts": ts,
            ":by": actor_sub,
            ":reason": reason,
            ":ticket": ticket,
        },
    )

    audit_event(
        "admin_capabilities_updated_cli",
        actor_sub,
        None,
        outcome="success",
        actor_sub=actor_sub,
        target_user_sub=target_user_sub,
        old_capabilities=old_caps,
        new_capabilities=new_caps,
        reason=reason,
        ticket_id=ticket,
        request_id=shared.request_id,
        correlation_id=shared.correlation_id,
        cli=True,
    )

    return {
        "ok": True,
        "group": str(args.group),
        "command": str(args.command),
        "permissions_command": str(getattr(args, "permissions_command", "")),
        "dry_run": False,
        "actor_sub": actor_sub,
        "target_user_sub": target_user_sub,
        "old_capabilities": old_caps,
        "new_capabilities": new_caps,
        "reason": reason,
        "ticket": ticket,
        "request_id": shared.request_id,
        "correlation_id": shared.correlation_id,
        "audit_event": "admin_capabilities_updated_cli",
    }


def _admin_permissions_list_command(args: argparse.Namespace) -> Dict[str, Any]:
    if not _admin_capabilities_enabled():
        raise CliPolicyError(
            "admin capability commands are disabled",
            details={"code": "feature_disabled", "feature_flag": ADMIN_CAPABILITY_FEATURE_FLAG},
        )

    target_user_sub = str(getattr(args, "target_user_sub", "") or "").strip()
    item = T.users.get_item(Key={"user_sub": target_user_sub}).get("Item") or {}
    if not item:
        raise ValueError("target user not found")
    role = normalize_role(item.get("role"))
    caps = _parse_capabilities(list(item.get("admin_capabilities", []) or []))
    return {
        "ok": True,
        "group": str(args.group),
        "command": str(args.command),
        "permissions_command": str(getattr(args, "permissions_command", "")),
        "target_user_sub": target_user_sub,
        "role": role.value,
        "capabilities": caps,
        "feature_flag": ADMIN_CAPABILITY_FEATURE_FLAG,
    }


def _timeline_matches_filters(
    item: Dict[str, Any],
    *,
    actor_sub: str,
    target_user_sub: str,
    event_filter: str,
    correlation_filter: str,
    start_ts: int,
    end_ts: int,
) -> bool:
    ts = int(item.get("ts") or 0)
    if ts < start_ts or ts > end_ts:
        return False
    if actor_sub and str(item.get("actor_sub") or "") != actor_sub:
        return False
    if target_user_sub and str(item.get("target_user_sub") or "") != target_user_sub:
        return False
    if event_filter:
        event_value = str(item.get("event") or "")
        action_value = str(item.get("action") or "")
        if event_filter not in {event_value, action_value}:
            return False
    if correlation_filter and str(item.get("correlation_id") or "") != correlation_filter:
        return False
    return True


def _role_timeline_command(args: argparse.Namespace) -> Dict[str, Any]:
    actor_filter = str(getattr(args, "actor_sub", "") or "").strip()
    target_filter = str(getattr(args, "target_user_sub", "") or "").strip()
    event_filter = str(getattr(args, "event", "") or "").strip()
    correlation_filter = str(getattr(args, "correlation_id", "") or "").strip()
    start_ts = int(getattr(args, "start_ts", 0) or 0)
    end_ts = int(getattr(args, "end_ts", now_ts()) or now_ts())
    limit = int(getattr(args, "limit", 50) or 50)
    if start_ts > end_ts:
        raise ValueError("start_ts must be <= end_ts")
    if limit < 1 or limit > 200:
        raise ValueError("limit must be between 1 and 200")

    cursor = str(getattr(args, "cursor", "") or "").strip()
    eks = decode_cursor(cursor) if cursor else None
    if cursor and not eks:
        raise ValueError("invalid cursor")

    if actor_filter:
        sk_start = f"TS#{int(start_ts):013d}"
        sk_end = f"TS#{int(end_ts):013d}~"
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("pk").eq(f"ACTOR#{actor_filter}") & Key("sk").between(sk_start, sk_end),
            "ScanIndexForward": False,
            "Limit": limit,
        }
        if eks:
            kwargs["ExclusiveStartKey"] = eks
        resp = T.role_audit.query(**kwargs)
        raw = resp.get("Items", [])
        last_key = resp.get("LastEvaluatedKey")
    else:
        kwargs2: Dict[str, Any] = {"Limit": limit}
        if eks:
            kwargs2["ExclusiveStartKey"] = eks
        resp = T.role_audit.scan(**kwargs2)
        raw = resp.get("Items", [])
        last_key = resp.get("LastEvaluatedKey")

    out = []
    for it in raw:
        row = {
            "event_id": it.get("event_id"),
            "ts": int(it.get("ts") or 0),
            "event": "role_assignment",
            "action": str(it.get("action") or ""),
            "actor_sub": str(it.get("actor_sub") or ""),
            "target_user_sub": str(it.get("target_user_sub") or ""),
            "previous_role": str(it.get("previous_role") or ""),
            "new_role": str(it.get("new_role") or ""),
            "reason": str(it.get("reason") or ""),
            "request_id": str(it.get("request_id") or ""),
            "correlation_id": str(it.get("correlation_id") or ""),
        }
        if _timeline_matches_filters(
            row,
            actor_sub=actor_filter,
            target_user_sub=target_filter,
            event_filter=event_filter,
            correlation_filter=correlation_filter,
            start_ts=start_ts,
            end_ts=end_ts,
        ):
            out.append(row)

    return {
        "ok": True,
        "group": str(args.group),
        "command": str(args.command),
        "timeline": "role",
        "items": out,
        "count": len(out),
        "cursor": encode_cursor(last_key),
    }


def _sanitize_for_json(obj: Any) -> Any:
    """Recursively convert DDB Decimal values to int/float so json.dumps works."""
    from decimal import Decimal
    if isinstance(obj, Decimal):
        return int(obj) if obj == obj.to_integral_value() else float(obj)
    if isinstance(obj, dict):
        return {k: _sanitize_for_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_for_json(i) for i in obj]
    return obj


def _alerts_event_matches_timeline(details: Dict[str, Any], timeline: str) -> bool:
    event = str(details.get("event") or "")
    if timeline == "impersonation":
        return event.startswith("impersonation_") or bool(details.get("impersonation"))
    if timeline == "file":
        return event.startswith(("fs_", "file_", "shared_")) or bool(details.get("file_path"))
    # security timeline
    return event.startswith(("root_", "admin_", "mfa_", "ui_session_", "api_key_", "device_", "alerts_"))


def _alerts_timeline_command(args: argparse.Namespace) -> Dict[str, Any]:
    timeline = str(getattr(args, "timeline", "") or "").strip()
    actor_filter = str(getattr(args, "actor_sub", "") or "").strip()
    target_filter = str(getattr(args, "target_user_sub", "") or "").strip()
    event_filter = str(getattr(args, "event", "") or "").strip()
    correlation_filter = str(getattr(args, "correlation_id", "") or "").strip()
    start_ts = int(getattr(args, "start_ts", 0) or 0)
    end_ts = int(getattr(args, "end_ts", now_ts()) or now_ts())
    limit = int(getattr(args, "limit", 50) or 50)
    if start_ts > end_ts:
        raise ValueError("start_ts must be <= end_ts")
    if limit < 1 or limit > 200:
        raise ValueError("limit must be between 1 and 200")

    cursor = str(getattr(args, "cursor", "") or "").strip()
    eks = decode_cursor(cursor) if cursor else None
    if cursor and not eks:
        raise ValueError("invalid cursor")

    kwargs: Dict[str, Any] = {"Limit": limit}
    if eks:
        kwargs["ExclusiveStartKey"] = eks
    resp = T.alerts.scan(**kwargs)
    raw = resp.get("Items", [])
    last_key = resp.get("LastEvaluatedKey")

    out = []
    for it in raw:
        details = it.get("details") if isinstance(it.get("details"), dict) else {}
        if not _alerts_event_matches_timeline(details, timeline):
            continue
        row = {
            "alert_id": it.get("alert_id"),
            "ts": int(details.get("ts") or it.get("ts") or 0),
            "event": str(details.get("event") or it.get("event") or ""),
            "outcome": str(details.get("outcome") or it.get("outcome") or ""),
            "actor_sub": str(details.get("actor_sub") or ""),
            "target_user_sub": str(details.get("target_user_sub") or ""),
            "user_sub": str(details.get("user_sub") or it.get("user_sub") or ""),
            "request_id": str(details.get("request_id") or ""),
            "correlation_id": str(details.get("correlation_id") or ""),
            "details": _sanitize_for_json(details),
        }
        if _timeline_matches_filters(
            row,
            actor_sub=actor_filter,
            target_user_sub=target_filter,
            event_filter=event_filter,
            correlation_filter=correlation_filter,
            start_ts=start_ts,
            end_ts=end_ts,
        ):
            out.append(row)

    return {
        "ok": True,
        "group": str(args.group),
        "command": str(args.command),
        "timeline": timeline,
        "items": out,
        "count": len(out),
        "cursor": encode_cursor(last_key),
    }


def _placeholder_mutation_command(args: argparse.Namespace) -> Dict[str, Any]:
    shared = _shared_opts(args)
    return {
        "ok": True,
        "group": str(args.group),
        "command": str(args.command),
        "dry_run": shared.dry_run,
        "request_id": shared.request_id,
        "correlation_id": shared.correlation_id,
        "actor_sub": str(getattr(args, "actor_sub", "") or ""),
        "target_user_sub": str(getattr(args, "target_user_sub", "") or ""),
        "requested_role": str(getattr(args, "role", "") or ""),
        "reason": str(getattr(args, "reason", "") or ""),
        "ticket": str(getattr(args, "ticket", "") or ""),
        "message": f"{args.group} {args.command} command scaffold is policy-guarded",
    }


def _rotate_secrets_command(args: argparse.Namespace) -> Dict[str, Any]:
    """Rotate signing secrets (UI_ACCESS_TOKEN_SECRET, API_KEY_PEPPER,
    WS_TOKEN_SECRET) and the KMS break-glass key (GAP-0345).

    Generates new cryptographically-strong values, persists them to the active
    secret store (``.env.local`` in dev, AWS Secrets Manager in prod), rotates
    the KMS break-glass key best-effort, revokes all active root sessions/API
    keys, and writes an immutable audit record. SECURITY: never returns or logs
    the raw secret values — only the rotated secret NAMES and identifiers.
    """
    from app.services import secret_rotation

    shared = _shared_opts(args)
    root_sub = _validate_preflight(args)

    scope = str(getattr(args, "scope", "all") or "all").strip() or "all"
    if scope not in secret_rotation.VALID_SCOPES:
        raise ValueError(
            "invalid scope; choose from: "
            + ", ".join(sorted(secret_rotation.VALID_SCOPES))
        )

    reason = str(getattr(args, "reason", "") or "").strip()
    ticket = str(getattr(args, "ticket", "") or "").strip()
    actor_sub = str(getattr(args, "actor_sub", "") or "").strip()

    new_values = secret_rotation.generate_new_secrets(scope)
    rotated_env_keys = sorted(new_values.keys())

    if shared.dry_run:
        kms_descr = {"rotated": False, "reason": "dry_run"}
        return {
            "ok": True,
            "group": str(args.group),
            "command": str(args.command),
            "dry_run": True,
            "scope": scope,
            "would_rotate": rotated_env_keys,
            "kms": kms_descr,
            "actor_sub": actor_sub,
            "request_id": shared.request_id,
            "correlation_id": shared.correlation_id,
        }

    # Persist the new secret values to the active store (env file / SM).
    persistence = secret_rotation.persist_secrets(new_values)

    # Rotate the KMS break-glass key (best-effort).
    kms_result = secret_rotation.rotate_kms_break_glass_key()

    rotated: Dict[str, Any] = {"secrets": rotated_env_keys}
    if "API_KEY_PEPPER" in new_values:
        rotated["api_keys_invalidated"] = (
            "All API key hashes are now stale; keys must be re-issued."
        )

    # Invalidate active root sessions/API keys so the old secret can't be used.
    sessions_revoked = False
    api_keys_revoked = False
    if "UI_ACCESS_TOKEN_SECRET" in new_values:
        try:
            revoke_all_sessions(root_sub)
            sessions_revoked = True
        except Exception:
            sessions_revoked = False
    if "API_KEY_PEPPER" in new_values:
        try:
            revoke_all_api_keys(root_sub)
            api_keys_revoked = True
        except Exception:
            api_keys_revoked = False

    ts = now_ts()
    audit_event(
        "rotate_secrets",
        root_sub,
        None,
        outcome="success",
        actor_sub=actor_sub,
        scope=scope,
        rotated_secrets=rotated_env_keys,
        kms_rotated=bool(kms_result.get("rotated", False)),
        kms_key_id=str(kms_result.get("key_id", "") or ""),
        persistence_backend=str(persistence.get("backend", "") or ""),
        sessions_revoked=sessions_revoked,
        api_keys_revoked=api_keys_revoked,
        reason=reason,
        ticket_id=ticket,
        request_id=shared.request_id,
        correlation_id=shared.correlation_id,
        cli=True,
    )

    return {
        "ok": True,
        "group": str(args.group),
        "command": str(args.command),
        "dry_run": False,
        "scope": scope,
        "rotated": rotated,
        "rotated_secrets": rotated_env_keys,
        "kms": kms_result,
        "persistence_backend": str(persistence.get("backend", "") or ""),
        "sessions_revoked": sessions_revoked,
        "api_keys_revoked": api_keys_revoked,
        "actor_sub": actor_sub,
        "reason": reason,
        "ticket": ticket,
        "request_id": shared.request_id,
        "correlation_id": shared.correlation_id,
        "audit_event": "rotate_secrets",
        "ts": ts,
        "note": "Backend processes must be restarted to pick up the new secret values.",
    }


_BREAK_GLASS_ENV = "ROOTCTL_BREAK_GLASS_SECRET"
_BREAK_GLASS_TOKEN_ENV = "ROOTCTL_BREAK_GLASS_TOKEN"


def _break_glass_expected_secret() -> str:
    """Resolve the configured break-glass secret.

    Prefers the live environment variable (prod injects it from Secrets Manager
    immediately before the command; same code path applies in dev where it is a
    well-known value in .env.local). Falls back to the Settings singleton so
    callers that load config through Settings stay consistent.
    """
    value = (os.environ.get(_BREAK_GLASS_ENV, "") or "").strip()
    if value:
        return value
    try:
        from app.core.settings import S

        return (getattr(S, "rootctl_break_glass_secret", "") or "").strip()
    except Exception:
        return ""


def _require_break_glass_auth() -> None:
    """Verify the break-glass secret before any mutating CLI command.

    The expected secret is read from ROOTCTL_BREAK_GLASS_SECRET (env/settings).
    The operator-supplied token is read from ROOTCTL_BREAK_GLASS_TOKEN (env, for
    non-interactive CI/CD) or prompted interactively via getpass. Comparison uses
    hmac.compare_digest to avoid timing leaks. This is additive: it runs in
    addition to (not instead of) the existing reason/ticket/confirm/actor guards.
    """
    expected = _break_glass_expected_secret()
    if not expected:
        raise CliPolicyError(
            f"{_BREAK_GLASS_ENV} is not configured; CLI mutations are disabled. "
            "Set the environment variable to enable break-glass operations.",
            details={"code": "break_glass_unconfigured"},
        )

    provided = (os.environ.get(_BREAK_GLASS_TOKEN_ENV, "") or "").strip()
    if not provided:
        try:
            provided = getpass.getpass(
                "Break-glass secret (or set ROOTCTL_BREAK_GLASS_TOKEN): "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            provided = ""

    if not provided:
        raise CliPolicyError(
            "break-glass authentication failed: no token provided",
            details={"code": "break_glass_no_token"},
        )

    if not hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8")):
        raise CliPolicyError(
            "break-glass authentication failed: invalid token",
            details={"code": "break_glass_auth_failed"},
        )


def _validate_preflight(args: argparse.Namespace) -> str:
    try:
        root_sub = validate_root_user_sub_config()
    except RuntimeError as exc:
        raise ValueError(str(exc)) from exc

    if not bool(getattr(args, "mutating", False)):
        return root_sub

    _require_break_glass_auth()

    reason = str(getattr(args, "reason", "") or "").strip()
    if not reason:
        raise ValueError("reason is required for mutating commands")

    if bool(getattr(args, "requires_ticket", False)):
        ticket = str(getattr(args, "ticket", "") or "").strip()
        if not ticket:
            raise ValueError("ticket is required for high-risk commands")

    if bool(getattr(args, "requires_confirm", False)):
        confirm = str(getattr(args, "confirm", "") or "").strip()
        expected = str(getattr(args, "confirm_expected", "") or "").strip()
        if not confirm:
            raise ValueError("confirm is required for destructive commands")
        if not expected or confirm != expected:
            raise ValueError(f"confirm must match expected value: {expected}")

    actor_sub = str(getattr(args, "actor_sub", "") or "").strip()
    if not actor_sub:
        raise ValueError("actor_sub is required for mutating commands")

    if bool(getattr(args, "requires_root", False)) and actor_sub != root_sub:
        raise CliPolicyError(
            "root actor required for mutating command",
            details={
                "code": "role_required",
                "required_roles": ["root"],
                "actual_actor_sub": actor_sub,
            },
        )

    requested_role = str(getattr(args, "role", "") or "").strip().lower()
    if requested_role == "root":
        raise CliPolicyError(
            "root role is immutable and cannot be assigned via CLI mutation command",
            details={"code": "root_immutable", "requested_role": "root"},
        )

    target_user_sub = str(getattr(args, "target_user_sub", "") or "").strip()
    if str(getattr(args, "group", "")) in {"user", "admin"} and target_user_sub == root_sub:
        raise CliPolicyError(
            "root identity cannot be mutated through user/admin command paths",
            details={"code": "root_immutable", "target_user_sub": target_user_sub},
        )

    return root_sub


def _add_shared_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output", choices=("table", "json"), default="table", help="Output format")
    parser.add_argument("--dry-run", action="store_true", help="Do not execute state changes")
    parser.add_argument("--request-id", default="", help="Operator request id for auditing")
    parser.add_argument("--correlation-id", default="", help="Correlation id for multi-step/bulk operations")


def _add_mutation_guard_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--actor-sub", default="", help="Acting principal subject")
    parser.add_argument("--reason", default="", help="Human-readable reason for privileged mutation")
    parser.add_argument("--ticket", default="", help="Incident/change ticket for high-risk actions")
    parser.add_argument("--confirm", default="", help="Destructive command confirmation challenge")


def _add_group_commands(group_name: str, group_parser: argparse.ArgumentParser) -> None:
    commands = group_parser.add_subparsers(dest="command", required=True)

    status = commands.add_parser("status", help=f"Show {group_name} CLI command framework status")
    _add_shared_options(status)
    status.set_defaults(handler=_status_command, group=group_name, mutating=False, requires_root=False)

    if group_name == "root":
        reset_password = commands.add_parser("reset-password", help="Reset immutable root password")
        _add_shared_options(reset_password)
        _add_mutation_guard_options(reset_password)
        reset_password.add_argument("--target-user-sub", default="", help="Optional target user subject (must resolve to root)")
        reset_password.add_argument("--new-password", default="", help="New password (avoid shell history; prefer prompt/stdin)")
        reset_password.add_argument("--password-stdin", action="store_true", help="Read new password from stdin")
        reset_password.set_defaults(
            handler=_root_reset_password_command,
            group=group_name,
            mutating=True,
            requires_root=True,
            requires_ticket=True,
            requires_confirm=False,
        )

        reset_mfa = commands.add_parser("reset-mfa", help="Reset immutable root MFA factors")
        _add_shared_options(reset_mfa)
        _add_mutation_guard_options(reset_mfa)
        reset_mfa.add_argument("--target-user-sub", default="", help="Optional target user subject (must resolve to root)")
        reset_mfa.add_argument("--factor", default="all", choices=("all", "totp", "sms", "email"), help="MFA factor scope to reset")
        reset_mfa.set_defaults(
            handler=_root_reset_mfa_command,
            group=group_name,
            mutating=True,
            requires_root=True,
            requires_ticket=True,
            requires_confirm=False,
        )

        set_verification = commands.add_parser("set-verification", help="Set root email/phone verification states")
        _add_shared_options(set_verification)
        _add_mutation_guard_options(set_verification)
        set_verification.add_argument("--target-user-sub", default="", help="Optional target user subject (must resolve to root)")
        set_verification.add_argument("--email", default="", help="Set email verification state: verified|unverified")
        set_verification.add_argument("--phone", default="", help="Set phone verification state: verified|unverified")
        set_verification.set_defaults(
            handler=_root_set_verification_command,
            group=group_name,
            mutating=True,
            requires_root=True,
            requires_ticket=True,
            requires_confirm=False,
        )

        set_email = commands.add_parser("set-email", help="Set root account email/security contact metadata")
        _add_shared_options(set_email)
        _add_mutation_guard_options(set_email)
        set_email.add_argument("--target-user-sub", default="", help="Optional target user subject (must resolve to root)")
        set_email.add_argument("--email", required=True, help="New root email address")
        set_email.add_argument("--verify", action="store_true", help="Mark root email as verified")
        set_email.set_defaults(
            handler=_root_set_email_command,
            group=group_name,
            mutating=True,
            requires_root=True,
            requires_ticket=True,
            requires_confirm=False,
        )

        set_security_profile = commands.add_parser("set-security-profile", help="Update root security metadata flags")
        _add_shared_options(set_security_profile)
        _add_mutation_guard_options(set_security_profile)
        set_security_profile.add_argument("--target-user-sub", default="", help="Optional target user subject (must resolve to root)")
        set_security_profile.add_argument("--force-password-rotate", default="", help="Set force password rotation: true|false")
        set_security_profile.add_argument("--recovery-lockdown", default="", help="Set recovery lockdown flag: true|false")
        set_security_profile.add_argument("--security-note", default="", help="Operator security note (max 512 chars)")
        set_security_profile.set_defaults(
            handler=_root_set_security_profile_command,
            group=group_name,
            mutating=True,
            requires_root=True,
            requires_ticket=True,
            requires_confirm=False,
        )

        rotate = commands.add_parser("rotate-secrets", help="Rotate signing secrets and KMS break-glass key")
        _add_shared_options(rotate)
        _add_mutation_guard_options(rotate)
        rotate.add_argument(
            "--scope",
            default="all",
            choices=("all", "ui_access_token", "api_key_pepper", "ws_token"),
            help="Which secrets to rotate (default: all)",
        )
        rotate.set_defaults(
            handler=_rotate_secrets_command,
            group=group_name,
            mutating=True,
            requires_root=True,
            requires_ticket=True,
            requires_confirm=False,
        )

    if group_name == "user":
        create = commands.add_parser("create", help="Create a non-root user")
        _add_shared_options(create)
        _add_mutation_guard_options(create)
        create.add_argument("--email", required=True, help="User email address")
        create.add_argument("--full-name", default="", help="User full name")
        create.add_argument("--password", default="", help="Initial password (if omitted, generate one)")
        create.add_argument("--role", default="user", choices=("user", "admin"), help="Initial role (default: user)")
        create.add_argument(
            "--status",
            default="active",
            choices=("active", "pending_verification", "deactivated", "deleted"),
            help="Initial account status",
        )
        create.set_defaults(
            handler=_user_create_command,
            group=group_name,
            mutating=True,
            requires_root=True,
            requires_ticket=False,
            requires_confirm=False,
        )

        list_cmd = commands.add_parser("list", help="List users with filtering and cursor pagination")
        _add_shared_options(list_cmd)
        list_cmd.add_argument("--role", default="", choices=("", "user", "admin", "root"), help="Filter by role")
        list_cmd.add_argument(
            "--status",
            default="",
            choices=("", "active", "pending_verification", "deactivated", "deleted"),
            help="Filter by account status",
        )
        list_cmd.add_argument("--limit", type=int, default=50, help="Page size (1-200)")
        list_cmd.add_argument("--cursor", default="", help="Pagination cursor")
        list_cmd.set_defaults(
            handler=_user_list_command,
            group=group_name,
            mutating=False,
            requires_root=False,
            requires_confirm=False,
        )

        verify = commands.add_parser("verify", help="Update user email/phone verification flags")
        _add_shared_options(verify)
        _add_mutation_guard_options(verify)
        verify.add_argument("--target-user-sub", required=True, help="Target user subject")
        verify.add_argument("--email", default="", help="Set email verification state: verified|unverified")
        verify.add_argument("--phone", default="", help="Set phone verification state: verified|unverified")
        verify.set_defaults(
            handler=_user_verify_command,
            group=group_name,
            mutating=True,
            requires_root=True,
            requires_ticket=False,
            requires_confirm=False,
        )

        set_password = commands.add_parser("set-password", help="Set user password and revoke user sessions")
        _add_shared_options(set_password)
        _add_mutation_guard_options(set_password)
        set_password.add_argument("--target-user-sub", required=True, help="Target user subject")
        set_password.add_argument("--new-password", default="", help="New password (avoid shell history; prefer prompt/stdin)")
        set_password.add_argument("--password-stdin", action="store_true", help="Read new password from stdin")
        set_password.set_defaults(
            handler=_user_set_password_command,
            group=group_name,
            mutating=True,
            requires_root=True,
            requires_ticket=True,
            requires_confirm=False,
        )

        deactivate = commands.add_parser("deactivate", help="Deactivate user and revoke sessions/api keys")
        _add_shared_options(deactivate)
        _add_mutation_guard_options(deactivate)
        deactivate.add_argument("--target-user-sub", required=True, help="Target user subject")
        deactivate.set_defaults(
            handler=_user_deactivate_command,
            group=group_name,
            mutating=True,
            requires_root=True,
            requires_ticket=True,
            requires_confirm=True,
        )

        deactivate_bulk = commands.add_parser("deactivate-bulk", help="Deactivate multiple users and emit per-target results")
        _add_shared_options(deactivate_bulk)
        _add_mutation_guard_options(deactivate_bulk)
        deactivate_bulk.add_argument(
            "--target-user-sub",
            action="append",
            default=[],
            help="Target user subject (repeat flag for multiple targets)",
        )
        deactivate_bulk.set_defaults(
            handler=_user_deactivate_bulk_command,
            group=group_name,
            mutating=True,
            requires_root=True,
            requires_ticket=True,
            requires_confirm=False,
        )

        delete = commands.add_parser("delete", help="Delete user (soft delete by default; optional hard delete)")
        _add_shared_options(delete)
        _add_mutation_guard_options(delete)
        delete.add_argument("--target-user-sub", required=True, help="Target user subject")
        delete.add_argument("--hard-delete", action="store_true", help="Permanently remove user and account state")
        delete.set_defaults(
            handler=_user_delete_command,
            group=group_name,
            mutating=True,
            requires_root=True,
            requires_ticket=True,
            requires_confirm=True,
        )

    if group_name == "admin":
        create = commands.add_parser("create", help="Create a new admin user in one controlled flow")
        _add_shared_options(create)
        _add_mutation_guard_options(create)
        create.add_argument("--email", required=True, help="Admin user email address")
        create.add_argument("--full-name", default="", help="Admin user full name")
        create.add_argument("--password", default="", help="Initial password (if omitted, generate one)")
        create.add_argument(
            "--status",
            default="active",
            choices=("active", "pending_verification", "deactivated", "deleted"),
            help="Initial account status",
        )
        create.set_defaults(
            handler=_admin_create_command,
            group=group_name,
            mutating=True,
            requires_root=True,
            requires_ticket=False,
            requires_confirm=False,
        )

        grant = commands.add_parser("grant", help="Grant admin role to target user")
        _add_shared_options(grant)
        _add_mutation_guard_options(grant)
        grant.add_argument("--target-user-sub", required=True, help="Target user subject")
        grant.add_argument("--role", default="admin", choices=("admin", "root"), help="Role to grant")
        grant.add_argument(
            "--capability",
            action="append",
            default=[],
            metavar="CAPABILITY",
            help=(
                "Admin capability to assign (repeatable). Allowed: "
                + ", ".join(sorted(ADMIN_CAPABILITIES))
                + ". Omit to create a general (full-access) admin."
            ),
        )
        grant.set_defaults(
            handler=_admin_grant_command,
            group=group_name,
            mutating=True,
            requires_root=True,
            requires_ticket=False,
            requires_confirm=False,
        )

        revoke = commands.add_parser("revoke", help="Revoke admin role from target user")
        _add_shared_options(revoke)
        _add_mutation_guard_options(revoke)
        revoke.add_argument("--target-user-sub", required=True, help="Target user subject")
        revoke.add_argument("--role", default="admin", choices=("admin", "root"), help="Role to revoke")
        revoke.set_defaults(
            handler=_admin_revoke_command,
            group=group_name,
            mutating=True,
            requires_root=True,
            requires_ticket=False,
            requires_confirm=False,
        )

        permissions = commands.add_parser("permissions", help="Manage granular admin capabilities")
        permissions_sub = permissions.add_subparsers(dest="permissions_command", required=True)

        permissions_list = permissions_sub.add_parser("list", help="List admin capabilities for a user")
        _add_shared_options(permissions_list)
        permissions_list.add_argument("--target-user-sub", required=True, help="Target user subject")
        permissions_list.set_defaults(
            handler=_admin_permissions_list_command,
            group=group_name,
            command="permissions",
            mutating=False,
            requires_root=False,
            requires_confirm=False,
        )

        permissions_set = permissions_sub.add_parser("set", help="Set exact admin capabilities for a user")
        _add_shared_options(permissions_set)
        _add_mutation_guard_options(permissions_set)
        permissions_set.add_argument("--target-user-sub", required=True, help="Target user subject")
        permissions_set.add_argument(
            "--capability",
            action="append",
            default=[],
            help="Capability to include (repeatable). Allowed: " + ", ".join(sorted(ADMIN_CAPABILITIES)),
        )
        permissions_set.set_defaults(
            handler=_admin_permissions_set_command,
            group=group_name,
            command="permissions",
            mutating=True,
            requires_root=True,
            requires_ticket=False,
            requires_confirm=False,
        )

    if group_name == "audit":
        role_timeline = commands.add_parser("role", help="Query role assignment timeline")
        _add_shared_options(role_timeline)
        role_timeline.add_argument("--actor-sub", default="", help="Filter by actor subject")
        role_timeline.add_argument("--target-user-sub", default="", help="Filter by target user subject")
        role_timeline.add_argument("--event", default="", help="Filter by action/event value")
        role_timeline.add_argument("--start-ts", type=int, default=0, help="Start timestamp (inclusive)")
        role_timeline.add_argument("--end-ts", type=int, default=0, help="End timestamp (inclusive; 0 => now)")
        role_timeline.add_argument("--limit", type=int, default=50, help="Page size (1-200)")
        role_timeline.add_argument("--cursor", default="", help="Pagination cursor")
        role_timeline.set_defaults(
            handler=_role_timeline_command,
            group=group_name,
            mutating=False,
            requires_root=False,
            requires_confirm=False,
        )

        for timeline in ("impersonation", "file", "security"):
            cmd = commands.add_parser(timeline, help=f"Query {timeline} event timeline")
            _add_shared_options(cmd)
            cmd.add_argument("--actor-sub", default="", help="Filter by actor subject")
            cmd.add_argument("--target-user-sub", default="", help="Filter by target user subject")
            cmd.add_argument("--event", default="", help="Filter by exact event name")
            cmd.add_argument("--start-ts", type=int, default=0, help="Start timestamp (inclusive)")
            cmd.add_argument("--end-ts", type=int, default=0, help="End timestamp (inclusive; 0 => now)")
            cmd.add_argument("--limit", type=int, default=50, help="Page size (1-200)")
            cmd.add_argument("--cursor", default="", help="Pagination cursor")
            cmd.set_defaults(
                handler=_alerts_timeline_command,
                group=group_name,
                timeline=timeline,
                mutating=False,
                requires_root=False,
                requires_confirm=False,
            )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rootctl",
        description="Server-side break-glass root CLI",
    )
    subparsers = parser.add_subparsers(dest="group", required=True)

    root_parser = subparsers.add_parser("root", help="Root recovery/security operations")
    _add_group_commands("root", root_parser)

    user_parser = subparsers.add_parser("user", help="User lifecycle operations")
    _add_group_commands("user", user_parser)

    admin_parser = subparsers.add_parser("admin", help="Admin lifecycle operations")
    _add_group_commands("admin", admin_parser)

    audit_parser = subparsers.add_parser("audit", help="Audit query operations")
    _add_group_commands("audit", audit_parser)

    return parser


def _run_with_args(args: argparse.Namespace) -> ExitCode:
    output = str(getattr(args, "output", "table") or "table")
    handler = getattr(args, "handler", None)
    if handler is None:
        _emit_error(
            "no command handler selected",
            code=ExitCode.VALIDATION_ERROR,
            output=output,
        )
        return ExitCode.VALIDATION_ERROR

    if bool(getattr(args, "requires_confirm", False)):
        setattr(args, "confirm_expected", str(getattr(args, "target_user_sub", "") or "").strip())

    try:
        root_sub = _validate_preflight(args)
        setattr(args, "root_sub", root_sub)
        payload = handler(args)
        _emit(payload, output=output)
        return ExitCode.SUCCESS
    except CliPolicyError as exc:
        _emit_error(str(exc), code=ExitCode.AUTHZ_ERROR, output=output, details=exc.details)
        return ExitCode.AUTHZ_ERROR
    except PermissionError as exc:
        _emit_error(str(exc) or "forbidden", code=ExitCode.AUTHZ_ERROR, output=output)
        return ExitCode.AUTHZ_ERROR
    except ValueError as exc:
        _emit_error(str(exc) or "invalid arguments", code=ExitCode.VALIDATION_ERROR, output=output)
        return ExitCode.VALIDATION_ERROR
    except Exception as exc:
        _emit_error(str(exc) or "backend error", code=ExitCode.BACKEND_ERROR, output=output)
        return ExitCode.BACKEND_ERROR


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)
    return int(_run_with_args(args))


if __name__ == "__main__":
    raise SystemExit(main())
