"""Connection Profiles & Quick Connect (INFRA-006).

A *connection profile* is a named, owner-scoped saved connection that bundles
everything needed for one-click ("quick") connect to a host or compute instance:

    - a target reference: either a free-form ``hostname`` or an ``instance_id``
      that points at an EC2 instance owned by the user (see ``ec2_launcher``).
    - the SSH ``port`` and ``username``.
    - which stored SSH key to authenticate with (``ssh_key_id`` referencing the
      key manager — see ``ssh_key_manager``), or password auth.
    - an optional ``bastion_path_id`` referencing a multi-hop bastion path
      (see ``ssh_bastion`` / INFRA-011) to chain the connection through.
    - terminal preferences (cols/rows/font/color scheme).
    - ``is_favorite`` for pinning + ``last_used_at`` for recency ordering.

This module does NOT re-implement the SSH/key/terminal/bastion infrastructure.
It validates references against those existing services and resolves a profile
into a connection descriptor used by the terminal/quick-connect flow.

DynamoDB layout (table ``connection_profiles``):
    PK ``user_sub``
    SK ``PROFILE#{profile_id}``
    GSI ``ByCreatedAt``   (user_sub, created_at:N)
    GSI ``ByLastUsedAt``  (user_sub, last_used_at:N)
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.crypto import kms_decrypt, kms_encrypt
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

# Reuse the existing host/port/username validators from the bastion module so
# validation stays consistent across the compute features.
from app.services.ssh_bastion import (
    InvalidHop,
    validate_host,
    validate_port,
    validate_username,
)

logger = logging.getLogger(__name__)

_VALID_AUTH_METHODS = {"key", "key_ref", "password"}
_VALID_COLOR_SCHEMES = {"dark", "light", "monokai", "solarized", "dracula"}
_VALID_PROTOCOLS = {"ssh", "vnc"}

# Maximum length of a stored VNC/SSH password (plaintext, pre-encryption).
_MAX_PASSWORD_LEN = 256


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ProfileNotFound(Exception):
    """Raised when a connection profile does not exist for the user."""


class ProfileLimitExceeded(Exception):
    """Raised when a user exceeds the maximum number of connection profiles."""


class ProfileValidationError(Exception):
    """Raised when profile input fails validation (bad host/port/field value)."""


class ReferenceNotFound(Exception):
    """Raised when a referenced key / bastion path / instance is not owned/found."""


# ---------------------------------------------------------------------------
# Reference ownership validation (against existing compute services)
# ---------------------------------------------------------------------------

def _assert_key_owned(user_sub: str, ssh_key_id: str) -> None:
    if not ssh_key_id:
        return
    from app.services.ssh_key_manager import get_key_metadata

    if not get_key_metadata(user_sub, ssh_key_id):
        raise ReferenceNotFound(f"SSH key {ssh_key_id} not found")


def _assert_bastion_owned(user_sub: str, bastion_path_id: str) -> None:
    if not bastion_path_id:
        return
    from app.services.ssh_bastion import get_path

    if not get_path(user_sub, bastion_path_id):
        raise ReferenceNotFound(f"Bastion path {bastion_path_id} not found")


def _resolve_instance_host(user_sub: str, instance_id: str) -> Optional[str]:
    """Return the connectable host for an owned instance, or None if not found."""
    if not instance_id:
        return None
    from app.services.ec2_launcher import get_instance

    inst = get_instance(user_sub, instance_id)
    if not inst:
        raise ReferenceNotFound(f"Instance {instance_id} not found")
    # Prefer a public address, fall back to private/internal fields, else the id.
    for field in ("public_ip", "public_dns", "private_ip", "hostname", "host"):
        val = inst.get(field)
        if val:
            return str(val)
    return instance_id


# ---------------------------------------------------------------------------
# Field validation / normalization
# ---------------------------------------------------------------------------

def _validate_terminal(name: str, value: Any, lo: int, hi: int) -> int:
    try:
        v = int(value)
    except (TypeError, ValueError):
        raise ProfileValidationError(f"{name} must be an integer")
    if v < lo or v > hi:
        raise ProfileValidationError(f"{name} must be {lo}-{hi}")
    return v


def _coerce_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _item_to_profile(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "profile_id": item["profile_id"],
        "label": item.get("label", ""),
        "protocol": item.get("protocol", "ssh"),
        "hostname": item.get("hostname", "") or "",
        "instance_id": item.get("instance_id", "") or "",
        "port": _coerce_int(item.get("port"), 22),
        "username": item.get("username", "") or "",
        "auth_method": item.get("auth_method", "key_ref"),
        # SEC-022: never expose the encrypted blob (``password_enc``) or any
        # plaintext password — only whether a password is stored.
        "has_password": bool(item.get("password_enc", "")),
        "ssh_key_id": item.get("ssh_key_id", "") or "",
        "bastion_path_id": item.get("bastion_path_id", "") or "",
        "terminal_cols": _coerce_int(item.get("terminal_cols"), 80),
        "terminal_rows": _coerce_int(item.get("terminal_rows"), 24),
        "terminal_font_size": _coerce_int(item.get("terminal_font_size"), 14),
        "terminal_color_scheme": item.get("terminal_color_scheme", "dark"),
        "is_favorite": bool(item.get("is_favorite", False)),
        "auto_connect": bool(item.get("auto_connect", False)),
        "use_count": _coerce_int(item.get("use_count"), 0),
        "created_at": _coerce_int(item.get("created_at")),
        "updated_at": _coerce_int(item.get("updated_at")),
        "last_used_at": _coerce_int(item.get("last_used_at")),
    }


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def _encrypt_password(raw_password: str) -> str:
    """KMS-encrypt a plaintext password for at-rest storage (SEC-022).

    Returns the base64 ciphertext, or "" for an empty password. Validates the
    length and surfaces a user-friendly error if KMS is not configured rather
    than silently storing plaintext.
    """
    if not raw_password:
        return ""
    if len(raw_password) > _MAX_PASSWORD_LEN:
        raise ProfileValidationError(
            f"password too long (max {_MAX_PASSWORD_LEN} characters)"
        )
    # SECOPS-007: KMS works identically in dev (mock KMS server) and prod (CMK).
    # Guard against a missing key so we fail with a 4xx instead of storing
    # plaintext or surfacing an opaque 500 deep in the write path.
    if not S.kms_key_id:
        raise ProfileValidationError(
            "Password authentication requires KMS to be configured"
        )
    return kms_encrypt(raw_password)


def _get_item(user_sub: str, profile_id: str) -> Optional[Dict[str, Any]]:
    resp = T.connection_profiles.get_item(
        Key={"user_sub": user_sub, "sk": f"PROFILE#{profile_id}"}
    )
    return resp.get("Item")


def create_profile(
    user_sub: str,
    *,
    label: str,
    protocol: str = "ssh",
    hostname: str = "",
    instance_id: str = "",
    port: Any = 22,
    username: str = "",
    auth_method: str = "key_ref",
    vnc_password: str = "",
    ssh_password: str = "",
    ssh_key_id: str = "",
    bastion_path_id: str = "",
    terminal_cols: Any = 80,
    terminal_rows: Any = 24,
    terminal_font_size: Any = 14,
    terminal_color_scheme: str = "dark",
    is_favorite: bool = False,
    auto_connect: bool = False,
) -> Dict[str, Any]:
    """Create a connection profile after validating host/port/key/bastion."""
    label = (label or "").strip()
    if not label:
        raise ProfileValidationError("label is required")
    if len(label) > 200:
        raise ProfileValidationError("label too long")

    protocol = (protocol or "ssh").strip().lower()
    if protocol not in _VALID_PROTOCOLS:
        raise ProfileValidationError("protocol must be ssh or vnc")

    auth_method = (auth_method or "key_ref").strip()
    if auth_method not in _VALID_AUTH_METHODS:
        raise ProfileValidationError("auth_method must be key, key_ref, or password")

    color = (terminal_color_scheme or "dark").strip()
    if color not in _VALID_COLOR_SCHEMES:
        raise ProfileValidationError(
            "terminal_color_scheme must be one of: " + ", ".join(sorted(_VALID_COLOR_SCHEMES))
        )

    instance_id = (instance_id or "").strip()
    hostname = (hostname or "").strip()
    if not hostname and not instance_id:
        raise ProfileValidationError("either hostname or instance_id is required")

    # Validate target reference / host.
    if instance_id:
        # Raises ReferenceNotFound if not owned.
        _resolve_instance_host(user_sub, instance_id)
    if hostname:
        try:
            hostname = validate_host(hostname)
        except InvalidHop as exc:
            raise ProfileValidationError(str(exc))

    try:
        port = validate_port(port)
    except InvalidHop as exc:
        raise ProfileValidationError(str(exc))

    username = (username or "").strip()
    if username:
        try:
            username = validate_username(username)
        except InvalidHop as exc:
            raise ProfileValidationError(str(exc))

    cols = _validate_terminal("terminal_cols", terminal_cols, 40, 300)
    rows = _validate_terminal("terminal_rows", terminal_rows, 10, 100)
    font = _validate_terminal("terminal_font_size", terminal_font_size, 8, 32)

    ssh_key_id = (ssh_key_id or "").strip()
    bastion_path_id = (bastion_path_id or "").strip()
    _assert_key_owned(user_sub, ssh_key_id)
    _assert_bastion_owned(user_sub, bastion_path_id)

    # SEC-022: resolve the applicable password (protocol-specific) and store it
    # KMS-encrypted only. An empty password is allowed (deferred entry) — the
    # profile is created with has_password=False.
    raw_password = vnc_password if protocol == "vnc" else ssh_password
    raw_password = raw_password or vnc_password or ssh_password or ""
    password_enc = _encrypt_password(raw_password)

    # Enforce per-user limit.
    existing = list_profiles(user_sub)
    if len(existing) >= S.connection_profiles_max_per_user:
        raise ProfileLimitExceeded(
            f"Maximum {S.connection_profiles_max_per_user} connection profiles per user"
        )

    profile_id = "cp_" + uuid.uuid4().hex[:16]
    ts = now_ts()
    item = {
        "user_sub": user_sub,
        "sk": f"PROFILE#{profile_id}",
        "profile_id": profile_id,
        "label": label,
        "protocol": protocol,
        "hostname": hostname,
        "instance_id": instance_id,
        "port": port,
        "username": username,
        "auth_method": auth_method,
        "password_enc": password_enc,
        "ssh_key_id": ssh_key_id,
        "bastion_path_id": bastion_path_id,
        "terminal_cols": cols,
        "terminal_rows": rows,
        "terminal_font_size": font,
        "terminal_color_scheme": color,
        "is_favorite": bool(is_favorite),
        "auto_connect": bool(auto_connect),
        "use_count": 0,
        "created_at": ts,
        "updated_at": ts,
        "last_used_at": 0,
    }
    T.connection_profiles.put_item(Item=item)
    logger.info(
        "connection_profiles.created profile_id=%s user_sub=%s protocol=%s",
        profile_id, user_sub, protocol,
    )
    return _item_to_profile(item)


def get_profile(user_sub: str, profile_id: str) -> Optional[Dict[str, Any]]:
    item = _get_item(user_sub, profile_id)
    return _item_to_profile(item) if item else None


def list_profiles(user_sub: str) -> List[Dict[str, Any]]:
    """List all connection profiles for a user.

    Ordering: favorites first, then by most-recently-used, then newest-created.
    This drives the "quick connect" list (pinned + recent at the top).
    """
    resp = T.connection_profiles.query(
        KeyConditionExpression=Key("user_sub").eq(user_sub) & Key("sk").begins_with("PROFILE#"),
    )
    profiles = [_item_to_profile(i) for i in resp.get("Items", [])]
    profiles.sort(
        key=lambda p: (
            0 if p["is_favorite"] else 1,
            -p["last_used_at"],
            -p["created_at"],
        )
    )
    return profiles


def update_profile(
    user_sub: str,
    profile_id: str,
    *,
    label: Optional[str] = None,
    hostname: Optional[str] = None,
    instance_id: Optional[str] = None,
    port: Optional[Any] = None,
    username: Optional[str] = None,
    auth_method: Optional[str] = None,
    password: Optional[str] = None,
    clear_password: bool = False,
    ssh_key_id: Optional[str] = None,
    bastion_path_id: Optional[str] = None,
    terminal_cols: Optional[Any] = None,
    terminal_rows: Optional[Any] = None,
    terminal_font_size: Optional[Any] = None,
    terminal_color_scheme: Optional[str] = None,
    is_favorite: Optional[bool] = None,
    auto_connect: Optional[bool] = None,
) -> Dict[str, Any]:
    """Update profile fields. Re-validates any supplied references / values."""
    item = _get_item(user_sub, profile_id)
    if not item:
        raise ProfileNotFound(f"Connection profile {profile_id} not found")

    sets = ["updated_at = :ts"]
    values: Dict[str, Any] = {":ts": now_ts()}
    names: Dict[str, str] = {}

    if label is not None:
        label = label.strip()
        if not label:
            raise ProfileValidationError("label cannot be empty")
        if len(label) > 200:
            raise ProfileValidationError("label too long")
        sets.append("#lbl = :lbl")
        names["#lbl"] = "label"
        values[":lbl"] = label

    if instance_id is not None:
        instance_id = instance_id.strip()
        if instance_id:
            _resolve_instance_host(user_sub, instance_id)
        sets.append("instance_id = :iid")
        values[":iid"] = instance_id

    if hostname is not None:
        hostname = hostname.strip()
        if hostname:
            try:
                hostname = validate_host(hostname)
            except InvalidHop as exc:
                raise ProfileValidationError(str(exc))
        sets.append("hostname = :host")
        values[":host"] = hostname

    if port is not None:
        try:
            port = validate_port(port)
        except InvalidHop as exc:
            raise ProfileValidationError(str(exc))
        sets.append("port = :port")
        values[":port"] = port

    if username is not None:
        username = username.strip()
        if username:
            try:
                username = validate_username(username)
            except InvalidHop as exc:
                raise ProfileValidationError(str(exc))
        sets.append("username = :usr")
        values[":usr"] = username

    if auth_method is not None:
        auth_method = auth_method.strip()
        if auth_method not in _VALID_AUTH_METHODS:
            raise ProfileValidationError("auth_method must be key, key_ref, or password")
        sets.append("auth_method = :am")
        values[":am"] = auth_method

    # SEC-022: password rotation / clearing. ``clear_password`` removes any
    # stored password; otherwise a non-None ``password`` is KMS-encrypted and
    # stored. Plaintext is never persisted or returned.
    if clear_password:
        sets.append("password_enc = :pe")
        values[":pe"] = ""
    elif password is not None:
        sets.append("password_enc = :pe")
        values[":pe"] = _encrypt_password(password)

    if ssh_key_id is not None:
        ssh_key_id = ssh_key_id.strip()
        _assert_key_owned(user_sub, ssh_key_id)
        sets.append("ssh_key_id = :kid")
        values[":kid"] = ssh_key_id

    if bastion_path_id is not None:
        bastion_path_id = bastion_path_id.strip()
        _assert_bastion_owned(user_sub, bastion_path_id)
        sets.append("bastion_path_id = :bid")
        values[":bid"] = bastion_path_id

    if terminal_cols is not None:
        sets.append("terminal_cols = :tc")
        values[":tc"] = _validate_terminal("terminal_cols", terminal_cols, 40, 300)

    if terminal_rows is not None:
        sets.append("terminal_rows = :tr")
        values[":tr"] = _validate_terminal("terminal_rows", terminal_rows, 10, 100)

    if terminal_font_size is not None:
        sets.append("terminal_font_size = :tf")
        values[":tf"] = _validate_terminal("terminal_font_size", terminal_font_size, 8, 32)

    if terminal_color_scheme is not None:
        color = terminal_color_scheme.strip()
        if color not in _VALID_COLOR_SCHEMES:
            raise ProfileValidationError(
                "terminal_color_scheme must be one of: " + ", ".join(sorted(_VALID_COLOR_SCHEMES))
            )
        sets.append("terminal_color_scheme = :cs")
        values[":cs"] = color

    if is_favorite is not None:
        sets.append("is_favorite = :fav")
        values[":fav"] = bool(is_favorite)

    if auto_connect is not None:
        sets.append("auto_connect = :ac")
        values[":ac"] = bool(auto_connect)

    kwargs: Dict[str, Any] = {
        "Key": {"user_sub": user_sub, "sk": f"PROFILE#{profile_id}"},
        "UpdateExpression": "SET " + ", ".join(sets),
        "ExpressionAttributeValues": values,
        "ReturnValues": "ALL_NEW",
    }
    if names:
        kwargs["ExpressionAttributeNames"] = names
    resp = T.connection_profiles.update_item(**kwargs)
    logger.info("connection_profiles.updated profile_id=%s user_sub=%s", profile_id, user_sub)
    return _item_to_profile(resp["Attributes"])


def delete_profile(user_sub: str, profile_id: str) -> bool:
    item = _get_item(user_sub, profile_id)
    if not item:
        raise ProfileNotFound(f"Connection profile {profile_id} not found")
    T.connection_profiles.delete_item(
        Key={"user_sub": user_sub, "sk": f"PROFILE#{profile_id}"}
    )
    logger.info("connection_profiles.deleted profile_id=%s user_sub=%s", profile_id, user_sub)
    return True


# ---------------------------------------------------------------------------
# Quick connect resolution
# ---------------------------------------------------------------------------

def quick_connect(user_sub: str, profile_id: str) -> Dict[str, Any]:
    """Resolve a profile into a connection descriptor and bump usage stats.

    Resolves the target host (from a referenced instance if any), optionally
    chains a bastion path (returning its resolved ProxyJump representation), and
    records this as the most-recent connection (``last_used_at`` + ``use_count``).

    Raises :class:`ProfileNotFound` if the profile does not exist, and
    :class:`ProfileValidationError` if the profile is incomplete (e.g. no
    username configured for an SSH quick-connect).
    """
    item = _get_item(user_sub, profile_id)
    if not item:
        raise ProfileNotFound(f"Connection profile {profile_id} not found")

    profile = _item_to_profile(item)

    # Resolve target host: prefer instance reference, else stored hostname.
    resolved_host = profile["hostname"]
    if profile["instance_id"]:
        host = _resolve_instance_host(user_sub, profile["instance_id"])
        if host:
            resolved_host = host
    if not resolved_host:
        raise ProfileValidationError("No host configured for this profile")

    if profile["protocol"] == "ssh" and not profile["username"]:
        raise ProfileValidationError("No username configured for this profile")

    # SEC-022: decrypt the stored password for the in-process terminal/session
    # layer only. ``password_resolved`` MUST be stripped by the router before
    # the descriptor is serialized into an HTTP response (see QuickConnectOut,
    # which has no password field).
    password_resolved = ""
    password_enc = item.get("password_enc", "")
    if password_enc and profile["auth_method"] == "password":
        try:
            password_resolved = kms_decrypt(password_enc).decode("utf-8")
        except Exception:
            logger.exception(
                "connection_profiles.password_decrypt_failed profile_id=%s",
                profile_id,
            )
            raise ProfileValidationError("Failed to decrypt stored password")

    # Chain the bastion path if referenced.
    bastion: Optional[Dict[str, Any]] = None
    if profile["bastion_path_id"]:
        from app.services.ssh_bastion import (
            BastionPathNotFound,
            ChainValidationError,
            resolve_path,
        )

        try:
            resolved = resolve_path(user_sub, profile["bastion_path_id"])
        except BastionPathNotFound:
            raise ReferenceNotFound(
                f"Bastion path {profile['bastion_path_id']} not found"
            )
        except ChainValidationError as exc:
            raise ProfileValidationError(str(exc))
        bastion = {
            "path_id": resolved["path_id"],
            "proxy_jump": resolved["proxy_jump"],
            "ssh_command": resolved["ssh_command"],
            "total_hops": resolved["total_hops"],
        }

    # Record usage (last_used_at + use_count) for recency / favorite ordering.
    ts = now_ts()
    T.connection_profiles.update_item(
        Key={"user_sub": user_sub, "sk": f"PROFILE#{profile_id}"},
        UpdateExpression="SET last_used_at = :ts, use_count = :uc",
        ExpressionAttributeValues={
            ":ts": ts,
            ":uc": profile["use_count"] + 1,
        },
    )

    logger.info(
        "connection_profiles.quick_connect profile_id=%s user_sub=%s protocol=%s bastion=%s",
        profile_id, user_sub, profile["protocol"], bool(bastion),
    )

    return {
        "profile_id": profile["profile_id"],
        "label": profile["label"],
        "protocol": profile["protocol"],
        "hostname": resolved_host,
        "port": profile["port"],
        "username": profile["username"],
        "auth_method": profile["auth_method"],
        "has_password": bool(password_enc),
        # Internal use only — the router must NOT serialize this into the HTTP
        # response. QuickConnectOut deliberately has no password field.
        "password_resolved": password_resolved,
        "ssh_key_id": profile["ssh_key_id"],
        "bastion_path_id": profile["bastion_path_id"],
        "bastion": bastion,
        "terminal_cols": profile["terminal_cols"],
        "terminal_rows": profile["terminal_rows"],
        "terminal_font_size": profile["terminal_font_size"],
        "terminal_color_scheme": profile["terminal_color_scheme"],
        "auto_connect": profile["auto_connect"],
        "connected_at": ts,
    }
