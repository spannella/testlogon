"""Multi-Hop SSH Bastion path management (INFRA-011).

A *bastion path* models a multi-hop SSH connection that routes through one or
more bastion / jump hosts to reach a final target host. Each path is owned by
a single user. Hops are an ordered list of jump hosts (outermost bastion
first); the target is the final destination.

In the local mock there is no real SSH proxying — this module models, validates
and persists the hop chain and can produce the resolved ProxyJump / ssh_config
representation for the chain.

DynamoDB layout (table ``ssh_bastion_paths``):
    PK ``user_sub``
    SK ``PATH#{path_id}``
    GSI ``ByCreatedAt`` (user_sub, created_at:N)
"""

from __future__ import annotations

import io
import ipaddress
import logging
import re
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class BastionPathNotFound(Exception):
    """Raised when a bastion path does not exist for the user."""


class BastionPathLimitExceeded(Exception):
    """Raised when a user exceeds the maximum number of bastion paths."""


class InvalidHop(Exception):
    """Raised when a hop has an invalid host / port / ordering."""


class ChainValidationError(Exception):
    """Raised when the resolved chain fails validation (too long, duplicate, etc.)."""


class BastionConnectError(Exception):
    """Raised when a multi-hop SSH dial-out through a bastion chain fails.

    Carries a stable ``code`` (for client-side handling) alongside the human
    message, mirroring ``BrowserSshError`` in
    ``app/routers/browser_ssh_terminal.py``.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------
# Host / IP validation (reuses ipaddress; falls back to hostname regex)
# ---------------------------------------------------------------------------

# RFC 1123 hostname (labels 1-63 chars, alnum + hyphen, dot-separated)
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)

# Private/reserved IP ranges that must not be used as bastion hops (SSRF guard,
# GAP-0022). Mirrors the denylist in ``app/services/webhook_ssrf.py`` so that a
# hop cannot target the AWS instance metadata endpoint (169.254.169.254),
# loopback, or any internal RFC-1918 / CGNAT / link-local address.
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local / AWS IMDS metadata
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),   # CGNAT / shared address space
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
    ipaddress.ip_network("fc00::/7"),         # IPv6 unique local
]


def validate_host(host: str) -> str:
    """Validate and normalize a hop hostname or IP address.

    Accepts IPv4 / IPv6 literals (normalized via ``ipaddress``) and RFC-1123
    hostnames. Rejects IP literals in private / loopback / link-local / CGNAT /
    metadata ranges to prevent SSRF (GAP-0022). Raises :class:`InvalidHop` for
    anything else.
    """
    host = (host or "").strip()
    if not host:
        raise InvalidHop("hostname is required")
    if len(host) > 253:
        raise InvalidHop("hostname too long")
    # Try IP literal first.
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        addr = None
    if addr is not None:
        for net in _BLOCKED_NETWORKS:
            if addr in net:
                raise InvalidHop(
                    f"hop targets a private or reserved address: {host}"
                )
        return str(addr)
    if _HOSTNAME_RE.match(host):
        return host.lower()
    raise InvalidHop(f"invalid hostname or IP: {host}")


def validate_port(port: Any) -> int:
    try:
        p = int(port)
    except (TypeError, ValueError):
        raise InvalidHop("port must be an integer")
    if p < 1 or p > 65535:
        raise InvalidHop("port must be between 1 and 65535")
    return p


def validate_username(username: str) -> str:
    username = (username or "").strip()
    if not username:
        raise InvalidHop("username is required")
    if len(username) > 64:
        raise InvalidHop("username too long")
    if not re.match(r"^[A-Za-z0-9._@-]+$", username):
        raise InvalidHop(f"invalid username: {username}")
    return username


def _normalize_hop(hop: Dict[str, Any], *, index: int, is_target: bool) -> Dict[str, Any]:
    """Validate & normalize a single hop dict. Raises InvalidHop on bad input."""
    if not isinstance(hop, dict):
        raise InvalidHop(f"hop {index} must be an object")
    hostname = validate_host(hop.get("hostname", ""))
    port = validate_port(hop.get("port", 22))
    username = validate_username(hop.get("username", ""))
    ssh_key_id = (hop.get("ssh_key_id") or "").strip()
    label = (hop.get("label") or "").strip() or hostname
    return {
        "hostname": hostname,
        "port": port,
        "username": username,
        "ssh_key_id": ssh_key_id,
        "label": label,
        "is_bastion": not is_target,
    }


def _validate_chain(jump_hops: List[Dict[str, Any]], target: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Validate the full ordered chain (jump hops + target).

    Returns the normalized chain (jump hops first, target last) with
    ``hop_number`` assigned. Raises InvalidHop / ChainValidationError.
    """
    if not isinstance(jump_hops, list):
        raise InvalidHop("jump_hops must be a list")

    norm_jumps = [
        _normalize_hop(h, index=i, is_target=False) for i, h in enumerate(jump_hops)
    ]
    norm_target = _normalize_hop(target, index=len(norm_jumps), is_target=True)

    chain = norm_jumps + [norm_target]

    max_hops = S.ssh_bastion_max_hops
    if len(chain) > max_hops:
        raise ChainValidationError(
            f"Connection chain exceeds maximum {max_hops} hops"
        )

    # Reachability / ordering check: no two consecutive hops may be identical
    # (would be a self-loop), and the full chain must not contain a duplicated
    # (hostname, port) which would indicate a circular route.
    seen: set[tuple[str, int]] = set()
    for i, hop in enumerate(chain):
        hop["hop_number"] = i + 1
        key = (hop["hostname"], hop["port"])
        if key in seen:
            raise ChainValidationError(
                f"Circular bastion chain detected at hop {i + 1} ({hop['hostname']}:{hop['port']})"
            )
        seen.add(key)
    return chain


# ---------------------------------------------------------------------------
# DDB item <-> dict
# ---------------------------------------------------------------------------

def _coerce_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _hop_out(hop: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "hostname": hop.get("hostname", ""),
        "port": _coerce_int(hop.get("port"), 22),
        "username": hop.get("username", ""),
        "ssh_key_id": hop.get("ssh_key_id", "") or "",
        "label": hop.get("label", "") or hop.get("hostname", ""),
        "is_bastion": bool(hop.get("is_bastion", False)),
        "hop_number": _coerce_int(hop.get("hop_number"), 0),
    }


def _item_to_path(item: Dict[str, Any]) -> Dict[str, Any]:
    hops = [_hop_out(h) for h in item.get("hops", [])]
    return {
        "path_id": item["path_id"],
        "label": item.get("label", ""),
        "description": item.get("description", "") or "",
        "hops": hops,
        "total_hops": len(hops),
        "created_at": _coerce_int(item.get("created_at")),
        "updated_at": _coerce_int(item.get("updated_at")),
    }


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def _get_item(user_sub: str, path_id: str) -> Optional[Dict[str, Any]]:
    resp = T.ssh_bastion_paths.get_item(
        Key={"user_sub": user_sub, "sk": f"PATH#{path_id}"}
    )
    return resp.get("Item")


def create_path(
    user_sub: str,
    *,
    label: str,
    jump_hops: List[Dict[str, Any]],
    target: Dict[str, Any],
    description: str = "",
) -> Dict[str, Any]:
    """Create a multi-hop bastion path. Validates the full chain first."""
    label = (label or "").strip()
    if not label:
        raise InvalidHop("label is required")
    if len(label) > 200:
        raise InvalidHop("label too long")

    chain = _validate_chain(jump_hops, target)

    # Enforce per-user limit.
    existing = list_paths(user_sub)
    if len(existing) >= S.ssh_bastion_max_paths_per_user:
        raise BastionPathLimitExceeded(
            f"Maximum {S.ssh_bastion_max_paths_per_user} bastion paths per user"
        )

    path_id = "bp_" + uuid.uuid4().hex[:16]
    ts = now_ts()
    item = {
        "user_sub": user_sub,
        "sk": f"PATH#{path_id}",
        "path_id": path_id,
        "label": label,
        "description": (description or "").strip(),
        "hops": chain,
        "created_at": ts,
        "updated_at": ts,
    }
    T.ssh_bastion_paths.put_item(Item=item)
    logger.info(
        "ssh_bastion.path_created path_id=%s user_sub=%s hops=%d",
        path_id, user_sub, len(chain),
    )
    return _item_to_path(item)


def get_path(user_sub: str, path_id: str) -> Optional[Dict[str, Any]]:
    item = _get_item(user_sub, path_id)
    return _item_to_path(item) if item else None


def list_paths(user_sub: str) -> List[Dict[str, Any]]:
    """List all bastion paths for a user, newest-first."""
    resp = T.ssh_bastion_paths.query(
        KeyConditionExpression=Key("user_sub").eq(user_sub) & Key("sk").begins_with("PATH#"),
    )
    paths = [_item_to_path(i) for i in resp.get("Items", [])]
    paths.sort(key=lambda p: -p["created_at"])
    return paths


def update_path(
    user_sub: str,
    path_id: str,
    *,
    label: Optional[str] = None,
    description: Optional[str] = None,
    jump_hops: Optional[List[Dict[str, Any]]] = None,
    target: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Update a bastion path. If hops/target supplied, the chain is re-validated.

    Updating hops requires supplying BOTH ``jump_hops`` and ``target`` together
    (the whole chain is replaced atomically).
    """
    item = _get_item(user_sub, path_id)
    if not item:
        raise BastionPathNotFound(f"Bastion path {path_id} not found")

    sets = ["updated_at = :ts"]
    values: Dict[str, Any] = {":ts": now_ts()}
    names: Dict[str, str] = {}

    if label is not None:
        label = label.strip()
        if not label:
            raise InvalidHop("label cannot be empty")
        if len(label) > 200:
            raise InvalidHop("label too long")
        sets.append("#lbl = :lbl")
        names["#lbl"] = "label"
        values[":lbl"] = label

    if description is not None:
        sets.append("description = :desc")
        values[":desc"] = description.strip()

    if jump_hops is not None or target is not None:
        if jump_hops is None or target is None:
            raise InvalidHop("updating hops requires both jump_hops and target")
        chain = _validate_chain(jump_hops, target)
        sets.append("hops = :hops")
        values[":hops"] = chain

    kwargs: Dict[str, Any] = {
        "Key": {"user_sub": user_sub, "sk": f"PATH#{path_id}"},
        "UpdateExpression": "SET " + ", ".join(sets),
        "ExpressionAttributeValues": values,
        "ReturnValues": "ALL_NEW",
    }
    if names:
        kwargs["ExpressionAttributeNames"] = names
    resp = T.ssh_bastion_paths.update_item(**kwargs)
    logger.info("ssh_bastion.path_updated path_id=%s user_sub=%s", path_id, user_sub)
    return _item_to_path(resp["Attributes"])


def delete_path(user_sub: str, path_id: str) -> bool:
    item = _get_item(user_sub, path_id)
    if not item:
        raise BastionPathNotFound(f"Bastion path {path_id} not found")
    T.ssh_bastion_paths.delete_item(Key={"user_sub": user_sub, "sk": f"PATH#{path_id}"})
    logger.info("ssh_bastion.path_deleted path_id=%s user_sub=%s", path_id, user_sub)
    return True


# ---------------------------------------------------------------------------
# Resolution: ProxyJump / ssh_config
# ---------------------------------------------------------------------------

def _proxyjump_token(hop: Dict[str, Any]) -> str:
    """Render a single hop as an OpenSSH ProxyJump token: ``user@host:port``."""
    user = hop.get("username", "")
    host = hop.get("hostname", "")
    port = _coerce_int(hop.get("port"), 22)
    token = f"{user}@{host}" if user else host
    if port != 22:
        token = f"{token}:{port}"
    return token


def resolve_path(user_sub: str, path_id: str) -> Dict[str, Any]:
    """Resolve a stored bastion path into ProxyJump / ssh_config representation.

    Re-validates the chain on read so a path that was stored before a config
    change (e.g. a lowered ``max_hops``) is reported as invalid rather than
    silently returned. Returns a dict with the resolved chain, the OpenSSH
    ``ProxyJump`` directive, an ``ssh -J`` command, and a generated
    ``ssh_config`` block.

    Raises :class:`BastionPathNotFound` if the path does not exist.
    """
    item = _get_item(user_sub, path_id)
    if not item:
        raise BastionPathNotFound(f"Bastion path {path_id} not found")

    chain = [_hop_out(h) for h in item.get("hops", [])]
    if not chain:
        raise ChainValidationError("Bastion path has no hops")

    # Re-validate length / circular against current settings.
    max_hops = S.ssh_bastion_max_hops
    if len(chain) > max_hops:
        raise ChainValidationError(f"Connection chain exceeds maximum {max_hops} hops")
    seen: set[tuple[str, int]] = set()
    for hop in chain:
        key = (hop["hostname"], hop["port"])
        if key in seen:
            raise ChainValidationError(
                f"Circular bastion chain detected ({hop['hostname']}:{hop['port']})"
            )
        seen.add(key)

    target = chain[-1]
    jump_hops = chain[:-1]

    # ProxyJump directive: comma-separated jump hosts (outermost first).
    proxy_jump = ",".join(_proxyjump_token(h) for h in jump_hops)

    # ssh -J command.
    if proxy_jump:
        ssh_command = f"ssh -J {proxy_jump} {_proxyjump_token(target)}"
    else:
        ssh_command = f"ssh {_proxyjump_token(target)}"

    # Generated ssh_config block.
    config_lines: List[str] = []
    alias = re.sub(r"[^A-Za-z0-9_.-]", "-", item.get("label", "") or target["hostname"])
    config_lines.append(f"Host {alias}")
    config_lines.append(f"    HostName {target['hostname']}")
    if target.get("username"):
        config_lines.append(f"    User {target['username']}")
    config_lines.append(f"    Port {target['port']}")
    if proxy_jump:
        config_lines.append(f"    ProxyJump {proxy_jump}")
    ssh_config = "\n".join(config_lines)

    return {
        "path_id": item["path_id"],
        "label": item.get("label", ""),
        "chain": chain,
        "jump_hops": jump_hops,
        "target": target,
        "total_hops": len(chain),
        "proxy_jump": proxy_jump,
        "ssh_command": ssh_command,
        "ssh_config": ssh_config,
    }


# ---------------------------------------------------------------------------
# Programmatic connection-chain resolution (GAP-0236)
# ---------------------------------------------------------------------------

def resolve_connection_chain(
    user_sub: str,
    path_id: str,
    *,
    include_keys: bool = True,
) -> List[Dict[str, Any]]:
    """Resolve a bastion path into a hop list ready for programmatic dial-out.

    Unlike :func:`resolve_path` (which produces a ProxyJump / ssh_config text
    representation for end-users), this returns a list of hop dicts ordered
    outermost-bastion-first with the target last. Each hop dict extends the
    base hop fields (``hostname``, ``port``, ``username``, ``ssh_key_id``,
    ``label``, ``is_bastion``, ``hop_number``) with:

        ``private_key_pem``:  decrypted PEM string if ``include_keys`` is True
                              and a key is stored for this hop, else ``None``.

    The function re-uses the validation logic of :func:`resolve_path` and
    inherits its :class:`BastionPathNotFound` / :class:`ChainValidationError`
    error contract.

    SECURITY: the returned dicts contain plaintext private key material when
    ``include_keys`` is True. They are *server-internal only* and must never be
    returned to the API layer / browser. Pass ``include_keys=False`` for
    topology-only callers (e.g. admin audit endpoints) to avoid triggering KMS
    decryption.
    """
    resolved = resolve_path(user_sub, path_id)  # raises BastionPathNotFound / ChainValidationError
    chain: List[Dict[str, Any]] = []

    for hop in resolved["chain"]:
        hop_out = dict(hop)  # copy: hostname, port, username, ssh_key_id, label, ...
        pem: Optional[str] = None

        if include_keys and hop.get("ssh_key_id"):
            # Local import avoids a circular dependency with ssh_key_manager.
            from app.services.ssh_key_manager import get_decrypted_private_key

            pem = get_decrypted_private_key(user_sub, hop["ssh_key_id"])
            if pem is None:
                logger.warning(
                    "ssh_bastion.key_not_found path_id=%s ssh_key_id=%s",
                    path_id, hop["ssh_key_id"],
                )

        hop_out["private_key_pem"] = pem
        chain.append(hop_out)

    logger.info(
        "ssh_bastion.chain_resolved path_id=%s user_sub=%s hops=%d",
        path_id, user_sub, len(chain),
    )
    return chain


# ---------------------------------------------------------------------------
# Multi-hop SSH bridge (GAP-0235)
# ---------------------------------------------------------------------------

class MultiHopSshBridge:
    """SSH bridge that tunnels through one or more bastion hosts using
    Paramiko ``direct-tcpip`` channel forwarding.

    ``hops`` is an ordered list of dicts (outermost bastion first, target
    last), each with:
        ``hostname``, ``port``, ``username`` and credentials --
        ``private_key_pem`` (preferred) and/or ``password``.

    The flow:
      1. Connect a Paramiko client directly to hop 0.
      2. For each subsequent hop, open a ``direct-tcpip`` channel through the
         *previous* hop's transport to the next hop's address, wrap it in a
         fresh Paramiko ``Transport``, and authenticate.
      3. Invoke an interactive shell on the final transport.

    The public surface (``connect``, ``poll_output``, ``send_input``,
    ``resize``, ``close``) mirrors ``ParamikoSshBridge`` so the WebSocket
    handler can use either bridge interchangeably.
    """

    def __init__(self, *, hops: List[Dict[str, Any]], cols: int, rows: int) -> None:
        if len(hops) < 2:
            raise BastionConnectError(
                "invalid_chain",
                "MultiHopSshBridge requires at least 2 hops (one bastion + target).",
            )
        self._hops = hops
        self._cols = max(cols, 80)
        self._rows = max(rows, 24)
        self._clients: List[Any] = []          # paramiko.SSHClient per hop
        self._transports: List[Any] = []       # paramiko.Transport per hop
        self._channel: Any | None = None       # interactive shell channel
        self._closed = False
        self._output_chunks: List[str] = []
        self._lock = threading.Lock()
        self._reader_thread: threading.Thread | None = None

    @staticmethod
    def _load_private_key(pem: str, passphrase: Optional[str], paramiko: Any) -> Any:
        """Load a PEM private key, trying each supported key type in turn."""
        key_text = (pem or "").strip()
        if not key_text:
            raise BastionConnectError(
                "invalid_private_key", "Private key is required for private key auth."
            )
        loaders = [
            paramiko.RSAKey.from_private_key,
            paramiko.Ed25519Key.from_private_key,
            paramiko.ECDSAKey.from_private_key,
            paramiko.DSSKey.from_private_key,
        ]
        last_exc: Exception | None = None
        for loader in loaders:
            try:
                return loader(io.StringIO(key_text), password=passphrase or None)
            except Exception as exc:  # pragma: no cover - aggregate error below
                last_exc = exc
        raise BastionConnectError(
            "invalid_private_key_format",
            "Unsupported private key format or invalid passphrase.",
        ) from last_exc

    @staticmethod
    def _has_key(hop: Dict[str, Any]) -> bool:
        return bool(hop.get("private_key_pem") or hop.get("private_key"))

    @classmethod
    def _hop_pem(cls, hop: Dict[str, Any]) -> str:
        return hop.get("private_key_pem") or hop.get("private_key") or ""

    def connect(self) -> None:
        try:
            import paramiko
        except ImportError as exc:  # pragma: no cover - dependency protection
            raise BastionConnectError(
                "ssh_unavailable", "SSH support is unavailable on this server."
            ) from exc

        try:
            # Hop 0: direct connection.
            first = self._hops[0]
            client0 = paramiko.SSHClient()
            client0.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            connect_kwargs: Dict[str, Any] = {
                "hostname": first["hostname"],
                "port": int(first["port"]),
                "username": first["username"],
                "look_for_keys": False,
                "allow_agent": False,
                "timeout": 10,
                "banner_timeout": 10,
                "auth_timeout": 10,
            }
            if self._has_key(first):
                connect_kwargs["pkey"] = self._load_private_key(
                    self._hop_pem(first), first.get("passphrase"), paramiko
                )
            else:
                connect_kwargs["password"] = first.get("password")
            client0.connect(**connect_kwargs)
            self._clients.append(client0)
            self._transports.append(client0.get_transport())

            # Each subsequent hop: tunnel via direct-tcpip through the previous
            # hop's transport, then start a fresh client transport and auth.
            for i in range(1, len(self._hops)):
                hop = self._hops[i]
                prev_transport = self._transports[-1]
                dest_addr = (hop["hostname"], int(hop["port"]))
                local_addr = ("127.0.0.1", 0)
                channel = prev_transport.open_channel(
                    "direct-tcpip", dest_addr, local_addr, timeout=10
                )
                transport = paramiko.Transport(channel)
                transport.start_client(timeout=10)
                if self._has_key(hop):
                    key = self._load_private_key(
                        self._hop_pem(hop), hop.get("passphrase"), paramiko
                    )
                    transport.auth_publickey(hop["username"], key)
                else:
                    transport.auth_password(hop["username"], hop.get("password") or "")
                self._transports.append(transport)

            # Interactive shell on the final transport.
            final_transport = self._transports[-1]
            shell = final_transport.open_session(timeout=10)
            shell.get_pty(term="xterm-256color", width=self._cols, height=self._rows)
            shell.invoke_shell()
            shell.settimeout(0.0)
            self._channel = shell
            self._reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
            self._reader_thread.start()
            logger.info(
                "ssh_bastion.multihop_connect hops=%d target=%s:%s",
                len(self._hops), self._hops[-1]["hostname"], self._hops[-1]["port"],
            )
        except BastionConnectError:
            self.close()
            raise
        except paramiko.AuthenticationException as exc:
            self.close()
            raise BastionConnectError(
                "auth_failed", "Authentication failed on a bastion hop."
            ) from exc
        except Exception as exc:  # pragma: no cover - network/paramiko failure modes
            self.close()
            raise BastionConnectError(
                "connect_failed", f"Multi-hop SSH connection failed: {exc}"
            ) from exc

    def _reader_loop(self) -> None:
        while not self._closed:
            try:
                if not self._channel:
                    return
                if self._channel.recv_ready():
                    chunk = self._channel.recv(4096)
                    if not chunk:
                        return
                    with self._lock:
                        self._output_chunks.append(chunk.decode("utf-8", errors="replace"))
                    continue
            except Exception:
                return
            time.sleep(0.01)

    def poll_output(self) -> str:
        with self._lock:
            if not self._output_chunks:
                return ""
            output = "".join(self._output_chunks)
            self._output_chunks.clear()
            return output

    def send_input(self, data: str) -> None:
        if not self._channel:
            raise BastionConnectError("not_connected", "SSH session is not connected.")
        try:
            self._channel.send(data)
        except Exception as exc:
            raise BastionConnectError("io_error", "SSH channel is unavailable.") from exc

    def resize(self, cols: int, rows: int) -> None:
        if not self._channel:
            raise BastionConnectError("not_connected", "SSH session is not connected.")
        try:
            self._channel.resize_pty(width=cols, height=rows)
        except Exception as exc:
            raise BastionConnectError("resize_failed", "Failed to resize terminal session.") from exc

    def close(self) -> None:
        self._closed = True
        try:
            if self._channel:
                self._channel.close()
        finally:
            self._channel = None
        # Close transports / clients in reverse (innermost hop first).
        for transport in reversed(self._transports):
            try:
                transport.close()
            except Exception:  # pragma: no cover - best-effort teardown
                pass
        self._transports = []
        for client in reversed(self._clients):
            try:
                client.close()
            except Exception:  # pragma: no cover - best-effort teardown
                pass
        self._clients = []


def build_multihop_bridge(
    user_sub: str,
    path_id: str,
    *,
    cols: int = 80,
    rows: int = 24,
) -> "MultiHopSshBridge":
    """Resolve a stored bastion path and build a connect-ready
    :class:`MultiHopSshBridge`.

    Resolves the full credentialled chain via :func:`resolve_connection_chain`
    (which decrypts per-hop SSH keys) and maps it into the bridge hop format.
    The chain must have at least 2 hops (one bastion + the target); a
    single-hop path should use the direct ``ParamikoSshBridge`` instead.

    Raises :class:`BastionPathNotFound` / :class:`ChainValidationError` from the
    underlying resolver, or :class:`BastionConnectError` for a too-short chain.
    """
    chain = resolve_connection_chain(user_sub, path_id, include_keys=True)
    if len(chain) < 2:
        raise BastionConnectError(
            "invalid_chain",
            "Bastion path must have at least 2 hops for a multi-hop connection.",
        )
    hops = [
        {
            "hostname": hop["hostname"],
            "port": hop["port"],
            "username": hop["username"],
            "private_key_pem": hop.get("private_key_pem"),
            "passphrase": hop.get("passphrase"),
            "password": hop.get("password"),
        }
        for hop in chain
    ]
    return MultiHopSshBridge(hops=hops, cols=cols, rows=rows)
