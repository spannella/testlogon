from __future__ import annotations

import base64
import hashlib
import io
import os
import socket
import threading
import time
from datetime import datetime
from ftplib import FTP, error_perm
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from fastapi import HTTPException

from app.core.settings import S
from app.services.sftp_destination_policy import enforce_sftp_destination_policy


@dataclass
class SftpConnectionConfig:
    owner: str
    mount_id: str
    host: str
    port: int
    username: str
    auth_mode: str  # password|private_key
    protocol: str = "sftp"  # sftp|scp|ftp
    password: Optional[str] = None
    private_key: Optional[str] = None
    private_key_passphrase: Optional[str] = None
    expected_host_key: Optional[str] = None


@dataclass
class SftpClientStats:
    active_sessions: int = 0
    total_connects: int = 0
    total_reuses: int = 0
    failed_connects: int = 0
    auth_failures: int = 0
    network_failures: int = 0
    host_key_failures: int = 0
    pool_evictions: int = 0
    total_connect_latency_ms: float = 0.0


@dataclass
class SftpClientError(RuntimeError):
    code: str
    message: str


@dataclass
class _PooledSession:
    key: str
    client: Any
    sftp: Any
    owner: str
    mount_id: str
    last_used_ts: float = field(default_factory=time.time)
    in_use: int = 0




class _LocalFsAttr:
    def __init__(self, filename: str, st: os.stat_result):
        self.filename = filename
        self.st_mode = st.st_mode
        self.st_size = st.st_size
        self.st_mtime = int(st.st_mtime)


class _LocalMockTransport:
    def __init__(self):
        self._active = True

    def is_active(self) -> bool:
        return self._active


class _LocalMockClient:
    def __init__(self):
        self._transport = _LocalMockTransport()

    def get_transport(self):
        return self._transport

    def close(self):
        self._transport._active = False


class _LocalMockSftp:
    def __init__(self, base_dir: str):
        self._base_dir = os.path.abspath(base_dir)
        os.makedirs(self._base_dir, exist_ok=True)

    def _resolve(self, remote: str) -> str:
        rel = str(remote or "/").lstrip("/")
        path = os.path.abspath(os.path.join(self._base_dir, rel))
        if not path.startswith(self._base_dir):
            raise FileNotFoundError("invalid remote path")
        return path

    def listdir_attr(self, remote_dir: str):
        folder = self._resolve(remote_dir)
        names = sorted(os.listdir(folder))
        out = []
        for name in names:
            p = os.path.join(folder, name)
            out.append(_LocalFsAttr(name, os.stat(p)))
        return out

    def stat(self, remote: str):
        p = self._resolve(remote)
        return _LocalFsAttr(os.path.basename(p) or "/", os.stat(p))

    def open(self, remote: str, mode: str):
        p = self._resolve(remote)
        m = str(mode or "rb")
        if "w" in m or "a" in m or "+" in m:
            os.makedirs(os.path.dirname(p), exist_ok=True)
        if "b" not in m:
            m += "b"
        return open(p, m)

    def mkdir(self, remote: str):
        os.makedirs(self._resolve(remote), exist_ok=False)

    def remove(self, remote: str):
        os.remove(self._resolve(remote))

    def rmdir(self, remote: str):
        os.rmdir(self._resolve(remote))

    def rename(self, src: str, dst: str):
        src_p = self._resolve(src)
        dst_p = self._resolve(dst)
        os.makedirs(os.path.dirname(dst_p), exist_ok=True)
        os.rename(src_p, dst_p)

    def close(self):
        return None


class _LocalMockBackend:
    def connect(self, cfg: SftpConnectionConfig, timeout_seconds: int):
        root = str(getattr(S, "filemgr_sftp_mock_root_dir", "/tmp/filemgr-sftp-mock") or "/tmp/filemgr-sftp-mock")
        base = os.path.join(root, cfg.owner, cfg.mount_id)
        os.makedirs(base, exist_ok=True)
        return _LocalMockClient(), _LocalMockSftp(base)

    def get_remote_host_key_fingerprint(self, client: Any) -> Optional[str]:
        digest = hashlib.sha256(b"filemgr-local-mock-host-key").digest()
        return base64.b64encode(digest).decode("utf-8").rstrip("=")

    def is_active(self, client: Any) -> bool:
        transport = client.get_transport()
        return bool(transport and transport.is_active())

    def close(self, client: Any, sftp: Any) -> None:
        try:
            sftp.close()
        finally:
            client.close()


class _FtpFsAttr:
    def __init__(self, filename: str, is_dir: bool, size: int = 0, mtime: int = 0):
        self.filename = filename
        self.st_mode = 0o040755 if is_dir else 0o100644
        self.st_size = int(size or 0)
        self.st_mtime = int(mtime or 0)


class _FtpSftpShim:
    def __init__(self, ftp: FTP):
        self._ftp = ftp

    def _split(self, path: str):
        clean = str(path or "/")
        if not clean.startswith("/"):
            clean = "/" + clean
        clean = clean.rstrip("/") or "/"
        if clean == "/":
            return "/", ""
        parent, _, name = clean.rpartition("/")
        return (parent or "/"), name

    def _listdir(self, remote_dir: str):
        entries = []
        try:
            for name, facts in self._ftp.mlsd(remote_dir):
                ftype = str(facts.get("type") or "file").lower()
                is_dir = ftype == "dir"
                size = int(facts.get("size") or 0)
                modify = str(facts.get("modify") or "")
                mtime = 0
                if modify:
                    try:
                        mtime = int(datetime.strptime(modify, "%Y%m%d%H%M%S").timestamp())
                    except Exception:
                        mtime = 0
                entries.append(_FtpFsAttr(name, is_dir=is_dir, size=size, mtime=mtime))
            return entries
        except Exception:
            names = self._ftp.nlst(remote_dir)
            out = []
            for n in names:
                base = n.rstrip("/").split("/")[-1]
                if not base:
                    continue
                out.append(_FtpFsAttr(base, is_dir=False, size=0, mtime=0))
            return out

    def listdir_attr(self, remote_dir: str):
        return self._listdir(remote_dir)

    def stat(self, remote: str):
        parent, name = self._split(remote)
        if not name and parent == "/":
            return _FtpFsAttr("/", is_dir=True, size=0, mtime=0)
        for attr in self._listdir(parent):
            if attr.filename == name:
                return attr
        raise FileNotFoundError("not found")

    def open(self, remote: str, mode: str):
        m = str(mode or "rb")
        if "w" in m or "a" in m or "+" in m:
            class _Writer(io.BytesIO):
                def close(inner):
                    try:
                        inner.seek(0)
                        self._ftp.storbinary(f"STOR {remote}", inner)
                    finally:
                        super().close()
            return _Writer()
        out = io.BytesIO()
        self._ftp.retrbinary(f"RETR {remote}", out.write)
        out.seek(0)
        return out

    def mkdir(self, remote: str):
        self._ftp.mkd(remote)

    def remove(self, remote: str):
        self._ftp.delete(remote)

    def rmdir(self, remote: str):
        self._ftp.rmd(remote)

    def rename(self, src: str, dst: str):
        self._ftp.rename(src, dst)

    def close(self):
        return None


class _FtpBackend:
    def connect(self, cfg: SftpConnectionConfig, timeout_seconds: int):
        if str(cfg.auth_mode or "") != "password":
            raise SftpClientError(code="auth_mode_unsupported", message="ftp backend requires password auth_mode")
        ftp = FTP()
        ftp.connect(host=cfg.host, port=int(cfg.port), timeout=timeout_seconds)
        ftp.login(user=cfg.username, passwd=cfg.password or "")
        return ftp, _FtpSftpShim(ftp)

    def get_remote_host_key_fingerprint(self, client: Any) -> Optional[str]:
        return None

    def is_active(self, client: Any) -> bool:
        try:
            client.voidcmd("NOOP")
            return True
        except Exception:
            return False

    def close(self, client: Any, sftp: Any) -> None:
        try:
            sftp.close()
        finally:
            try:
                client.quit()
            except Exception:
                try:
                    client.close()
                except Exception:
                    pass
class _ParamikoBackend:
    def __init__(self):
        try:
            import paramiko  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise HTTPException(status_code=500, detail="paramiko not installed") from exc
        self.paramiko = paramiko

    def _load_private_key(self, private_key: str, passphrase: Optional[str]):
        p = self.paramiko
        key_stream = io.StringIO(private_key)
        loaders = [
            p.RSAKey.from_private_key,
            p.ECDSAKey.from_private_key,
            p.Ed25519Key.from_private_key,
            p.DSSKey.from_private_key,
        ]
        for loader in loaders:
            key_stream.seek(0)
            try:
                return loader(key_stream, password=passphrase)
            except Exception:
                continue
        raise SftpClientError(code="invalid_private_key", message="private key could not be parsed")

    def connect(self, cfg: SftpConnectionConfig, timeout_seconds: int):
        p = self.paramiko
        client = p.SSHClient()
        client.set_missing_host_key_policy(p.RejectPolicy())

        kwargs: Dict[str, Any] = {
            "hostname": cfg.host,
            "port": int(cfg.port),
            "username": cfg.username,
            "timeout": timeout_seconds,
            "auth_timeout": timeout_seconds,
            "banner_timeout": timeout_seconds,
            "look_for_keys": False,
            "allow_agent": False,
        }
        if cfg.auth_mode == "password":
            kwargs["password"] = cfg.password or ""
        else:
            kwargs["pkey"] = self._load_private_key(cfg.private_key or "", cfg.private_key_passphrase)

        client.connect(**kwargs)
        sftp = client.open_sftp()
        return client, sftp

    def get_remote_host_key_fingerprint(self, client: Any) -> Optional[str]:
        transport = client.get_transport()
        if not transport:
            return None
        key = transport.get_remote_server_key()
        if key is None:
            return None
        digest = hashlib.sha256(key.asbytes()).digest()
        return base64.b64encode(digest).decode("utf-8").rstrip("=")

    def is_active(self, client: Any) -> bool:
        transport = client.get_transport()
        return bool(transport and transport.is_active())

    def close(self, client: Any, sftp: Any) -> None:
        try:
            sftp.close()
        finally:
            client.close()


def _build_sftp_backend() -> Any:
    mode = str(getattr(S, "filemgr_sftp_backend", "paramiko") or "paramiko").strip().lower()
    if mode == "mock":
        return _LocalMockBackend()
    return _ParamikoBackend()


class SftpConnectionPool:
    def __init__(self, backend: Optional[Any] = None):
        self._backend = backend or _build_sftp_backend()
        self._lock = threading.Lock()
        self._pool: "OrderedDict[str, _PooledSession]" = OrderedDict()
        self._stats = SftpClientStats()


    def _session_is_active(self, client: Any) -> bool:
        if isinstance(client, FTP):
            return _FtpBackend().is_active(client)
        return self._backend.is_active(client)

    def _session_close(self, client: Any, sftp: Any) -> None:
        if isinstance(client, FTP):
            return _FtpBackend().close(client, sftp)
        return self._backend.close(client, sftp)

    def _connect_backend(self, protocol: str) -> Any:
        proto = str(protocol or "sftp").strip().lower()
        if proto == "ftp" and not isinstance(self._backend, _LocalMockBackend):
            return _FtpBackend()
        return self._backend

    def _pool_key(self, cfg: SftpConnectionConfig) -> str:
        protocol = str(getattr(cfg, "protocol", "sftp") or "sftp").strip().lower()
        return f"{cfg.owner}|{cfg.mount_id}|{protocol}|{cfg.host}|{cfg.port}|{cfg.username}|{cfg.auth_mode}"

    def _max_pool(self) -> int:
        return max(1, int(getattr(S, "filemgr_sftp_pool_max_connections", 64) or 64))

    def _connect_timeout(self) -> int:
        return max(1, int(getattr(S, "filemgr_sftp_connect_timeout_seconds", 10) or 10))

    def _host_key_policy(self) -> str:
        policy = str(getattr(S, "filemgr_sftp_host_key_policy", "strict") or "strict").strip().lower()
        return policy if policy in {"strict", "accept_new", "off"} else "strict"

    def _verify_host_key(self, *, cfg: SftpConnectionConfig, observed_fingerprint: Optional[str]) -> None:
        policy = self._host_key_policy()
        expected = (cfg.expected_host_key or "").strip().rstrip("=")
        observed = (observed_fingerprint or "").strip().rstrip("=")
        if policy == "off":
            return
        if policy == "accept_new":
            if expected and observed and expected != observed:
                raise SftpClientError(code="host_key_mismatch", message="remote host key does not match expected fingerprint")
            return
        # strict policy
        if not expected:
            raise SftpClientError(code="host_key_required", message="expected host key fingerprint is required")
        if not observed:
            raise SftpClientError(code="host_key_missing", message="remote host key fingerprint is unavailable")
        if expected != observed:
            raise SftpClientError(code="host_key_mismatch", message="remote host key does not match expected fingerprint")

    def _map_error(self, exc: Exception) -> SftpClientError:
        name = exc.__class__.__name__.lower()
        msg = str(exc) or "sftp connection failed"
        if isinstance(exc, SftpClientError):
            return exc
        if isinstance(exc, (TimeoutError, socket.timeout)):
            return SftpClientError(code="network_timeout", message="sftp connection timed out")
        if isinstance(exc, (error_perm,)):
            return SftpClientError(code="auth_failed", message="ftp authentication failed")
        if isinstance(exc, OSError):
            return SftpClientError(code="network_unreachable", message="sftp host is unreachable")
        if "authentication" in name or "auth" in name:
            return SftpClientError(code="auth_failed", message="sftp authentication failed")
        if "badhostkey" in name or "hostkey" in name:
            return SftpClientError(code="host_key_mismatch", message="sftp host key verification failed")
        if "ssh" in name:
            return SftpClientError(code="protocol_error", message="sftp ssh protocol negotiation failed")
        return SftpClientError(code="connection_failed", message=msg)

    def _record_error(self, mapped: SftpClientError) -> None:
        self._stats.failed_connects += 1
        if mapped.code == "auth_failed":
            self._stats.auth_failures += 1
        elif mapped.code in {"network_timeout", "network_unreachable"}:
            self._stats.network_failures += 1
        elif mapped.code.startswith("host_key"):
            self._stats.host_key_failures += 1

    def _evict_if_needed(self) -> None:
        max_pool = self._max_pool()
        if len(self._pool) < max_pool:
            return
        for key, sess in list(self._pool.items()):
            if sess.in_use == 0:
                try:
                    self._session_close(sess.client, sess.sftp)
                finally:
                    self._pool.pop(key, None)
                    self._stats.pool_evictions += 1
                    self._stats.active_sessions = max(0, self._stats.active_sessions - 1)
                return
        raise SftpClientError(code="pool_exhausted", message="all pooled sftp sessions are currently in use")

    def acquire(self, cfg: SftpConnectionConfig) -> _PooledSession:
        enforce_sftp_destination_policy(host=cfg.host, owner=cfg.owner, mount_id=cfg.mount_id, stage="connection")
        key = self._pool_key(cfg)
        with self._lock:
            existing = self._pool.get(key)
            if existing and self._session_is_active(existing.client):
                existing.in_use += 1
                existing.last_used_ts = time.time()
                self._pool.move_to_end(key)
                self._stats.total_reuses += 1
                return existing
            if existing:
                try:
                    self._session_close(existing.client, existing.sftp)
                finally:
                    self._pool.pop(key, None)
                    self._stats.active_sessions = max(0, self._stats.active_sessions - 1)

            self._evict_if_needed()

        start = time.perf_counter()
        try:
            protocol = str(getattr(cfg, "protocol", "sftp") or "sftp").strip().lower()
            backend = self._connect_backend(protocol)
            client, sftp = backend.connect(cfg, timeout_seconds=self._connect_timeout())
            observed = backend.get_remote_host_key_fingerprint(client)
            if protocol != "ftp":
                self._verify_host_key(cfg=cfg, observed_fingerprint=observed)
        except Exception as exc:
            mapped = self._map_error(exc)
            with self._lock:
                self._record_error(mapped)
                self._stats.total_connect_latency_ms += (time.perf_counter() - start) * 1000.0
            raise HTTPException(status_code=502, detail={"code": mapped.code, "message": mapped.message}) from exc

        sess = _PooledSession(key=key, client=client, sftp=sftp, owner=cfg.owner, mount_id=cfg.mount_id, in_use=1)
        with self._lock:
            self._pool[key] = sess
            self._stats.total_connects += 1
            self._stats.active_sessions += 1
            self._stats.total_connect_latency_ms += (time.perf_counter() - start) * 1000.0
        return sess

    def release(self, sess: _PooledSession) -> None:
        with self._lock:
            current = self._pool.get(sess.key)
            if not current:
                return
            current.in_use = max(0, current.in_use - 1)
            current.last_used_ts = time.time()

    def invalidate_mount(self, *, owner: str, mount_id: str) -> int:
        prefix = f"{owner}|{mount_id}|"
        removed = 0
        with self._lock:
            for key, sess in list(self._pool.items()):
                if not key.startswith(prefix):
                    continue
                try:
                    self._session_close(sess.client, sess.sftp)
                finally:
                    self._pool.pop(key, None)
                    removed += 1
                    self._stats.active_sessions = max(0, self._stats.active_sessions - 1)
        return removed

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            avg_ms = 0.0
            if self._stats.total_connects > 0:
                avg_ms = self._stats.total_connect_latency_ms / float(self._stats.total_connects)
            return {
                "active_sessions": int(self._stats.active_sessions),
                "total_connects": int(self._stats.total_connects),
                "total_reuses": int(self._stats.total_reuses),
                "failed_connects": int(self._stats.failed_connects),
                "auth_failures": int(self._stats.auth_failures),
                "network_failures": int(self._stats.network_failures),
                "host_key_failures": int(self._stats.host_key_failures),
                "pool_evictions": int(self._stats.pool_evictions),
                "avg_connect_latency_ms": float(round(avg_ms, 3)),
            }


_POOL: Optional[SftpConnectionPool] = None


def _default_pool() -> SftpConnectionPool:
    global _POOL
    if _POOL is None:
        _POOL = SftpConnectionPool()
    return _POOL


def acquire_sftp_session(cfg: SftpConnectionConfig) -> _PooledSession:
    return _default_pool().acquire(cfg)


def release_sftp_session(sess: _PooledSession) -> None:
    _default_pool().release(sess)


def invalidate_sftp_sessions_for_mount(*, owner: str, mount_id: str) -> int:
    return _default_pool().invalidate_mount(owner=owner, mount_id=mount_id)


def get_sftp_client_stats() -> Dict[str, Any]:
    return _default_pool().stats()
