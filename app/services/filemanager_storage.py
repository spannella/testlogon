from __future__ import annotations

import io
import stat as statmod
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Protocol

from fastapi import HTTPException, UploadFile

from app.services import filemanager
from app.services.sftp_client import SftpConnectionConfig, acquire_sftp_session, release_sftp_session
from app.services.sftp_credentials import get_sftp_credential
from app.services.sftp_mounts import find_sftp_mount_by_id, get_sftp_mount, update_sftp_mount


class FileManagerStorageProvider(Protocol):
    provider_name: str

    def list_dir(self, owner: str, path: str) -> List[Dict[str, Any]]:
        ...

    def stat(self, owner: str, path: str) -> Dict[str, Any]:
        ...

    def read_stream(self, owner: str, path: str) -> Dict[str, Any]:
        ...

    def write_stream(self, owner: str, path: str, content: bytes, *, content_type: Optional[str] = None, overwrite: bool = True) -> Dict[str, Any]:
        ...

    def mkdir(self, owner: str, path: str) -> Dict[str, Any]:
        ...

    def delete(self, owner: str, path: str) -> Dict[str, Any]:
        ...

    def move(self, owner: str, src: str, dst: str, *, overwrite: bool = False) -> Dict[str, Any]:
        ...


@dataclass
class _MountCircuitState:
    failures: int = 0
    open_until_ts: float = 0.0
    last_error_code: Optional[str] = None


_MOUNT_CIRCUITS: Dict[str, _MountCircuitState] = {}
_MOUNT_CIRCUITS_LOCK = threading.Lock()


class S3FileManagerStorageProvider:
    provider_name = "s3"

    def list_dir(self, owner: str, path: str) -> List[Dict[str, Any]]:
        folder = filemanager.norm_path(path, is_folder=True)
        return filemanager.list_children(owner, folder)

    def stat(self, owner: str, path: str) -> Dict[str, Any]:
        normalized = filemanager.norm_path(path, is_folder=None)
        return filemanager.get_node(owner, normalized)

    def read_stream(self, owner: str, path: str) -> Dict[str, Any]:
        return filemanager.download_file(owner, path)

    def write_stream(self, owner: str, path: str, content: bytes, *, content_type: Optional[str] = None, overwrite: bool = True) -> Dict[str, Any]:
        headers = {"content-type": content_type} if content_type else None
        upload = UploadFile(
            filename=filemanager.split_parent_name(filemanager.norm_path(path, is_folder=False))[1],
            file=io.BytesIO(content),
            headers=headers,
        )
        return filemanager.upload_file(owner, path, upload)

    def mkdir(self, owner: str, path: str) -> Dict[str, Any]:
        folder = filemanager.create_empty_folder(owner, path)
        return {"path": folder, "type": "folder"}

    def delete(self, owner: str, path: str) -> Dict[str, Any]:
        normalized = filemanager.norm_path(path, is_folder=None)
        if normalized.endswith("/"):
            deleted_count = filemanager.remove_folder(owner, normalized)
            return {"ok": True, "deleted_count": int(deleted_count), "type": "folder"}
        filemanager.remove_file(owner, normalized)
        return {"ok": True, "type": "file"}

    def move(self, owner: str, src: str, dst: str, *, overwrite: bool = False) -> Dict[str, Any]:
        return filemanager.move_node(owner, src, dst)


class SftpMountStorageProvider:
    provider_name = "sftp"

    def __init__(self, mount_id: str):
        self.mount_id = mount_id

    def _mount_and_credentials(self, owner: str):
        mount = get_sftp_mount(owner=owner, mount_id=self.mount_id)
        cred = get_sftp_credential(owner=owner, mount_id=str(mount.auth_credential_ref), include_secret=True)
        secret = cred.get("secret") or {}
        cfg = SftpConnectionConfig(
            owner=owner,
            mount_id=self.mount_id,
            host=str(mount.host),
            port=int(mount.port),
            username=str(cred.get("username") or ""),
            auth_mode=str(cred.get("auth_mode") or ""),
            protocol=str(getattr(mount, "protocol", "sftp") or "sftp"),
            password=secret.get("password"),
            private_key=secret.get("private_key"),
            private_key_passphrase=secret.get("private_key_passphrase"),
            expected_host_key=None,
        )
        return mount, cfg

    def _norm_remote_root(self, root: str) -> str:
        base = (root or "").strip()
        if not base:
            raise HTTPException(status_code=500, detail="mount remote_root not configured")
        if not base.startswith("/"):
            raise HTTPException(status_code=500, detail="mount remote_root must start with '/'")
        clean_parts = [p for p in base.split("/") if p and p != "."]
        if any(p == ".." for p in clean_parts):
            raise HTTPException(status_code=500, detail="mount remote_root contains invalid segment")
        return "/" + "/".join(clean_parts)

    def _split_virtual(self, path: str) -> Dict[str, Any]:
        normalized = filemanager.norm_path(path, is_folder=None)
        parts = [p for p in normalized.split("/") if p]
        if len(parts) < 2 or parts[0] != "mounts" or parts[1] != self.mount_id:
            raise HTTPException(status_code=400, detail="invalid mounted path")
        rel_parts = parts[2:]
        if any(p in {"", ".", ".."} for p in rel_parts):
            raise HTTPException(status_code=400, detail="invalid mounted path")
        return {
            "normalized": normalized,
            "is_folder": normalized.endswith("/"),
            "rel_parts": rel_parts,
        }

    def _remote_path(self, *, mount_root: str, rel_parts: List[str], is_folder: bool) -> str:
        base = self._norm_remote_root(mount_root)
        if not rel_parts:
            return base if base != "" else "/"
        remote = base.rstrip("/") + "/" + "/".join(rel_parts)
        if is_folder and not remote.endswith("/"):
            remote = remote + "/"
        return remote

    def _iso_from_mtime(self, mtime: Optional[int]) -> Optional[str]:
        if mtime is None:
            return None
        try:
            return datetime.fromtimestamp(int(mtime), tz=timezone.utc).isoformat()
        except Exception:
            return None

    def _map_fs_error(self, exc: Exception) -> HTTPException:
        msg = str(exc) or "sftp operation failed"
        lower = msg.lower()
        if "no such file" in lower or "not found" in lower:
            return HTTPException(status_code=404, detail={"code": "remote_not_found", "message": "remote path not found"})
        if "permission denied" in lower:
            return HTTPException(status_code=403, detail={"code": "remote_permission_denied", "message": "remote permission denied"})
        return HTTPException(status_code=502, detail={"code": "remote_io_error", "message": msg})

    def list_dir(self, owner: str, path: str) -> List[Dict[str, Any]]:
        mount, cfg = self._mount_and_credentials(owner)
        split = self._split_virtual(filemanager.norm_path(path, is_folder=True))
        remote_dir = self._remote_path(mount_root=str(mount.remote_root), rel_parts=split["rel_parts"], is_folder=True)

        def _op():
            sess = acquire_sftp_session(cfg)
            try:
                rows = sess.sftp.listdir_attr(remote_dir)
                return rows
            except HTTPException:
                raise
            except Exception as exc:  # pragma: no cover - depends on backend
                raise self._map_fs_error(exc) from exc
            finally:
                release_sftp_session(sess)

        rows = self._run_with_resilience(owner, mount, "list_dir", _op)

        base_virtual = filemanager.norm_path(path, is_folder=True).rstrip("/")
        out: List[Dict[str, Any]] = []
        for attr in rows:
            name = str(getattr(attr, "filename", "") or "")
            if not name:
                continue
            mode = int(getattr(attr, "st_mode", 0) or 0)
            is_dir = statmod.S_ISDIR(mode)
            child_path = f"{base_virtual}/{name}" if base_virtual else f"/{name}"
            if is_dir:
                child_path = child_path.rstrip("/") + "/"
            out.append(
                {
                    "path": child_path,
                    "type": "folder" if is_dir else "file",
                    "name": name,
                    "parent": filemanager.norm_path(path, is_folder=True),
                    "size": None if is_dir else int(getattr(attr, "st_size", 0) or 0),
                    "updated_at": self._iso_from_mtime(getattr(attr, "st_mtime", None)),
                    "content_type": None,
                }
            )
        return out

    def stat(self, owner: str, path: str) -> Dict[str, Any]:
        mount, cfg = self._mount_and_credentials(owner)
        normalized = filemanager.norm_path(path, is_folder=None)
        split = self._split_virtual(normalized)
        remote = self._remote_path(mount_root=str(mount.remote_root), rel_parts=split["rel_parts"], is_folder=split["is_folder"])

        def _op():
            sess = acquire_sftp_session(cfg)
            try:
                return sess.sftp.stat(remote)
            except HTTPException:
                raise
            except Exception as exc:  # pragma: no cover
                raise self._map_fs_error(exc) from exc
            finally:
                release_sftp_session(sess)

        attr = self._run_with_resilience(owner, mount, "stat", _op)

        mode = int(getattr(attr, "st_mode", 0) or 0)
        is_dir = statmod.S_ISDIR(mode) or split["is_folder"]
        parent, name = filemanager.split_parent_name(filemanager.norm_path(path, is_folder=is_dir if is_dir else False))
        return {
            "path": filemanager.norm_path(path, is_folder=True if is_dir else False),
            "type": "folder" if is_dir else "file",
            "name": name.rstrip("/") if is_dir else name,
            "parent": parent,
            "size": None if is_dir else int(getattr(attr, "st_size", 0) or 0),
            "updated_at": self._iso_from_mtime(getattr(attr, "st_mtime", None)),
            "content_type": None,
            "created_at": None,
            "upload_at": None,
            "upload_by": None,
            "last_download_at": None,
            "last_download_by": None,
            "duration_seconds": None,
            "thumbnail": None,
            "shared": False,
            "is_encrypted": False,
        }

    def read_stream(self, owner: str, path: str) -> Dict[str, Any]:
        node = self.stat(owner, path)
        if node.get("type") != "file":
            raise HTTPException(status_code=400, detail={"code": "not_a_file", "message": "path is not a file"})

        mount, cfg = self._mount_and_credentials(owner)
        split = self._split_virtual(filemanager.norm_path(path, is_folder=False))
        remote = self._remote_path(mount_root=str(mount.remote_root), rel_parts=split["rel_parts"], is_folder=False)

        def _op():
            sess = acquire_sftp_session(cfg)
            try:
                fd = sess.sftp.open(remote, "rb")
                data = fd.read()
                try:
                    fd.close()
                except Exception:
                    pass
                return data
            except HTTPException:
                raise
            except Exception as exc:  # pragma: no cover
                raise self._map_fs_error(exc) from exc
            finally:
                release_sftp_session(sess)

        data = self._run_with_resilience(owner, mount, "read_stream", _op)

        return {
            "node": node,
            "object": {"Body": io.BytesIO(data)},
        }

    def _enforce_mount_write_policy(self, mount: Any) -> None:
        if bool(getattr(mount, "read_only", False)):
            raise HTTPException(
                status_code=403,
                detail={"code": "mount_read_only", "message": "mount is read-only and does not permit write operations"},
            )

    def _exists(self, sftp: Any, remote: str) -> bool:
        try:
            sftp.stat(remote)
            return True
        except Exception:
            return False

    def _delete_remote_tree(self, sftp: Any, remote_dir: str) -> int:
        deleted = 0
        for child in sftp.listdir_attr(remote_dir):
            name = str(getattr(child, "filename", "") or "")
            if not name:
                continue
            child_remote = remote_dir.rstrip("/") + "/" + name
            mode = int(getattr(child, "st_mode", 0) or 0)
            if statmod.S_ISDIR(mode):
                deleted += self._delete_remote_tree(sftp, child_remote)
                sftp.rmdir(child_remote)
                deleted += 1
            else:
                sftp.remove(child_remote)
                deleted += 1
        return deleted

    def _operation_timeout_budget_seconds(self) -> float:
        from app.core.settings import S

        return float(max(1, int(getattr(S, "filemgr_sftp_operation_timeout_seconds", 20) or 20)))

    def _retry_max_attempts(self) -> int:
        from app.core.settings import S

        return int(max(1, int(getattr(S, "filemgr_sftp_retry_max_attempts", 2) or 2)))

    def _retry_backoff_seconds(self) -> float:
        from app.core.settings import S

        ms = int(max(0, int(getattr(S, "filemgr_sftp_retry_backoff_ms", 100) or 100)))
        return float(ms) / 1000.0

    def _circuit_failure_threshold(self) -> int:
        from app.core.settings import S

        return int(max(1, int(getattr(S, "filemgr_sftp_circuit_failure_threshold", 5) or 5)))

    def _circuit_open_seconds(self) -> int:
        from app.core.settings import S

        return int(max(1, int(getattr(S, "filemgr_sftp_circuit_open_seconds", 30) or 30)))

    def _is_retryable_error(self, exc: HTTPException) -> bool:
        detail = exc.detail if isinstance(exc.detail, dict) else {}
        code = str(detail.get("code") or "")
        return code in {"network_timeout", "network_unreachable", "connection_failed", "protocol_error", "pool_exhausted", "remote_io_error"}

    def _mount_status_from_error(self, exc: HTTPException) -> str:
        detail = exc.detail if isinstance(exc.detail, dict) else {}
        code = str(detail.get("code") or "")
        if code == "auth_failed":
            return "auth_failed"
        if code in {"network_timeout", "network_unreachable", "host_key_mismatch", "host_key_required", "host_key_missing", "connection_failed", "pool_exhausted"}:
            return "unreachable"
        return "degraded"

    def _record_mount_failure(self, owner: str, mount: Any, exc: HTTPException) -> None:
        mount_key = f"{owner}:{self.mount_id}"
        code = "remote_error"
        message = str(exc.detail)
        if isinstance(exc.detail, dict):
            code = str(exc.detail.get("code") or code)
            message = str(exc.detail.get("message") or message)
        now = time.time()
        with _MOUNT_CIRCUITS_LOCK:
            state = _MOUNT_CIRCUITS.get(mount_key)
            if not state:
                state = _MountCircuitState()
                _MOUNT_CIRCUITS[mount_key] = state
            state.failures += 1
            state.last_error_code = code
            if state.failures >= self._circuit_failure_threshold() and self._is_retryable_error(exc):
                state.open_until_ts = now + float(self._circuit_open_seconds())
        try:
            update_sftp_mount(
                owner=owner,
                mount_id=str(getattr(mount, "id", self.mount_id)),
                status=self._mount_status_from_error(exc),
                last_error_code=code,
                last_error_message=message,
            )
        except Exception:
            pass

    def _record_mount_success(self, owner: str, mount: Any) -> None:
        mount_key = f"{owner}:{self.mount_id}"
        with _MOUNT_CIRCUITS_LOCK:
            state = _MOUNT_CIRCUITS.get(mount_key)
            if state:
                state.failures = 0
                state.open_until_ts = 0.0
                state.last_error_code = None
        try:
            if str(getattr(mount, "status", "")) != "healthy":
                update_sftp_mount(
                    owner=owner,
                    mount_id=str(getattr(mount, "id", self.mount_id)),
                    status="healthy",
                    last_error_code=None,
                    last_error_message=None,
                )
        except Exception:
            pass

    def _check_circuit_open(self, owner: str) -> None:
        mount_key = f"{owner}:{self.mount_id}"
        with _MOUNT_CIRCUITS_LOCK:
            state = _MOUNT_CIRCUITS.get(mount_key)
            if not state:
                return
            if state.open_until_ts > time.time():
                retry_after = max(1, int(state.open_until_ts - time.time()))
                raise HTTPException(
                    status_code=503,
                    detail={
                        "code": "sftp_mount_circuit_open",
                        "message": "sftp mount temporarily unavailable due to repeated remote failures",
                        "retry_after_seconds": retry_after,
                        "mount_id": self.mount_id,
                    },
                )

    def _run_with_resilience(self, owner: str, mount: Any, operation: str, fn):
        self._check_circuit_open(owner)
        deadline = time.perf_counter() + self._operation_timeout_budget_seconds()
        attempts = self._retry_max_attempts()
        backoff = self._retry_backoff_seconds()
        last_exc: Optional[HTTPException] = None
        for idx in range(attempts):
            if time.perf_counter() > deadline:
                break
            try:
                out = fn()
                self._record_mount_success(owner, mount)
                return out
            except HTTPException as exc:
                last_exc = exc
                self._record_mount_failure(owner, mount, exc)
                if not self._is_retryable_error(exc) or idx + 1 >= attempts:
                    raise
                if time.perf_counter() + backoff > deadline:
                    break
                time.sleep(backoff)

        raise HTTPException(
            status_code=504,
            detail={
                "code": "sftp_operation_timeout_budget_exceeded",
                "message": f"sftp operation '{operation}' exceeded retry/time budget",
                "mount_id": self.mount_id,
                "last_error": (last_exc.detail if isinstance(last_exc, HTTPException) else None),
            },
        )

    def write_stream(
        self,
        owner: str,
        path: str,
        content: bytes,
        *,
        content_type: Optional[str] = None,
        overwrite: bool = True,
    ) -> Dict[str, Any]:
        mount, cfg = self._mount_and_credentials(owner)
        self._enforce_mount_write_policy(mount)
        split = self._split_virtual(filemanager.norm_path(path, is_folder=False))
        remote = self._remote_path(mount_root=str(mount.remote_root), rel_parts=split["rel_parts"], is_folder=False)

        def _op():
            sess = acquire_sftp_session(cfg)
            try:
                if not overwrite and self._exists(sess.sftp, remote):
                    raise HTTPException(status_code=409, detail={"code": "overwrite_not_allowed", "message": "destination already exists"})
                fd = sess.sftp.open(remote, "wb")
                try:
                    fd.write(content or b"")
                finally:
                    try:
                        fd.close()
                    except Exception:
                        pass
            except HTTPException:
                raise
            except Exception as exc:  # pragma: no cover
                raise self._map_fs_error(exc) from exc
            finally:
                release_sftp_session(sess)

        self._run_with_resilience(owner, mount, "write_stream", _op)

        return self.stat(owner, path)

    def mkdir(self, owner: str, path: str) -> Dict[str, Any]:
        mount, cfg = self._mount_and_credentials(owner)
        self._enforce_mount_write_policy(mount)
        split = self._split_virtual(filemanager.norm_path(path, is_folder=True))
        remote = self._remote_path(mount_root=str(mount.remote_root), rel_parts=split["rel_parts"], is_folder=True).rstrip("/")

        def _op():
            sess = acquire_sftp_session(cfg)
            try:
                sess.sftp.mkdir(remote)
            except HTTPException:
                raise
            except Exception as exc:  # pragma: no cover
                raise self._map_fs_error(exc) from exc
            finally:
                release_sftp_session(sess)

        self._run_with_resilience(owner, mount, "mkdir", _op)

        return {"ok": True, "path": filemanager.norm_path(path, is_folder=True), "type": "folder"}

    def delete(self, owner: str, path: str) -> Dict[str, Any]:
        mount, cfg = self._mount_and_credentials(owner)
        self._enforce_mount_write_policy(mount)
        normalized = filemanager.norm_path(path, is_folder=None)
        split = self._split_virtual(normalized)
        remote = self._remote_path(mount_root=str(mount.remote_root), rel_parts=split["rel_parts"], is_folder=split["is_folder"])

        def _op():
            sess = acquire_sftp_session(cfg)
            try:
                node = self.stat(owner, normalized)
                if node.get("type") == "folder":
                    deleted_count = self._delete_remote_tree(sess.sftp, remote.rstrip("/"))
                    sess.sftp.rmdir(remote.rstrip("/"))
                    deleted_count += 1
                    return {"ok": True, "deleted_count": int(deleted_count), "type": "folder"}
                sess.sftp.remove(remote)
                return {"ok": True, "type": "file"}
            except HTTPException:
                raise
            except Exception as exc:  # pragma: no cover
                raise self._map_fs_error(exc) from exc
            finally:
                release_sftp_session(sess)

        return self._run_with_resilience(owner, mount, "delete", _op)

    def move(self, owner: str, src: str, dst: str, *, overwrite: bool = False) -> Dict[str, Any]:
        mount, cfg = self._mount_and_credentials(owner)
        self._enforce_mount_write_policy(mount)
        src_split = self._split_virtual(filemanager.norm_path(src, is_folder=None))
        dst_split = self._split_virtual(filemanager.norm_path(dst, is_folder=None))
        src_remote = self._remote_path(mount_root=str(mount.remote_root), rel_parts=src_split["rel_parts"], is_folder=src_split["is_folder"])
        dst_remote = self._remote_path(mount_root=str(mount.remote_root), rel_parts=dst_split["rel_parts"], is_folder=dst_split["is_folder"])

        def _op():
            sess = acquire_sftp_session(cfg)
            try:
                if not overwrite and self._exists(sess.sftp, dst_remote):
                    raise HTTPException(status_code=409, detail={"code": "overwrite_not_allowed", "message": "destination already exists"})
                sess.sftp.rename(src_remote.rstrip("/"), dst_remote.rstrip("/"))
            except HTTPException:
                raise
            except Exception as exc:  # pragma: no cover
                raise self._map_fs_error(exc) from exc
            finally:
                release_sftp_session(sess)

        self._run_with_resilience(owner, mount, "move", _op)
        return {
            "src": filemanager.norm_path(src, is_folder=src_split["is_folder"]),
            "dst": filemanager.norm_path(dst, is_folder=dst_split["is_folder"]),
            "type": "folder" if src_split["is_folder"] else "file",
        }


@dataclass
class ResolvedStorageProvider:
    provider: FileManagerStorageProvider
    backend: str
    mount_id: Optional[str] = None


def _extract_mount_id(path: str) -> Optional[str]:
    normalized = filemanager.norm_path(path, is_folder=None)
    if not normalized.startswith("/mounts/"):
        return None
    parts = [p for p in normalized.split("/") if p]
    if len(parts) < 2:
        raise HTTPException(status_code=400, detail="invalid mount path")
    return parts[1]


def resolve_storage_provider(owner: str, path: str) -> ResolvedStorageProvider:
    mount_id = _extract_mount_id(path)
    if not mount_id:
        return ResolvedStorageProvider(provider=S3FileManagerStorageProvider(), backend="s3", mount_id=None)

    try:
        get_sftp_mount(owner=owner, mount_id=mount_id)
    except HTTPException as exc:
        if exc.status_code == 404:
            mount = find_sftp_mount_by_id(mount_id=mount_id)
            if mount and str(getattr(mount, "owner", "")) != str(owner):
                raise HTTPException(
                    status_code=403,
                    detail={
                        "code": "mount_forbidden",
                        "message": "you do not have access to this mount",
                        "mount_id": mount_id,
                    },
                ) from exc
            raise HTTPException(
                status_code=404,
                detail={
                    "code": "mount_not_found",
                    "message": "sftp mount not found",
                    "mount_id": mount_id,
                },
            ) from exc
        raise
    return ResolvedStorageProvider(provider=SftpMountStorageProvider(mount_id=mount_id), backend="sftp", mount_id=mount_id)
