from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Any, Callable, Dict, List, Optional, Protocol, runtime_checkable

from fastapi import HTTPException, UploadFile

from app.core.settings import S
from app.metrics import record_filemgr_icloud_read_cache


@dataclass(frozen=True)
class MountResolution:
    provider: str
    mount_id: Optional[str] = None
    mount_path: Optional[str] = None
    status: Optional[str] = None


@runtime_checkable
class FileStorageProvider(Protocol):
    """Provider contract for file-manager storage backends."""

    name: str

    def list(self, user: str, path: str, *, include_deleted: bool = False) -> List[Dict[str, Any]]:
        ...

    def stat(self, user: str, path: str) -> Dict[str, Any]:
        ...

    def read(self, user: str, path: str) -> Dict[str, Any]:
        ...

    def write(
        self,
        user: str,
        path: str,
        upload: UploadFile,
        *,
        encryption_meta: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        ...

    def delete(self, user: str, path: str) -> Any:
        ...

    def mkdir(self, user: str, path: str) -> str:
        ...

    def move(self, user: str, src: str, dst: str) -> Dict[str, Any]:
        ...


class S3FileStorageProvider:
    """Default provider backed by the existing filemanager service implementation."""

    name = "s3"

    def list(self, user: str, path: str, *, include_deleted: bool = False) -> List[Dict[str, Any]]:
        from app.services import filemanager as svc

        folder = svc.norm_path(path, is_folder=True)
        return svc.list_children(user, folder, include_deleted=include_deleted)

    def stat(self, user: str, path: str) -> Dict[str, Any]:
        from app.services import filemanager as svc

        p = svc.norm_path(path, is_folder=None)
        return svc.get_node(user, p)

    def read(self, user: str, path: str) -> Dict[str, Any]:
        from app.services import filemanager as svc

        p = svc.norm_path(path, is_folder=False)
        return svc.download_file(user, p)

    def write(
        self,
        user: str,
        path: str,
        upload: UploadFile,
        *,
        encryption_meta: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        from app.services import filemanager as svc

        del idempotency_key
        p = svc.norm_path(path, is_folder=False)
        return svc.upload_file(user, p, upload, encryption_meta=encryption_meta)

    def delete(self, user: str, path: str) -> Any:
        from app.services import filemanager as svc

        if str(path).endswith("/"):
            return svc.remove_folder(user, svc.norm_path(path, is_folder=True))
        return svc.remove_file(user, svc.norm_path(path, is_folder=False))

    def mkdir(self, user: str, path: str) -> str:
        from app.services import filemanager as svc

        p = svc.norm_path(path, is_folder=True)
        return svc.create_empty_folder(user, p)

    def move(self, user: str, src: str, dst: str) -> Dict[str, Any]:
        from app.services import filemanager as svc

        src_n = svc.norm_path(src, is_folder=None)
        dst_n = svc.norm_path(dst, is_folder=None)
        return svc.move_node(user, src_n, dst_n)


class RemoteUnavailableProvider:
    """Placeholder remote provider that confirms routing but blocks operations until implemented."""

    def __init__(self, name: str):
        self.name = name

    def _raise(self) -> None:
        raise HTTPException(status_code=501, detail=f"provider '{self.name}' is not configured")

    def list(self, user: str, path: str, *, include_deleted: bool = False) -> List[Dict[str, Any]]:
        self._raise()

    def stat(self, user: str, path: str) -> Dict[str, Any]:
        self._raise()

    def read(self, user: str, path: str) -> Dict[str, Any]:
        self._raise()

    def write(
        self,
        user: str,
        path: str,
        upload: UploadFile,
        *,
        encryption_meta: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        del user, path, upload, encryption_meta, idempotency_key
        self._raise()

    def delete(self, user: str, path: str) -> Any:
        self._raise()

    def mkdir(self, user: str, path: str) -> str:
        self._raise()

    def move(self, user: str, src: str, dst: str) -> Dict[str, Any]:
        self._raise()


class MountUnavailableProvider:
    """Provider wrapper for mounts in unavailable/reauth-required states."""

    def __init__(self, name: str, *, mount_status: str):
        self.name = name
        self.mount_status = (mount_status or "unavailable").lower()

    def _raise(self) -> None:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "mount_unavailable",
                "provider": self.name,
                "mount_status": self.mount_status,
                "message": "mount is temporarily unavailable",
            },
        )

    def list(self, user: str, path: str, *, include_deleted: bool = False) -> List[Dict[str, Any]]:
        del user, path, include_deleted
        self._raise()

    def stat(self, user: str, path: str) -> Dict[str, Any]:
        del user, path
        self._raise()

    def read(self, user: str, path: str) -> Dict[str, Any]:
        del user, path
        self._raise()

    def write(
        self,
        user: str,
        path: str,
        upload: UploadFile,
        *,
        encryption_meta: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        del user, path, upload, encryption_meta, idempotency_key
        self._raise()

    def delete(self, user: str, path: str) -> Any:
        del user, path
        self._raise()

    def mkdir(self, user: str, path: str) -> str:
        del user, path
        self._raise()

    def move(self, user: str, src: str, dst: str) -> Dict[str, Any]:
        del user, src, dst
        self._raise()


class ICloudProviderError(Exception):
    """Base class for iCloud transport/provider exceptions."""


class ICloudAuthExpiredError(ICloudProviderError):
    pass


class ICloudMFARequiredError(ICloudProviderError):
    pass


class ICloudThrottledError(ICloudProviderError):
    pass


class ICloudTransientError(ICloudProviderError):
    pass


class ICloudPermanentError(ICloudProviderError):
    pass


class ICloudConflictError(ICloudProviderError):
    pass


class ICloudNotFoundError(ICloudProviderError):
    pass


class ICloudTransportUnavailableError(ICloudTransientError):
    pass


class ICloudAuthError(ICloudAuthExpiredError):
    """Backward-compatible alias for previous auth error naming."""


class ICloudTransport(Protocol):
    def list(self, *, user_sub: str, path: str) -> List[Dict[str, Any]]:
        ...

    def stat(self, *, user_sub: str, path: str) -> Dict[str, Any]:
        ...

    def read(self, *, user_sub: str, path: str) -> Dict[str, Any]:
        ...

    def write(self, *, user_sub: str, path: str, data: bytes, content_type: Optional[str], overwrite: bool = False) -> Dict[str, Any]:
        ...

    def delete(self, *, user_sub: str, path: str) -> Any:
        ...

    def move(self, *, user_sub: str, src: str, dst: str, overwrite: bool = False) -> Dict[str, Any]:
        ...


class UnconfiguredICloudTransport:
    """Default transport placeholder until a real iCloud connector is wired."""

    def list(self, *, user_sub: str, path: str) -> List[Dict[str, Any]]:
        raise ICloudTransportUnavailableError("icloud connector is unavailable")

    def stat(self, *, user_sub: str, path: str) -> Dict[str, Any]:
        raise ICloudTransportUnavailableError("icloud connector is unavailable")

    def read(self, *, user_sub: str, path: str) -> Dict[str, Any]:
        raise ICloudTransportUnavailableError("icloud connector is unavailable")

    def write(self, *, user_sub: str, path: str, data: bytes, content_type: Optional[str], overwrite: bool = False) -> Dict[str, Any]:
        del user_sub, path, data, content_type, overwrite
        raise ICloudTransportUnavailableError("icloud connector is unavailable")

    def delete(self, *, user_sub: str, path: str) -> Any:
        del user_sub, path
        raise ICloudTransportUnavailableError("icloud connector is unavailable")

    def move(self, *, user_sub: str, src: str, dst: str, overwrite: bool = False) -> Dict[str, Any]:
        del user_sub, src, dst, overwrite
        raise ICloudTransportUnavailableError("icloud connector is unavailable")


class _BytesBody:
    def __init__(self, data: bytes):
        self._data = data
        self._sent = False

    def read(self, n: int = -1) -> bytes:
        del n
        if self._sent:
            return b""
        self._sent = True
        return self._data


class ICloudProvider:
    """iCloud provider with retry policy + conflict resolution semantics."""

    name = "icloud"

    def __init__(self, *, transport: Optional[ICloudTransport] = None):
        self._transport = transport or UnconfiguredICloudTransport()
        self._idempotency_results: Dict[str, Dict[str, Any]] = {}
        self._read_cache: Dict[str, tuple[float, Dict[str, Any], bytes]] = {}
        self._read_counts: Dict[str, int] = {}

    def _ensure_enabled(self) -> None:
        if not bool(getattr(S, "filemgr_icloud_provider_enabled", False)):
            raise HTTPException(status_code=503, detail={"code": "feature_disabled", "provider": "icloud"})

    def _ensure_write_enabled(self) -> None:
        if bool(getattr(S, "filemgr_icloud_read_only", True)):
            raise HTTPException(status_code=405, detail={"code": "provider_read_only", "provider": "icloud"})

    @staticmethod
    def _error_detail(*, code: str, retryable: bool, action: str) -> Dict[str, Any]:
        return {
            "code": code,
            "provider": "icloud",
            "retryable": bool(retryable),
            "action": action,
        }

    @staticmethod
    def _is_retryable(exc: Exception) -> bool:
        return isinstance(exc, (ICloudThrottledError, ICloudTransientError, ICloudTransportUnavailableError))

    @staticmethod
    def _map_error(exc: Exception) -> HTTPException:
        if isinstance(exc, HTTPException):
            return exc
        if isinstance(exc, ICloudAuthExpiredError):
            return HTTPException(status_code=401, detail=ICloudProvider._error_detail(code="auth_expired", retryable=False, action="reconnect"))
        if isinstance(exc, ICloudMFARequiredError):
            return HTTPException(status_code=409, detail=ICloudProvider._error_detail(code="mfa_required", retryable=False, action="complete_mfa"))
        if isinstance(exc, ICloudThrottledError):
            return HTTPException(status_code=429, detail=ICloudProvider._error_detail(code="throttled", retryable=True, action="retry_with_backoff"))
        if isinstance(exc, ICloudConflictError):
            return HTTPException(status_code=409, detail=ICloudProvider._error_detail(code="conflict", retryable=False, action="resolve_conflict"))
        if isinstance(exc, ICloudNotFoundError):
            return HTTPException(status_code=404, detail=ICloudProvider._error_detail(code="not_found", retryable=False, action="refresh_path"))
        if isinstance(exc, ICloudTransientError):
            return HTTPException(status_code=503, detail=ICloudProvider._error_detail(code="transient", retryable=True, action="retry"))
        if isinstance(exc, ICloudPermanentError):
            return HTTPException(status_code=502, detail=ICloudProvider._error_detail(code="permanent", retryable=False, action="contact_support"))
        return HTTPException(status_code=502, detail=ICloudProvider._error_detail(code="upstream_error", retryable=False, action="contact_support"))

    def _retry_policy(self) -> tuple[int, float, float]:
        attempts = int(getattr(S, "filemgr_icloud_retry_max_attempts", 3) or 3)
        base = float(getattr(S, "filemgr_icloud_retry_base_seconds", 0.2) or 0.2)
        cap = float(getattr(S, "filemgr_icloud_retry_cap_seconds", 2.0) or 2.0)
        if attempts < 1:
            attempts = 1
        if base < 0:
            base = 0.0
        if cap < base:
            cap = base
        return attempts, base, cap

    def _call_with_retry(self, op: Callable[[], Any]) -> Any:
        attempts, base, cap = self._retry_policy()
        last_exc: Optional[Exception] = None
        for i in range(attempts):
            try:
                return op()
            except Exception as exc:
                last_exc = exc
                if (not self._is_retryable(exc)) or i >= attempts - 1:
                    raise
                delay = min(base * (2 ** i), cap)
                time.sleep(delay)
        if last_exc is not None:
            raise last_exc
        raise HTTPException(
            status_code=502,
            detail=ICloudProvider._error_detail(code="upstream_error", retryable=False, action="contact_support"),
        )

    def _mount_policy(self, user: str, path: str) -> str:
        from app.services.filemanager_mounts import resolve_mount_for_path

        try:
            mount = resolve_mount_for_path(owner_user_sub=user, path=path) or {}
        except Exception:
            mount = {}
        policy = str(mount.get("conflict_policy") or "fail").lower()
        if policy not in {"fail", "rename", "last_write_wins"}:
            policy = "fail"
        return policy

    def _exists(self, user: str, path: str) -> bool:
        try:
            self._call_with_retry(lambda: self._transport.stat(user_sub=user, path=path))
            return True
        except ICloudNotFoundError:
            return False

    @staticmethod
    def _renamed_path(path: str, n: int) -> str:
        if path.endswith("/"):
            return path
        idx = path.rfind("/")
        parent = path[:idx + 1] if idx >= 0 else ""
        name = path[idx + 1:] if idx >= 0 else path
        dot = name.rfind(".")
        if dot > 0:
            stem = name[:dot]
            ext = name[dot:]
        else:
            stem = name
            ext = ""
        return f"{parent}{stem} ({n}){ext}"

    @staticmethod
    def _idempotency_scope(user: str, path: str, key: str) -> str:
        return f"{user}:{path}:{key}"

    @staticmethod
    def _read_cache_scope(user: str, path: str) -> str:
        return f"{user}:{path}"

    def _is_cache_enabled(self) -> bool:
        return bool(getattr(S, "filemgr_icloud_read_cache_enabled", False))

    def _cache_policy(self) -> tuple[int, int, int, int]:
        ttl = int(getattr(S, "filemgr_icloud_read_cache_ttl_seconds", 120) or 120)
        min_bytes = int(getattr(S, "filemgr_icloud_read_cache_min_bytes", 1024 * 1024) or (1024 * 1024))
        freq = int(getattr(S, "filemgr_icloud_read_cache_freq_threshold", 3) or 3)
        max_entries = int(getattr(S, "filemgr_icloud_read_cache_max_entries", 256) or 256)
        if ttl < 1:
            ttl = 1
        if min_bytes < 1:
            min_bytes = 1
        if freq < 1:
            freq = 1
        if max_entries < 1:
            max_entries = 1
        return ttl, min_bytes, freq, max_entries

    def _cache_get(self, user: str, path: str) -> Optional[Dict[str, Any]]:
        if not self._is_cache_enabled():
            record_filemgr_icloud_read_cache(result="bypass", reason="disabled")
            return None
        key = self._read_cache_scope(user, path)
        cached = self._read_cache.get(key)
        if not cached:
            record_filemgr_icloud_read_cache(result="miss", reason="cold")
            return None
        expires_at, node, blob = cached
        if expires_at < time.time():
            self._read_cache.pop(key, None)
            record_filemgr_icloud_read_cache(result="miss", reason="expired")
            return None
        record_filemgr_icloud_read_cache(result="hit", reason="warm")
        return {"node": dict(node), "object": {"Body": _BytesBody(blob)}}

    def _cache_put(self, *, user: str, path: str, node: Dict[str, Any], blob: bytes) -> None:
        if not self._is_cache_enabled():
            return
        ttl, min_bytes, freq, max_entries = self._cache_policy()
        scope = self._read_cache_scope(user, path)
        hits = int(self._read_counts.get(scope, 0)) + 1
        self._read_counts[scope] = hits
        if len(blob) < min_bytes and hits < freq:
            record_filemgr_icloud_read_cache(result="bypass", reason="small_or_infrequent")
            return
        if scope not in self._read_cache and len(self._read_cache) >= max_entries:
            evict_scope = min(self._read_cache.items(), key=lambda item: float(item[1][0]))[0]
            self._read_cache.pop(evict_scope, None)
            self._read_counts.pop(evict_scope, None)
            record_filemgr_icloud_read_cache(result="invalidate", reason="evict")
        self._read_cache[scope] = (time.time() + ttl, dict(node), bytes(blob))
        record_filemgr_icloud_read_cache(result="store", reason="eligible")

    def _cache_invalidate(self, *, user: str, path: str, reason: str) -> None:
        scope = self._read_cache_scope(user, path)
        removed = self._read_cache.pop(scope, None)
        self._read_counts.pop(scope, None)
        if removed is not None:
            record_filemgr_icloud_read_cache(result="invalidate", reason=reason)

    def list(self, user: str, path: str, *, include_deleted: bool = False) -> List[Dict[str, Any]]:
        del include_deleted
        self._ensure_enabled()
        try:
            return self._call_with_retry(lambda: self._transport.list(user_sub=user, path=path))
        except Exception as exc:
            raise self._map_error(exc) from exc

    def stat(self, user: str, path: str) -> Dict[str, Any]:
        self._ensure_enabled()
        try:
            return self._call_with_retry(lambda: self._transport.stat(user_sub=user, path=path))
        except Exception as exc:
            raise self._map_error(exc) from exc

    def read(self, user: str, path: str) -> Dict[str, Any]:
        self._ensure_enabled()
        cached = self._cache_get(user, path)
        if cached is not None:
            return cached
        try:
            result = self._call_with_retry(lambda: self._transport.read(user_sub=user, path=path))
            node = dict((result or {}).get("node") or {})
            body = ((result or {}).get("object") or {}).get("Body")
            blob = body.read() if body is not None else b""
            self._cache_put(user=user, path=path, node=node, blob=blob)
            return {"node": node, "object": {"Body": _BytesBody(blob)}}
        except Exception as exc:
            raise self._map_error(exc) from exc

    def write(
        self,
        user: str,
        path: str,
        upload: UploadFile,
        *,
        encryption_meta: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        del encryption_meta
        self._ensure_enabled()
        self._ensure_write_enabled()
        idem = str(idempotency_key or "").strip()
        scope = self._idempotency_scope(user, path, idem) if idem else ""
        if scope and scope in self._idempotency_results:
            return self._idempotency_results[scope]

        policy = self._mount_policy(user, path)
        target = path
        overwrite = False
        try:
            if policy == "fail":
                if self._exists(user, target):
                    raise ICloudConflictError("target already exists")
            elif policy == "rename":
                if self._exists(user, target):
                    suffix = 1
                    while True:
                        candidate = self._renamed_path(path, suffix)
                        if not self._exists(user, candidate):
                            target = candidate
                            break
                        suffix += 1
            elif policy == "last_write_wins":
                overwrite = True

            data = upload.file.read()
            try:
                upload.file.seek(0)
            except Exception:
                pass
            result = self._call_with_retry(
                lambda: self._transport.write(
                    user_sub=user,
                    path=target,
                    data=data,
                    content_type=upload.content_type,
                    overwrite=overwrite,
                )
            )
            if isinstance(result, dict) and not result.get("path"):
                result["path"] = target
            if scope and isinstance(result, dict):
                self._idempotency_results[scope] = dict(result)
            self._cache_invalidate(user=user, path=target, reason="write")
            return result
        except Exception as exc:
            raise self._map_error(exc) from exc

    def delete(self, user: str, path: str) -> Any:
        self._ensure_enabled()
        self._ensure_write_enabled()
        try:
            result = self._call_with_retry(lambda: self._transport.delete(user_sub=user, path=path))
            self._cache_invalidate(user=user, path=path, reason="delete")
            return result
        except Exception as exc:
            raise self._map_error(exc) from exc

    def mkdir(self, user: str, path: str) -> str:
        del user, path
        raise HTTPException(status_code=405, detail={"code": "provider_read_only", "provider": "icloud"})

    def move(self, user: str, src: str, dst: str) -> Dict[str, Any]:
        self._ensure_enabled()
        self._ensure_write_enabled()
        policy = self._mount_policy(user, dst)
        overwrite = policy == "last_write_wins"
        target = dst
        try:
            if policy == "fail" and self._exists(user, target):
                raise ICloudConflictError("destination already exists")
            if policy == "rename" and self._exists(user, target):
                suffix = 1
                while True:
                    candidate = self._renamed_path(dst, suffix)
                    if not self._exists(user, candidate):
                        target = candidate
                        break
                    suffix += 1
            moved = self._call_with_retry(
                lambda: self._transport.move(user_sub=user, src=src, dst=target, overwrite=overwrite)
            )
            self._cache_invalidate(user=user, path=src, reason="move")
            self._cache_invalidate(user=user, path=target, reason="move")
            return moved
        except Exception as exc:
            raise self._map_error(exc) from exc


MountResolver = Callable[[str, str], Optional[MountResolution]]




class ReadOnlyProviderWrapper:
    def __init__(self, base: FileStorageProvider):
        self._base = base
        self.name = getattr(base, "name", "provider")

    def list(self, user: str, path: str, *, include_deleted: bool = False) -> List[Dict[str, Any]]:
        return self._base.list(user, path, include_deleted=include_deleted)

    def stat(self, user: str, path: str) -> Dict[str, Any]:
        return self._base.stat(user, path)

    def read(self, user: str, path: str) -> Dict[str, Any]:
        return self._base.read(user, path)

    def write(self, user: str, path: str, upload: UploadFile, *, encryption_meta: Optional[Dict[str, Any]] = None, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        del user, path, upload, encryption_meta, idempotency_key
        raise HTTPException(status_code=503, detail={"code": "mount_read_only", "message": "mount is in read-only degraded mode"})

    def delete(self, user: str, path: str) -> Any:
        del user, path
        raise HTTPException(status_code=503, detail={"code": "mount_read_only", "message": "mount is in read-only degraded mode"})

    def mkdir(self, user: str, path: str) -> str:
        del user, path
        raise HTTPException(status_code=503, detail={"code": "mount_read_only", "message": "mount is in read-only degraded mode"})

    def move(self, user: str, src: str, dst: str) -> Dict[str, Any]:
        del user, src, dst
        raise HTTPException(status_code=503, detail={"code": "mount_read_only", "message": "mount is in read-only degraded mode"})

class FileStorageDispatcher:
    def __init__(
        self,
        *,
        default_provider: FileStorageProvider,
        providers: Optional[Dict[str, FileStorageProvider]] = None,
        resolver: Optional[MountResolver] = None,
    ):
        base = {default_provider.name: default_provider}
        if providers:
            base.update(providers)
        self._providers = base
        self._default = default_provider
        self._resolver = resolver

    def _provider_for(self, user: str, path: str) -> FileStorageProvider:
        if self._resolver is None:
            return self._default
        try:
            resolution = self._resolver(user, path)
        except Exception:
            return self._default
        if not resolution:
            return self._default
        provider = self._providers.get(resolution.provider, self._default)
        status = str(getattr(resolution, "status", "") or "").lower()
        if status == "degraded":
            return ReadOnlyProviderWrapper(provider)
        if status in {"reauth_required", "unavailable"}:
            return MountUnavailableProvider(
                getattr(provider, "name", str(resolution.provider or "provider")),
                mount_status=status,
            )
        return provider

    def resolve(self, user: str, path: str) -> Optional[MountResolution]:
        if self._resolver is None:
            return None
        try:
            return self._resolver(user, path)
        except Exception:
            return None

    def list(self, user: str, path: str, *, include_deleted: bool = False) -> List[Dict[str, Any]]:
        return self._provider_for(user, path).list(user, path, include_deleted=include_deleted)

    def stat(self, user: str, path: str) -> Dict[str, Any]:
        return self._provider_for(user, path).stat(user, path)

    def read(self, user: str, path: str) -> Dict[str, Any]:
        return self._provider_for(user, path).read(user, path)

    def write(
        self,
        user: str,
        path: str,
        upload: UploadFile,
        *,
        encryption_meta: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        return self._provider_for(user, path).write(
            user,
            path,
            upload,
            encryption_meta=encryption_meta,
            idempotency_key=idempotency_key,
        )

    def delete(self, user: str, path: str) -> Any:
        return self._provider_for(user, path).delete(user, path)

    def mkdir(self, user: str, path: str) -> str:
        return self._provider_for(user, path).mkdir(user, path)

    def move(self, user: str, src: str, dst: str) -> Dict[str, Any]:
        return self._provider_for(user, src).move(user, src, dst)


def build_default_dispatcher(*, resolver: Optional[MountResolver] = None, icloud_transport: Optional[ICloudTransport] = None) -> FileStorageDispatcher:
    if resolver is None:
        from app.services.filemanager_mounts import resolve_mount_for_path

        def _resolver(user: str, path: str) -> Optional[MountResolution]:
            mount = resolve_mount_for_path(owner_user_sub=user, path=path)
            if not mount:
                return None
            return MountResolution(
                provider=str(mount.get("provider") or ""),
                mount_id=str(mount.get("mount_id") or ""),
                mount_path=str(mount.get("mount_path") or ""),
                status=str(mount.get("status") or ""),
            )

        resolver = _resolver
    default_provider = S3FileStorageProvider()
    providers: Dict[str, FileStorageProvider] = {
        "icloud": ICloudProvider(transport=icloud_transport),
    }
    return FileStorageDispatcher(default_provider=default_provider, providers=providers, resolver=resolver)
