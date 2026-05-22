from __future__ import annotations

from dataclasses import dataclass, field
import json
import random
import time
from urllib.parse import parse_qs
from urllib.parse import quote
from typing import Any, Dict, List, Optional, Protocol

import requests
from fastapi import HTTPException

from app.core.settings import S
from app.services import filemanager
from app.metrics import record_filemgr_mount_api_error, record_filemgr_mount_upload_method
from app.services.provider_credentials import (
    get_provider_auth_context,
    normalize_github_api_base_url,
    normalize_gitlab_api_base_url,
)


class FileProvider(Protocol):
    provider_name: str

    def resolve(self, ref: str) -> str:
        ...

    def exists(self, canonical_ref: str) -> bool:
        ...

    def get_metadata(self, canonical_ref: str) -> Dict[str, Any]:
        ...

    def list_children(self, canonical_ref: str) -> List[str]:
        ...

    def create_folder(self, parent_ref: str, name: str) -> str:
        ...

    def upload_file(self, parent_ref: str, name: str, *, file_obj: Any, content_type: Optional[str], overwrite: bool) -> Dict[str, Any]:
        ...

    def delete_item(self, canonical_ref: str) -> None:
        ...

    def move_item(self, canonical_ref: str, *, new_parent_ref: str, new_name: str) -> str:
        ...


class LocalFileProvider:
    provider_name = "local"

    def __init__(self, owner: str):
        self.owner = owner

    def resolve(self, ref: str) -> str:
        return filemanager.norm_path(ref, is_folder=None)

    def exists(self, canonical_ref: str) -> bool:
        try:
            filemanager.get_node(self.owner, canonical_ref)
            return True
        except HTTPException as exc:
            if exc.status_code == 404:
                return False
            raise

    def get_metadata(self, canonical_ref: str) -> Dict[str, Any]:
        node = filemanager.get_node(self.owner, canonical_ref)
        return {
            "path": node.get("path"),
            "type": node.get("type"),
            "name": node.get("name"),
            "size": node.get("size"),
            "content_type": node.get("content_type"),
            "updated_at": node.get("updated_at"),
            "last_download_at": node.get("last_download_at"),
            "is_encrypted": node.get("is_encrypted", False),
        }

    def list_children(self, canonical_ref: str) -> List[str]:
        folder = filemanager.norm_path(canonical_ref, is_folder=True)
        children = filemanager.list_children(self.owner, folder)
        out: List[str] = []
        for item in children:
            path = item.get("path")
            if isinstance(path, str) and path:
                out.append(path)
        return out


class GitHubProvider:
    provider_name = "github"

    def __init__(self, owner: str):
        self.owner = owner

    def _parse_ref(self, ref: str) -> Dict[str, str]:
        raw = (ref or "").strip()
        if raw.startswith("github://"):
            raw = raw[len("github://") :]

        query: Dict[str, List[str]] = {}
        if "?" in raw:
            path_part, query_string = raw.split("?", 1)
            raw = path_part
            query = parse_qs(query_string, keep_blank_values=False)

        pieces = [p for p in raw.split("/") if p]
        if len(pieces) < 3:
            raise HTTPException(
                status_code=400,
                detail="invalid github ref; expected owner/repo/path?ref=<branch-or-sha>",
            )

        repo_owner, repo, *path_parts = pieces
        file_path = "/".join(path_parts)
        if not file_path:
            raise HTTPException(status_code=400, detail="github ref path is required")

        ref_value = (query.get("ref") or ["HEAD"])[0].strip() or "HEAD"
        return {
            "repo_owner": repo_owner,
            "repo": repo,
            "path": file_path,
            "ref": ref_value,
        }

    def resolve(self, ref: str) -> str:
        parsed = self._parse_ref(ref)
        return f"github://{parsed['repo_owner']}/{parsed['repo']}/{parsed['path']}?ref={parsed['ref']}"

    def _request(self, canonical_ref: str) -> requests.Response:
        parsed = self._parse_ref(canonical_ref)
        auth = get_provider_auth_context(self.owner, "github")
        token = auth["token"]
        metadata = auth.get("metadata") if isinstance(auth, dict) else {}
        api_base_url = normalize_github_api_base_url((metadata or {}).get("api_base_url") if isinstance(metadata, dict) else S.github_api_base_url)
        url = f"{api_base_url}/repos/{parsed['repo_owner']}/{parsed['repo']}/contents/{parsed['path']}"
        response = requests.get(
            url,
            params={"ref": parsed["ref"]},
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
            },
            timeout=10,
        )
        return response

    def _raise_for_error(self, response: requests.Response) -> None:
        if response.status_code < 400:
            return
        if response.status_code == 404:
            raise HTTPException(status_code=404, detail="github path not found")
        if response.status_code in (401, 403):
            remaining = response.headers.get("X-RateLimit-Remaining", "")
            if remaining == "0":
                reset = response.headers.get("X-RateLimit-Reset", "unknown")
                raise HTTPException(status_code=429, detail=f"github rate limit exceeded; retry after reset={reset}")
            raise HTTPException(status_code=401, detail="github credential invalid or access denied")
        raise HTTPException(status_code=502, detail=f"github api error ({response.status_code})")

    def exists(self, canonical_ref: str) -> bool:
        try:
            response = self._request(canonical_ref)
        except requests.RequestException as exc:
            raise HTTPException(status_code=502, detail="github api request failed") from exc

        if response.status_code == 404:
            return False
        self._raise_for_error(response)
        return True

    def get_metadata(self, canonical_ref: str) -> Dict[str, Any]:
        try:
            response = self._request(canonical_ref)
        except requests.RequestException as exc:
            raise HTTPException(status_code=502, detail="github api request failed") from exc
        self._raise_for_error(response)

        body = response.json() if response.content else {}
        if isinstance(body, list):
            return {
                "type": "dir",
                "entry_count": len(body),
                "path": canonical_ref,
            }
        return {
            "type": body.get("type"),
            "size": body.get("size"),
            "sha": body.get("sha"),
            "name": body.get("name"),
            "path": body.get("path"),
            "html_url": body.get("html_url"),
            "download_url": body.get("download_url"),
        }

    def list_children(self, canonical_ref: str) -> List[str]:
        try:
            response = self._request(canonical_ref)
        except requests.RequestException as exc:
            raise HTTPException(status_code=502, detail="github api request failed") from exc
        self._raise_for_error(response)

        body = response.json() if response.content else []
        if not isinstance(body, list):
            raise HTTPException(status_code=400, detail="github ref is not a directory")

        out: List[str] = []
        for child in body:
            path = child.get("path")
            if not isinstance(path, str) or not path:
                continue
            parsed = self._parse_ref(canonical_ref)
            out.append(f"github://{parsed['repo_owner']}/{parsed['repo']}/{path}?ref={parsed['ref']}")
        return out


class GitLabProvider:
    provider_name = "gitlab"

    def __init__(self, owner: str):
        self.owner = owner

    def _parse_ref(self, ref: str) -> Dict[str, str]:
        raw = (ref or "").strip()
        if raw.startswith("gitlab://"):
            raw = raw[len("gitlab://") :]

        query: Dict[str, List[str]] = {}
        if "?" in raw:
            path_part, query_string = raw.split("?", 1)
            raw = path_part
            query = parse_qs(query_string, keep_blank_values=False)

        if "//" in raw:
            project_path, file_path = raw.split("//", 1)
            if not project_path or not file_path:
                raise HTTPException(status_code=400, detail="invalid gitlab ref; expected <project>//<path>?ref=<branch-or-sha>")
        else:
            parts = [p for p in raw.split("/") if p]
            if len(parts) < 3:
                raise HTTPException(
                    status_code=400,
                    detail="invalid gitlab ref; expected namespace/project/path or namespace/project//path",
                )
            project_path = "/".join(parts[:2])
            file_path = "/".join(parts[2:])

        ref_value = (query.get("ref") or ["HEAD"])[0].strip() or "HEAD"
        return {
            "project_path": project_path,
            "path": file_path,
            "ref": ref_value,
        }

    def resolve(self, ref: str) -> str:
        parsed = self._parse_ref(ref)
        return f"gitlab://{parsed['project_path']}//{parsed['path']}?ref={parsed['ref']}"

    def _request_file(self, canonical_ref: str) -> requests.Response:
        parsed = self._parse_ref(canonical_ref)
        auth = get_provider_auth_context(self.owner, "gitlab")
        token = auth["token"]
        metadata = auth.get("metadata") if isinstance(auth, dict) else {}
        api_base_url = normalize_gitlab_api_base_url((metadata or {}).get("api_base_url") if isinstance(metadata, dict) else S.gitlab_api_base_url)
        project = quote(parsed["project_path"], safe="")
        file_path = quote(parsed["path"], safe="")
        url = f"{api_base_url}/projects/{project}/repository/files/{file_path}"
        return requests.get(
            url,
            params={"ref": parsed["ref"]},
            headers={"PRIVATE-TOKEN": token},
            timeout=10,
        )

    def _request_tree(self, canonical_ref: str) -> requests.Response:
        parsed = self._parse_ref(canonical_ref)
        auth = get_provider_auth_context(self.owner, "gitlab")
        token = auth["token"]
        metadata = auth.get("metadata") if isinstance(auth, dict) else {}
        api_base_url = normalize_gitlab_api_base_url((metadata or {}).get("api_base_url") if isinstance(metadata, dict) else S.gitlab_api_base_url)
        project = quote(parsed["project_path"], safe="")
        url = f"{api_base_url}/projects/{project}/repository/tree"
        return requests.get(
            url,
            params={"path": parsed["path"], "ref": parsed["ref"]},
            headers={"PRIVATE-TOKEN": token},
            timeout=10,
        )

    def _raise_for_error(self, response: requests.Response) -> None:
        if response.status_code < 400:
            return
        if response.status_code == 404:
            raise HTTPException(status_code=404, detail="gitlab path not found")
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After", "unknown")
            raise HTTPException(status_code=429, detail=f"gitlab rate limit exceeded; retry_after={retry_after}")
        if response.status_code in (401, 403):
            remaining = response.headers.get("RateLimit-Remaining", "")
            if remaining == "0":
                reset = response.headers.get("RateLimit-Reset", "unknown")
                raise HTTPException(status_code=429, detail=f"gitlab rate limit exceeded; reset={reset}")
            raise HTTPException(status_code=401, detail="gitlab credential invalid or access denied")
        raise HTTPException(status_code=502, detail=f"gitlab api error ({response.status_code})")

    def exists(self, canonical_ref: str) -> bool:
        try:
            response = self._request_file(canonical_ref)
        except requests.RequestException as exc:
            raise HTTPException(status_code=502, detail="gitlab api request failed") from exc

        if response.status_code == 404:
            return False
        self._raise_for_error(response)
        return True

    def get_metadata(self, canonical_ref: str) -> Dict[str, Any]:
        try:
            response = self._request_file(canonical_ref)
        except requests.RequestException as exc:
            raise HTTPException(status_code=502, detail="gitlab api request failed") from exc
        self._raise_for_error(response)

        body = response.json() if response.content else {}
        return {
            "type": "file",
            "size": body.get("size"),
            "blob_id": body.get("blob_id"),
            "commit_id": body.get("commit_id"),
            "last_commit_id": body.get("last_commit_id"),
            "file_name": body.get("file_name"),
            "file_path": body.get("file_path"),
            "content_sha256": body.get("content_sha256"),
            "encoding": body.get("encoding"),
            "ref": body.get("ref"),
        }

    def list_children(self, canonical_ref: str) -> List[str]:
        try:
            response = self._request_tree(canonical_ref)
        except requests.RequestException as exc:
            raise HTTPException(status_code=502, detail="gitlab api request failed") from exc
        self._raise_for_error(response)

        body = response.json() if response.content else []
        if not isinstance(body, list):
            raise HTTPException(status_code=400, detail="gitlab ref is not a directory")

        parsed = self._parse_ref(canonical_ref)
        out: List[str] = []
        for child in body:
            path = child.get("path")
            if not isinstance(path, str) or not path:
                continue
            out.append(f"gitlab://{parsed['project_path']}//{path}?ref={parsed['ref']}")
        return out




class GoogleDriveProvider:
    provider_name = "google_drive"

    def __init__(self, owner: str):
        self.owner = owner

    def _parse_ref(self, ref: str) -> Dict[str, str]:
        raw = (ref or "").strip()
        if raw.startswith("gdrive://"):
            raw = raw[len("gdrive://") :]

        parts = [p for p in raw.split("/") if p]
        if len(parts) == 3 and parts[0] == "me" and parts[1] == "items":
            item_id = parts[2].strip()
            if not item_id:
                raise HTTPException(status_code=400, detail="gdrive ref item_id is required")
            return {"space": "me", "item_id": item_id}

        if len(parts) == 4 and parts[0] == "drive" and parts[2] == "items":
            drive_id = parts[1].strip()
            item_id = parts[3].strip()
            if not drive_id or not item_id:
                raise HTTPException(status_code=400, detail="invalid gdrive ref")
            return {"space": "drive", "drive_id": drive_id, "item_id": item_id}

        raise HTTPException(
            status_code=400,
            detail="invalid gdrive ref; expected gdrive://me/items/<item_id> or gdrive://drive/<drive_id>/items/<item_id>",
        )

    def resolve(self, ref: str) -> str:
        parsed = self._parse_ref(ref)
        if parsed["space"] == "me":
            return f"gdrive://me/items/{parsed['item_id']}"
        return f"gdrive://drive/{parsed['drive_id']}/items/{parsed['item_id']}"

    def _build_headers(self) -> Dict[str, str]:
        auth = get_provider_auth_context(self.owner, "google_drive")
        token = auth["token"]
        return {"Authorization": f"Bearer {token}"}

    def _request_retry_config(self) -> Dict[str, Any]:
        max_attempts = max(1, int(getattr(S, "google_drive_api_retry_max_attempts", 3) or 3))
        timeout_seconds = max(1.0, float(getattr(S, "google_drive_api_timeout_seconds", 10.0) or 10.0))
        base_delay = max(0.0, float(getattr(S, "google_drive_api_retry_base_delay_seconds", 0.2) or 0.2))
        jitter = max(0.0, float(getattr(S, "google_drive_api_retry_jitter_seconds", 0.1) or 0.1))
        return {
            "max_attempts": max_attempts,
            "timeout_seconds": timeout_seconds,
            "base_delay": base_delay,
            "jitter": jitter,
        }

    def _is_retryable_status(self, status_code: int) -> bool:
        return status_code == 429 or status_code >= 500

    def _request_with_retry(self, *, url: str, params: Optional[Dict[str, Any]], operation: str, stream: bool = False) -> requests.Response:
        cfg = self._request_retry_config()
        headers = self._build_headers()

        attempt = 0
        while True:
            attempt += 1
            try:
                response = requests.get(
                    url,
                    params=params,
                    headers=headers,
                    timeout=cfg["timeout_seconds"],
                    stream=stream,
                )
            except requests.RequestException as exc:
                if attempt >= cfg["max_attempts"]:
                    record_filemgr_mount_api_error("google_drive", operation, "request_exception", "request_exception")
                    raise HTTPException(status_code=502, detail=f"gdrive api request failed during {operation}") from exc
                sleep_s = min(2.0, cfg["base_delay"] * (2 ** (attempt - 1)) + random.uniform(0.0, cfg["jitter"]))
                if sleep_s > 0:
                    time.sleep(sleep_s)
                continue

            if self._is_retryable_status(response.status_code) and attempt < cfg["max_attempts"]:
                retry_after_header = response.headers.get("Retry-After")
                sleep_s: float
                if retry_after_header:
                    try:
                        sleep_s = min(5.0, max(0.0, float(retry_after_header)))
                    except ValueError:
                        sleep_s = min(2.0, cfg["base_delay"] * (2 ** (attempt - 1)) + random.uniform(0.0, cfg["jitter"]))
                else:
                    sleep_s = min(2.0, cfg["base_delay"] * (2 ** (attempt - 1)) + random.uniform(0.0, cfg["jitter"]))
                if sleep_s > 0:
                    time.sleep(sleep_s)
                continue

            return response

    def _get_file(self, parsed: Dict[str, str]) -> requests.Response:
        fields = "id,name,mimeType,size,modifiedTime,parents,trashed,driveId"
        url = f"{S.google_drive_api_base_url}/files/{quote(parsed['item_id'], safe='')}"
        params: Dict[str, Any] = {"fields": fields, "supportsAllDrives": "true"}
        return self._request_with_retry(url=url, params=params, operation="get_file")

    def _list_files(self, parsed: Dict[str, str]) -> requests.Response:
        url = f"{S.google_drive_api_base_url}/files"
        params: Dict[str, Any] = {
            "q": f"'{parsed['item_id']}' in parents and trashed=false",
            "fields": "files(id,name,mimeType,size,modifiedTime,parents,driveId)",
            "pageSize": 200,
            "supportsAllDrives": "true",
            "includeItemsFromAllDrives": "true",
        }
        if parsed.get("space") == "drive" and parsed.get("drive_id"):
            params["corpora"] = "drive"
            params["driveId"] = parsed["drive_id"]
        return self._request_with_retry(url=url, params=params, operation="list_files")

    def _raise_for_error(self, response: requests.Response, *, operation: str = "unknown") -> None:
        if response.status_code < 400:
            return
        body = response.json() if response.content else {}
        err = body.get("error") if isinstance(body, dict) else {}
        message = str((err or {}).get("message") or "google drive api error")
        record_filemgr_mount_api_error("google_drive", operation, response.status_code, message)
        if response.status_code == 404:
            raise HTTPException(status_code=404, detail="gdrive path not found")
        if response.status_code == 401:
            raise HTTPException(
                status_code=401,
                detail={
                    "code": "provider_reconnect_required",
                    "provider": "google_drive",
                    "reason": "revoked",
                    "reconnect_required": True,
                    "action": "reconnect_google_drive",
                },
            )
        if response.status_code == 403:
            msg_l = message.lower()
            reason = "access_removed"
            reconnect_required = False
            if "insufficient" in msg_l or "scope" in msg_l:
                reason = "insufficient_scope"
                reconnect_required = True
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "provider_access_denied",
                    "provider": "google_drive",
                    "reason": reason,
                    "reconnect_required": reconnect_required,
                },
            )
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After", "unknown")
            raise HTTPException(status_code=429, detail=f"gdrive rate limit exceeded; retry_after={retry_after}")
        if response.status_code >= 500:
            raise HTTPException(status_code=502, detail=f"gdrive api transient failure ({response.status_code})")
        raise HTTPException(status_code=502, detail=f"gdrive api error ({response.status_code})")

    def exists(self, canonical_ref: str) -> bool:
        parsed = self._parse_ref(canonical_ref)
        response = self._get_file(parsed)
        if response.status_code == 404:
            return False
        self._raise_for_error(response, operation="exists")
        return True

    def get_metadata(self, canonical_ref: str) -> Dict[str, Any]:
        parsed = self._parse_ref(canonical_ref)
        response = self._get_file(parsed)
        self._raise_for_error(response, operation="list_children")

        body = response.json() if response.content else {}
        mime = str(body.get("mimeType") or "")
        item_type = "dir" if mime == "application/vnd.google-apps.folder" else "file"
        out: Dict[str, Any] = {
            "provider": "google_drive",
            "id": body.get("id"),
            "name": body.get("name"),
            "mime_type": mime,
            "size": int(body.get("size") or 0) if str(body.get("size") or "").isdigit() else body.get("size"),
            "modified_time": body.get("modifiedTime"),
            "parents": body.get("parents") or [],
            "type": item_type,
            "path": self.resolve(canonical_ref),
        }
        if parsed.get("space") == "drive":
            out["drive_id"] = parsed.get("drive_id")
        return out

    def list_children(self, canonical_ref: str) -> List[str]:
        parsed = self._parse_ref(canonical_ref)
        meta = self.get_metadata(canonical_ref)
        if str(meta.get("type") or "") != "dir":
            raise HTTPException(status_code=400, detail="gdrive ref is not a directory")

        response = self._list_files(parsed)
        self._raise_for_error(response, operation="get_metadata")

        body = response.json() if response.content else {}
        files = body.get("files") if isinstance(body, dict) else []
        if not isinstance(files, list):
            return []
        out: List[str] = []
        for item in files:
            item_id = str(item.get("id") or "").strip()
            if not item_id:
                continue
            item_drive_id = str(item.get("driveId") or "").strip()
            if parsed.get("space") == "drive" and parsed.get("drive_id"):
                drive_id = parsed["drive_id"]
            elif item_drive_id:
                drive_id = item_drive_id
            else:
                drive_id = ""

            if drive_id:
                out.append(f"gdrive://drive/{drive_id}/items/{item_id}")
            else:
                out.append(f"gdrive://me/items/{item_id}")
        return out

    def _find_child_ref_by_name(self, parent_ref: str, name: str) -> Optional[str]:
        for child_ref in self.list_children(parent_ref):
            child_meta = self.get_metadata(child_ref)
            if str(child_meta.get("name") or "") == name:
                return self.resolve(child_ref)
        return None

    def create_folder(self, parent_ref: str, name: str) -> str:
        parent = self._parse_ref(parent_ref)
        parent_canonical = self.resolve(parent_ref)
        existing = self._find_child_ref_by_name(parent_canonical, name)
        if existing:
            meta = self.get_metadata(existing)
            if str(meta.get("type") or "") in {"dir", "folder"}:
                return existing
            raise HTTPException(status_code=409, detail="mount path conflict: file already exists")

        url = f"{S.google_drive_api_base_url}/files"
        body = {
            "name": name,
            "mimeType": "application/vnd.google-apps.folder",
            "parents": [parent["item_id"]],
        }
        response = requests.post(
            url,
            json=body,
            headers={**self._build_headers(), "Content-Type": "application/json"},
            params={"supportsAllDrives": "true", "fields": "id,driveId"},
            timeout=self._request_retry_config()["timeout_seconds"],
        )
        self._raise_for_error(response, operation="create_folder")
        payload = response.json() if response.content else {}
        item_id = str(payload.get("id") or "").strip()
        if not item_id:
            raise HTTPException(status_code=502, detail="gdrive create folder missing id")
        drive_id = str(payload.get("driveId") or "").strip()
        if drive_id:
            return f"gdrive://drive/{drive_id}/items/{item_id}"
        return f"gdrive://me/items/{item_id}"

    def _probe_stream_size(self, file_obj: Any) -> Optional[int]:
        if not hasattr(file_obj, "tell") or not hasattr(file_obj, "seek"):
            return None
        try:
            pos = file_obj.tell()
            file_obj.seek(0, 2)
            end = file_obj.tell()
            file_obj.seek(pos)
            return max(0, int(end - pos))
        except Exception:
            return None

    def _upload_via_resumable(
        self,
        *,
        endpoint_url: str,
        metadata: Dict[str, Any],
        file_obj: Any,
        content_type: str,
        supports_all_drives: bool = True,
        init_method: str = "post",
    ) -> requests.Response:
        cfg = self._request_retry_config()
        headers = self._build_headers()
        stream_size = self._probe_stream_size(file_obj)
        init_headers = {**headers, "Content-Type": "application/json; charset=UTF-8", "X-Upload-Content-Type": content_type}
        if stream_size is not None:
            init_headers["X-Upload-Content-Length"] = str(stream_size)

        init_call = requests.post if init_method.lower() == "post" else requests.patch
        init_resp = init_call(
            endpoint_url,
            params={"uploadType": "resumable", "supportsAllDrives": "true" if supports_all_drives else "false", "fields": "id,driveId"},
            json=metadata,
            headers=init_headers,
            timeout=cfg["timeout_seconds"],
        )
        self._raise_for_error(init_resp, operation="upload_file")
        session_url = str(init_resp.headers.get("Location") or "").strip()
        if not session_url:
            raise HTTPException(status_code=502, detail="gdrive resumable session missing location")

        can_seek = hasattr(file_obj, "seek")
        if can_seek:
            try:
                file_obj.seek(0)
            except Exception:
                can_seek = False

        attempt = 0
        while True:
            attempt += 1
            if can_seek:
                try:
                    file_obj.seek(0)
                except Exception:
                    can_seek = False
            put_resp = requests.put(
                session_url,
                data=file_obj,
                headers={**headers, "Content-Type": content_type},
                timeout=cfg["timeout_seconds"],
            )
            if self._is_retryable_status(put_resp.status_code) and attempt < cfg["max_attempts"] and can_seek:
                sleep_s = min(2.0, cfg["base_delay"] * (2 ** (attempt - 1)) + random.uniform(0.0, cfg["jitter"]))
                if sleep_s > 0:
                    time.sleep(sleep_s)
                continue
            self._raise_for_error(put_resp, operation="upload_file")
            return put_resp

    def upload_file(self, parent_ref: str, name: str, *, file_obj: Any, content_type: Optional[str], overwrite: bool) -> Dict[str, Any]:
        parent = self._parse_ref(parent_ref)
        parent_canonical = self.resolve(parent_ref)
        existing = self._find_child_ref_by_name(parent_canonical, name)
        if existing and not overwrite:
            raise HTTPException(status_code=409, detail="mount path conflict: file already exists")

        timeout_seconds = self._request_retry_config()["timeout_seconds"]
        headers = self._build_headers()
        ctype = content_type or "application/octet-stream"
        threshold = max(0, int(getattr(S, "google_drive_resumable_upload_threshold_bytes", 8 * 1024 * 1024) or 0))
        stream_size = self._probe_stream_size(file_obj)
        use_resumable = stream_size is not None and stream_size >= threshold
        method_used = "resumable" if use_resumable else "simple"

        if existing:
            existing_meta = self.get_metadata(existing)
            if str(existing_meta.get("type") or "") in {"dir", "folder"}:
                raise HTTPException(status_code=409, detail="mount path conflict: folder already exists")
            existing_parsed = self._parse_ref(existing)
            url = f"{S.google_drive_upload_api_base_url}/files/{quote(existing_parsed['item_id'], safe='')}"
            if use_resumable:
                resp = self._upload_via_resumable(
                    endpoint_url=url,
                    metadata={"name": name},
                    file_obj=file_obj,
                    content_type=ctype,
                    init_method="patch",
                )
            else:
                resp = requests.patch(
                    url,
                    params={"uploadType": "media", "supportsAllDrives": "true"},
                    data=file_obj,
                    headers={**headers, "Content-Type": ctype},
                    timeout=timeout_seconds,
                )
                self._raise_for_error(resp, operation="upload_file")
            record_filemgr_mount_upload_method("google_drive", method_used, "success")
            meta = self.get_metadata(existing)
            return {
                "ref": existing,
                "size": meta.get("size"),
                "content_type": meta.get("mime_type") or ctype,
                "name": meta.get("name") or name,
            }

        url = f"{S.google_drive_upload_api_base_url}/files"
        if use_resumable:
            resp = self._upload_via_resumable(
                endpoint_url=url,
                metadata={"name": name, "parents": [parent["item_id"]]},
                file_obj=file_obj,
                content_type=ctype,
            )
        else:
            metadata_json = json.dumps({"name": name, "parents": [parent["item_id"]]})
            files = {
                "metadata": (None, metadata_json, "application/json; charset=UTF-8"),
                "file": (name, file_obj, ctype),
            }
            resp = requests.post(
                url,
                params={"uploadType": "multipart", "supportsAllDrives": "true", "fields": "id,driveId"},
                files=files,
                headers=headers,
                timeout=timeout_seconds,
            )
            self._raise_for_error(resp, operation="upload_file")

        record_filemgr_mount_upload_method("google_drive", method_used, "success")
        payload = resp.json() if resp.content else {}
        item_id = str(payload.get("id") or "").strip()
        if not item_id:
            raise HTTPException(status_code=502, detail="gdrive upload missing id")
        drive_id = str(payload.get("driveId") or "").strip()
        ref = f"gdrive://drive/{drive_id}/items/{item_id}" if drive_id else f"gdrive://me/items/{item_id}"
        meta = self.get_metadata(ref)
        return {
            "ref": ref,
            "size": meta.get("size"),
            "content_type": meta.get("mime_type") or ctype,
            "name": meta.get("name") or name,
        }

    def delete_item(self, canonical_ref: str) -> None:
        parsed = self._parse_ref(canonical_ref)
        url = f"{S.google_drive_api_base_url}/files/{quote(parsed['item_id'], safe='')}"
        response = requests.delete(
            url,
            params={"supportsAllDrives": "true"},
            headers=self._build_headers(),
            timeout=self._request_retry_config()["timeout_seconds"],
        )
        if response.status_code == 404:
            return
        self._raise_for_error(response, operation="delete_item")

    def move_item(self, canonical_ref: str, *, new_parent_ref: str, new_name: str) -> str:
        src = self._parse_ref(canonical_ref)
        dst_parent = self._parse_ref(new_parent_ref)

        src_meta = self.get_metadata(canonical_ref)
        src_parents = src_meta.get("parents") if isinstance(src_meta.get("parents"), list) else []
        remove_parents = ",".join([str(p).strip() for p in src_parents if str(p).strip()])

        url = f"{S.google_drive_api_base_url}/files/{quote(src['item_id'], safe='')}"
        params = {
            "supportsAllDrives": "true",
            "fields": "id,driveId",
            "addParents": dst_parent["item_id"],
        }
        if remove_parents:
            params["removeParents"] = remove_parents

        response = requests.patch(
            url,
            params=params,
            json={"name": new_name},
            headers={**self._build_headers(), "Content-Type": "application/json"},
            timeout=self._request_retry_config()["timeout_seconds"],
        )
        self._raise_for_error(response, operation="move_item")
        payload = response.json() if response.content else {}
        item_id = str(payload.get("id") or src["item_id"]).strip()
        drive_id = str(payload.get("driveId") or "").strip()
        if drive_id:
            return f"gdrive://drive/{drive_id}/items/{item_id}"
        return f"gdrive://me/items/{item_id}"

    def stream_file(self, canonical_ref: str) -> requests.Response:
        parsed = self._parse_ref(canonical_ref)
        url = f"{S.google_drive_api_base_url}/files/{quote(parsed['item_id'], safe='')}"
        response = self._request_with_retry(
            url=url,
            params={"alt": "media", "supportsAllDrives": "true"},
            operation="download_file",
            stream=True,
        )
        self._raise_for_error(response, operation="stream_file")
        return response


@dataclass
class ProviderRegistry:
    _factories: Dict[str, Any] = field(default_factory=dict)

    def register(self, name: str, factory: Any) -> None:
        normalized = (name or "").strip().lower()
        if not normalized:
            raise HTTPException(status_code=400, detail="provider is required")
        self._factories[normalized] = factory

    def get(self, owner: str, name: str) -> FileProvider:
        normalized = (name or "").strip().lower()
        factory = self._factories.get(normalized)
        if not factory:
            raise HTTPException(status_code=400, detail="unsupported provider")
        return factory(owner)


_DEFAULT_REGISTRY: Optional[ProviderRegistry] = None


def default_provider_registry() -> ProviderRegistry:
    global _DEFAULT_REGISTRY
    if _DEFAULT_REGISTRY is None:
        registry = ProviderRegistry()
        registry.register("local", lambda owner: LocalFileProvider(owner))
        registry.register("github", lambda owner: GitHubProvider(owner))
        registry.register("gitlab", lambda owner: GitLabProvider(owner))
        registry.register("google_drive", lambda owner: GoogleDriveProvider(owner))
        _DEFAULT_REGISTRY = registry
    return _DEFAULT_REGISTRY
