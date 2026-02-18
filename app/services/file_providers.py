from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import parse_qs
from urllib.parse import quote
from typing import Any, Dict, List, Optional, Protocol

import requests
from fastapi import HTTPException

from app.core.settings import S
from app.services import filemanager
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
        _DEFAULT_REGISTRY = registry
    return _DEFAULT_REGISTRY
