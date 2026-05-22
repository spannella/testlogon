"""Stateful mock for Jira/Atlassian OAuth and REST API v3."""
from __future__ import annotations

import hashlib
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request, Response

from app.core.settings import S
from app.core.time import now_ts

router = APIRouter(tags=["mock"])

_TOKENS: Dict[str, Dict[str, Any]] = {}
_SITES: List[Dict[str, Any]] = []
_PROJECTS: Dict[str, List[Dict[str, Any]]] = {}
_ISSUES: Dict[str, Dict[str, Any]] = {}
_ISSUE_COUNTER: int = 0


def _ensure_mock_enabled() -> None:
    if not S.jira_mock_enabled:
        raise HTTPException(404, "Not found")


def _extract_bearer(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(401, "Missing bearer token")
    return auth.split(" ", 1)[1].strip()


def _validate_token(request: Request) -> str:
    token = _extract_bearer(request)
    if token.startswith("mock-"):
        return token
    info = _TOKENS.get(token)
    if not info:
        raise HTTPException(401, "Invalid token")
    if info.get("expires_at", 0) <= now_ts():
        raise HTTPException(401, "Token expired")
    return token


def _default_sites() -> List[Dict[str, Any]]:
    return [
        {
            "id": "cloud-id-1",
            "url": "https://mock-site.atlassian.net",
            "name": "Mock Site",
            "scopes": ["read:jira-work", "write:jira-work", "offline_access"],
            "avatarUrl": "https://mock-site.atlassian.net/avatar",
        }
    ]


@router.post("/mock/jira/oauth/token")
async def jira_mock_oauth_token(request: Request) -> Dict[str, Any]:
    _ensure_mock_enabled()
    body = await request.form()
    grant_type = body.get("grant_type", "")
    client_id = body.get("client_id", "")
    client_secret = body.get("client_secret", "")

    if grant_type == "authorization_code":
        code = body.get("code", "")
        if not code:
            raise HTTPException(400, "Missing code")
    elif grant_type == "refresh_token":
        refresh_token = body.get("refresh_token", "")
        if not refresh_token:
            raise HTTPException(400, "Missing refresh_token")
    else:
        raise HTTPException(400, f"Unsupported grant_type: {grant_type}")

    if not client_id or not client_secret:
        raise HTTPException(401, "Missing client credentials")

    ts = now_ts()
    access_token = f"mock-at-{hashlib.sha256(f'{client_id}:{ts}'.encode()).hexdigest()[:24]}"
    refresh_token_out = f"mock-rt-{hashlib.sha256(f'{client_id}:rt:{ts}'.encode()).hexdigest()[:24]}"
    expires_in = 3600

    _TOKENS[access_token] = {
        "client_id": client_id,
        "created_at": ts,
        "expires_at": ts + expires_in,
    }

    return {
        "access_token": access_token,
        "refresh_token": refresh_token_out,
        "expires_in": expires_in,
        "token_type": "Bearer",
        "scope": "read:jira-work write:jira-work offline_access",
    }


@router.get("/mock/jira/oauth/accessible-resources")
async def jira_mock_accessible_resources(request: Request) -> List[Dict[str, Any]]:
    _ensure_mock_enabled()
    _validate_token(request)
    return _SITES if _SITES else _default_sites()


_JIRA_API_PREFIX = "/mock/jira/ex/jira/{cloud_id}/rest/api/3"


@router.get(_JIRA_API_PREFIX + "/project/search")
async def jira_mock_project_search(cloud_id: str, request: Request) -> Dict[str, Any]:
    _ensure_mock_enabled()
    _validate_token(request)
    projects = _PROJECTS.get(cloud_id, [])
    return {
        "values": projects,
        "total": len(projects),
        "isLast": True,
    }


@router.get(_JIRA_API_PREFIX + "/search")
async def jira_mock_search(cloud_id: str, request: Request) -> Dict[str, Any]:
    _ensure_mock_enabled()
    _validate_token(request)
    jql = request.query_params.get("jql", "")
    max_results = int(request.query_params.get("maxResults", "50"))
    start_at = int(request.query_params.get("startAt", "0"))

    all_issues = [
        v for v in _ISSUES.values()
        if v.get("cloud_id") == cloud_id
    ]

    if jql:
        jql_lower = jql.lower()
        if "project" in jql_lower:
            for part in jql.split("="):
                part = part.strip().strip("'\"")
                if part and part not in ("project", "Project"):
                    all_issues = [
                        i for i in all_issues
                        if i.get("fields", {}).get("project", {}).get("key", "").upper() == part.upper()
                    ]
                    break
        if "status" in jql_lower:
            for segment in jql.split("AND"):
                segment = segment.strip()
                if "status" in segment.lower():
                    for part in segment.split("="):
                        part = part.strip().strip("'\"")
                        if part.lower() not in ("status",):
                            all_issues = [
                                i for i in all_issues
                                if i.get("fields", {}).get("status", {}).get("name", "").lower() == part.lower()
                            ]
                            break

    page = all_issues[start_at:start_at + max_results]
    return {
        "issues": page,
        "total": len(all_issues),
        "maxResults": max_results,
        "startAt": start_at,
    }


@router.post(_JIRA_API_PREFIX + "/issue")
async def jira_mock_create_issue(cloud_id: str, request: Request) -> Dict[str, Any]:
    global _ISSUE_COUNTER
    _ensure_mock_enabled()
    _validate_token(request)
    body = await request.json()
    fields = body.get("fields", {})

    project_key = fields.get("project", {}).get("key", "MOCK")
    summary = fields.get("summary", "")
    description = fields.get("description")
    issue_type = fields.get("issuetype", {}).get("name", "Task")

    _ISSUE_COUNTER += 1
    issue_id = str(10000 + _ISSUE_COUNTER)
    issue_key = f"{project_key}-{_ISSUE_COUNTER}"

    issue = {
        "id": issue_id,
        "key": issue_key,
        "self": f"{S.jira_api_base_url}/ex/jira/{cloud_id}/rest/api/3/issue/{issue_id}",
        "cloud_id": cloud_id,
        "fields": {
            "project": {"key": project_key},
            "summary": summary,
            "description": description,
            "issuetype": {"name": issue_type},
            "status": {"name": "To Do"},
            "created": time.strftime("%Y-%m-%dT%H:%M:%S.000+0000", time.gmtime()),
            "updated": time.strftime("%Y-%m-%dT%H:%M:%S.000+0000", time.gmtime()),
            "comment": {"comments": [], "total": 0},
        },
    }

    _ISSUES[issue_id] = issue
    _ISSUES[issue_key] = issue

    return {"id": issue_id, "key": issue_key, "self": issue["self"]}


@router.get(_JIRA_API_PREFIX + "/issue/{issue_id_or_key}")
async def jira_mock_get_issue(cloud_id: str, issue_id_or_key: str, request: Request) -> Dict[str, Any]:
    _ensure_mock_enabled()
    _validate_token(request)
    issue = _ISSUES.get(issue_id_or_key)
    if not issue or issue.get("cloud_id") != cloud_id:
        raise HTTPException(404, f"Issue {issue_id_or_key} not found")
    return issue


@router.put(_JIRA_API_PREFIX + "/issue/{issue_id_or_key}")
async def jira_mock_update_issue(cloud_id: str, issue_id_or_key: str, request: Request) -> Response:
    _ensure_mock_enabled()
    _validate_token(request)
    issue = _ISSUES.get(issue_id_or_key)
    if not issue or issue.get("cloud_id") != cloud_id:
        raise HTTPException(404, f"Issue {issue_id_or_key} not found")

    body = await request.json()
    update_fields = body.get("fields", {})
    for k, v in update_fields.items():
        issue["fields"][k] = v
    issue["fields"]["updated"] = time.strftime("%Y-%m-%dT%H:%M:%S.000+0000", time.gmtime())

    other_key = issue.get("key") if issue_id_or_key == issue.get("id") else issue.get("id")
    if other_key and other_key in _ISSUES:
        _ISSUES[other_key] = issue

    return Response(status_code=204)


@router.delete(_JIRA_API_PREFIX + "/issue/{issue_id_or_key}")
async def jira_mock_delete_issue(cloud_id: str, issue_id_or_key: str, request: Request) -> Response:
    _ensure_mock_enabled()
    _validate_token(request)
    issue = _ISSUES.get(issue_id_or_key)
    if not issue or issue.get("cloud_id") != cloud_id:
        raise HTTPException(404, f"Issue {issue_id_or_key} not found")

    _ISSUES.pop(issue.get("id", ""), None)
    _ISSUES.pop(issue.get("key", ""), None)

    return Response(status_code=204)


@router.post(_JIRA_API_PREFIX + "/issue/{issue_id_or_key}/comment")
async def jira_mock_add_comment(cloud_id: str, issue_id_or_key: str, request: Request) -> Dict[str, Any]:
    _ensure_mock_enabled()
    _validate_token(request)
    issue = _ISSUES.get(issue_id_or_key)
    if not issue or issue.get("cloud_id") != cloud_id:
        raise HTTPException(404, f"Issue {issue_id_or_key} not found")

    body = await request.json()
    comment_body = body.get("body", "")

    comment_id = str(int(time.time() * 1000))
    created = time.strftime("%Y-%m-%dT%H:%M:%S.000+0000", time.gmtime())

    comment = {
        "id": comment_id,
        "body": comment_body,
        "author": {
            "accountId": "mock-user-1",
            "displayName": "Mock User",
            "emailAddress": "mock@example.com",
        },
        "created": created,
        "updated": created,
    }

    comments_container = issue["fields"].setdefault("comment", {"comments": [], "total": 0})
    comments_container["comments"].append(comment)
    comments_container["total"] = len(comments_container["comments"])
    issue["fields"]["updated"] = created

    return comment


@router.post("/mock/jira/seed")
async def jira_mock_seed(request: Request) -> Dict[str, Any]:
    global _ISSUE_COUNTER
    _ensure_mock_enabled()
    body = await request.json()

    if "tokens" in body:
        for token_val, token_info in body["tokens"].items():
            _TOKENS[token_val] = token_info

    if "sites" in body:
        _SITES.clear()
        _SITES.extend(body["sites"])

    if "projects" in body:
        for cid, proj_list in body["projects"].items():
            _PROJECTS[cid] = proj_list

    if "issues" in body:
        for issue in body["issues"]:
            issue_id = issue.get("id", str(10000 + _ISSUE_COUNTER + 1))
            issue_key = issue.get("key", f"SEED-{_ISSUE_COUNTER + 1}")
            issue.setdefault("id", issue_id)
            issue.setdefault("key", issue_key)
            issue.setdefault("cloud_id", "cloud-id-1")
            issue.setdefault("fields", {})
            _ISSUES[issue_id] = issue
            _ISSUES[issue_key] = issue
            _ISSUE_COUNTER += 1

    return {"ok": True}


@router.post("/mock/jira/reset")
async def jira_mock_reset() -> Dict[str, Any]:
    global _ISSUE_COUNTER
    _ensure_mock_enabled()
    _TOKENS.clear()
    _SITES.clear()
    _PROJECTS.clear()
    _ISSUES.clear()
    _ISSUE_COUNTER = 0
    return {"ok": True}
