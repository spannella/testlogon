from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode

from app.core.settings import S
try:
    from app.metrics import Counter, Histogram
except Exception:  # pragma: no cover - fallback for minimal test/runtime envs
    class _NoopMetric:
        def labels(self, **kwargs):
            return self

        def inc(self, value: float = 1.0) -> None:
            return None

        def observe(self, value: float) -> None:
            return None

    def Counter(*args, **kwargs):
        return _NoopMetric()

    def Histogram(*args, **kwargs):
        return _NoopMetric()

JIRA_API_REQUESTS = Counter(
    "jira_api_requests_total",
    "Jira API requests by endpoint/status/outcome",
    ["endpoint", "status", "outcome"],
)
JIRA_API_RETRIES = Counter(
    "jira_api_retries_total",
    "Jira API retries by endpoint/reason",
    ["endpoint", "reason"],
)
JIRA_API_LATENCY = Histogram(
    "jira_api_request_duration_seconds",
    "Jira API request latency",
    ["endpoint", "outcome"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30),
)


@dataclass(frozen=True)
class JiraApiClientError(RuntimeError):
    code: str
    message: str
    status_code: int


@dataclass(frozen=True)
class JiraApiClientConfig:
    base_url: str
    timeout_seconds: int
    max_retries: int
    backoff_base_seconds: float


class JiraApiClient:
    def __init__(self, *, config: JiraApiClientConfig | None = None):
        self._config = config or JiraApiClientConfig(
            base_url=str(getattr(S, "jira_api_base_url", "https://api.atlassian.com")).rstrip("/"),
            timeout_seconds=max(1, int(getattr(S, "jira_api_timeout_seconds", 15))),
            max_retries=max(0, int(getattr(S, "jira_api_max_retries", 2))),
            backoff_base_seconds=max(0.01, float(getattr(S, "jira_api_backoff_base_seconds", 0.25))),
        )

    def search_projects(
        self,
        *,
        cloud_id: str,
        access_token: str,
        start_at: int,
        max_results: int,
        query: str | None,
        project_keys: list[str] | None,
    ) -> tuple[int, dict[str, Any]]:
        params: dict[str, Any] = {"startAt": max(0, int(start_at)), "maxResults": max(1, min(int(max_results), 100))}
        if query:
            params["query"] = query
        if project_keys:
            params["keys"] = ",".join([k for k in project_keys if k])
        path = f"/ex/jira/{cloud_id}/rest/api/3/project/search?{urlencode(params)}"
        return self.request_json(path=path, access_token=access_token, endpoint="project_search")

    def search_issues(
        self,
        *,
        cloud_id: str,
        access_token: str,
        jql: str,
        start_at: int,
        max_results: int,
    ) -> tuple[int, dict[str, Any]]:
        params: dict[str, Any] = {
            "jql": jql,
            "startAt": max(0, int(start_at)),
            "maxResults": max(1, min(int(max_results), 100)),
        }
        path = f"/ex/jira/{cloud_id}/rest/api/3/search?{urlencode(params)}"
        return self.request_json(path=path, access_token=access_token, endpoint="issue_search")

    def request_json(self, *, path: str, access_token: str, endpoint: str) -> tuple[int, dict[str, Any]]:
        return self.request_json_with_body(path=path, access_token=access_token, endpoint=endpoint, method="GET", payload=None)

    def request_json_with_body(
        self,
        *,
        path: str,
        access_token: str,
        endpoint: str,
        method: str,
        payload: dict[str, Any] | None,
    ) -> tuple[int, dict[str, Any]]:
        attempt = 0
        last_status = 502
        last_body: dict[str, Any] = {}

        while True:
            started = time.time()
            try:
                status, body = self._request_once(path=path, access_token=access_token, method=method, payload=payload)
                outcome = "success" if status < 400 else "http_error"
                JIRA_API_REQUESTS.labels(endpoint=endpoint, status=str(status), outcome=outcome).inc()
                JIRA_API_LATENCY.labels(endpoint=endpoint, outcome=outcome).observe(max(0.0, time.time() - started))
            except JiraApiClientError as exc:
                JIRA_API_REQUESTS.labels(endpoint=endpoint, status=str(exc.status_code), outcome="network_error").inc()
                JIRA_API_LATENCY.labels(endpoint=endpoint, outcome="network_error").observe(max(0.0, time.time() - started))
                if attempt < self._config.max_retries:
                    JIRA_API_RETRIES.labels(endpoint=endpoint, reason="network_error").inc()
                    self._sleep_backoff(attempt)
                    attempt += 1
                    continue
                raise

            last_status, last_body = status, body
            if status in {429, 500, 502, 503, 504} and attempt < self._config.max_retries:
                reason = "rate_limit" if status == 429 else "server_error"
                JIRA_API_RETRIES.labels(endpoint=endpoint, reason=reason).inc()
                self._sleep_backoff(attempt)
                attempt += 1
                continue

            return last_status, last_body

    def _sleep_backoff(self, attempt: int) -> None:
        delay = self._config.backoff_base_seconds * (2 ** max(0, attempt))
        time.sleep(min(delay, 5.0))

    def _request_once(
        self, *, path: str, access_token: str, method: str = "GET", payload: dict[str, Any] | None = None
    ) -> tuple[int, dict[str, Any]]:
        url = f"{self._config.base_url}{path}"
        data = None
        headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
        if payload is not None:
            data = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib_request.Request(
            url=url,
            headers=headers,
            method=method.upper(),
            data=data,
        )
        try:
            with urllib_request.urlopen(req, timeout=self._config.timeout_seconds) as resp:  # nosec B310
                status = int(getattr(resp, "status", 200))
                raw = resp.read().decode("utf-8") if resp else ""
                body = json.loads(raw) if raw else {}
                return status, body if isinstance(body, dict) else {}
        except HTTPError as exc:
            raw = exc.read().decode("utf-8") if hasattr(exc, "read") else ""
            try:
                body = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                body = {}
            return int(exc.code or 500), body if isinstance(body, dict) else {}
        except URLError as exc:
            raise JiraApiClientError(
                code="jira_api_network_error",
                message="Unable to reach Jira API",
                status_code=502,
            ) from exc

    def create_issue(
        self,
        *,
        cloud_id: str,
        access_token: str,
        project_key: str,
        issue_type: str,
        summary: str,
        description: str,
    ) -> tuple[int, dict[str, Any]]:
        path = f"/ex/jira/{cloud_id}/rest/api/3/issue"
        payload = {
            "fields": {
                "project": {"key": project_key},
                "issuetype": {"name": issue_type},
                "summary": summary,
                "description": description,
            }
        }
        return self.request_json_with_body(
            path=path,
            access_token=access_token,
            endpoint="issue_create",
            method="POST",
            payload=payload,
        )

    def delete_issue(self, *, cloud_id: str, access_token: str, issue_id: str) -> tuple[int, dict[str, Any]]:
        path = f"/ex/jira/{cloud_id}/rest/api/3/issue/{issue_id}"
        return self.request_json_with_body(
            path=path,
            access_token=access_token,
            endpoint="issue_delete",
            method="DELETE",
            payload=None,
        )

    def get_issue(self, *, cloud_id: str, access_token: str, issue_id_or_key: str) -> tuple[int, dict[str, Any]]:
        path = f"/ex/jira/{cloud_id}/rest/api/3/issue/{issue_id_or_key}"
        return self.request_json(path=path, access_token=access_token, endpoint="issue_get")

    def update_issue(
        self, *, cloud_id: str, access_token: str, issue_id: str, fields: dict[str, Any]
    ) -> tuple[int, dict[str, Any]]:
        path = f"/ex/jira/{cloud_id}/rest/api/3/issue/{issue_id}"
        return self.request_json_with_body(
            path=path,
            access_token=access_token,
            endpoint="issue_update",
            method="PUT",
            payload={"fields": fields},
        )

    def add_comment(
        self, *, cloud_id: str, access_token: str, issue_id: str, body_text: str
    ) -> tuple[int, dict[str, Any]]:
        path = f"/ex/jira/{cloud_id}/rest/api/3/issue/{issue_id}/comment"
        return self.request_json_with_body(
            path=path,
            access_token=access_token,
            endpoint="issue_comment_create",
            method="POST",
            payload={"body": body_text},
        )
