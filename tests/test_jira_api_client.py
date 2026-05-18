from __future__ import annotations

from app.services.jira_api_client import JiraApiClient, JiraApiClientConfig, JiraApiClientError


class _MetricSpy:
    def __init__(self):
        self.inc_calls = []
        self.observe_calls = []

    def labels(self, **kwargs):
        self._labels = kwargs
        return self

    def inc(self, value=1.0):
        self.inc_calls.append((getattr(self, "_labels", {}), value))

    def observe(self, value):
        self.observe_calls.append((getattr(self, "_labels", {}), value))


class _Client(JiraApiClient):
    def __init__(self, responses, *, max_retries=2):
        super().__init__(config=JiraApiClientConfig(base_url="https://api.atlassian.com", timeout_seconds=5, max_retries=max_retries, backoff_base_seconds=0.01))
        self.responses = list(responses)
        self.sleep_calls = 0

    def _request_once(self, *, path: str, access_token: str, method: str = "GET", payload=None):
        _ = (method, payload)
        nxt = self.responses.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt

    def _sleep_backoff(self, attempt: int) -> None:
        self.sleep_calls += 1


def test_retries_on_429_and_succeeds(monkeypatch) -> None:
    req = _MetricSpy()
    ret = _MetricSpy()
    lat = _MetricSpy()
    monkeypatch.setattr("app.services.jira_api_client.JIRA_API_REQUESTS", req)
    monkeypatch.setattr("app.services.jira_api_client.JIRA_API_RETRIES", ret)
    monkeypatch.setattr("app.services.jira_api_client.JIRA_API_LATENCY", lat)

    client = _Client([(429, {}), (200, {"values": []})], max_retries=2)
    status, body = client.request_json(path="/x", access_token="t", endpoint="project_search")

    assert status == 200
    assert body == {"values": []}
    assert client.sleep_calls == 1
    assert len(ret.inc_calls) == 1


def test_retry_is_bounded_by_max_retries(monkeypatch) -> None:
    req = _MetricSpy()
    ret = _MetricSpy()
    lat = _MetricSpy()
    monkeypatch.setattr("app.services.jira_api_client.JIRA_API_REQUESTS", req)
    monkeypatch.setattr("app.services.jira_api_client.JIRA_API_RETRIES", ret)
    monkeypatch.setattr("app.services.jira_api_client.JIRA_API_LATENCY", lat)

    client = _Client([(429, {}), (429, {}), (429, {})], max_retries=1)
    status, _ = client.request_json(path="/x", access_token="t", endpoint="project_search")

    assert status == 429
    assert client.sleep_calls == 1


def test_network_error_retries_then_raises(monkeypatch) -> None:
    req = _MetricSpy()
    ret = _MetricSpy()
    lat = _MetricSpy()
    monkeypatch.setattr("app.services.jira_api_client.JIRA_API_REQUESTS", req)
    monkeypatch.setattr("app.services.jira_api_client.JIRA_API_RETRIES", ret)
    monkeypatch.setattr("app.services.jira_api_client.JIRA_API_LATENCY", lat)

    client = _Client([JiraApiClientError(code="jira_api_network_error", message="net", status_code=502), JiraApiClientError(code="jira_api_network_error", message="net", status_code=502)], max_retries=1)

    try:
        client.request_json(path="/x", access_token="t", endpoint="project_search")
        raise AssertionError("expected error")
    except JiraApiClientError as exc:
        assert exc.code == "jira_api_network_error"
        assert client.sleep_calls == 1


def test_timeout_like_network_error_retries_and_then_succeeds(monkeypatch) -> None:
    req = _MetricSpy()
    ret = _MetricSpy()
    lat = _MetricSpy()
    monkeypatch.setattr("app.services.jira_api_client.JIRA_API_REQUESTS", req)
    monkeypatch.setattr("app.services.jira_api_client.JIRA_API_RETRIES", ret)
    monkeypatch.setattr("app.services.jira_api_client.JIRA_API_LATENCY", lat)

    timeout_exc = JiraApiClientError(code="jira_api_network_error", message="timed out", status_code=502)
    client = _Client([timeout_exc, (200, {"ok": True})], max_retries=2)
    status, body = client.request_json(path="/x", access_token="t", endpoint="project_search")

    assert status == 200
    assert body == {"ok": True}
    assert client.sleep_calls == 1


def test_non_retryable_http_error_returns_immediately_without_backoff(monkeypatch) -> None:
    req = _MetricSpy()
    ret = _MetricSpy()
    lat = _MetricSpy()
    monkeypatch.setattr("app.services.jira_api_client.JIRA_API_REQUESTS", req)
    monkeypatch.setattr("app.services.jira_api_client.JIRA_API_RETRIES", ret)
    monkeypatch.setattr("app.services.jira_api_client.JIRA_API_LATENCY", lat)

    client = _Client([(400, {"errorMessages": ["bad request"]})], max_retries=3)
    status, body = client.request_json(path="/x", access_token="t", endpoint="project_search")

    assert status == 400
    assert body == {"errorMessages": ["bad request"]}
    assert client.sleep_calls == 0
    assert len(ret.inc_calls) == 0
