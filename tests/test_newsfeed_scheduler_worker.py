from app.services import newsfeed_scheduler as svc


class _FakeTable:
    def __init__(self, item):
        self._item = item
        self.get_calls = 0

    def get_item(self, **kwargs):
        self.get_calls += 1
        return {"Item": self._item}


class _QueryTable:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = 0

    def query(self, **kwargs):
        self.calls += 1
        value = self._responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return value


def test_process_due_scheduled_posts_counts_published_and_duplicates(monkeypatch) -> None:
    monkeypatch.setattr(
        svc,
        "_query_due_posts",
        lambda **kwargs: {
            "Items": [
                {"post_id": "p1", "user_id": "u1", "publish_at": 100, "created_at": "2026-01-01T00:00:00+00:00"},
                {"post_id": "p2", "user_id": "u1", "publish_at": 100, "created_at": "2026-01-01T00:00:00+00:00"},
            ]
        },
    )
    statuses = iter(["published", "already_published"])
    monkeypatch.setattr(svc, "_publish_with_retry", lambda *args, **kwargs: next(statuses))
    meter_calls = {"n": 0}
    monkeypatch.setattr(
        svc,
        "_meter_publish_once",
        lambda **kwargs: meter_calls.__setitem__("n", meter_calls["n"] + 1) or True,
    )

    out = svc.process_due_scheduled_posts(now_ts=123, page_limit=10, max_batches=1)

    assert out["scanned"] == 2
    assert out["published"] == 1
    assert out["already_published"] == 1
    assert out["metered"] == 1
    assert out["meter_errors"] == 0
    assert out["error"] == 0
    assert meter_calls["n"] == 1


def test_publish_with_retry_retries_and_exhausts(monkeypatch) -> None:
    class _RetryExc(Exception):
        pass

    monkeypatch.setattr(svc, "ClientError", _RetryExc)

    calls = {"n": 0}

    def _raise(*args, **kwargs):
        calls["n"] += 1
        raise _RetryExc()

    monkeypatch.setattr(svc, "_publish_due_post", _raise)
    monkeypatch.setattr(svc.time, "sleep", lambda *_: None)

    out = svc._publish_with_retry({}, now_ts=1, now_iso="2026-01-01T00:00:00+00:00", max_retries=2, backoff_seconds=0.01)
    assert out == "retry_exhausted"
    assert calls["n"] == 3


def test_run_scheduler_loop_respects_iterations(monkeypatch) -> None:
    monkeypatch.setattr(svc, "process_due_scheduled_posts", lambda **kwargs: {"published": 0, "scanned": 0})
    runs = svc.run_scheduler_loop(interval_seconds=0.1, iterations=2)
    assert len(runs) == 2


def test_scheduler_summary_has_failures_detects_run_exception_and_errors() -> None:
    assert svc.scheduler_summary_has_failures({"run_exception": 1, "error": 0, "retry_exhausted": 0}) is True
    assert svc.scheduler_summary_has_failures({"run_exception": 0, "error": 2, "retry_exhausted": 0}) is True
    assert svc.scheduler_summary_has_failures({"run_exception": 0, "error": 0, "retry_exhausted": 1}) is True
    assert svc.scheduler_summary_has_failures({"run_exception": 0, "error": 0, "retry_exhausted": 0, "conflict": 1}) is True
    assert svc.scheduler_summary_has_failures({"run_exception": 0, "error": 0, "retry_exhausted": 0, "meter_errors": 1}) is True
    assert svc.scheduler_summary_has_failures({"run_exception": 0, "error": 0, "retry_exhausted": 0, "conflict": 0, "meter_errors": 0}) is False


def test_query_due_posts_retries_retryable_client_error(monkeypatch) -> None:
    class _RetryClientError(Exception):
        def __init__(self, code: str):
            self.response = {"Error": {"Code": code}}

    table = _QueryTable([_RetryClientError("ThrottlingException"), {"Items": []}])
    monkeypatch.setattr(svc, "ClientError", _RetryClientError)
    monkeypatch.setattr(svc, "_tbl", lambda: table)
    monkeypatch.setattr(svc, "QUERY_RETRY_MAX", 2)
    monkeypatch.setattr(svc, "QUERY_RETRY_BACKOFF_SECONDS", 0.01)
    sleeps = {"n": 0}
    ops = []
    monkeypatch.setattr(svc.time, "sleep", lambda *_: sleeps.__setitem__("n", sleeps["n"] + 1))
    monkeypatch.setattr(
        svc,
        "record_newsfeed_schedule_operation",
        lambda **kwargs: ops.append((kwargs["operation"], kwargs["outcome"])),
    )

    out = svc._query_due_posts(now_ts=123, limit=10)

    assert out == {"Items": []}
    assert table.calls == 2
    assert sleeps["n"] == 1
    assert ("query_due_posts", "retry") in ops
    assert ("query_due_posts", "recovered") in ops


def test_process_due_scheduled_posts_clamps_page_limit_and_batches(monkeypatch) -> None:
    monkeypatch.setattr(svc, "MAX_QUERY_PAGE_LIMIT", 5)
    monkeypatch.setattr(svc, "MAX_RUN_BATCHES", 2)
    monkeypatch.setattr(svc, "_query_due_backlog", lambda **kwargs: 0)
    monkeypatch.setattr(svc, "_query_oldest_due_publish_at", lambda **kwargs: None)
    monkeypatch.setattr(svc, "set_newsfeed_schedule_backlog", lambda **kwargs: None)
    monkeypatch.setattr(svc, "set_newsfeed_schedule_oldest_due_age", lambda **kwargs: None)
    monkeypatch.setattr(svc, "record_newsfeed_schedule_operation", lambda **kwargs: None)

    calls = []

    def _query_due_posts(**kwargs):
        calls.append(kwargs["limit"])
        return {"Items": [], "LastEvaluatedKey": {"pk": "x"}} if len(calls) == 1 else {"Items": []}

    monkeypatch.setattr(svc, "_query_due_posts", _query_due_posts)

    out = svc.process_due_scheduled_posts(now_ts=123, page_limit=9999, max_batches=9999)
    assert out["page_limit_effective"] == 5
    assert out["max_batches_effective"] == 2
    assert out["batches"] == 2
    assert calls == [5, 5]


def test_publish_due_post_is_idempotent_when_already_published(monkeypatch) -> None:
    fake_tbl = _FakeTable({"status": "published"})
    monkeypatch.setattr(svc, "_tbl", lambda: fake_tbl)

    called = {"n": 0}

    def _tx(**kwargs):
        called["n"] += 1

    monkeypatch.setattr(svc.ddb.meta.client, "transact_write_items", _tx)
    out = svc._publish_due_post({"post_id": "p1", "user_id": "u1", "publish_at": 100}, now_ts=100, now_iso="2026-01-01T00:00:00+00:00")
    assert out == "already_published"
    assert called["n"] == 0


def test_publish_due_post_fails_safely_when_cancelled(monkeypatch) -> None:
    fake_tbl = _FakeTable({"status": "cancelled"})
    monkeypatch.setattr(svc, "_tbl", lambda: fake_tbl)
    monkeypatch.setattr(svc.ddb.meta.client, "transact_write_items", lambda **kwargs: (_ for _ in ()).throw(AssertionError("should not transact")))
    out = svc._publish_due_post({"post_id": "p1", "user_id": "u1", "publish_at": 100}, now_ts=100, now_iso="2026-01-01T00:00:00+00:00")
    assert out == "already_cancelled"


def test_publish_due_post_uses_publish_time_for_feedref_ordering(monkeypatch) -> None:
    fake_tbl = _FakeTable({"status": "scheduled"})
    monkeypatch.setattr(svc, "_tbl", lambda: fake_tbl)
    captured = {}

    def _tx(**kwargs):
        captured["tx"] = kwargs["TransactItems"]

    monkeypatch.setattr(svc.ddb.meta.client, "transact_write_items", _tx)
    out = svc._publish_due_post(
        {"post_id": "p1", "user_id": "u1", "publish_at": 100, "created_at": "2025-01-01T00:00:00+00:00"},
        now_ts=100,
        now_iso="2026-01-01T00:00:00+00:00",
    )
    assert out == "published"
    put_item = captured["tx"][2]["Put"]["Item"]
    assert put_item["created_at"]["S"] == "2026-01-01T00:00:00+00:00"
    assert put_item["GSI1SK"]["S"] == "2026-01-01T00:00:00+00:00"


def test_process_due_scheduled_posts_cancelled_rows_do_not_meter(monkeypatch) -> None:
    monkeypatch.setattr(
        svc,
        "_query_due_posts",
        lambda **kwargs: {"Items": [{"post_id": "p1", "user_id": "u1", "publish_at": 100}]},
    )
    monkeypatch.setattr(svc, "_publish_with_retry", lambda *args, **kwargs: "already_cancelled")
    meter_calls = {"n": 0}
    monkeypatch.setattr(
        svc,
        "_meter_publish_once",
        lambda **kwargs: meter_calls.__setitem__("n", meter_calls["n"] + 1) or True,
    )

    out = svc.process_due_scheduled_posts(now_ts=123, page_limit=10, max_batches=1)
    assert out["already_cancelled"] == 1
    assert out["metered"] == 0
    assert out["meter_errors"] == 0
    assert meter_calls["n"] == 0


def test_publish_with_retry_succeeds_after_single_retry_without_duplicate_publish(monkeypatch) -> None:
    class _RetryExc(Exception):
        pass

    monkeypatch.setattr(svc, "ClientError", _RetryExc)
    calls = {"n": 0}

    def _publish(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise _RetryExc()
        return "published"

    sleep_calls = {"n": 0}
    monkeypatch.setattr(svc, "_publish_due_post", _publish)
    monkeypatch.setattr(svc.time, "sleep", lambda *_: sleep_calls.__setitem__("n", sleep_calls["n"] + 1))

    out = svc._publish_with_retry({}, now_ts=1, now_iso="2026-01-01T00:00:00+00:00", max_retries=3, backoff_seconds=0.01)
    assert out == "published"
    assert calls["n"] == 2
    assert sleep_calls["n"] == 1


def test_process_due_scheduled_posts_recovers_from_partial_failures(monkeypatch) -> None:
    monkeypatch.setattr(
        svc,
        "_query_due_posts",
        lambda **kwargs: {
            "Items": [
                {"post_id": "p-fail", "user_id": "u1", "publish_at": 100},
                {"post_id": "p-ok", "user_id": "u1", "publish_at": 100},
            ]
        },
    )
    statuses = iter(["retry_exhausted", "published"])
    monkeypatch.setattr(svc, "_publish_with_retry", lambda *args, **kwargs: next(statuses))
    monkeypatch.setattr(svc, "_meter_publish_once", lambda **kwargs: True)

    out = svc.process_due_scheduled_posts(now_ts=123, page_limit=10, max_batches=1)
    assert out["scanned"] == 2
    assert out["retry_exhausted"] == 1
    assert out["published"] == 1
    assert out["metered"] == 1
    assert out["meter_errors"] == 0


def test_meter_publish_once_logs_actionable_telemetry_on_failure(monkeypatch) -> None:
    # Force lazy import path to fail and assert contextual logging fields.
    import builtins

    real_import = builtins.__import__

    def _fake_import(name, *args, **kwargs):
        if name == "app.routers.newsfeed":
            raise RuntimeError("boom")
        return real_import(name, *args, **kwargs)

    log_args = {}

    def _log(msg, extra=None):
        log_args["msg"] = msg
        log_args["extra"] = extra or {}

    monkeypatch.setattr(builtins, "__import__", _fake_import)
    monkeypatch.setattr(svc.logger, "exception", _log)

    ok = svc._meter_publish_once(user_id="u1", post_id="p1")
    assert ok is False
    assert "metering failed" in log_args["msg"]
    assert log_args["extra"]["user_id"] == "u1"
    assert log_args["extra"]["post_id"] == "p1"


def test_process_due_scheduled_posts_records_backlog_publish_lag_and_outcomes(monkeypatch) -> None:
    monkeypatch.setattr(svc, "_query_due_backlog", lambda **kwargs: 4)
    monkeypatch.setattr(svc, "_query_oldest_due_publish_at", lambda **kwargs: 90)
    monkeypatch.setattr(
        svc,
        "_query_due_posts",
        lambda **kwargs: {"Items": [{"post_id": "p1", "user_id": "u1", "publish_at": 100}]},
    )
    monkeypatch.setattr(svc, "_publish_with_retry", lambda *args, **kwargs: "published")
    monkeypatch.setattr(svc, "_meter_publish_once", lambda **kwargs: True)
    ops = []
    lags = []
    backlog = {}
    oldest_due = {}
    monkeypatch.setattr(
        svc,
        "record_newsfeed_schedule_operation",
        lambda **kwargs: ops.append((kwargs["operation"], kwargs["outcome"])),
    )
    monkeypatch.setattr(
        svc,
        "record_newsfeed_schedule_publish_lag",
        lambda **kwargs: lags.append(int(kwargs["elapsed_seconds"])),
    )
    monkeypatch.setattr(
        svc,
        "set_newsfeed_schedule_backlog",
        lambda **kwargs: backlog.__setitem__("due", kwargs["due_count"]),
    )
    monkeypatch.setattr(
        svc,
        "set_newsfeed_schedule_oldest_due_age",
        lambda **kwargs: oldest_due.__setitem__("age", int(kwargs["elapsed_seconds"])),
    )

    out = svc.process_due_scheduled_posts(now_ts=130, page_limit=10, max_batches=1)

    assert out["backlog_due"] == 4
    assert backlog["due"] == 4
    assert out["backlog_oldest_due_age_seconds"] == 40
    assert oldest_due["age"] == 40
    assert out["max_publish_lag_seconds"] == 30
    assert lags == [30]
    assert ("publish", "published") in ops


def test_process_due_scheduled_posts_records_alerts_for_error_lag_and_oldest_due_thresholds(monkeypatch) -> None:
    monkeypatch.setattr(svc, "ALERT_ERROR_THRESHOLD", 1)
    monkeypatch.setattr(svc, "ALERT_PUBLISH_LAG_SECONDS", 5)
    monkeypatch.setattr(svc, "ALERT_OLDEST_DUE_AGE_SECONDS", 15)
    monkeypatch.setattr(svc, "_query_due_backlog", lambda **kwargs: 2)
    monkeypatch.setattr(svc, "_query_oldest_due_publish_at", lambda **kwargs: 100)
    monkeypatch.setattr(
        svc,
        "_query_due_posts",
        lambda **kwargs: {
            "Items": [
                {"post_id": "p-err", "user_id": "u1", "publish_at": 100},
                {"post_id": "p-lag", "user_id": "u1", "publish_at": 100},
            ]
        },
    )
    statuses = iter(["retry_exhausted", "published"])
    monkeypatch.setattr(svc, "_publish_with_retry", lambda *args, **kwargs: next(statuses))
    monkeypatch.setattr(svc, "_meter_publish_once", lambda **kwargs: True)
    alerts = []
    monkeypatch.setattr(svc, "record_newsfeed_schedule_alert", lambda **kwargs: alerts.append(kwargs["alert_type"]))
    monkeypatch.setattr(svc, "record_newsfeed_schedule_operation", lambda **kwargs: None)
    monkeypatch.setattr(svc, "record_newsfeed_schedule_publish_lag", lambda **kwargs: None)
    monkeypatch.setattr(svc, "set_newsfeed_schedule_backlog", lambda **kwargs: None)

    out = svc.process_due_scheduled_posts(now_ts=120, page_limit=10, max_batches=1)

    assert out["retry_exhausted"] == 1
    assert out["max_publish_lag_seconds"] == 20
    assert out["backlog_oldest_due_age_seconds"] == 20
    assert "error_threshold_breach" in alerts
    assert "lag_threshold_breach" in alerts
    assert "oldest_due_age_threshold_breach" in alerts


def test_process_due_scheduled_posts_is_noop_when_worker_flag_disabled(monkeypatch) -> None:
    monkeypatch.setattr(svc.S, "newsfeed_scheduling_worker_enabled", False)
    out = svc.process_due_scheduled_posts(now_ts=120, page_limit=10, max_batches=1)
    assert out["worker_enabled"] is False
    assert out["scanned"] == 0
    assert out["published"] == 0


def test_process_due_scheduled_posts_records_disabled_run_outcome(monkeypatch) -> None:
    monkeypatch.setattr(svc.S, "newsfeed_scheduling_worker_enabled", False)
    run_outcomes = []
    durations = []
    heartbeats = []
    monkeypatch.setattr(svc, "record_newsfeed_schedule_run", lambda **kwargs: run_outcomes.append(kwargs["outcome"]))
    monkeypatch.setattr(svc, "record_newsfeed_schedule_run_duration", lambda **kwargs: durations.append(kwargs["elapsed_seconds"]))
    monkeypatch.setattr(svc, "set_newsfeed_schedule_last_run", lambda **kwargs: heartbeats.append(kwargs["unix_seconds"]))

    out = svc.process_due_scheduled_posts(now_ts=120, page_limit=10, max_batches=1)

    assert out["worker_enabled"] is False
    assert out["run_exception"] == 0
    assert run_outcomes == ["disabled"]
    assert len(durations) == 1
    assert durations[0] >= 0
    assert len(heartbeats) == 1
    assert heartbeats[0] >= 0


def test_process_due_scheduled_posts_recovers_from_unhandled_run_exception(monkeypatch) -> None:
    monkeypatch.setattr(svc.S, "newsfeed_scheduling_worker_enabled", True)
    monkeypatch.setattr(svc, "_query_due_backlog", lambda **kwargs: 0)
    monkeypatch.setattr(svc, "_query_due_posts", lambda **kwargs: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(svc, "set_newsfeed_schedule_backlog", lambda **kwargs: None)

    run_outcomes = []
    durations = []
    heartbeats = []
    monkeypatch.setattr(svc, "record_newsfeed_schedule_run", lambda **kwargs: run_outcomes.append(kwargs["outcome"]))
    monkeypatch.setattr(svc, "record_newsfeed_schedule_run_duration", lambda **kwargs: durations.append(kwargs["elapsed_seconds"]))
    monkeypatch.setattr(svc, "set_newsfeed_schedule_last_run", lambda **kwargs: heartbeats.append(kwargs["unix_seconds"]))

    out = svc.process_due_scheduled_posts(now_ts=120, page_limit=10, max_batches=1)

    assert out["worker_enabled"] is True
    assert out["run_exception"] == 1
    assert out["error"] == 1
    assert run_outcomes == ["failed"]
    assert len(durations) == 1
    assert durations[0] >= 0
    assert len(heartbeats) == 1
    assert heartbeats[0] >= 0
