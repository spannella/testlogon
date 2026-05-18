from __future__ import annotations

from app.services import jira_webhook


def test_process_jira_webhook_acknowledges_unsupported_event_without_enqueue(monkeypatch) -> None:
    called = {"count": 0}

    def _never_enqueue(*, envelope):  # type: ignore[no-untyped-def]
        called["count"] += 1
        return True

    monkeypatch.setattr(jira_webhook, "_enqueue_to_sqs", _never_enqueue)
    result = jira_webhook.process_jira_webhook(
        event_type="custom_unknown_event",
        cloud_id="cloud-1",
        issue_id="10001",
        issue_key="PROJ-1",
        payload={"foo": "bar"},
        header_event_type="custom_unknown_event",
        webhook_identifier="wh-1",
        signature_header=None,
    )

    assert result.accepted is True
    assert result.enqueued is False
    assert called["count"] == 0


def test_process_jira_webhook_enqueues_supported_event_with_trace_metadata(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def _capture_enqueue(*, envelope):  # type: ignore[no-untyped-def]
        captured.update(envelope)
        return True

    monkeypatch.setattr(jira_webhook, "_enqueue_to_sqs", _capture_enqueue)
    result = jira_webhook.process_jira_webhook(
        event_type="jira:issue_updated",
        cloud_id="cloud-1",
        issue_id="10001",
        issue_key="PROJ-1",
        payload={"payload_version": 1},
        header_event_type="jira:issue_updated",
        webhook_identifier="wh-2",
        signature_header=None,
    )

    assert result.accepted is True
    assert result.enqueued is True
    assert result.trace_id.startswith("jira-webhook-")
    assert captured["trace_id"] == result.trace_id
    assert captured["event_type"] == "jira:issue_updated"
    assert captured["issue_id"] == "10001"
    assert captured["webhook_id"] == "wh-2"


def test_process_jira_webhook_rejects_supported_event_without_issue_identifier(monkeypatch) -> None:
    monkeypatch.setattr(jira_webhook, "_enqueue_to_sqs", lambda *, envelope: True)
    try:
        jira_webhook.process_jira_webhook(
            event_type="jira:issue_updated",
            cloud_id="cloud-1",
            issue_id=None,
            issue_key=None,
            payload={"issue": {}},
            header_event_type="jira:issue_updated",
            webhook_identifier=None,
            signature_header=None,
        )
        assert False, "expected payload validation error"
    except ValueError as exc:
        assert "issue_id or issue_key" in str(exc)


def test_process_jira_webhook_rejects_missing_signature_when_secret_configured(monkeypatch) -> None:
    monkeypatch.setenv("JIRA_WEBHOOK_SIGNING_SECRET", "test-secret")
    monkeypatch.setattr(jira_webhook, "_enqueue_to_sqs", lambda *, envelope: True)
    try:
        jira_webhook.process_jira_webhook(
            event_type="jira:issue_updated",
            cloud_id="cloud-1",
            issue_id="10001",
            issue_key="PROJ-1",
            payload={"payload_version": 1},
            header_event_type="jira:issue_updated",
            webhook_identifier="wh-3",
            signature_header=None,
        )
        assert False, "expected missing signature auth error"
    except jira_webhook.JiraWebhookAuthError as exc:
        assert exc.status_code == 401


def test_process_jira_webhook_rejects_invalid_signature(monkeypatch) -> None:
    monkeypatch.setenv("JIRA_WEBHOOK_SIGNING_SECRET", "test-secret")
    monkeypatch.setattr(jira_webhook, "_enqueue_to_sqs", lambda *, envelope: True)
    try:
        jira_webhook.process_jira_webhook(
            event_type="jira:issue_updated",
            cloud_id="cloud-1",
            issue_id="10001",
            issue_key="PROJ-1",
            payload={"payload_version": 1},
            header_event_type="jira:issue_updated",
            webhook_identifier="wh-4",
            signature_header="sha256=bad-signature",
        )
        assert False, "expected invalid signature auth error"
    except jira_webhook.JiraWebhookAuthError as exc:
        assert exc.status_code == 403


def test_process_jira_webhook_deduplicates_by_replay_key(monkeypatch) -> None:
    monkeypatch.setattr(jira_webhook, "_enqueue_to_sqs", lambda *, envelope: True)
    with jira_webhook._REPLAY_LOCK:
        jira_webhook._REPLAY_KEYS.clear()

    first = jira_webhook.process_jira_webhook(
        event_type="jira:issue_updated",
        cloud_id="cloud-1",
        issue_id="10001",
        issue_key="PROJ-1",
        payload={"payload_version": 1},
        header_event_type="jira:issue_updated",
        webhook_identifier="wh-replay-1",
        signature_header=None,
    )
    second = jira_webhook.process_jira_webhook(
        event_type="jira:issue_updated",
        cloud_id="cloud-1",
        issue_id="10001",
        issue_key="PROJ-1",
        payload={"payload_version": 1},
        header_event_type="jira:issue_updated",
        webhook_identifier="wh-replay-1",
        signature_header=None,
    )

    assert first.enqueued is True
    assert first.deduplicated is False
    assert second.enqueued is False
    assert second.deduplicated is True


def test_process_jira_webhook_enforces_allowed_source_ip(monkeypatch) -> None:
    monkeypatch.setenv("JIRA_WEBHOOK_ALLOWED_IPS", "10.0.0.0/8,192.168.1.0/24")
    monkeypatch.setattr(jira_webhook, "_enqueue_to_sqs", lambda *, envelope: True)
    result = jira_webhook.process_jira_webhook(
        event_type="jira:issue_updated",
        cloud_id="cloud-1",
        issue_id="10001",
        issue_key="PROJ-1",
        payload={"payload_version": 1},
        header_event_type="jira:issue_updated",
        webhook_identifier="wh-ip-ok",
        signature_header=None,
        remote_ip="10.2.3.4",
    )
    assert result.enqueued is True


def test_process_jira_webhook_rejects_disallowed_source_ip(monkeypatch) -> None:
    monkeypatch.setenv("JIRA_WEBHOOK_ALLOWED_IPS", "10.0.0.0/8")
    monkeypatch.setattr(jira_webhook, "_enqueue_to_sqs", lambda *, envelope: True)
    try:
        jira_webhook.process_jira_webhook(
            event_type="jira:issue_updated",
            cloud_id="cloud-1",
            issue_id="10001",
            issue_key="PROJ-1",
            payload={"payload_version": 1},
            header_event_type="jira:issue_updated",
            webhook_identifier="wh-ip-no",
            signature_header=None,
            remote_ip="203.0.113.10",
        )
        assert False, "expected source ip auth error"
    except jira_webhook.JiraWebhookAuthError as exc:
        assert exc.status_code == 403
        assert "not allowed" in exc.message


def test_process_jira_webhook_allows_disallowed_source_ip_in_monitor_mode(monkeypatch) -> None:
    jira_webhook._reset_source_ip_policy_violation_counts_for_tests()
    monkeypatch.setenv("JIRA_WEBHOOK_ALLOWED_IPS", "10.0.0.0/8")
    monkeypatch.setenv("JIRA_WEBHOOK_IP_POLICY_MODE", "monitor")
    monkeypatch.setattr(jira_webhook, "_enqueue_to_sqs", lambda *, envelope: True)
    result = jira_webhook.process_jira_webhook(
        event_type="jira:issue_updated",
        cloud_id="cloud-1",
        issue_id="10001",
        issue_key="PROJ-1",
        payload={"payload_version": 1},
        header_event_type="jira:issue_updated",
        webhook_identifier="wh-ip-monitor",
        signature_header=None,
        remote_ip="203.0.113.10",
    )
    assert result.enqueued is True
    counts = jira_webhook.get_source_ip_policy_violation_counts()
    assert counts.get("jira webhook source ip not allowed") == 1
    counts_by_mode = jira_webhook.get_source_ip_policy_violation_counts_by_mode()
    assert counts_by_mode.get("monitor:jira webhook source ip not allowed") == 1


def test_process_jira_webhook_skips_ip_checks_when_policy_off(monkeypatch) -> None:
    monkeypatch.setenv("JIRA_WEBHOOK_ALLOWED_IPS", "10.0.0.0/8")
    monkeypatch.setenv("JIRA_WEBHOOK_IP_POLICY_MODE", "off")
    monkeypatch.setattr(jira_webhook, "_enqueue_to_sqs", lambda *, envelope: True)
    result = jira_webhook.process_jira_webhook(
        event_type="jira:issue_updated",
        cloud_id="cloud-1",
        issue_id="10001",
        issue_key="PROJ-1",
        payload={"payload_version": 1},
        header_event_type="jira:issue_updated",
        webhook_identifier="wh-ip-off",
        signature_header=None,
        remote_ip=None,
    )
    assert result.enqueued is True


def test_process_jira_webhook_counts_enforced_source_ip_rejections(monkeypatch) -> None:
    jira_webhook._reset_source_ip_policy_violation_counts_for_tests()
    monkeypatch.setenv("JIRA_WEBHOOK_ALLOWED_IPS", "10.0.0.0/8")
    monkeypatch.setenv("JIRA_WEBHOOK_IP_POLICY_MODE", "enforce")
    monkeypatch.setattr(jira_webhook, "_enqueue_to_sqs", lambda *, envelope: True)
    try:
        jira_webhook.process_jira_webhook(
            event_type="jira:issue_updated",
            cloud_id="cloud-1",
            issue_id="10001",
            issue_key="PROJ-1",
            payload={"payload_version": 1},
            header_event_type="jira:issue_updated",
            webhook_identifier="wh-ip-enforce",
            signature_header=None,
            remote_ip="198.51.100.20",
        )
        assert False, "expected enforced source ip auth error"
    except jira_webhook.JiraWebhookAuthError:
        counts = jira_webhook.get_source_ip_policy_violation_counts()
        assert counts.get("jira webhook source ip not allowed") == 1
        counts_by_mode = jira_webhook.get_source_ip_policy_violation_counts_by_mode()
        assert counts_by_mode.get("enforce:jira webhook source ip not allowed") == 1


def test_process_jira_webhook_rejects_misconfigured_source_ip_policy_in_enforce_mode(monkeypatch) -> None:
    jira_webhook._reset_source_ip_policy_violation_counts_for_tests()
    monkeypatch.setenv("JIRA_WEBHOOK_ALLOWED_IPS", "not-a-cidr")
    monkeypatch.setenv("JIRA_WEBHOOK_IP_POLICY_MODE", "enforce")
    monkeypatch.setattr(jira_webhook, "_enqueue_to_sqs", lambda *, envelope: True)
    try:
        jira_webhook.process_jira_webhook(
            event_type="jira:issue_updated",
            cloud_id="cloud-1",
            issue_id="10001",
            issue_key="PROJ-1",
            payload={"payload_version": 1},
            header_event_type="jira:issue_updated",
            webhook_identifier="wh-ip-bad-cidr",
            signature_header=None,
            remote_ip="10.0.0.1",
        )
        assert False, "expected source ip policy misconfiguration error"
    except jira_webhook.JiraWebhookAuthError as exc:
        assert exc.status_code == 503
        assert "misconfigured" in exc.message
    counts = jira_webhook.get_source_ip_policy_violation_counts()
    assert counts.get("jira webhook source ip policy misconfigured") == 1
    counts_by_mode = jira_webhook.get_source_ip_policy_violation_counts_by_mode()
    assert counts_by_mode.get("enforce:jira webhook source ip policy misconfigured") == 1


def test_process_jira_webhook_allows_misconfigured_policy_in_monitor_mode(monkeypatch) -> None:
    jira_webhook._reset_source_ip_policy_violation_counts_for_tests()
    monkeypatch.setenv("JIRA_WEBHOOK_ALLOWED_IPS", "not-a-cidr")
    monkeypatch.setenv("JIRA_WEBHOOK_IP_POLICY_MODE", "monitor")
    monkeypatch.setattr(jira_webhook, "_enqueue_to_sqs", lambda *, envelope: True)
    result = jira_webhook.process_jira_webhook(
        event_type="jira:issue_updated",
        cloud_id="cloud-1",
        issue_id="10001",
        issue_key="PROJ-1",
        payload={"payload_version": 1},
        header_event_type="jira:issue_updated",
        webhook_identifier="wh-ip-bad-cidr-monitor",
        signature_header=None,
        remote_ip="10.0.0.1",
    )
    assert result.enqueued is True
    counts = jira_webhook.get_source_ip_policy_violation_counts()
    assert counts.get("jira webhook source ip policy misconfigured") == 1
    counts_by_mode = jira_webhook.get_source_ip_policy_violation_counts_by_mode()
    assert counts_by_mode.get("monitor:jira webhook source ip policy misconfigured") == 1


def test_process_jira_webhook_allows_when_any_cidr_is_valid(monkeypatch) -> None:
    jira_webhook._reset_source_ip_policy_violation_counts_for_tests()
    monkeypatch.setenv("JIRA_WEBHOOK_ALLOWED_IPS", "bad-cidr,10.0.0.0/8")
    monkeypatch.setenv("JIRA_WEBHOOK_IP_POLICY_MODE", "enforce")
    monkeypatch.setattr(jira_webhook, "_enqueue_to_sqs", lambda *, envelope: True)
    result = jira_webhook.process_jira_webhook(
        event_type="jira:issue_updated",
        cloud_id="cloud-1",
        issue_id="10001",
        issue_key="PROJ-1",
        payload={"payload_version": 1},
        header_event_type="jira:issue_updated",
        webhook_identifier="wh-ip-mixed-cidr",
        signature_header=None,
        remote_ip="10.3.4.5",
    )
    assert result.enqueued is True
    assert jira_webhook.get_source_ip_policy_violation_counts() == {}
    assert jira_webhook.get_source_ip_policy_violation_counts_by_mode() == {}


def test_consume_source_ip_policy_violation_counts_by_mode_drains_mode_snapshot(monkeypatch) -> None:
    jira_webhook._reset_source_ip_policy_violation_counts_for_tests()
    monkeypatch.setenv("JIRA_WEBHOOK_ALLOWED_IPS", "10.0.0.0/8")
    monkeypatch.setenv("JIRA_WEBHOOK_IP_POLICY_MODE", "monitor")
    monkeypatch.setattr(jira_webhook, "_enqueue_to_sqs", lambda *, envelope: True)
    jira_webhook.process_jira_webhook(
        event_type="jira:issue_updated",
        cloud_id="cloud-1",
        issue_id="10001",
        issue_key="PROJ-1",
        payload={"payload_version": 1},
        header_event_type="jira:issue_updated",
        webhook_identifier="wh-ip-drain",
        signature_header=None,
        remote_ip="203.0.113.10",
    )
    snapshot = jira_webhook.consume_source_ip_policy_violation_counts_by_mode()
    assert snapshot.get("monitor:jira webhook source ip not allowed") == 1
    assert jira_webhook.get_source_ip_policy_violation_counts_by_mode() == {}
    # Aggregate counts remain available for cumulative reporting.
    assert jira_webhook.get_source_ip_policy_violation_counts().get("jira webhook source ip not allowed") == 1


def test_process_jira_webhook_rejects_invalid_policy_mode_when_allowlist_configured(monkeypatch) -> None:
    jira_webhook._reset_source_ip_policy_violation_counts_for_tests()
    monkeypatch.setenv("JIRA_WEBHOOK_ALLOWED_IPS", "10.0.0.0/8")
    monkeypatch.setenv("JIRA_WEBHOOK_IP_POLICY_MODE", "definitely-invalid")
    monkeypatch.setattr(jira_webhook, "_enqueue_to_sqs", lambda *, envelope: True)
    try:
        jira_webhook.process_jira_webhook(
            event_type="jira:issue_updated",
            cloud_id="cloud-1",
            issue_id="10001",
            issue_key="PROJ-1",
            payload={"payload_version": 1},
            header_event_type="jira:issue_updated",
            webhook_identifier="wh-ip-invalid-mode",
            signature_header=None,
            remote_ip="10.0.0.1",
        )
        assert False, "expected invalid policy mode error"
    except jira_webhook.JiraWebhookAuthError as exc:
        assert exc.status_code == 503
        assert "policy mode invalid" in exc.message
    assert jira_webhook.get_source_ip_policy_violation_counts().get("jira webhook source ip policy mode invalid") == 1
    assert (
        jira_webhook.get_source_ip_policy_violation_counts_by_mode().get("invalid:jira webhook source ip policy mode invalid")
        == 1
    )


def test_source_ip_policy_violation_snapshot_reports_totals_and_can_drain_mode(monkeypatch) -> None:
    jira_webhook._reset_source_ip_policy_violation_counts_for_tests()
    monkeypatch.setenv("JIRA_WEBHOOK_ALLOWED_IPS", "10.0.0.0/8")
    monkeypatch.setenv("JIRA_WEBHOOK_IP_POLICY_MODE", "monitor")
    monkeypatch.setattr(jira_webhook, "_enqueue_to_sqs", lambda *, envelope: True)
    jira_webhook.process_jira_webhook(
        event_type="jira:issue_updated",
        cloud_id="cloud-1",
        issue_id="10001",
        issue_key="PROJ-1",
        payload={"payload_version": 1},
        header_event_type="jira:issue_updated",
        webhook_identifier="wh-ip-snapshot",
        signature_header=None,
        remote_ip="203.0.113.10",
    )
    snapshot = jira_webhook.get_source_ip_policy_violation_snapshot()
    assert snapshot["drained_mode_counts"] is False
    assert snapshot["total_aggregate"] == 1
    assert snapshot["total_by_mode"] == 1
    assert snapshot["by_mode"].get("monitor:jira webhook source ip not allowed") == 1
    drained_snapshot = jira_webhook.get_source_ip_policy_violation_snapshot(drain_mode_counts=True)
    assert drained_snapshot["drained_mode_counts"] is True
    assert drained_snapshot["total_by_mode"] == 1
    after = jira_webhook.get_source_ip_policy_violation_snapshot()
    assert after["total_by_mode"] == 0
    assert after["total_aggregate"] == 1


def test_replay_key_store_is_bounded_by_max_keys(monkeypatch) -> None:
    with jira_webhook._REPLAY_LOCK:
        jira_webhook._REPLAY_KEYS.clear()
    monkeypatch.setenv("JIRA_WEBHOOK_REPLAY_MAX_KEYS", "100")
    monkeypatch.setenv("JIRA_WEBHOOK_REPLAY_TTL_SECONDS", "9999")
    # Fill to max capacity using unique keys.
    for idx in range(100):
        assert jira_webhook._check_and_mark_replay(f"rk-{idx}") is False
    assert len(jira_webhook._REPLAY_KEYS) == 100
    # Adding one more key should evict one oldest entry and keep store bounded.
    assert jira_webhook._check_and_mark_replay("rk-overflow") is False
    assert len(jira_webhook._REPLAY_KEYS) == 100
