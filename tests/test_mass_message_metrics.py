from __future__ import annotations

from unittest.mock import MagicMock, patch

from app import metrics


def test_record_mass_message_campaign_event_increments_counter() -> None:
    with patch.object(metrics, "MASS_MESSAGE_CAMPAIGN_EVENTS") as metric:
        labels = MagicMock()
        metric.labels.return_value = labels
        metrics.record_mass_message_campaign_event(event="create", mode="immediate", outcome="success")
    metric.labels.assert_called_once_with(event="create", mode="immediate", outcome="success")
    labels.inc.assert_called_once()


def test_record_mass_message_destination_outcome_increments_counter() -> None:
    with patch.object(metrics, "MASS_MESSAGE_DESTINATION_OUTCOMES") as metric:
        labels = MagicMock()
        metric.labels.return_value = labels
        metrics.record_mass_message_destination_outcome(mode="scheduled", outcome="failed", error_code="policy_blocked")
    metric.labels.assert_called_once_with(mode="scheduled", outcome="failed", error_code="policy_blocked")
    labels.inc.assert_called_once()


def test_record_mass_message_destination_retry_increments_counter() -> None:
    with patch.object(metrics, "MASS_MESSAGE_DESTINATION_RETRIES") as metric:
        labels = MagicMock()
        metric.labels.return_value = labels
        metrics.record_mass_message_destination_retry(mode="immediate", error_code="transient_infra")
    metric.labels.assert_called_once_with(mode="immediate", error_code="transient_infra")
    labels.inc.assert_called_once()


def test_record_mass_message_worker_latency_observes_histogram() -> None:
    with patch.object(metrics, "MASS_MESSAGE_WORKER_LATENCY") as metric:
        labels = MagicMock()
        metric.labels.return_value = labels
        metrics.record_mass_message_worker_latency(mode="immediate", outcome="success", elapsed_seconds=0.25)
    metric.labels.assert_called_once_with(mode="immediate", outcome="success")
    labels.observe.assert_called_once_with(0.25)
