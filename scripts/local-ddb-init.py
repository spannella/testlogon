#!/usr/bin/env python3
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError
from app.core.settings import S
from app.services.messaging_thread_contract import (
    INDEX_BY_CONVERSATION_CREATED_AT,
    INDEX_BY_PARENT_MESSAGE_ID,
    INDEX_BY_ROOT_MESSAGE,
    INDEX_BY_THREAD_CREATED_AT,
    INDEX_BY_THREAD_ROOT_MESSAGE_ID,
    MESSAGE_FIELD_PARENT_ID,
    MESSAGE_FIELD_THREAD_ID,
    MESSAGE_FIELD_THREAD_ROOT_ID,
    THREAD_FIELD_CONVERSATION_ID,
    THREAD_FIELD_CREATED_AT,
    THREAD_FIELD_ID,
    THREAD_FIELD_ROOT_MESSAGE_ID,
)


@dataclass(frozen=True)
class TableDef:
    name: str
    partition_key: str
    sort_key: Optional[str] = None
    gsi: List[Dict[str, str]] = field(default_factory=list)
    # Override attribute types (default "S"). Use for numeric keys, e.g. {"created_at": "N"}
    attr_types: Dict[str, str] = field(default_factory=dict)


def _resolve_table_name(name: str, fallback: str) -> str:
    return name or fallback


def _table_defs() -> List[TableDef]:
    return [
        TableDef(_resolve_table_name(S.ddb_sessions_table, "sessions"), "user_sub", "session_id"),
        TableDef(_resolve_table_name(S.ddb_totp_table, "totp_devices"), "user_sub", "device_id"),
        TableDef(_resolve_table_name(S.ddb_sms_table, "sms_devices"), "user_sub", "sms_device_id"),
        TableDef(_resolve_table_name(S.ddb_email_table, "email_devices"), "user_sub", "email_device_id"),
        TableDef(_resolve_table_name(S.ddb_recovery_table, "recovery_codes"), "user_sub", "code_hash"),
        TableDef(
            _resolve_table_name(S.users_table_name, "users"),
            "user_sub",
            gsi=[{"index_name": "ByKycTier", "partition_key": "kyc_tier", "sort_key": "kyc_tier_updated_at"}],
            attr_types={"kyc_tier": "N", "kyc_tier_updated_at": "N"},
        ),
        TableDef(_resolve_table_name(S.role_audit_table_name, "role_audit"), "pk", "sk"),
        TableDef(
            _resolve_table_name(S.api_keys_table_name, "api_keys"),
            "key_id",
            gsi=[{"index_name": S.api_keys_user_index, "partition_key": "user_sub"}],
        ),
        TableDef(_resolve_table_name(S.alerts_table_name, "alerts"), "user_sub", "alert_id"),
        TableDef(_resolve_table_name(S.alert_prefs_table_name, "alert_prefs"), "user_sub"),
        TableDef(_resolve_table_name(S.push_devices_table_name, "push_devices"), "user_sub", "device_id"),
        TableDef(_resolve_table_name(S.billing_table_name, "billing"), "pk", "sk"),
        TableDef(_resolve_table_name(S.billing_config_table_name, "billing_config"), "pk", "sk"),
        TableDef(
            _resolve_table_name(S.ddb_sticker_collections_table, "sticker_collections"),
            "collection_id",
            "sk",
            gsi=[{"index_name": "GSI1", "partition_key": "is_active", "sort_key": "created_at"}],
            attr_types={"created_at": "N"},
        ),
        TableDef(
            _resolve_table_name(S.ddb_custom_emojis_table, "custom_emojis"),
            "owner_scope",
            "emoji_sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "owner_scope", "sort_key": "shortcode"},
                {"index_name": "GSI2", "partition_key": "created_by", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        TableDef(_resolve_table_name(S.account_state_table_name, "account_state"), "user_sub"),
        TableDef(_resolve_table_name(S.profile_table_name, "profiles"), "user_sub"),
        TableDef(_resolve_table_name(S.addresses_table_name, "addresses"), "user_sub", "address_id"),
        TableDef(_resolve_table_name(S.calendar_table_name, "calendar"), "calendar_id", "sk"),
        TableDef(_resolve_table_name(S.purchase_transactions_table_name, "purchase_transactions"), "user_sub", "sk"),
        TableDef(_resolve_table_name(S.purchase_events_table_name, "purchase_transaction_events"), "pk", "sk"),
        TableDef(
            _resolve_table_name(S.shopping_cart_table_name, "shopping_cart"),
            "PK", "SK",
            gsi=[{"index_name": "ByStatusActivity", "partition_key": "status", "sort_key": "last_activity_at"}],
            attr_types={"last_activity_at": "N"},
        ),
        TableDef(
            _resolve_table_name(S.catalog_table_name, "shopping_catalog"),
            "PK",
            "SK",
            gsi=[{"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"}],
        ),
        TableDef(_resolve_table_name(S.subscriptions_table_name, "subscriptions"), "pk", "sk"),
        TableDef(
            _resolve_table_name(S.questionnaire_table_name, "questionnaires"),
            "pk",
            "sk",
            gsi=[
                {"index_name": S.questionnaire_owner_index_name, "partition_key": "gsi_owner_pk", "sort_key": "gsi_owner_sk"},
                {"index_name": S.questionnaire_status_index_name, "partition_key": "gsi_status_pk", "sort_key": "gsi_status_sk"},
                {"index_name": S.questionnaire_published_index_name, "partition_key": "gsi_published_pk", "sort_key": "gsi_published_sk"},
                {"index_name": S.questionnaire_response_status_index_name, "partition_key": "gsi_response_status_pk", "sort_key": "gsi_response_status_sk"},
            ],
        ),
        TableDef(
            _resolve_table_name(S.kyc_cases_table_name, "kyc_cases"),
            "pk",
            "sk",
            gsi=[
                {"index_name": S.kyc_cases_owner_index_name, "partition_key": "gsi_owner_pk", "sort_key": "gsi_owner_sk"},
                {"index_name": S.kyc_cases_status_index_name, "partition_key": "gsi_status_pk", "sort_key": "gsi_status_sk"},
                # KYC-023: PII access audit log, queryable by accessor (newest first).
                {"index_name": S.kyc_pii_audit_accessor_index_name, "partition_key": "gsi_pii_accessor_pk", "sort_key": "gsi_pii_accessor_sk"},
            ],
            attr_types={"gsi_pii_accessor_sk": "N"},
        ),
        TableDef(
            _resolve_table_name(S.kyc_business_cases_table_name, "kyc_business_cases"),
            "pk",
            "sk",
            gsi=[
                {"index_name": S.kyc_business_cases_owner_index_name, "partition_key": "gsi_owner_pk", "sort_key": "gsi_owner_sk"},
                {"index_name": S.kyc_business_cases_status_index_name, "partition_key": "gsi_status_pk", "sort_key": "gsi_status_sk"},
                {"index_name": S.kyc_business_cases_org_index_name, "partition_key": "gsi_org_pk", "sort_key": "gsi_org_sk"},
            ],
        ),
        TableDef(
            _resolve_table_name(S.kyc_risk_scores_table_name, "kyc_risk_scores"),
            "user_sub",
            "timestamp",
            gsi=[
                {"index_name": "case-timestamp-index", "partition_key": "case_id", "sort_key": "timestamp"},
                {"index_name": "tier-timestamp-index", "partition_key": "risk_tier", "sort_key": "timestamp"},
            ],
            attr_types={"timestamp": "N"},
        ),
        # KYC Multi-Language Support (KYC-020)
        TableDef(
            _resolve_table_name(S.kyc_translations_table_name, "kyc_translations"),
            "language_code",
            "key",
            gsi=[
                {"index_name": "status-language-index", "partition_key": "status", "sort_key": "language_code"},
            ],
        ),
        TableDef(
            _resolve_table_name(S.kyc_review_schedule_table_name, "kyc_review_schedule"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByNextReviewDate", "partition_key": "gsi_status_pk", "sort_key": "next_review_date"},
            ],
            attr_types={"next_review_date": "N"},
        ),
        # KYC-017: Document Signing Template Library
        TableDef(
            _resolve_table_name(S.kyc_document_templates_table_name, "kyc_document_templates"),
            "template_id",
            "sk",
            gsi=[
                {"index_name": "slug-status-index", "partition_key": "slug", "sort_key": "status"},
                {"index_name": "status-updated-index", "partition_key": "status", "sort_key": "updated_at"},
            ],
            attr_types={"updated_at": "N"},
        ),
        TableDef(
            _resolve_table_name(S.kyc_documents_table_name, "kyc_documents"),
            "document_id",
            gsi=[
                {"index_name": S.kyc_documents_status_index_name, "partition_key": "status", "sort_key": "created_at"},
                {"index_name": "ByCase", "partition_key": "case_id", "sort_key": "created_at"},
                {"index_name": "ByOwner", "partition_key": "user_sub", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        TableDef(
            _resolve_table_name(S.kyc_id_scans_table_name, "kyc_id_scans"),
            "scan_id",
            gsi=[
                {"index_name": S.kyc_id_scanner_status_index_name, "partition_key": "status", "sort_key": "created_at"},
                {"index_name": "ByCase", "partition_key": "case_id", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        TableDef(
            _resolve_table_name(S.kyc_residency_documents_table_name, "kyc_residency_documents"),
            "document_id",
            gsi=[
                {"index_name": S.kyc_residency_documents_status_index_name, "partition_key": "status", "sort_key": "created_at"},
                {"index_name": "ByCase", "partition_key": "case_id", "sort_key": "created_at"},
                {"index_name": "ByOwner", "partition_key": "user_sub", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        TableDef(
            _resolve_table_name(S.kyc_screening_results_table_name, "kyc_screening_results"),
            "case_id",
            "screen_key",
            gsi=[
                {"index_name": S.kyc_screening_user_index_name, "partition_key": "user_sub", "sort_key": "created_at"},
                {"index_name": S.kyc_screening_status_index_name, "partition_key": "result", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        TableDef(
            _resolve_table_name(S.kyc_liveness_calls_table_name, "kyc_liveness_calls"),
            "call_id",
            gsi=[
                {"index_name": S.kyc_liveness_call_status_index_name, "partition_key": "status", "sort_key": "created_at"},
                {"index_name": "ByCase", "partition_key": "case_id", "sort_key": "created_at"},
                {"index_name": "ByOwner", "partition_key": "user_sub", "sort_key": "created_at"},
                {"index_name": "ByVerifier", "partition_key": "verifier_sub", "sort_key": "scheduled_at"},
            ],
            attr_types={"created_at": "N", "scheduled_at": "N"},
        ),
        TableDef(
            _resolve_table_name(S.kyc_proof_of_funds_table_name, "kyc_proof_of_funds"),
            "user_sub",
            "submission_id",
            gsi=[
                {"index_name": "ByStatus", "partition_key": "status", "sort_key": "created_at"},
                {"index_name": "BySubmissionId", "partition_key": "submission_id"},
            ],
            attr_types={"created_at": "N"},
        ),
        TableDef(
            _resolve_table_name(S.projects_table_name, "projects"),
            "PK",
            "SK",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
            ],
        ),
        TableDef(
            _resolve_table_name(S.catalog_products_table_name, "catalog_products"),
            "PK",
            "SK",
            gsi=[
                {"index_name": "GSI_PRODUCT_TYPE", "partition_key": "GSI_PRODUCT_TYPE_PK", "sort_key": "GSI_PRODUCT_TYPE_SK"},
            ],
        ),
        TableDef(_resolve_table_name(S.catalog_product_versions_table_name, "catalog_product_versions"), "sku", "effective_at"),
        TableDef(
            _resolve_table_name(S.orders_table_name, "orders"),
            "order_id",
            gsi=[
                {"index_name": "GSI_USER", "partition_key": "user_id", "sort_key": "created_at"},
                {"index_name": "GSI_STATUS", "partition_key": "status", "sort_key": "created_at"},
            ],
        ),
        TableDef(_resolve_table_name(S.order_items_table_name, "order_items"), "order_id", "item_id"),
        TableDef(
            _resolve_table_name(S.payment_incidents_table_name, "payment_incidents"),
            "incident_id",
        ),
        TableDef(
            _resolve_table_name(S.payments_table_name, "payments"),
            "payment_id",
            "event_id",
            gsi=[
                {"index_name": "GSI_ORDER", "partition_key": "order_id", "sort_key": "created_at"},
                {"index_name": "GSI_PROVIDER_EVENT_IDEMPOTENCY", "partition_key": "provider_event_idempotency_key"},
            ],
        ),
        TableDef(
            _resolve_table_name(S.entitlements_table_name, "entitlements"),
            "user_id",
            "entitlement_id",
            gsi=[
                {"index_name": "GSI_STATUS", "partition_key": "status", "sort_key": "ends_at"},
                {"index_name": "GSI_SKU", "partition_key": "sku", "sort_key": "starts_at"},
            ],
        ),
        TableDef(
            _resolve_table_name(S.entitlement_usage_events_table_name, "entitlement_usage_events"),
            "entitlement_id",
            "event_id",
            gsi=[
                {"index_name": "GSI_IDEMPOTENCY", "partition_key": "idempotency_key"},
                {"index_name": "GSI_TIMESTAMP", "partition_key": "event_date", "sort_key": "event_ts"},
            ],
        ),
        TableDef(
            _resolve_table_name(S.filemgr_table_name, "file_manager"),
            "PK",
            "SK",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
            ],
        ),
        TableDef(
            _resolve_table_name(S.filemgr_mounts_table_name, "filemgr_mounts"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "gsi_owner_pk", "sort_key": "gsi_owner_sk"},
            ],
        ),
        TableDef(
            _resolve_table_name(S.signature_packets_table_name, "signature_packets"),
            "packet_id",
            gsi=[
                {
                    "index_name": "OWNER_CREATED_INDEX",
                    "partition_key": "owner_user_id",
                    "sort_key": "created_at",
                }
            ],
        ),
        TableDef(
            _resolve_table_name(S.signature_packet_signers_table_name, "signature_packet_signers"),
            "packet_id",
            "signer_id",
            gsi=[
                {
                    "index_name": "SIGNER_STATUS_INDEX",
                    "partition_key": "signer_id",
                    "sort_key": "status_key",
                }
            ],
        ),
        TableDef(
            _resolve_table_name(S.signature_packet_fields_table_name, "signature_packet_fields"),
            "packet_id",
            "field_id",
        ),
        TableDef(
            _resolve_table_name(S.signature_packet_events_table_name, "signature_packet_events"),
            "packet_id",
            "event_id",
        ),
        TableDef(
            _resolve_table_name(S.signature_packet_artifacts_table_name, "signature_packet_artifacts"),
            "packet_id",
        ),
        TableDef(
            _resolve_table_name(S.signature_templates_table_name, "signature_templates"),
            "template_key",
            "version",
            attr_types={"version": "N"},
        ),
        TableDef(
            _resolve_table_name(S.api_usage_table_name, "api_usage_events"),
            "PK",
            "SK",
            gsi=[
                {"index_name": "GSI_PERIOD", "partition_key": "GSI_PERIOD_PK", "sort_key": "GSI_PERIOD_SK"},
                {"index_name": "GSI_API_KEY", "partition_key": "GSI_API_KEY_PK", "sort_key": "GSI_API_KEY_SK"},
                {"index_name": "GSI_ROUTE", "partition_key": "GSI_ROUTE_PK", "sort_key": "GSI_ROUTE_SK"},
            ],
        ),
        TableDef(
            os.getenv("APP_TABLE", "app_single_table"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
                {"index_name": "GSI3", "partition_key": "GSI3PK", "sort_key": "GSI3SK"},
                {"index_name": "GSI_SCHEDULE_DUE", "partition_key": "GSI_SCHEDULE_PK", "sort_key": "GSI_SCHEDULE_SK"},
                {"index_name": "GSI4", "partition_key": "GSI4PK", "sort_key": "GSI4SK"},
                {"index_name": "GSI5", "partition_key": "GSI5PK", "sort_key": "GSI5SK"},
            ],
            # GSI5SK is a string sort key ("{created_at}#{follower_id}", written by
            # social.follow_user — the sole GSI5 writer). It was mistakenly typed "N"
            # (DELEGATE-003), which made every follow PutItem fail with a key type mismatch.
            attr_types={"GSI5SK": "S"},
        ),
        TableDef(
            os.getenv("DDB_CONVERSATIONS", "Conversations"),
            "conversation_id",
            gsi=[
                {
                    "index_name": "RoutingStateGroupIndex",
                    "partition_key": "routing_state_group_pk",
                    "sort_key": "routing_state_group_sk",
                }
            ],
        ),
        TableDef(
            os.getenv("DDB_PARTICIPANTS", "Participants"),
            "user_id",
            "conversation_id",
            gsi=[{"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"}],
        ),
        TableDef(
            os.getenv("DDB_MESSAGES", "Messages"),
            "conversation_id",
            "message_id",
            gsi=[
                {"index_name": INDEX_BY_CONVERSATION_CREATED_AT, "partition_key": "conversation_id", "sort_key": "created_at"},
                {"index_name": INDEX_BY_PARENT_MESSAGE_ID, "partition_key": MESSAGE_FIELD_PARENT_ID},
                {"index_name": INDEX_BY_THREAD_CREATED_AT, "partition_key": MESSAGE_FIELD_THREAD_ID, "sort_key": "created_at"},
                {"index_name": INDEX_BY_THREAD_ROOT_MESSAGE_ID, "partition_key": MESSAGE_FIELD_THREAD_ROOT_ID},
            ],
            attr_types={"created_at": "N"},
        ),
        TableDef(os.getenv("DDB_USER_EVENTS", "UserEvents"), "user_id", "event_id"),
        TableDef(os.getenv("DDB_USERS", "Users"), "user_id"),
        TableDef(os.getenv("DDB_USER_SEARCH", "UserSearch"), "token"),
        TableDef(
            os.getenv("DDB_DISCOVERY_INDEX", "DiscoveryIndex"),
            "pk",
            "sk",
            gsi=[{"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"}],
            attr_types={"GSI1SK": "N"},
        ),
        TableDef(os.getenv("DDB_MESSAGE_SEARCH", "MessageSearch"), "token", "message_key"),
        TableDef(os.getenv("DDB_PRESENCE", "UserPresence"), "user_id"),
        TableDef(os.getenv("DDB_TYPING", "Typing"), "conversation_id", "user_id"),
        TableDef(os.getenv("DDB_MESSAGE_EDITS", "MessageEdits"), "message_key", "edited_at"),
        TableDef(os.getenv("DDB_MESSAGE_VIEWS", "MessageViews"), "conversation_id", "message_user"),
        TableDef(os.getenv("DDB_MESSAGE_RECEIPTS", "MessageReceipts"), "conversation_id", "message_user"),
        TableDef(
            _resolve_table_name(S.message_visibility_overrides_table_name, "MessageVisibilityOverrides"),
            "conversation_id",
            "message_user",
            gsi=[
                {
                    "index_name": "ByConversationUserUpdatedAt",
                    "partition_key": "conversation_user",
                    "sort_key": "updated_at",
                }
            ],
        ),
        TableDef(
            _resolve_table_name(S.conversation_pins_table_name, "ConversationPins"),
            "conversation_id",
            "message_id",
            gsi=[
                {
                    "index_name": "ByConversationActivePinnedAt",
                    "partition_key": "conversation_active",
                    "sort_key": "pinned_at",
                },
                {
                    "index_name": "ByConversationLatestActivePin",
                    "partition_key": "conversation_active",
                    "sort_key": "latest_pin_sort",
                },
            ],
        ),
        TableDef(
            _resolve_table_name(S.mass_message_campaigns_table_name, "MassMessageCampaigns"),
            "campaign_id",
            gsi=[
                {
                    "index_name": "BySenderCreatedAt",
                    "partition_key": "sender_id",
                    "sort_key": "created_at",
                },
                {
                    "index_name": "ByStatusSendAt",
                    "partition_key": "status",
                    "sort_key": "send_at",
                },
            ],
            attr_types={"created_at": "N", "send_at": "N"},
        ),
        TableDef(
            _resolve_table_name(S.mass_message_campaign_destinations_table_name, "MassMessageCampaignDestinations"),
            "campaign_id",
            "conversation_id",
            gsi=[
                {
                    "index_name": "ByCampaignStateUpdatedAt",
                    "partition_key": "campaign_state",
                    "sort_key": "updated_at",
                },
            ],
            attr_types={"updated_at": "N"},
        ),
        TableDef(
            _resolve_table_name(S.message_report_context_table_name, "MessageReportContext"),
            "report_id",
            "message_id",
        ),
        TableDef(
            _resolve_table_name(S.content_reports_table_name, "ContentReports"),
            "report_id",
            gsi=[
                {
                    "index_name": "ByContentCreatedAt",
                    "partition_key": "content_ref",
                    "sort_key": "created_at",
                },
                {
                    "index_name": "ByReporterCreatedAt",
                    "partition_key": "reporter_user_id",
                    "sort_key": "created_at",
                },
                {
                    "index_name": "ByCreatedAt",
                    "partition_key": "created_scope",
                    "sort_key": "created_at",
                },
            ],
        ),
        TableDef(
            _resolve_table_name(S.moderation_tickets_table_name, "ModerationTickets"),
            "ticket_id",
            gsi=[
                {
                    "index_name": "ByStatusLatestReportAt",
                    "partition_key": "status",
                    "sort_key": "latest_report_at",
                },
                {
                    "index_name": "ByQueueLatestReportAt",
                    "partition_key": "queue",
                    "sort_key": "latest_report_at",
                },
                {
                    "index_name": "ByAssignedAdminLatestReportAt",
                    "partition_key": "assigned_admin_user_id",
                    "sort_key": "latest_report_at",
                },
                {
                    "index_name": "ByLatestReportAt",
                    "partition_key": "latest_report_scope",
                    "sort_key": "latest_report_at",
                },
                {
                    "index_name": "ByContentStatusLatestReportAt",
                    "partition_key": "content_ref_status",
                    "sort_key": "latest_report_at",
                },
            ],
        ),
        TableDef(
            _resolve_table_name(S.moderation_actions_table_name, "ModerationActions"),
            "action_id",
            gsi=[
                {
                    "index_name": "ByTicketCreatedAt",
                    "partition_key": "ticket_id",
                    "sort_key": "created_at",
                },
                {
                    "index_name": "ByActionTypeCreatedAt",
                    "partition_key": "action_type",
                    "sort_key": "created_at",
                },
                {
                    "index_name": "ByTargetUserCreatedAt",
                    "partition_key": "target_user_id",
                    "sort_key": "created_at",
                },
            ],
        ),
        TableDef(
            _resolve_table_name(S.moderation_audit_log_table_name, "ModerationAuditLog"),
            "audit_id",
            gsi=[
                {
                    "index_name": "ByTicketCreatedAt",
                    "partition_key": "ticket_id",
                    "sort_key": "created_at",
                },
                {
                    "index_name": "ByActorCreatedAt",
                    "partition_key": "actor_user_id",
                    "sort_key": "created_at",
                },
                {
                    "index_name": "ByActionCreatedAt",
                    "partition_key": "action",
                    "sort_key": "created_at",
                },
            ],
        ),
        TableDef(
            _resolve_table_name(S.moderation_video_queue_table_name, "ModerationVideoQueue"),
            "entry_id",
            gsi=[
                {
                    "index_name": "ByStatusCreatedAt",
                    "partition_key": "status",
                    "sort_key": "created_at",
                },
                {
                    "index_name": "ByStatusPriority",
                    "partition_key": "status",
                    "sort_key": "priority_rank",
                },
                {
                    "index_name": "ByVideo",
                    "partition_key": "video_id",
                },
            ],
            attr_types={"created_at": "N", "priority_rank": "N"},
        ),
        TableDef(
            _resolve_table_name(S.user_enforcement_history_table_name, "UserEnforcementHistory"),
            "user_id",
            "enforcement_id",
            gsi=[
                {
                    "index_name": "ByStatusCreatedAt",
                    "partition_key": "status",
                    "sort_key": "created_at",
                },
                {
                    "index_name": "BySourceTicketCreatedAt",
                    "partition_key": "source_ticket_id",
                    "sort_key": "created_at",
                },
            ],
        ),
        TableDef(
            _resolve_table_name(S.dmca_claims_table_name, "DmcaClaims"),
            "claim_id",
            gsi=[
                {"index_name": "ByStatusCreatedAt", "partition_key": "status", "sort_key": "created_at"},
                {"index_name": "ByTargetUserCreatedAt", "partition_key": "target_user_id", "sort_key": "created_at"},
                {"index_name": "ByClaimantCreatedAt", "partition_key": "claimant_email", "sort_key": "created_at"},
                {"index_name": "ByWaitingPeriodExpiry", "partition_key": "status", "sort_key": "waiting_period_expires_at"},
            ],
            attr_types={"created_at": "N", "waiting_period_expires_at": "N"},
        ),
        TableDef(
            _resolve_table_name(S.appeals_table_name, "Appeals"),
            "appeal_id",
            gsi=[
                {"index_name": "ByStatusCreatedAt", "partition_key": "status", "sort_key": "created_at"},
                {"index_name": "ByUserCreatedAt", "partition_key": "user_id", "sort_key": "created_at"},
                {"index_name": "ByEnforcementId", "partition_key": "enforcement_id", "sort_key": "created_at"},
                {"index_name": "ByAssignedAdminCreatedAt", "partition_key": "assigned_admin_user_id", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        TableDef(
            _resolve_table_name(S.message_archive_chain_heads_table_name, "MessageArchiveChainHeads"),
            "partition_key",
        ),
        TableDef(
            os.getenv("DDB_MESSAGE_CONSUMPTION", "MessageConsumption"),
            "conversation_id",
            "recipient_message",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "GSI2", "partition_key": "recipient_id", "sort_key": "GSI2SK"},
            ],
        ),
        TableDef(os.getenv("DDB_CONVERSATION_ROUTING_EVENTS", "ConversationRoutingEvents"), "conversation_id", "event_id"),
        TableDef(os.getenv("DDB_CONTACTS_TABLE", "Contacts"), "owner_id", "contact_id"),
        # Tickets (composite GSI keys: gsi1pk/gsi1sk=owner, gsi2pk/gsi2sk=status, gsi3pk/gsi3sk=assignee,
        # gsi_space_pk/sk=space, gsi_space_status_pk/sk=space+status, gsi_space_assignee_pk/sk=space+assignee,
        # gsi_member_pk/sk=member spaces)
        TableDef(
            _resolve_table_name(S.tickets_table_name, "tickets"),
            "pk",
            "sk",
            gsi=[
                {"index_name": S.tickets_owner_index_name, "partition_key": "gsi1pk", "sort_key": "gsi1sk"},
                {"index_name": S.tickets_status_index_name, "partition_key": "gsi2pk", "sort_key": "gsi2sk"},
                {"index_name": S.tickets_assignee_index_name, "partition_key": "gsi3pk", "sort_key": "gsi3sk"},
                {"index_name": S.tickets_space_index_name, "partition_key": "gsi_space_pk", "sort_key": "gsi_space_sk"},
                {"index_name": S.tickets_space_status_index_name, "partition_key": "gsi_space_status_pk", "sort_key": "gsi_space_status_sk"},
                {"index_name": S.tickets_space_assignee_index_name, "partition_key": "gsi_space_assignee_pk", "sort_key": "gsi_space_assignee_sk"},
                {"index_name": S.tickets_member_spaces_index_name, "partition_key": "gsi_member_pk", "sort_key": "gsi_member_sk"},
                {"index_name": S.tickets_jira_workspace_index_name, "partition_key": "gsi_jira_workspace_pk", "sort_key": "gsi_jira_workspace_sk"},
                {"index_name": S.tickets_jira_issue_index_name, "partition_key": "gsi_jira_issue_pk", "sort_key": "gsi_jira_issue_sk"},
                {"index_name": S.tickets_jira_sync_state_index_name, "partition_key": "gsi_jira_sync_state_pk", "sort_key": "gsi_jira_sync_state_sk"},
            ],
        ),
        # Broadcast tables
        TableDef(
            _resolve_table_name(S.broadcast_profiles_table_name, "BroadcastProfiles"),
            "profile_id",
        ),
        TableDef(
            _resolve_table_name(S.broadcast_promo_posts_table_name, "BroadcastPromoPosts"),
            "broadcast_id",
        ),
        TableDef(
            _resolve_table_name(S.broadcast_sessions_table_name, "BroadcastSessions"),
            "session_id",
            gsi=[
                {"index_name": "ByStatusCreatedAt", "partition_key": "status", "sort_key": "created_at"},
                {"index_name": "ByCreatorCreatedAt", "partition_key": "created_by", "sort_key": "created_at"},
                {"index_name": "ByScheduledAt", "partition_key": "schedule_status", "sort_key": "scheduled_at"},
            ],
            attr_types={"scheduled_at": "N"},
        ),
        TableDef(
            _resolve_table_name(S.broadcast_outputs_table_name, "BroadcastOutputs"),
            "session_id",
            "scope",
        ),
        TableDef(
            _resolve_table_name(S.broadcast_session_transitions_table_name, "BroadcastSessionTransitions"),
            "transition_id",
            "session_id",
        ),
        TableDef(
            _resolve_table_name(S.broadcast_action_audit_table_name, "BroadcastActionAudit"),
            "audit_id",
            gsi=[
                {"index_name": "ByActorCreatedAt", "partition_key": "actor", "sort_key": "created_at"},
                {"index_name": "ByCreatedAt", "partition_key": "scope", "sort_key": "created_at"},
            ],
        ),
        TableDef(
            _resolve_table_name(S.broadcast_viewers_table_name, "BroadcastViewers"),
            "session_id",
            "viewer_id",
        ),
        TableDef(
            _resolve_table_name(S.broadcast_health_snapshots_table_name, "BroadcastHealthSnapshots"),
            "session_id",
            "snapshot_ts",
            attr_types={"snapshot_ts": "N"},
        ),
        # Broadcast chat (BCAST-005)
        TableDef(
            _resolve_table_name(S.broadcast_chat_messages_table_name, "BroadcastChatMessages"),
            "session_id",
            "sort_key",
        ),
        TableDef(
            _resolve_table_name(S.broadcast_chat_mutes_table_name, "BroadcastChatMutes"),
            "session_user",
        ),
        # Broadcast recordings (BCAST-006)
        TableDef(
            _resolve_table_name(S.broadcast_recordings_table_name, "BroadcastRecordings"),
            "recording_id",
            gsi=[
                {"index_name": "BySessionId", "partition_key": "session_id", "sort_key": "created_at"},
                {"index_name": "ByStatusCreatedAt", "partition_key": "status", "sort_key": "created_at"},
                {"index_name": "ByExpiresAt", "partition_key": "scope", "sort_key": "expires_at"},
            ],
            attr_types={"created_at": "N", "expires_at": "N"},
        ),
        # Broadcast product shelf (LCOM-001)
        TableDef(
            _resolve_table_name(S.broadcast_product_shelf_table_name, "BroadcastProductShelf"),
            "session_id",
            "SK",
        ),
        # VOD Entitlements (MON-001): tracks video purchases / access grants
        TableDef(
            _resolve_table_name(S.vod_entitlements_table_name, "VodEntitlements"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByVideoCreatedAt", "partition_key": "video_id", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # VOD Rentals (VOD-019): time-limited rental + view-once access grants.
        # pk=USER#{buyer} sk=VIDEO#{video_id}; GSI ByVideoExpiresAt for owner history.
        TableDef(
            _resolve_table_name(S.vod_rentals_table_name, "VodRentals"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByVideoExpiresAt", "partition_key": "video_id", "sort_key": "expires_at"},
            ],
            attr_types={"expires_at": "N"},
        ),
        # Messaging extended tables (from PR 127 compliance/visibility features)
        # ConversationPins: pk=(conversation_id, message_id), GSI ByConversationActivePinnedAt
        TableDef(
            _resolve_table_name(S.conversation_pins_table_name, "ConversationPins"),
            "conversation_id", "message_id",
            gsi=[{"index_name": "ByConversationActivePinnedAt", "partition_key": "conversation_active", "sort_key": "latest_pin_sort"}],
        ),
        # MessageVisibilityOverrides: pk=(conversation_id, message_user), GSI ByConversationUserUpdatedAt
        TableDef(
            _resolve_table_name(S.message_visibility_overrides_table_name, "MessageVisibilityOverrides"),
            "conversation_id", "message_user",
            gsi=[{"index_name": "ByConversationUserUpdatedAt", "partition_key": "conversation_user", "sort_key": "updated_at"}],
            attr_types={"updated_at": "N"},
        ),
        # MessageReports: pk=report_id, GSIs ByConversationCreatedAt + ByStatusCreatedAt + ByReporterCreatedAt
        TableDef(
            _resolve_table_name(S.message_reports_table_name, "MessageReports"),
            "report_id",
            gsi=[
                {"index_name": "ByConversationCreatedAt", "partition_key": "conversation_id", "sort_key": "created_at"},
                {"index_name": "ByStatusCreatedAt", "partition_key": "status", "sort_key": "created_at"},
                {"index_name": "ByReporterCreatedAt", "partition_key": "reported_by_user_id", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # MessageReportContext: pk=(report_id, message_id)
        TableDef(_resolve_table_name(S.message_report_context_table_name, "MessageReportContext"), "report_id", "message_id"),
        # MessageThreads: pk=id, GSIs ByConversationCreatedAt + ByRootMessage
        TableDef(
            _resolve_table_name(S.message_threads_table_name, "MessageThreads"),
            THREAD_FIELD_ID,
            gsi=[
                {"index_name": INDEX_BY_CONVERSATION_CREATED_AT, "partition_key": THREAD_FIELD_CONVERSATION_ID, "sort_key": THREAD_FIELD_CREATED_AT},
                {"index_name": INDEX_BY_ROOT_MESSAGE, "partition_key": THREAD_FIELD_ROOT_MESSAGE_ID},
            ],
            attr_types={THREAD_FIELD_CREATED_AT: "N"},
        ),
        # MessageCallSessions: pk=call_id, GSIs by conversation + participant
        TableDef(
            _resolve_table_name(S.message_call_sessions_table_name, "MessageCallSessions"),
            "call_id",
            gsi=[
                {"index_name": "ByConversationStartedAt", "partition_key": "conversation_id", "sort_key": "start_ts_sort"},
                {"index_name": "ByCallerStartedAt", "partition_key": "caller_user_id", "sort_key": "start_ts_sort"},
                {"index_name": "ByCalleeStartedAt", "partition_key": "callee_user_id", "sort_key": "start_ts_sort"},
            ],
            attr_types={"start_ts_sort": "N"},
        ),
        # CallRecordings: pk=recording_id, GSIs ByCallId + ByConversation + ByStatus (CALL-009)
        TableDef(
            _resolve_table_name(S.call_recordings_table_name, "CallRecordings"),
            "recording_id",
            gsi=[
                {"index_name": "ByCallIdCreatedAt", "partition_key": "call_id", "sort_key": "created_at"},
                {"index_name": "ByConversationCreatedAt", "partition_key": "conversation_id", "sort_key": "created_at"},
                {"index_name": "ByStatus", "partition_key": "status", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # CallBillingLedger: pk=call_id, sk=entry_id, GSIs ByCallerCreatedAt + ByCreatorCreatedAt (CALL-011)
        TableDef(
            _resolve_table_name(S.call_billing_ledger_table_name, "CallBillingLedger"),
            "call_id",
            "entry_id",
            gsi=[
                {"index_name": "ByCallerCreatedAt", "partition_key": "caller_user_id", "sort_key": "created_at"},
                {"index_name": "ByCreatorCreatedAt", "partition_key": "creator_user_id", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # MessageLegalHolds: pk=hold_id, GSIs ByConversationStatusCreatedAt + ByStatusCreatedAt
        TableDef(
            _resolve_table_name(S.message_legal_holds_table_name, "MessageLegalHolds"),
            "hold_id",
            gsi=[
                {"index_name": "ByConversationStatusCreatedAt", "partition_key": "conversation_status", "sort_key": "created_at"},
                {"index_name": "ByStatusCreatedAt", "partition_key": "status", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # LotteryMessageConfig: pk=message_id
        TableDef(os.getenv("DDB_LOTTERY_MESSAGE_CONFIG", "LotteryMessageConfig"), "message_id"),
        # LotteryMessageUnlocks: pk=message_id, sk=recipient_id
        TableDef(os.getenv("DDB_LOTTERY_MESSAGE_UNLOCKS", "LotteryMessageUnlocks"), "message_id", "recipient_id"),
        # MessageDrafts: pk=owner_user_id, sk=draft_id, GSI ByConversationUpdatedAt
        TableDef(
            os.getenv("DDB_MESSAGE_DRAFTS", "MessageDrafts"),
            "owner_user_id",
            "draft_id",
            gsi=[
                {"index_name": "ByConversationUpdatedAt", "partition_key": "conversation_owner_key", "sort_key": "updated_at"},
            ],
            attr_types={"updated_at": "N"},
        ),
        # MessageArchiveChainHeads: pk=conversation_id
        TableDef(_resolve_table_name(S.message_archive_chain_heads_table_name, "MessageArchiveChainHeads"), "conversation_id"),
        # MessageComplianceExports: pk=export_id, GSIs ByCaseCreatedAt + ByStatusCreatedAt
        TableDef(
            _resolve_table_name(S.message_compliance_exports_table_name, "MessageComplianceExports"),
            "export_id",
            gsi=[
                {"index_name": "ByCaseCreatedAt", "partition_key": "case_id", "sort_key": "created_at"},
                {"index_name": "ByStatusCreatedAt", "partition_key": "status", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # SFTP mounts: pk=PK, sk=SK
        TableDef(os.getenv("FILEMGR_SFTP_MOUNTS_TABLE_NAME", "filemgr_sftp_mounts"), "PK", "SK"),
        # Calendar integration tables (Apple CalDAV / Google)
        TableDef(os.getenv("CALENDAR_CONNECTIONS_TABLE_NAME", "calendar_connections"), "connection_id"),
        TableDef(os.getenv("CALENDAR_CONNECTION_SECRETS_TABLE_NAME", "calendar_connection_secrets"), "credential_ref"),
        TableDef(os.getenv("EXTERNAL_CALENDARS_TABLE_NAME", "external_calendars"), "external_calendar_id"),
        TableDef(os.getenv("CALENDAR_SYNC_RUNS_TABLE_NAME", "calendar_sync_runs"), "run_id"),
        TableDef(os.getenv("EXTERNAL_EVENT_LINKS_TABLE_NAME", "external_event_links"), "connection_uid_key"),
        # Video metadata (VOD-001)
        TableDef(
            _resolve_table_name(S.video_metadata_table_name, "VideoMetadata"),
            "video_id",
            gsi=[
                {
                    "index_name": "ByOwnerCreatedAt",
                    "partition_key": "owner_user_id",
                    "sort_key": "created_at",
                },
                {
                    "index_name": "ByStatusCreatedAt",
                    "partition_key": "status",
                    "sort_key": "created_at",
                },
                {
                    "index_name": "BySourceBroadcast",
                    "partition_key": "source_broadcast_session_id",
                },
                {
                    "index_name": "ByCategory",
                    "partition_key": "category",
                    "sort_key": "trending_score_sort",
                },
                {
                    "index_name": "ByGalleryPublished",
                    "partition_key": "gallery_status",
                    "sort_key": "published_at",
                },
            ],
            attr_types={"created_at": "N", "trending_score_sort": "N", "published_at": "N"},
        ),
        # Transcode jobs (VOD-003)
        TableDef(
            _resolve_table_name(S.transcode_jobs_table_name, "TranscodeJobs"),
            "job_id",
            gsi=[
                {
                    "index_name": "ByStatusCreatedAt",
                    "partition_key": "status",
                    "sort_key": "created_at",
                },
                {
                    "index_name": "ByVideoId",
                    "partition_key": "video_id",
                    "sort_key": "created_at",
                },
                {
                    "index_name": "ByTenantStatus",
                    "partition_key": "tenant_id",
                    "sort_key": "status_created_at",
                },
            ],
            attr_types={"created_at": "N"},
        ),
        # Creator Payouts (MON-004)
        TableDef(
            _resolve_table_name(S.creator_payouts_table_name, "CreatorPayouts"),
            "payout_id",
            gsi=[
                {"index_name": "ByUserCreatedAt", "partition_key": "user_id", "sort_key": "created_at"},
                {"index_name": "ByStatusCreatedAt", "partition_key": "status", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # Bulk Payout & Refund Tools (FIN-017)
        TableDef(
            _resolve_table_name(S.bulk_payout_batches_table_name, "BulkPayoutBatches"),
            "batch_id",
            gsi=[
                {"index_name": "gsi_all-created_at-index", "partition_key": "gsi_all", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # Broadcast Reminders (BCAST-009)
        TableDef(
            os.environ.get("DDB_BROADCAST_REMINDERS", "BroadcastReminders"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByRemindAt", "partition_key": "remind_status", "sort_key": "remind_at"},
            ],
            attr_types={"remind_at": "N"},
        ),
        # Broadcast Inputs (BCAST-016)
        TableDef(
            _resolve_table_name(S.broadcast_inputs_table_name, "BroadcastInputs"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByCreator", "partition_key": "created_by", "sort_key": "created_at"},
                {"index_name": "ByStatus", "partition_key": "invite_status", "sort_key": "expires_at"},
            ],
            attr_types={"expires_at": "N"},
        ),
        # Broadcast Tip Goals (BCAST-013)
        TableDef(
            _resolve_table_name(S.broadcast_tip_goals_table_name, "BroadcastTipGoals"),
            "session_id",
            "goal_id",
        ),
        # Broadcast Ad Events (ADS-006) — pre-roll/mid-roll impression/skip/complete/click tracking
        TableDef(
            _resolve_table_name(S.broadcast_ad_events_table_name, "BroadcastAdEvents"),
            "session_id",
            "event_sk",
            gsi=[
                {"index_name": "BySessionCreatedAt", "partition_key": "session_id", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # Broadcast Private Sessions (BCAST-011/012)
        TableDef(
            os.environ.get("DDB_BROADCAST_PRIVATE_SESSIONS", "BroadcastPrivateSessions"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "BySessionCreatedAt", "partition_key": "session_id", "sort_key": "created_at"},
                {"index_name": "ByUserCreatedAt", "partition_key": "user_id", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # Broadcast Go-Private Allowlist / Invite Tokens (BCAST-011)
        TableDef(
            os.environ.get("DDB_BROADCAST_ALLOWLIST", "BroadcastAllowlist"),
            "pk",
            "sk",
        ),
        # Video Views (VOD-017)
        TableDef(
            os.environ.get("DDB_VIDEO_VIEWS", "VideoViews"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByVideoViewedAt", "partition_key": "video_id", "sort_key": "viewed_at"},
            ],
            attr_types={"viewed_at": "N"},
        ),
        # Video Likes (VOD-017)
        TableDef(
            os.environ.get("DDB_VIDEO_LIKES", "VideoLikes"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByVideoLikedAt", "partition_key": "video_id", "sort_key": "liked_at"},
                {"index_name": "ByUserLikedAt", "partition_key": "user_id", "sort_key": "liked_at"},
            ],
            attr_types={"liked_at": "N"},
        ),
        # Ad Impressions (VOD-018)
        TableDef(
            os.environ.get("DDB_AD_IMPRESSIONS", "AdImpressions"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByVideoCreatedAt", "partition_key": "video_id", "sort_key": "created_at"},
                {"index_name": "ByCreatorCreatedAt", "partition_key": "creator_id", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # VOD-018: ad-supported viewing sessions (pk = USER#{viewer}, sk = VIDEO#{video_id})
        TableDef(
            os.environ.get("DDB_VOD_AD_SESSIONS", "VodAdSessions"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByVideo", "partition_key": "video_id", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # Advertiser Accounts (ADS-001)
        TableDef(
            _resolve_table_name(S.ad_accounts_table_name, "AdAccounts"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByOwner", "partition_key": "owner_sub", "sort_key": "created_at"},
                {"index_name": "ByStatus", "partition_key": "status", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # Ad Campaigns (ADS-001)
        TableDef(
            _resolve_table_name(S.ad_campaigns_table_name, "AdCampaigns"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByStatusCreatedAt", "partition_key": "status", "sort_key": "created_at"},
                {"index_name": "ByCampaignId", "partition_key": "campaign_id", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        TableDef(
            _resolve_table_name(S.content_boosts_table_name, "content_boosts"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
            ],
            attr_types={"GSI1SK": "N", "GSI2SK": "N"},
        ),
        # Ad Creatives (ADS-002)
        TableDef(
            _resolve_table_name(S.ad_creatives_table_name, "AdCreatives"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByStatus", "partition_key": "status", "sort_key": "created_at"},
                {"index_name": "ByFormat", "partition_key": "format", "sort_key": "created_at"},
                {"index_name": "ByCreativeId", "partition_key": "creative_id", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # Admin Ad Platform Moderation Log (ADS-018)
        TableDef(
            _resolve_table_name(S.ad_moderation_log_table_name, "AdModerationLog"),
            "pk",
            "sk",
            gsi=[],
        ),
        # Ad Targeting (ADS-003)
        TableDef(
            os.environ.get("DDB_AD_TARGETING", "AdTargeting"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByCampaignCreatedAt", "partition_key": "campaign_id", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # Ad Frequency Caps (ADS-004)
        TableDef(
            os.environ.get("DDB_AD_FREQUENCY_CAPS", "AdFrequencyCaps"),
            "pk",
            "sk",
        ),
        # Ad Billing (ADS-007)
        TableDef(
            _resolve_table_name(S.ad_billing_table_name, "AdBilling"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByCampaign", "partition_key": "campaign_id", "sort_key": "created_at"},
                {"index_name": "ByMonth", "partition_key": "month_key", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # Content-Provider Ad Controls (ADS-010) — per-content ad overrides
        TableDef(
            _resolve_table_name(
                getattr(S, "content_ad_controls_table_name", "ContentAdControls"),
                "ContentAdControls",
            ),
            "content_id",
            gsi=[{"index_name": "ByOwner", "partition_key": "owner_sub"}],
        ),
        # Ad Analytics Rollups (ADS-008)
        TableDef(
            os.environ.get("DDB_AD_ANALYTICS_ROLLUPS", "AdAnalyticsRollups"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByAccountDate", "partition_key": "account_id", "sort_key": "date"},
            ],
        ),
        # Ad Optimization Recommendations (ADS-017)
        TableDef(
            _resolve_table_name(
                S.ad_optimization_recommendations_table_name,
                "AdOptimizationRecommendations",
            ),
            "pk",
            "sk",
            gsi=[
                {
                    "index_name": "ByCampaignCreatedAt",
                    "partition_key": "campaign_id",
                    "sort_key": "created_at",
                },
            ],
            attr_types={"created_at": "N"},
        ),
        # Ad Fraud Events (ADS-014)
        TableDef(
            _resolve_table_name(S.ad_fraud_events_table_name, "AdFraudEvents"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},  # by account
                {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},  # by campaign
            ],
            attr_types={"GSI1SK": "N", "GSI2SK": "N"},
        ),
        # Rate limiting (PLATFORM-001)
        TableDef(
            _resolve_table_name(S.rate_limits_table_name, "rate_limits"),
            "pk",
            "sk",
        ),
        TableDef(
            _resolve_table_name(S.rate_limit_events_table_name, "rate_limit_events"),
            "pk",
            "sk",
        ),
        # Analytics Rollups (ANALYTICS-001)
        TableDef(
            os.environ.get("DDB_ANALYTICS_ROLLUPS", "AnalyticsRollups"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByDateCreatedAt", "partition_key": "date_scope", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # Privacy / GDPR (PRIVACY-001)
        TableDef(
            _resolve_table_name(S.data_requests_table_name, "data_requests"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByStatus", "partition_key": "status", "sort_key": "created_at"},
                {"index_name": "ByType", "partition_key": "request_type", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        TableDef(
            _resolve_table_name(S.data_request_audit_table_name, "data_request_audit"),
            "pk",
            "sk",
        ),
        # Account Deletion (PLATFORM-018)
        TableDef(
            _resolve_table_name(S.account_deletion_requests_table_name, "account_deletion_requests"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByStatusScheduled", "partition_key": "status", "sort_key": "scheduled_for"},
            ],
            attr_types={"scheduled_for": "N"},
        ),
        # Webhooks (PLATFORM-002)
        TableDef(
            _resolve_table_name(S.webhook_endpoints_table_name, "webhook_endpoints"),
            "pk",
            "sk",
        ),
        TableDef(
            _resolve_table_name(S.webhook_deliveries_table_name, "webhook_deliveries"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByStatus", "partition_key": "status", "sort_key": "next_retry_at"},
                {"index_name": "ByUser", "partition_key": "user_sub", "sort_key": "created_at"},
            ],
            attr_types={"next_retry_at": "N", "created_at": "N"},
        ),
        # Webhook Stats (ENTERPRISE-005)
        TableDef(
            _resolve_table_name(S.webhooks_stats_table_name, "webhook_stats"),
            "pk",
            "sk",
        ),
        # Promo Codes & Coupons (PROMO-001)
        TableDef(
            _resolve_table_name(S.promo_codes_table_name, "PromoCodes"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByCreatorCreatedAt", "partition_key": "creator_scope", "sort_key": "created_at"},
                {"index_name": "ByCodeString", "partition_key": "code_lookup_pk", "sort_key": "code_lookup_sk"},
            ],
            attr_types={"created_at": "N"},
        ),
        # Unified Content Scheduling (SCHED-001)
        TableDef(
            _resolve_table_name(S.scheduled_actions_table_name, "scheduled_actions"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByDue", "partition_key": "GSI_DUE_PK", "sort_key": "GSI_DUE_SK"},
                {"index_name": "ByType", "partition_key": "GSI_TYPE_PK", "sort_key": "GSI_TYPE_SK"},
            ],
            attr_types={"GSI_DUE_SK": "N", "GSI_TYPE_SK": "N"},
        ),
        # Watermark Jobs (VOD-020)
        TableDef(
            _resolve_table_name(S.watermark_jobs_table_name, "watermark_jobs"),
            "job_id",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
            ],
            attr_types={"GSI1SK": "N"},
        ),
        # Per-viewer Watermarked Download renders (VOD-020 — distinct pipeline)
        TableDef(
            _resolve_table_name(S.vod_watermark_downloads_table_name, "vod_watermark_downloads"),
            "render_id",
            gsi=[
                {"index_name": "ByViewerVideo", "partition_key": "viewer_video_key", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # Content Recommendations (DISC-001)
        TableDef(
            _resolve_table_name(S.recommendations_table_name, "recommendations"),
            "pk",
            "sk",
        ),
        # Internationalization (PLATFORM-003)
        TableDef(
            _resolve_table_name(S.translations_table_name, "translations"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByStatus", "partition_key": "status", "sort_key": "pk"},
            ],
        ),
        # Refund Requests (BILLING-001)
        TableDef(
            _resolve_table_name(S.refund_requests_table_name, "RefundRequests"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByStatusCreatedAt", "partition_key": "status_scope", "sort_key": "created_at"},
                {"index_name": "ByRequesterCreatedAt", "partition_key": "requester_scope", "sort_key": "created_at"},
                {"index_name": "ByTransactionId", "partition_key": "transaction_entry_id"},
            ],
            attr_types={"created_at": "N"},
        ),
        # Billing Disputes / Chargebacks (BILLING-001)
        TableDef(
            _resolve_table_name(S.billing_disputes_table_name, "BillingDisputes"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByStatusCreatedAt", "partition_key": "status_scope", "sort_key": "created_at"},
                {"index_name": "ByProviderCreatedAt", "partition_key": "provider_scope", "sort_key": "created_at"},
                {"index_name": "ByUserCreatedAt", "partition_key": "user_scope", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # GroupCallSessions: pk=pk, sk=sk, GSIs ByConversationCreatedAt + ByStateCreatedAt (CALL-012)
        TableDef(
            _resolve_table_name(S.group_call_sessions_table_name, "GroupCallSessions"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByConversationCreatedAt", "partition_key": "conversation_id", "sort_key": "created_at"},
                {"index_name": "ByStateCreatedAt", "partition_key": "state", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # SmsDelivery: pk=pk, sk=sk, GSI ByStatus, TTL ttl_epoch
        TableDef(
            _resolve_table_name(S.sms_delivery_table_name, "SmsDelivery"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByStatus", "partition_key": "status", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # EmailDelivery: pk=pk, sk=sk, GSI ByStatus, TTL ttl_epoch
        TableDef(
            _resolve_table_name(S.email_delivery_table_name, "EmailDelivery"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByStatus", "partition_key": "status", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # AdminMessagingTemplates (ADMIN-002): notification templates, pk=pk, sk=sk
        TableDef(
            _resolve_table_name(S.admin_messaging_templates_table_name, "admin_messaging_templates"),
            "pk",
            "sk",
        ),
        # Affiliate Links (CREATOR-004)
        TableDef(
            _resolve_table_name(S.affiliate_links_table_name, "AffiliateLinks"),
            "link_id",
            gsi=[
                {"index_name": "ByAffiliate", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "ByCode", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
                {"index_name": "ByProduct", "partition_key": "GSI3PK", "sort_key": "GSI3SK"},
            ],
            attr_types={"GSI1SK": "N", "GSI3SK": "N"},
        ),
        # Affiliate Clicks (CREATOR-004)
        TableDef(
            _resolve_table_name(S.affiliate_clicks_table_name, "AffiliateClicks"),
            "link_id",
            "click_id",
            gsi=[
                {"index_name": "ByVisitor", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
            ],
            attr_types={"GSI1SK": "N"},
        ),
        # Achievements & Gamification (ENGAGE-001)
        TableDef(
            _resolve_table_name(S.achievements_table_name, "achievements"),
            "achievement_id",
            gsi=[
                {"index_name": "ByMetric", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
            ],
            attr_types={"GSI1SK": "N"},
        ),
        TableDef(
            _resolve_table_name(S.user_achievements_table_name, "user_achievements"),
            "user_sub",
            "achievement_id",
            gsi=[
                {"index_name": "ByLeaderboard", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "ByDisplay", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
            ],
            attr_types={"GSI2SK": "N"},
        ),
        TableDef(
            _resolve_table_name(S.user_achievement_progress_table_name, "user_achievement_progress"),
            "user_sub",
            "metric_key",
        ),
        TableDef(
            _resolve_table_name(S.achievement_leaderboard_table_name, "achievement_leaderboard"),
            "period_key",
            "user_sub",
            gsi=[
                {"index_name": "ByPoints", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
            ],
            attr_types={"GSI1SK": "N"},
        ),
        # Audit Log Export (ENTERPRISE-004)
        TableDef(
            _resolve_table_name(S.audit_export_table_name, "AuditExports"),
            "export_id",
            "sk",
            gsi=[
                {"index_name": "status-created-index", "partition_key": "status", "sort_key": "created_at"},
                {"index_name": "user-created-index", "partition_key": "created_by", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # Broadcast Q&A Questions (ENGAGE-003)
        TableDef(
            _resolve_table_name(S.broadcast_qa_questions_table_name, "broadcast_qa_questions"),
            "session_id",
            "question_id",
            gsi=[
                {"index_name": "BySessionStatus", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
            ],
        ),
        # Live Q&A Mode questions (ENGAGE-003 — distinct implementation)
        TableDef(
            _resolve_table_name(S.live_qa_questions_table_name, "live_qa_questions"),
            "session_id",
            "question_id",
            gsi=[
                {"index_name": "ByStatusVotes", "partition_key": "gsi_status_pk", "sort_key": "gsi_votes_sk"},
            ],
        ),
        # Collaboration Requests (CREATOR-001) + Revenue Splitting (FIN-011)
        TableDef(
            _resolve_table_name(S.collaboration_agreements_table_name, "collaboration_agreements"),
            "collaboration_id",
            "sk",
            gsi=[
                {"index_name": "ByInitiator", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "ByRecipient", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
                {"index_name": "ByStatus", "partition_key": "GSI3PK", "sort_key": "GSI3SK"},
                {"index_name": "ByContentId", "partition_key": "gsi_content_pk", "sort_key": "gsi_content_sk"},
                {"index_name": "ByDisputeStatus", "partition_key": "gsi_dispute_pk", "sort_key": "gsi_dispute_sk"},
            ],
            attr_types={
                "GSI1SK": "N", "GSI2SK": "N", "GSI3SK": "N",
                "gsi_dispute_sk": "N",
            },
        ),
        # Fan Club Channels (CREATOR-002)
        TableDef(
            _resolve_table_name(S.fan_club_channels_table_name, "fan_club_channels"),
            "channel_id",
            gsi=[
                {"index_name": "ByCreator", "partition_key": "creator_id", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # Fan Club Messages (CREATOR-002)
        TableDef(
            _resolve_table_name(S.fan_club_messages_table_name, "fan_club_messages"),
            "channel_id",
            "sort_key",
        ),
        # Organizations / Workspaces (ENTERPRISE-003)
        TableDef(
            _resolve_table_name(S.organizations_table_name, "organizations"),
            "org_id",
            "sk",
            gsi=[
                {"index_name": "user-orgs-index", "partition_key": "user_sub", "sort_key": "org_id"},
                {"index_name": "invite-email-index", "partition_key": "email", "sort_key": "org_id"},
                {"index_name": "slug-index", "partition_key": "slug", "sort_key": "org_id"},
            ],
        ),
        # User Groups (GROUP-001 / GROUP-002)
        TableDef(
            _resolve_table_name(S.ddb_user_groups_table, "user_groups"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
            ],
            attr_types={"GSI1SK": "N", "GSI2SK": "N"},
        ),
        # Group Advertising & Fundraising (GROUP-003)
        TableDef(
            _resolve_table_name(S.group_fundraising_campaigns_table_name, "group_fundraising_campaigns"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByGroupCreated", "partition_key": "group_id", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # Watch Parties (ENGAGE-004)
        TableDef(
            _resolve_table_name(S.watch_parties_table_name, "watch_parties"),
            "party_id",
            gsi=[
                {"index_name": "ByHost", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "ByInvite", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
            ],
            attr_types={"GSI1SK": "N"},
        ),
        TableDef(
            _resolve_table_name(S.watch_party_participants_table_name, "watch_party_participants"),
            "party_id",
            "user_sub",
        ),
        # Broadcast Clips (ENGAGE-005)
        TableDef(
            _resolve_table_name(S.broadcast_clips_table_name, "broadcast_clips"),
            "clip_id",
            gsi=[
                {"index_name": "BySession", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "ByCreator", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
                {"index_name": "ByGallery", "partition_key": "GSI3PK", "sort_key": "GSI3SK"},
            ],
            attr_types={"GSI1SK": "N", "GSI2SK": "N"},
        ),
        # Multi-Tenancy (ENTERPRISE-001)
        TableDef(
            _resolve_table_name(S.tenants_table_name, "tenants"),
            "tenant_id",
        ),
        TableDef(
            _resolve_table_name(S.tenant_domains_table_name, "tenant_domains"),
            "domain",
            "sk",
        ),
        TableDef(
            _resolve_table_name(S.tenant_members_table_name, "tenant_members"),
            "tenant_id",
            "user_sub",
            gsi=[
                {"index_name": "user-tenant-index", "partition_key": "user_sub", "sort_key": "tenant_id"},
            ],
        ),
        # Chat Bots (BOT-001)
        TableDef(
            _resolve_table_name(S.chat_bots_table_name, "chat_bots"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
            ],
            # GSI1SK holds string sort keys (META / BOT#... / RULE#...); created_at/updated_at
            # are non-key attributes and must NOT be declared in AttributeDefinitions.
        ),
        # Bot Assignments (BOT-001)
        TableDef(
            _resolve_table_name(S.bot_assignments_table_name, "bot_assignments"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
            ],
            # GSI1SK holds a string sort key (BOT#...); created_at is a non-key attribute.
        ),
        # Bot Templates (BOT-002)
        TableDef(
            _resolve_table_name(S.bot_templates_table_name, "bot_templates"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
            ],
            # Only GSI1SK is a key attribute (numeric timestamp); the rest are non-key.
            attr_types={"GSI1SK": "N"},
        ),
        # Bot Scheduled Sends (BOT-002)
        TableDef(
            _resolve_table_name(S.bot_scheduled_sends_table_name, "bot_scheduled_sends"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
            ],
            # Only GSI1SK is a key attribute (numeric next_run); the rest are non-key.
            attr_types={"GSI1SK": "N"},
        ),
        # SSO / SAML (ENTERPRISE-002)
        TableDef(
            _resolve_table_name(S.sso_providers_table_name, "sso_providers"),
            "tenant_id",
            "sk",
            gsi=[
                {"index_name": "provider-id-index", "partition_key": "provider_id", "sort_key": "tenant_id"},
            ],
        ),
        TableDef(
            _resolve_table_name(S.sso_sessions_table_name, "sso_sessions"),
            "session_id",
            "sk",
        ),
        TableDef(
            _resolve_table_name(S.sso_assertion_cache_table_name, "sso_assertion_cache"),
            "assertion_id",
        ),
        # LLM Provider Keys (AGENT-001)
        TableDef(
            _resolve_table_name(S.llm_provider_keys_table_name, "llm_provider_keys"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByProvider", "partition_key": "pk", "sort_key": "provider"},
                {"index_name": "ByCreatedAt", "partition_key": "pk", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # Delegates (DELEGATE-001 .. DELEGATE-003)
        TableDef(
            _resolve_table_name(S.delegates_table_name, "delegates"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
            ],
            attr_types={"GSI1SK": "N", "GSI2SK": "N"},
        ),
        # Delegation API keys (DELEGATE-005)
        TableDef(
            _resolve_table_name(S.delegation_api_keys_table_name, "delegation_api_keys"),
            "key_id",
            gsi=[
                {"index_name": "ByOwner", "partition_key": "GSI_OWNER_PK", "sort_key": "GSI_OWNER_SK"},
                {"index_name": "ByDelegationCreator", "partition_key": "GSI_CREATOR_PK", "sort_key": "GSI_CREATOR_SK"},
            ],
            attr_types={"GSI_OWNER_SK": "N", "GSI_CREATOR_SK": "N"},
        ),
        # Syndicates (SYND-001 / SYND-002)
        TableDef(
            _resolve_table_name(S.syndicates_table_name, "syndicates"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
            ],
            attr_types={"GSI1SK": "N", "GSI2SK": "N"},
        ),
        # Syndicate Revenue Splitting (SYND-003)
        TableDef(
            _resolve_table_name(S.syndicate_revenue_split_table_name, "syndicate_revenue_split"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
            ],
            attr_types={"GSI1SK": "N"},
        ),
        # Syndicate Treasury / Fund Management (SYND-004)
        TableDef(
            _resolve_table_name(S.syndicate_treasury_table_name, "syndicate_treasury"),
            "pk",
            "sk",
        ),
        # Syndicate Page & Newsfeed (SYND-005)
        TableDef(
            _resolve_table_name(S.syndicate_posts_table_name, "syndicate_posts"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSSYND", "partition_key": "GSSYND_PK", "sort_key": "GSSYND_SK"},
            ],
            attr_types={"GSSYND_SK": "N"},
        ),
        # Syndicate Advertising (SYND-006)
        TableDef(
            _resolve_table_name(S.syndicate_ad_campaigns_table_name, "syndicate_ad_campaigns"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
            ],
            attr_types={"GSI1SK": "N"},
        ),
        # Syndicate Open Licensing (LICENSE-005)
        TableDef(
            _resolve_table_name(S.syndicate_open_licensing_table_name, "syndicate_open_licensing"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
            ],
            attr_types={"GSI1SK": "N"},
        ),
        # Issued Licenses (LICENSE-002) + License Requests (LICENSE-004)
        TableDef(
            _resolve_table_name(S.issued_licenses_table_name, "issued_licenses"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
                {"index_name": "GSI3", "partition_key": "GSI3PK", "sort_key": "GSI3SK"},
                {"index_name": "GSI4", "partition_key": "GSI4PK", "sort_key": "GSI4SK"},
            ],
            attr_types={"GSI1SK": "N", "GSI2SK": "N", "GSI3SK": "N", "GSI4SK": "N"},
        ),
        # License Agreements (LICENSE-001)
        TableDef(
            _resolve_table_name(S.license_agreements_table_name, "license_agreements"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
                {"index_name": "GSI3", "partition_key": "GSI3PK", "sort_key": "GSI3SK"},
            ],
            attr_types={"GSI1SK": "N", "GSI2SK": "N", "GSI3SK": "N"},
        ),
        # License Compliance Verification (LICENSE-006)
        TableDef(
            _resolve_table_name(S.license_compliance_checks_table_name, "license_compliance_checks"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
                {"index_name": "GSI3", "partition_key": "GSI3PK", "sort_key": "GSI3SK"},
            ],
            attr_types={"GSI1SK": "N", "GSI2SK": "N", "GSI3SK": "N"},
        ),
        # License Revenue (LICENSE-003)
        TableDef(
            _resolve_table_name(S.license_revenue_table_name, "license_revenue"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
            ],
            attr_types={"GSI1SK": "N", "GSI2SK": "N"},
        ),
        # SSH Key Manager (INFRA-002)
        TableDef(
            _resolve_table_name(S.ssh_keys_table_name, "ssh_keys"),
            "user_sub",
            "sk",
            gsi=[
                {"index_name": "ByCreatedAt", "partition_key": "user_sub", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # Media Preferences (CALL-003)
        TableDef(
            _resolve_table_name(S.media_preferences_table_name, "media_preferences"),
            "user_sub",
            "sk",
        ),
        # EC2 Instance Launcher (INFRA-003)
        TableDef(
            _resolve_table_name(S.ec2_instances_table_name, "ec2_instances"),
            "user_sub",
            "sk",
            gsi=[
                {"index_name": "ByStatus", "partition_key": "user_sub", "sort_key": "status"},
                {"index_name": "ByCreatedAt", "partition_key": "user_sub", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # Instance Monitoring & Health (INFRA-008)
        # Time-series metric datapoints per instance. SK = TS#{ts}; numeric `ts`
        # attribute used as the ByTs GSI sort key for ordered range queries.
        TableDef(
            _resolve_table_name(S.instance_metrics_table_name, "instance_metrics"),
            "instance_id",
            "sk",
            gsi=[
                {"index_name": "ByTs", "partition_key": "instance_id", "sort_key": "ts"},
            ],
            attr_types={"ts": "N"},
        ),
        # Security Groups & Network Rules (INFRA-009)
        TableDef(
            _resolve_table_name(S.security_groups_table_name, "security_groups"),
            "user_sub",
            "sk",
            gsi=[
                {"index_name": "ByCreatedAt", "partition_key": "user_sub", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # SSH Session Recording & Playback (INFRA-010)
        TableDef(
            _resolve_table_name(S.ssh_session_recordings_table_name, "ssh_session_recordings"),
            "user_sub",
            "sk",
            gsi=[
                {"index_name": "ByHost", "partition_key": "user_sub", "sort_key": "host_key"},
                {"index_name": "ByCreatedAt", "partition_key": "user_sub", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # Multi-Hop SSH Bastion (INFRA-011)
        TableDef(
            _resolve_table_name(S.ssh_bastion_paths_table_name, "ssh_bastion_paths"),
            "user_sub",
            "sk",
            gsi=[
                {"index_name": "ByCreatedAt", "partition_key": "user_sub", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # Connection Profiles & Quick Connect (INFRA-006)
        TableDef(
            _resolve_table_name(S.connection_profiles_table_name, "connection_profiles"),
            "user_sub",
            "sk",
            gsi=[
                {"index_name": "ByCreatedAt", "partition_key": "user_sub", "sort_key": "created_at"},
                {"index_name": "ByLastUsedAt", "partition_key": "user_sub", "sort_key": "last_used_at"},
            ],
            attr_types={"created_at": "N", "last_used_at": "N"},
        ),
        # Host Inventory Management (INFRA-001)
        TableDef(
            _resolve_table_name(S.ddb_host_inventory_table, "host_inventory"),
            "user_sub",
            "sk",
            gsi=[
                {"index_name": "ByLabel", "partition_key": "user_sub", "sort_key": "label_lower"},
                {"index_name": "ByProtocol", "partition_key": "user_sub", "sort_key": "protocol"},
                {"index_name": "ByLastConnected", "partition_key": "user_sub", "sort_key": "last_connected_at"},
            ],
            attr_types={"last_connected_at": "N"},
        ),
        # Kubernetes Container Launcher (INFRA-004)
        TableDef(
            _resolve_table_name(S.k8s_pods_table_name, "k8s_pods"),
            "user_sub",
            "sk",
            gsi=[
                {"index_name": "ByNamespace", "partition_key": "namespace", "sort_key": "created_at"},
                {"index_name": "ByStatus", "partition_key": "user_sub", "sort_key": "status"},
                {"index_name": "ByCreatedAt", "partition_key": "user_sub", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # Activity Feed (SOC-003)
        TableDef(
            _resolve_table_name(S.activity_feed_table_name, "activity_feed"),
            "user_id",
            "sk",
        ),
        # Notification Engine (SOC-004)
        TableDef(
            _resolve_table_name(S.notifications_engine_table_name, "notifications_engine"),
            "user_id",
            "sk",
        ),
        # Call History (CALL-004)
        TableDef(
            _resolve_table_name(S.call_history_table_name, "call_history"),
            "user_id",
            "sk",
        ),
        # Broadcast Moderation (DELEGATE-004)
        TableDef(
            _resolve_table_name(S.broadcast_moderation_table_name, "broadcast_moderation"),
            "pk",
            "sk",
        ),
        # Agent Workers (AGENT-002 / AGENT-003)
        TableDef(
            _resolve_table_name(S.agent_workers_table_name, "agent_workers"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByStatus", "partition_key": "pk", "sort_key": "worker_status"},
                {"index_name": "ByCreatedAt", "partition_key": "pk", "sort_key": "created_at"},
                {"index_name": "ByAgentType", "partition_key": "pk", "sort_key": "agent_type"},
            ],
            attr_types={"created_at": "N"},
        ),
        # Compute Cost Tracking (INFRA-005)
        TableDef(
            _resolve_table_name(S.compute_billing_table_name, "compute_billing"),
            "user_sub",
            "sk",
            gsi=[
                {"index_name": "ByResourceId", "partition_key": "resource_id", "sort_key": "created_at"},
                {"index_name": "ByMonth", "partition_key": "month_key", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # Admin Compute Quotas (INFRA-012)
        TableDef(
            _resolve_table_name(S.compute_quotas_table_name, "compute_quotas"),
            "user_sub",
        ),
        # Instance Templates & Presets (INFRA-007)
        TableDef(
            _resolve_table_name(S.instance_templates_table_name, "instance_templates"),
            "owner_sub",
            "sk",
            gsi=[
                {"index_name": "ByCategory", "partition_key": "category", "sort_key": "name_lower"},
                {"index_name": "ByCreatedAt", "partition_key": "owner_sub", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # Agent Memory (AGENT-005)
        TableDef(
            _resolve_table_name(S.agent_memory_table_name, "agent_memory"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByCreatedAt", "partition_key": "pk", "sort_key": "created_at"},
                {"index_name": "ByCategory", "partition_key": "pk", "sort_key": "category"},
            ],
            attr_types={"created_at": "N"},
        ),
        # Agent Feedback & Terminal Monitoring (AGENT-006)
        TableDef(
            _resolve_table_name(S.agent_feedback_table_name, "agent_feedback"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByStatus", "partition_key": "pk", "sort_key": "feedback_status"},
                {"index_name": "ByCreatedAt", "partition_key": "pk", "sort_key": "created_at"},
                {"index_name": "ByUser", "partition_key": "user_id", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # Coder Agent (AGENT-008) — agent type configs (pk=TYPE#{id}, sk=CONFIG|META)
        TableDef(
            _resolve_table_name(S.agent_types_table_name, "agent_types"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByKind", "partition_key": "agent_type", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # Coder Agent (AGENT-008) — agent run output (pk=RUN#{id}, sk=OUTPUT)
        TableDef(
            _resolve_table_name(S.agent_runs_table_name, "agent_runs"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByTypeDate", "partition_key": "gsi_type_date_pk", "sort_key": "gsi_type_date_sk"},
            ],
        ),
        # DevOps/SRE Agent (AGENT-010) — deployment audit log (pk=DEPLOY#{id}, sk=STEP#{nnnn})
        TableDef(
            _resolve_table_name(S.deployment_log_table_name, "deployment_log"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByEnv", "partition_key": "gsi_env_pk", "sort_key": "gsi_env_sk"},
            ],
            attr_types={"gsi_env_sk": "N"},
        ),
        # Solution Architect Agent (AGENT-011) — feature -> dev ticket decompositions
        TableDef(
            _resolve_table_name(S.feature_decompositions_table_name, "feature_decompositions"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
            ],
            attr_types={"GSI1SK": "N"},
        ),
        # Documentation Agent (AGENT-014) — doc coverage + freshness tracking
        # (pk=USER#{id}, sk=DOC#{path}). GSI1 = by doc_type, GSI2 = by staleness.
        TableDef(
            _resolve_table_name(S.agent_doc_coverage_table_name, "agent_doc_coverage"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
            ],
            attr_types={"GSI1SK": "N", "GSI2SK": "N"},
        ),
        # Stylist / UI Agent (AGENT-016) — UI review results (pk=USER#{id}, sk=REVIEW#{id})
        TableDef(
            _resolve_table_name(S.stylist_ui_reviews_table_name, "stylist_ui_reviews"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
            ],
            attr_types={"GSI1SK": "N", "GSI2SK": "N"},
        ),
        # Stylist / UI Agent (AGENT-016) — design rules (pk=USER#{id}, sk=RULE#{id})
        TableDef(
            _resolve_table_name(S.stylist_design_rules_table_name, "stylist_design_rules"),
            "pk",
            "sk",
        ),
        # Documentation Agent (AGENT-014) — doc templates (pk=USER#{id}, sk=TMPL#{id})
        TableDef(
            _resolve_table_name(S.agent_doc_templates_table_name, "agent_doc_templates"),
            "pk",
            "sk",
        ),
        # Product Manager Agent (AGENT-013) — feature ideas with approval workflow
        TableDef(
            _resolve_table_name(S.agent_feature_ideas_table_name, "agent_feature_ideas"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
            ],
            attr_types={"GSI1SK": "N", "GSI2SK": "N"},
        ),
        # Product Manager Agent (AGENT-013) — preference learning (pk=USER#id, sk=PREF#cat)
        TableDef(
            _resolve_table_name(S.agent_preference_learning_table_name, "agent_preference_learning"),
            "pk",
            "sk",
        ),
        # Project Manager Agent (AGENT-012) — product idea intake funnel
        TableDef(
            _resolve_table_name(S.product_ideas_table_name, "product_ideas"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
            ],
            attr_types={"GSI1SK": "N", "GSI2SK": "N"},
        ),
        # Project Manager Agent (AGENT-012) — sprint/cycle boundaries + velocity
        TableDef(
            _resolve_table_name(S.project_sprints_table_name, "project_sprints"),
            "pk",
            "sk",
        ),
        # Project Manager Agent (AGENT-012) — generated progress reports
        TableDef(
            _resolve_table_name(S.project_reports_table_name, "project_reports"),
            "pk",
            "sk",
        ),
        # Marketing Agent (AGENT-017) — content drafts/lifecycle (pk=USER#id, sk=CONTENT#id)
        # GSI1 = by content_type, GSI2 = by status, GSI3 = scheduled-publish calendar.
        TableDef(
            _resolve_table_name(S.marketing_content_table_name, "marketing_content"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
                {"index_name": "GSI3", "partition_key": "GSI3PK", "sort_key": "GSI3SK"},
            ],
            attr_types={"GSI1SK": "N", "GSI2SK": "N", "GSI3SK": "N"},
        ),
        # Marketing Agent (AGENT-017) — daily engagement counters (pk=CONTENT#id, sk=DAY#date)
        TableDef(
            _resolve_table_name(S.marketing_engagement_table_name, "marketing_engagement"),
            "pk",
            "sk",
        ),
        # Compliance & Security Agent (AGENT-015) — security findings.
        # pk=USER#{id}, sk=FINDING#{id}. GSI1=by severity, GSI2=by status, GSI3=by source_ref.
        TableDef(
            _resolve_table_name(
                S.compliance_security_findings_table_name, "compliance_security_findings"
            ),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
                {"index_name": "GSI3", "partition_key": "GSI3PK", "sort_key": "GSI3SK"},
            ],
            attr_types={"GSI1SK": "N", "GSI2SK": "N", "GSI3SK": "N"},
        ),
        # Compliance & Security Agent (AGENT-015) — periodic/manual audit runs.
        # pk=USER#{id}, sk=AUDIT#{id}. GSI1=audits by started_at.
        TableDef(
            _resolve_table_name(
                S.compliance_security_audits_table_name, "compliance_security_audits"
            ),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
            ],
            attr_types={"GSI1SK": "N"},
        ),
        # Admin Subscription Tier Manager (ADMIN-001).
        # pk=CREATOR#{creator_id}, sk=TIER#{tier_id}.
        TableDef(
            _resolve_table_name(
                S.admin_subscription_tiers_table_name, "admin_subscription_tiers"
            ),
            "pk",
            "sk",
        ),
        # Accountant / Cost Tracking Agent (AGENT-018) — daily cost entries.
        # pk=USER#{id}, sk=COST#{date}#{worker}. GSI1=by date, GSI2=by agent_type.
        TableDef(
            _resolve_table_name(S.agent_costs_table_name, "accountant_costs"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
            ],
        ),
        # Accountant / Cost Tracking Agent (AGENT-018) — per-ticket cost attribution.
        # pk=USER#{id}, sk=TCOST#{ticket}. GSI1=tickets sorted by total_cost_cents.
        TableDef(
            _resolve_table_name(S.agent_ticket_costs_table_name, "accountant_ticket_costs"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
            ],
            attr_types={"GSI1SK": "N"},
        ),
        # Accountant / Cost Tracking Agent (AGENT-018) — budget caps.
        # pk=USER#{id}, sk=BUDGET#{id}. No GSI.
        TableDef(
            _resolve_table_name(S.agent_cost_budgets_table_name, "accountant_cost_budgets"),
            "pk",
            "sk",
        ),
        # Accountant / Cost Tracking Agent (AGENT-018) — budget/anomaly alerts.
        # pk=USER#{id}, sk=ALERT#{id}. GSI1=alerts by created_at.
        TableDef(
            _resolve_table_name(S.agent_cost_alerts_table_name, "accountant_cost_alerts"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
            ],
            attr_types={"GSI1SK": "N"},
        ),
        # FIN-001: Invoices / Receipt PDF.
        # pk=USER#{user_sub}, sk=INV#{invoice_number}; plus COUNTER/SEQ row.
        # GSI1=invoices by type (USER#{sub}#TYPE#{type} / created_at).
        # GSI2=admin lookup (ADMIN_ALL / created_at).
        TableDef(
            _resolve_table_name(S.invoices_table_name, "invoices"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
            ],
            attr_types={"GSI1SK": "N", "GSI2SK": "N"},
        ),
        # Platform Financial Dashboard daily/live rollups (FIN-013).
        # pk=ROLLUP#DAILY sk=YYYY-MM-DD ; pk=ROLLUP#LIVE sk=CURRENT
        TableDef(
            _resolve_table_name(S.platform_financial_dashboard_rollups_table_name, "financial_rollups"),
            "pk",
            "sk",
        ),
        # FIN-014: Payment Provider Health.
        # Datapoints: pk=PROVIDER#{provider} sk=DP#{ts}#{uuid}; GSI1 time-ordered.
        # Config:     pk=PROVIDER#{provider} sk=CONFIG
        # Incidents:  pk=PROVIDER#{provider} sk=INCIDENT#{id};
        #             GSI1PK=INCIDENTS#ALL GSI1SK={started_at} (numeric).
        TableDef(
            _resolve_table_name(S.payment_provider_health_table_name, "payment_provider_health"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
            ],
            attr_types={"GSI1SK": "N"},
        ),
        # FIN-004: Consumer Tax Documents.
        # Doc records: pk=USER#{user_sub} sk=DOC#{year}#{doc_id}
        # Cache rows:  pk=USER#{user_sub} sk=CACHE#{year}
        # All access is by user PK; no GSI needed.
        TableDef(
            _resolve_table_name(S.tax_documents_table_name, "tax_documents"),
            "pk",
            "sk",
        ),
        # FIN-008: Creator 1099 / Tax-Form generation (platform-issuer 1099-NEC).
        # Form records: pk=USER#{user_sub} sk=FORM#{tax_year}
        # Batch locks:  pk=BATCH#{tax_year} sk=LOCK
        # GSI ByTaxYear: GSI1PK=YEAR#{tax_year} GSI1SK=created_at(N) — list all
        # forms issued for a tax year (admin).
        TableDef(
            _resolve_table_name(S.tax_forms_1099_table_name, "tax_forms_1099"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByTaxYear", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
            ],
            attr_types={"GSI1SK": "N"},
        ),
        # Background Job Dashboard (PLATFORM-008): run history.
        # pk=job_name sk=RUN#{started_at}#{uuid}
        # GSI ByStartedAt: GSI_PK="JOBRUN" started_at(N) for cross-job recents.
        TableDef(
            _resolve_table_name(S.job_runs_table_name, "job_runs"),
            "job_name",
            "run_id",
            gsi=[
                {"index_name": "ByStartedAt", "partition_key": "GSI_PK", "sort_key": "started_at"},
            ],
            attr_types={"started_at": "N"},
        ),
        TableDef(
            _resolve_table_name(S.user_themes_table_name, "user_themes"),
            "user_sub",
        ),
        # Sponsored Content & Creator Partnerships (ADS-013)
        TableDef(
            _resolve_table_name(S.sponsorship_deals_table_name, "sponsorship_deals"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
                {"index_name": "GSI3", "partition_key": "GSI3PK", "sort_key": "GSI3SK"},
            ],
            attr_types={"GSI1SK": "N", "GSI2SK": "N", "GSI3SK": "N"},
        ),
        # Image Optimization records + cache (PLATFORM-004)
        TableDef(
            _resolve_table_name(S.image_optimizations_table_name, "image_optimizations"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "BySourceKey", "partition_key": "source_key_hash", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # Ad Creative Affiliate Discounts (ADS-015)
        # PK=CREATIVE#{creative_id}; SK=CONFIG (link), CLICK#{ts}#{id}, REDEEM#{ts}#{id}
        TableDef(
            _resolve_table_name(S.ad_creative_affiliates_table_name, "AdCreativeAffiliates"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByOwner", "partition_key": "owner_scope", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # Encrypted one-time share links (FILES-001)
        # PK=link_id (fsl_<uuid>); SK=META; GSI1 lists links by owner, GSI2 by file
        TableDef(
            _resolve_table_name(S.ddb_file_share_links_table, "file_share_links"),
            "link_id",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "owner_sub", "sort_key": "created_at"},
                {"index_name": "GSI2", "partition_key": "file_node_id", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # FIN-015: Fraud Detection Dashboard. PK=pk, SK=sk.
        # GSI1 lists review queue/cases by status (FLAGS#PENDING, CASES#OPEN, ...).
        # GSI2 lists a user's flag history (FLAGS#USER#{id}). Both SKs numeric (created_at).
        TableDef(
            _resolve_table_name(S.ddb_fraud_cases_table, "fraud_detection"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
            ],
            attr_types={"GSI1SK": "N", "GSI2SK": "N"},
        ),
    ]


def _attribute_definitions(table: TableDef) -> List[Dict[str, str]]:
    attrs = {table.partition_key: "S"}
    if table.sort_key:
        attrs[table.sort_key] = "S"
    for gsi in table.gsi:
        attrs[gsi["partition_key"]] = "S"
        if gsi.get("sort_key"):
            attrs[gsi["sort_key"]] = "S"
    # Apply type overrides (e.g. numeric keys)
    attrs.update(table.attr_types)
    return [{"AttributeName": k, "AttributeType": v} for k, v in attrs.items()]


def _key_schema(table: TableDef) -> List[Dict[str, str]]:
    schema = [{"AttributeName": table.partition_key, "KeyType": "HASH"}]
    if table.sort_key:
        schema.append({"AttributeName": table.sort_key, "KeyType": "RANGE"})
    return schema


def _global_secondary_indexes(table: TableDef) -> Optional[List[Dict[str, object]]]:
    if not table.gsi:
        return None
    indexes = []
    for gsi in table.gsi:
        key_schema = [{"AttributeName": gsi["partition_key"], "KeyType": "HASH"}]
        if gsi.get("sort_key"):
            key_schema.append({"AttributeName": gsi["sort_key"], "KeyType": "RANGE"})
        indexes.append(
            {
                "IndexName": gsi["index_name"],
                "KeySchema": key_schema,
                "Projection": {"ProjectionType": "ALL"},
            }
        )
    return indexes


def _ensure_table(ddb, table: TableDef) -> None:
    client = ddb.meta.client
    existing = _retry_transient_ddb_call(client.list_tables).get("TableNames", [])
    if table.name in existing:
        if table.gsi:
            desc = _retry_transient_ddb_call(client.describe_table, TableName=table.name).get("Table", {})
            existing_indexes = {idx.get("IndexName") for idx in desc.get("GlobalSecondaryIndexes", [])}
            existing_attributes = {attr.get("AttributeName") for attr in desc.get("AttributeDefinitions", [])}
            missing = [g for g in table.gsi if g["index_name"] not in existing_indexes]
            for gsi in missing:
                attr_defs = []
                if gsi["partition_key"] not in existing_attributes:
                    attr_defs.append({"AttributeName": gsi["partition_key"], "AttributeType": "S"})
                if gsi.get("sort_key") and gsi["sort_key"] not in existing_attributes:
                    attr_defs.append({"AttributeName": gsi["sort_key"], "AttributeType": "S"})

                update_kwargs: Dict[str, object] = {
                    "TableName": table.name,
                    "GlobalSecondaryIndexUpdates": [
                        {
                            "Create": {
                                "IndexName": gsi["index_name"],
                                "KeySchema": [
                                    {"AttributeName": gsi["partition_key"], "KeyType": "HASH"},
                                    *(
                                        [{"AttributeName": gsi["sort_key"], "KeyType": "RANGE"}]
                                        if gsi.get("sort_key")
                                        else []
                                    ),
                                ],
                                "Projection": {"ProjectionType": "ALL"},
                            }
                        }
                    ],
                }
                if attr_defs:
                    update_kwargs["AttributeDefinitions"] = attr_defs

                _retry_transient_ddb_call(client.update_table, **update_kwargs)
                waiter = client.get_waiter("table_exists")
                waiter.wait(TableName=table.name)
                desc = _retry_transient_ddb_call(client.describe_table, TableName=table.name).get("Table", {})
                existing_attributes = {attr.get("AttributeName") for attr in desc.get("AttributeDefinitions", [])}
        return
    kwargs: Dict[str, object] = {
        "TableName": table.name,
        "AttributeDefinitions": _attribute_definitions(table),
        "KeySchema": _key_schema(table),
        "BillingMode": "PAY_PER_REQUEST",
    }
    gsi = _global_secondary_indexes(table)
    if gsi:
        kwargs["GlobalSecondaryIndexes"] = gsi
    try:
        _retry_transient_ddb_call(client.create_table, **kwargs)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceInUseException":
            return
        raise


def _retry_transient_ddb_call(func, *args, retries: int = 20, delay_seconds: float = 1.0, **kwargs):
    """Retry DynamoDB Local operations when the embedded server is still warming up."""
    for attempt in range(1, retries + 1):
        try:
            return func(*args, **kwargs)
        except EndpointConnectionError:
            if attempt == retries:
                raise
            time.sleep(delay_seconds)
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "")
            if error_code not in {"InternalFailure", "ThrottlingException", "LimitExceededException"}:
                raise
            if attempt == retries:
                raise
            time.sleep(delay_seconds)


def _wait_for_tables(ddb, table_names: Iterable[str]) -> None:
    client = ddb.meta.client
    for name in table_names:
        waiter = client.get_waiter("table_exists")
        waiter.wait(TableName=name)
        table = _retry_transient_ddb_call(client.describe_table, TableName=name).get("Table", {})
        for _ in range(120):
            indexes = table.get("GlobalSecondaryIndexes", [])
            if all(idx.get("IndexStatus") == "ACTIVE" for idx in indexes):
                break
            time.sleep(1)
            table = _retry_transient_ddb_call(client.describe_table, TableName=name).get("Table", {})


def _ddb_resource_for_local_bootstrap():
    endpoint = os.getenv("DDB_ENDPOINT_URL") or os.getenv("AWS_ENDPOINT_URL") or "http://localhost:8001"
    return boto3.resource(
        "dynamodb",
        region_name=S.aws_region or "us-east-1",
        endpoint_url=endpoint,
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID", "test"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY", "test"),
        aws_session_token=os.getenv("AWS_SESSION_TOKEN", "test"),
    )


def _enable_ttl_if_needed(ddb, table_name: str) -> None:
    if not table_name:
        return
    client = ddb.meta.client
    attr = getattr(S, "ddb_ttl_attr", "ttl_epoch") or "ttl_epoch"
    try:
        desc = _retry_transient_ddb_call(client.describe_time_to_live, TableName=table_name)
        ttl_desc = desc.get("TimeToLiveDescription", {})
        status = ttl_desc.get("TimeToLiveStatus")
        existing_attr = ttl_desc.get("AttributeName")
        if status in {"ENABLED", "ENABLING"} and existing_attr == attr:
            return
    except ClientError:
        pass
    try:
        _retry_transient_ddb_call(
            client.update_time_to_live,
            TableName=table_name,
            TimeToLiveSpecification={"Enabled": True, "AttributeName": attr},
        )
    except ClientError:
        # DynamoDB Local may not fully emulate TTL APIs; table writes still include ttl attr.
        pass


def main() -> None:
    ddb = _ddb_resource_for_local_bootstrap()
    tables = _table_defs()
    created = []
    for table in tables:
        _ensure_table(ddb, table)
        created.append(table.name)
    _wait_for_tables(ddb, created)
    _enable_ttl_if_needed(ddb, _resolve_table_name(S.api_usage_table_name, "api_usage_events"))
    _enable_ttl_if_needed(ddb, os.getenv("APP_TABLE", "app_single_table"))
    # SHOP-003: Enable TTL on shopping_cart table with attribute "ttl"
    _cart_table = _resolve_table_name(S.shopping_cart_table_name, "shopping_cart")
    try:
        client = ddb.meta.client
        _retry_transient_ddb_call(
            client.update_time_to_live,
            TableName=_cart_table,
            TimeToLiveSpecification={"Enabled": True, "AttributeName": "ttl"},
        )
    except Exception:
        pass
    print(f"Ensured {len(created)} DynamoDB tables exist.")


if __name__ == "__main__":
    main()
