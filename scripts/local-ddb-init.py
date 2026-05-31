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
        TableDef(_resolve_table_name(S.users_table_name, "users"), "user_sub"),
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
            ],
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
        # Collaboration Requests (CREATOR-001)
        TableDef(
            _resolve_table_name(S.collaboration_agreements_table_name, "collaboration_agreements"),
            "collaboration_id",
            "sk",
            gsi=[
                {"index_name": "ByInitiator", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "ByRecipient", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
                {"index_name": "ByStatus", "partition_key": "GSI3PK", "sort_key": "GSI3SK"},
            ],
            attr_types={"GSI1SK": "N", "GSI2SK": "N", "GSI3SK": "N"},
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
        # Notification Engine (SOC-004)
        TableDef(
            _resolve_table_name(S.notifications_engine_table_name, "notifications_engine"),
            "user_id",
            "sk",
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
