from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .aws import ddb
from .settings import S

@dataclass(frozen=True)
class Tables:
    sessions: Any
    totp: Any
    sms: Any
    recovery: Any
    email: Any
    users: Any
    role_audit: Any
    api_keys: Any
    alerts: Any
    alert_prefs: Any
    push_devices: Any
    billing: Any
    account_state: Any
    profile: Any
    addresses: Any
    calendar: Any
    purchase_transactions: Any
    purchase_events: Any
    shopping_cart: Any
    catalog: Any
    subscriptions: Any
    projects: Any
    contacts: Any
    message_visibility_overrides: Any
    conversation_pins: Any
    message_reports: Any
    message_report_context: Any
    content_reports: Any
    moderation_tickets: Any
    moderation_actions: Any
    moderation_audit_log: Any
    user_enforcement_history: Any
    message_legal_holds: Any
    message_archive_chain_heads: Any
    message_compliance_exports: Any
    catalog_products: Any
    catalog_product_versions: Any
    orders: Any
    order_items: Any
    payments: Any
    entitlements: Any
    entitlement_usage_events: Any
    signature_packets: Any
    signature_packet_signers: Any
    signature_packet_fields: Any
    signature_packet_events: Any
    signature_packet_artifacts: Any
    tickets: Any
    questionnaires: Any

T = Tables(
    sessions=ddb.Table(S.ddb_sessions_table),
    totp=ddb.Table(S.ddb_totp_table),
    sms=ddb.Table(S.ddb_sms_table),
    recovery=ddb.Table(S.ddb_recovery_table),
    email=ddb.Table(S.ddb_email_table),
    users=ddb.Table(S.users_table_name),
    role_audit=ddb.Table(S.role_audit_table_name),
    api_keys=ddb.Table(S.api_keys_table_name),
    alerts=ddb.Table(S.alerts_table_name),
    alert_prefs=ddb.Table(S.alert_prefs_table_name),
    push_devices=ddb.Table(S.push_devices_table_name),
    billing=ddb.Table(S.billing_table_name),
    account_state=ddb.Table(S.account_state_table_name),
    profile=ddb.Table(S.profile_table_name),
    addresses=ddb.Table(S.addresses_table_name),
    calendar=ddb.Table(S.calendar_table_name),
    purchase_transactions=ddb.Table(S.purchase_transactions_table_name),
    purchase_events=ddb.Table(S.purchase_events_table_name),
    shopping_cart=ddb.Table(S.shopping_cart_table_name),
    catalog=ddb.Table(S.catalog_table_name),
    subscriptions=ddb.Table(S.subscriptions_table_name),
    projects=ddb.Table(S.projects_table_name),
    contacts=ddb.Table(S.contacts_table_name),
    message_visibility_overrides=ddb.Table(S.message_visibility_overrides_table_name),
    conversation_pins=ddb.Table(S.conversation_pins_table_name),
    message_reports=ddb.Table(S.message_reports_table_name),
    message_report_context=ddb.Table(S.message_report_context_table_name),
    content_reports=ddb.Table(S.content_reports_table_name),
    moderation_tickets=ddb.Table(S.moderation_tickets_table_name),
    moderation_actions=ddb.Table(S.moderation_actions_table_name),
    moderation_audit_log=ddb.Table(S.moderation_audit_log_table_name),
    user_enforcement_history=ddb.Table(S.user_enforcement_history_table_name),
    message_legal_holds=ddb.Table(S.message_legal_holds_table_name),
    message_archive_chain_heads=ddb.Table(S.message_archive_chain_heads_table_name),
    message_compliance_exports=ddb.Table(S.message_compliance_exports_table_name),
    catalog_products=ddb.Table(S.catalog_products_table_name),
    catalog_product_versions=ddb.Table(S.catalog_product_versions_table_name),
    orders=ddb.Table(S.orders_table_name),
    order_items=ddb.Table(S.order_items_table_name),
    payments=ddb.Table(S.payments_table_name),
    entitlements=ddb.Table(S.entitlements_table_name),
    entitlement_usage_events=ddb.Table(S.entitlement_usage_events_table_name),
    signature_packets=ddb.Table(S.signature_packets_table_name),
    signature_packet_signers=ddb.Table(S.signature_packet_signers_table_name),
    signature_packet_fields=ddb.Table(S.signature_packet_fields_table_name),
    signature_packet_events=ddb.Table(S.signature_packet_events_table_name),
    signature_packet_artifacts=ddb.Table(S.signature_packet_artifacts_table_name),
    tickets=ddb.Table(S.tickets_table_name),
    questionnaires=ddb.Table(S.questionnaire_table_name),
)
