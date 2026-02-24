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
    signature_packets: Any
    signature_packet_signers: Any
    signature_packet_fields: Any
    signature_packet_events: Any
    signature_packet_artifacts: Any

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
    signature_packets=ddb.Table(S.signature_packets_table_name),
    signature_packet_signers=ddb.Table(S.signature_packet_signers_table_name),
    signature_packet_fields=ddb.Table(S.signature_packet_fields_table_name),
    signature_packet_events=ddb.Table(S.signature_packet_events_table_name),
    signature_packet_artifacts=ddb.Table(S.signature_packet_artifacts_table_name),
)
