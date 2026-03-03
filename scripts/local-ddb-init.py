#!/usr/bin/env python3
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError
from app.core.settings import S


@dataclass(frozen=True)
class TableDef:
    name: str
    partition_key: str
    sort_key: Optional[str] = None
    gsi: List[Dict[str, str]] = field(default_factory=list)


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
        TableDef(_resolve_table_name(S.shopping_cart_table_name, "shopping_cart"), "PK", "SK"),
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
        TableDef(os.getenv("DDB_MESSAGES", "Messages"), "conversation_id", "message_id"),
        TableDef(os.getenv("DDB_USER_EVENTS", "UserEvents"), "user_id", "event_id"),
        TableDef(os.getenv("DDB_USERS", "Users"), "user_id"),
        TableDef(os.getenv("DDB_USER_SEARCH", "UserSearch"), "token"),
        TableDef(os.getenv("DDB_MESSAGE_SEARCH", "MessageSearch"), "token", "message_key"),
        TableDef(os.getenv("DDB_PRESENCE", "UserPresence"), "user_id"),
        TableDef(os.getenv("DDB_TYPING", "Typing"), "conversation_id", "user_id"),
        TableDef(os.getenv("DDB_MESSAGE_EDITS", "MessageEdits"), "message_key", "edited_at"),
        TableDef(os.getenv("DDB_MESSAGE_VIEWS", "MessageViews"), "conversation_id", "message_user"),
        TableDef(os.getenv("DDB_MESSAGE_RECEIPTS", "MessageReceipts"), "conversation_id", "message_user"),
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
    ]


def _attribute_definitions(table: TableDef) -> List[Dict[str, str]]:
    attrs = {table.partition_key: "S"}
    if table.sort_key:
        attrs[table.sort_key] = "S"
    for gsi in table.gsi:
        attrs[gsi["partition_key"]] = "S"
        if gsi.get("sort_key"):
            attrs[gsi["sort_key"]] = "S"
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
    _retry_transient_ddb_call(client.create_table, **kwargs)


def _retry_transient_ddb_call(func, *args, retries: int = 12, delay_seconds: float = 1.0, **kwargs):
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
    print(f"Ensured {len(created)} DynamoDB tables exist.")


if __name__ == "__main__":
    main()
