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
        # OFBiz Fixed Assets — FXA-003.
        # fixed_assets: one row per registered asset (PK=ASSET#{id}, SK=META).
        # GSI_OWNER lets users list their assets by acquisition date.
        # GSI_STATUS lets ops filter the active/disposed fleet.
        TableDef(
            _resolve_table_name(S.fixed_assets_table_name, "fixed_assets"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI_OWNER", "partition_key": "owner_sub", "sort_key": "acquired_at"},
                {"index_name": "GSI_STATUS", "partition_key": "status", "sort_key": "acquired_at"},
            ],
            attr_types={"acquired_at": "N"},
        ),
        # fixed_asset_schedule: one row per depreciation period per asset.
        # GSI_DUE lets the background poster find all due-but-unposted periods
        # efficiently (schedule_status=scheduled, period_end_ts <= now).
        TableDef(
            _resolve_table_name(S.fixed_asset_schedule_table_name, "fixed_asset_schedule"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI_DUE", "partition_key": "schedule_status", "sort_key": "period_end_ts"},
            ],
            attr_types={"period_end_ts": "N"},
        ),
        # HRM-002: HR single-table for positions, employments, and payroll runs.
        # PK/SK are uppercase per OFBiz ERP convention.  GSI1 enables status-
        # filtered listing; GSI2 enables party reverse-lookup; GSI_CREATED
        # enables newest-first listing across all entity types.
        # attr_types={"created_at": "N"} prevents ValidationException when the
        # GSI_CREATED sort key (an integer Unix timestamp) is queried with
        # integer values (CLAUDE.md "DynamoDB numeric GSI sort keys" gotcha).
        TableDef(
            _resolve_table_name(S.hr_table_name, "hr"),
            "PK",
            "SK",
            gsi=[
                {"index_name": "GSI1",        "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "GSI2",        "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
                {"index_name": "GSI_CREATED", "partition_key": "entity_type", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # MFG-002: Manufacturing/MRP tables (flag-gated; always provisioned, never
        # accessed when manufacturing_mrp_enabled=false).
        TableDef(
            _resolve_table_name(S.mfg_boms_table_name, "mfg_boms"),
            "bom_id",
            "sk",
            gsi=[
                {"index_name": "GSI_PRODUCT", "partition_key": "product_sku", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        TableDef(
            _resolve_table_name(S.mfg_work_centers_table_name, "mfg_work_centers"),
            "work_center_id",
            "sk",
            gsi=[
                {"index_name": "GSI_STATUS", "partition_key": "status", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        TableDef(
            _resolve_table_name(S.mfg_work_orders_table_name, "mfg_work_orders"),
            "work_order_id",
            "sk",
            gsi=[
                {"index_name": "GSI_STATUS", "partition_key": "status", "sort_key": "created_at"},
                {"index_name": "GSI_PRODUCT", "partition_key": "product_sku", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        TableDef(
            _resolve_table_name(S.mfg_mrp_table_name, "mfg_mrp"),
            "mrp_run_id",
            "sk",
            gsi=[
                {"index_name": "GSI_RUN_STATUS", "partition_key": "status", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # PLT-003: Glossary endpoint (GSI sort key is string — no attr_types needed)
        TableDef(
            _resolve_table_name(S.glossary_table_name, "glossary"),
            "term_id",
            gsi=[
                {"index_name": "GSI_BY_TERM", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
            ],
        ),
        # EVT-001: CRM Events — event metadata + invitee rows
        TableDef(
            _resolve_table_name(S.crm_events_table_name, "crm_events"),
            "event_id",
            "sk",
            gsi=[
                {"index_name": "ByOwner", "partition_key": "owner_sub", "sort_key": "created_at"},
                {"index_name": "ByCalendar", "partition_key": "calendar_event_id", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # EVT-001: CRM Event Registrations — one row per registrant per event
        TableDef(
            _resolve_table_name(S.crm_event_registrations_table_name, "crm_event_registrations"),
            "event_id",
            "registrant_sub",
            gsi=[
                {"index_name": "ByRegistrant", "partition_key": "registrant_sub", "sort_key": "registered_at"},
            ],
            attr_types={"registered_at": "N"},
        ),
        # EVT-014: CRM Contact SMS Log — per-contact outbound SMS history
        TableDef(
            _resolve_table_name(S.crm_contact_sms_log_table_name, "crm_contact_sms_log"),
            "sender_sub",
            "sk",
            gsi=[
                {"index_name": "ByContact", "partition_key": "contact_id", "sort_key": "sent_at_ts"},
                {"index_name": "ByStatus", "partition_key": "status", "sort_key": "sent_at_ts"},
            ],
            attr_types={"sent_at_ts": "N"},
        ),
        # CSN-001: PSD2 AIS/PIS Consents
        TableDef(
            _resolve_table_name(S.consents_table_name, "consents"),
            "owner_sub",
            "consent_id",
            gsi=[
                {
                    "index_name": S.consents_consumer_index,
                    "partition_key": "consumer_ref",
                    "sort_key": "created_at",
                },
                {
                    "index_name": S.consents_status_index,
                    "partition_key": "status",
                    "sort_key": "valid_until",
                },
                {
                    "index_name": S.consents_by_payment_ref_index,
                    "partition_key": "payment_ref",
                },
            ],
            attr_types={"created_at": "N", "valid_until": "N"},
        ),
        # CSN-003: Dynamic Entity Definitions
        TableDef(
            _resolve_table_name(S.dynamic_entity_defs_table_name, "dynamic_entity_defs"),
            "entity_name",
            "sk",
            gsi=[
                {
                    "index_name": S.dynamic_entity_defs_creator_index,
                    "partition_key": "created_by",
                    "sort_key": "created_at",
                },
            ],
            attr_types={"created_at": "N"},
        ),
        # CSN-003: Dynamic Entity Rows (generic per-entity row store)
        TableDef(
            _resolve_table_name(S.dynamic_entity_rows_table_name, "dynamic_entity_rows"),
            "entity_name",
            "row_id",
            gsi=[
                {
                    "index_name": S.dynamic_entity_rows_owner_index,
                    "partition_key": "owner_sub",
                    "sort_key": "created_at",
                },
            ],
            attr_types={"created_at": "N"},
        ),
        # CSN-004: Dynamic Endpoints
        TableDef(
            _resolve_table_name(S.dynamic_endpoints_table_name, "dynamic_endpoints"),
            "endpoint_id",
            "sk",
            gsi=[
                {
                    "index_name": S.dynamic_endpoints_method_path_index,
                    "partition_key": "method_path",
                    "sort_key": "sk",
                },
                {
                    "index_name": S.dynamic_endpoints_created_by_index,
                    "partition_key": "created_by",
                    "sort_key": "created_at",
                },
            ],
            attr_types={"created_at": "N"},
        ),
        # CSN-005: Open Data (Branches + ATMs)
        TableDef(
            _resolve_table_name(S.open_data_table_name, "open_data"),
            "kind",
            "resource_id",
            gsi=[
                {
                    "index_name": S.open_data_active_index,
                    "partition_key": "kind_active",
                    "sort_key": "name",
                },
            ],
        ),
        # PUR-002: Purchasing / SCM tables
        TableDef(
            _resolve_table_name(S.suppliers_table_name, "suppliers"),
            "supplier_id",
            "sk",
            gsi=[
                {"index_name": "GSI_STATUS", "partition_key": "status", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        TableDef(
            _resolve_table_name(S.supplier_products_table_name, "supplier_products"),
            "supplier_id",
            "sk",
            gsi=[
                {"index_name": "GSI_SKU", "partition_key": "sku", "sort_key": "unit_cost_cents"},
            ],
            attr_types={"unit_cost_cents": "N"},
        ),
        TableDef(
            _resolve_table_name(S.purchase_orders_table_name, "purchase_orders"),
            "po_id",
            "sk",
            gsi=[
                {"index_name": "GSI_SUPPLIER", "partition_key": "supplier_id", "sort_key": "created_at"},
                {"index_name": "GSI_STATUS", "partition_key": "status", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        TableDef(
            _resolve_table_name(S.po_receipts_table_name, "po_receipts"),
            "po_id",
            "sk",
            gsi=[
                {"index_name": "GSI_RECEIPT", "partition_key": "receipt_id"},
            ],
        ),
        # HTL-029: Guest folio entity — running stay-balance table.
        # PK=reservation_id, SK=META (header) or LINE#{line_id} (charge rows).
        # GSI_FOLIO_HOTEL: hotel_id (S) / created_at (N) — lists a hotel's
        # folios newest-first; sparse (only META rows carry hotel_id).
        # attr_types: created_at must be N or DynamoDB stores it as S →
        # ValidationException when queried with integer values (CLAUDE.md gotcha).
        TableDef(
            _resolve_table_name(S.hotel_folios_table_name, "hotel_folios"),
            "reservation_id",
            "sk",
            gsi=[
                {"index_name": "GSI_FOLIO_HOTEL", "partition_key": "hotel_id", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # PMD-001: Per-owner rent-policy settings. pk="POLICY#{owner_sub}", sk="CURRENT" or
        # sk="AUDIT#{ts:010d}#{event_id}". No GSI needed; all access patterns are
        # single-owner point reads + prefix queries.
        TableDef(
            _resolve_table_name(S.rent_policy_table_name, "rent_policy"),
            "pk",
            "sk",
        ),
        # PMD-002: Property document link store. pk="LINK#{record_type}#{record_id}",
        # sk="DOC#{doc_id}". GSI allows listing all docs for an owner.
        # EVT-011 is not yet built; PMD-002 uses this local link store instead.
        TableDef(
            _resolve_table_name(S.property_documents_table_name, "property_documents"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "owner-index", "partition_key": "owner_sub", "sort_key": "sk"},
            ],
        ),
        TableDef(
            _resolve_table_name(S.customers_table_name, "customers"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI_NUMBER", "partition_key": "gsi_number_pk", "sort_key": "customer_number"},
                {"index_name": "GSI_BRANCH", "partition_key": "gsi_branch_pk", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        TableDef(
            _resolve_table_name(S.financial_products_table_name, "financial_products"),
            "PK",
            "SK",
            gsi=[
                {"index_name": "GSI_CATEGORY", "partition_key": "gsi_cat_pk", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # OFBiz Phase 8 — Shipping/Logistics (SHP-002). Four new tables. All
        # default OFF (SHIPPING_ENABLED=false); existing paths byte-for-byte
        # unchanged when the flag is off.
        TableDef(
            _resolve_table_name(S.shipping_carriers_table_name, "shipping_carriers"),
            "carrier_id",
            "sk",
            gsi=[{"index_name": "GSI_CODE", "partition_key": "carrier_code", "sort_key": "sk"}],
        ),
        TableDef(
            _resolve_table_name(S.shipments_table_name, "shipments"),
            "shipment_id",
            gsi=[
                {"index_name": "GSI_ORDER", "partition_key": "order_id", "sort_key": "created_at"},
                {"index_name": "GSI_STATUS", "partition_key": "status", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        TableDef(
            _resolve_table_name(S.shipment_items_table_name, "shipment_items"),
            "shipment_id",
            "item_id",
        ),
        TableDef(
            _resolve_table_name(S.shipment_packages_table_name, "shipment_packages"),
            "shipment_id",
            "package_seq",
        ),
        TableDef(
            _resolve_table_name(S.account_views_table_name, "account_views"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "by-owner", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "by-grantee", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
            ],
            attr_types={"GSI1SK": "N", "GSI2SK": "N"},
        ),
        TableDef(
            _resolve_table_name(S.entitlement_requests_table_name, "entitlement_requests"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "by-status", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "by-requester", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
            ],
            attr_types={"GSI1SK": "N", "GSI2SK": "N"},
        ),
        # WOV-001: maintenance work orders — co-located by property partition.
        # GSI_WO_STATUS: system-wide status queue (Kanban columns).
        # GSI_WO_ASSIGNEE: sparse — WOs with assignee_sub only; drives "my work" view.
        TableDef(
            _resolve_table_name(S.maintenance_orders_table_name, "maintenance_orders"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI_WO_STATUS", "partition_key": "wo_status", "sort_key": "created_at"},
                {"index_name": "GSI_WO_ASSIGNEE", "partition_key": "assignee_sub", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # WOV-004: standalone vendor directory (used when PUR-002/003 are unbuilt).
        # GSI_VENDOR_STATUS: active/inactive listing by trade category.
        TableDef(
            _resolve_table_name(S.maintenance_vendors_table_name, "maintenance_vendors"),
            "vendor_id",
            "sk",
            gsi=[
                {"index_name": "GSI_VENDOR_STATUS", "partition_key": "status", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # ── CRM Activities scaffold (ACT-001) ────────────────────────────────
        TableDef(
            _resolve_table_name(S.crm_tasks_table_name, "crm_tasks"),
            "user_sub",
            "sk",
            gsi=[
                {"index_name": "ByStatus",   "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "ByAssignee", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
            ],
            attr_types={"GSI1SK": "N", "GSI2SK": "N"},
        ),
        TableDef(
            _resolve_table_name(S.crm_notes_table_name, "crm_notes"),
            "user_sub",
            "sk",
            gsi=[
                {"index_name": "ByEntity", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
            ],
            attr_types={"GSI1SK": "N"},
        ),
        TableDef(
            _resolve_table_name(S.crm_activity_timeline_table_name, "crm_activity_timeline"),
            "entity_key",
            "sk",
            gsi=[
                {"index_name": "ByType", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
            ],
            attr_types={"GSI1SK": "N"},
        ),
        TableDef(
            _resolve_table_name(S.crm_event_rsvp_table_name, "crm_event_rsvp"),
            "event_key",
            "attendee_sub",
            gsi=[
                {"index_name": "ByUser", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
            ],
            attr_types={"GSI1SK": "N"},
        ),
        TableDef(
            _resolve_table_name(S.crm_event_reminders_table_name, "crm_event_reminders"),
            "reminder_key",
            "reminder_id",
            gsi=[
                {"index_name": "DueReminders", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
            ],
            attr_types={"GSI1SK": "N"},
        ),
        # PRT-001: ATS Career Portal
        TableDef(
            _resolve_table_name(S.career_portal_table_name, "CareerPortal"),
            "pk",      # partition key (String)
            "sk",      # sort key (String)
            gsi=[
                {"index_name": "ByJob", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
            ],
            attr_types={"GSI1SK": "N"},   # numeric sort key — MUST be declared (CLAUDE.md gotcha)
        ),
        # QloApps Hotel PMS — HTL-018: hotel_reservations
        # PK=reservation_id, SK=sk (META header + HIST#* history rows).
        # GSI_HOTEL_ARRIVALS: PK=hotel_id, SK=checkin (S) — arrivals board.
        # GSI_GUEST:          PK=guest_party_id, SK=created_at (N) — guest history.
        # GSI_HOTEL_STATUS:   PK=hotel_id, SK=status (S) — in-house / confirmed buckets.
        TableDef(
            _resolve_table_name(S.hotel_reservations_table_name, "hotel_reservations"),
            "reservation_id",
            "sk",
            gsi=[
                {
                    "index_name": "GSI_HOTEL_ARRIVALS",
                    "partition_key": "hotel_id",
                    "sort_key": "checkin",
                },
                {
                    "index_name": "GSI_GUEST",
                    "partition_key": "guest_party_id",
                    "sort_key": "created_at",
                },
                {
                    "index_name": "GSI_HOTEL_STATUS",
                    "partition_key": "hotel_id",
                    "sort_key": "status",
                },
            ],
            attr_types={"created_at": "N"},
        ),
        # QloApps Hotel PMS — HTL-006: hotel_rooms
        # PK=hotel_id, SK=ROOM#{room_id}.
        # GSI_ROOMTYPE:  PK=room_type_id, SK=created_at (N).
        # GSI_HK_STATUS: PK=hotel_id, SK=housekeeping_status (S) — HK board.
        TableDef(
            _resolve_table_name(S.hotel_rooms_table_name, "hotel_rooms"),
            "hotel_id",
            "sk",
            gsi=[
                {
                    "index_name": "GSI_ROOMTYPE",
                    "partition_key": "room_type_id",
                    "sort_key": "created_at",
                },
                {
                    "index_name": "GSI_HK_STATUS",
                    "partition_key": "hotel_id",
                    "sort_key": "housekeeping_status",
                },
            ],
            attr_types={"created_at": "N"},
        ),
        # OFBiz Facility/Fulfillment (FAC-002) — Milestone 4+
        # facilities: facility headers (SK=META) + location rows (SK=LOC#{id}).
        # GSI_OWNER for per-owner list; GSI_STATUS for admin queue.
        TableDef(
            _resolve_table_name(S.facilities_table_name, "facilities"),
            "facility_id",
            "sk",
            gsi=[
                {"index_name": "GSI_OWNER",  "partition_key": "owner_sub",  "sort_key": "created_at"},
                {"index_name": "GSI_STATUS", "partition_key": "status",     "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # transfers: header (SK=META) + per-SKU line rows (SK=ITEM#{n}).
        TableDef(
            _resolve_table_name(S.transfers_table_name, "transfers"),
            "transfer_id",
            "sk",
            gsi=[
                {"index_name": "GSI_STATUS",   "partition_key": "status",           "sort_key": "created_at"},
                {"index_name": "GSI_FROM_LOC", "partition_key": "from_location_id", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # receipts: inbound goods receipts. Header (SK=META) + line rows (SK=ITEM#{n}).
        # GSI_FACILITY for per-facility listing; GSI_PO consumed by PUR module;
        # GSI_STATUS for admin queue.
        TableDef(
            _resolve_table_name(S.receipts_table_name, "receipts"),
            "receipt_id",
            "sk",
            gsi=[
                {"index_name": "GSI_FACILITY", "partition_key": "facility_id", "sort_key": "created_at"},
                {"index_name": "GSI_PO",       "partition_key": "po_id",       "sort_key": "created_at"},
                {"index_name": "GSI_STATUS",   "partition_key": "status",      "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # picklists: pick work orders. Header (SK=META) + line rows (SK=LINE#{n}).
        TableDef(
            _resolve_table_name(S.picklists_table_name, "picklists"),
            "picklist_id",
            "sk",
            gsi=[
                {"index_name": "GSI_ORDER",  "partition_key": "order_id", "sort_key": "created_at"},
                {"index_name": "GSI_STATUS", "partition_key": "status",   "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # lot_serial: reserved for FAC-011+ lot/serial tracking. Not wired in T
        # until FAC-014 explicitly enables it. Created now to avoid a breaking
        # just-restart when that ticket ships.
        TableDef(
            _resolve_table_name(S.lot_serial_table_name, "lot_serial"),
            "sku",
            "sk",   # LOT#{lot_id}  or  SERIAL#{serial}
            gsi=[
                {"index_name": "GSI_LOT_STATUS", "partition_key": "lot_status", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        TableDef(
            _resolve_table_name(S.rent_period_markers_table_name, "rent_period_markers"),
            "pk",
            "sk",
        ),
        # INV-002: currency registry. pk=CURRENCY#{iso}, sk=META.
        # GSI1=active currencies alphabetically (CURRENCIES#ACTIVE / iso_code, string).
        TableDef(
            _resolve_table_name(S.crm_currencies_table_name, "crm_currencies"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
            ],
        ),
        # INV-005: named tax rate registry. pk=TAXRATE#{id}, sk=META.
        # GSI1=active rates alphabetically; GSI2=by jurisdiction. Both SKs string.
        TableDef(
            _resolve_table_name(S.crm_tax_rates_table_name, "crm_tax_rates"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "taxrates-active-index", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "taxrates-jurisdiction-index", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
            ],
        ),
        # OBP Transaction Requests + Step-Up SCA (TXR-001..TXR-005)
        TableDef(
            _resolve_table_name(S.txn_requests_table_name, "txn_requests"),
            "user_sub",
            "request_id",
            gsi=[{"index_name": "GSI_STATUS", "partition_key": "status", "sort_key": "created_at"}],
            attr_types={"created_at": "N"},
        ),
        # EML-002: Admin runtime email settings (single CONFIG/GLOBAL row)
        TableDef(
            _resolve_table_name(S.email_settings_table_name, "email_settings"),
            "pk",
            "sk",
        ),
        # EML-003: Per-user IMAP/SMTP account connections
        TableDef(
            _resolve_table_name(S.user_email_accounts_table_name, "user_email_accounts"),
            "pk",
            "sk",
            gsi=[
                {
                    "index_name": "ByUser",
                    "partition_key": "pk",
                    "sort_key": "created_at",
                }
            ],
            attr_types={"created_at": "N"},
        ),
        # EML-004: IMAP inbox sync messages (and sync cursor rows)
        TableDef(
            _resolve_table_name(S.user_email_messages_table_name, "user_email_messages"),
            "pk",
            "sk",
            gsi=[
                {
                    "index_name": "ByFolder",
                    "partition_key": "folder_pk",
                    "sort_key": "date_ts",
                },
                {
                    "index_name": "ByThread",
                    "partition_key": "pk",
                    "sort_key": "thread_id",
                },
            ],
            attr_types={"date_ts": "N"},
        ),
        # EML-007: Email archiving — relate email to CRM record
        TableDef(
            _resolve_table_name(S.email_archive_table_name, "email_archive"),
            "pk",
            "sk",
            gsi=[
                {
                    "index_name": "ByUser",
                    "partition_key": "gsi_user_pk",
                    "sort_key": "archived_at",
                }
            ],
            attr_types={"archived_at": "N"},
        ),
        # QloApps hotel-PMS vertical (HTL-018): reservation entity with three GSIs.
        # GSI_HOTEL_ARRIVALS: arrivals board (hotel_id/checkin S)
        # GSI_GUEST: guest booking history newest-first (guest_party_id/created_at N)
        # GSI_HOTEL_STATUS: hotel reservations by lifecycle status (hotel_id/status S)
        # attr_types: created_at is numeric (GSI_GUEST SK) — omitting would cause
        #             ValidationException when querying with integer values.
        TableDef(
            _resolve_table_name(S.hotel_reservations_table_name, "hotel_reservations"),
            "reservation_id",
            "sk",
            gsi=[
                {"index_name": "GSI_HOTEL_ARRIVALS", "partition_key": "hotel_id",       "sort_key": "checkin"},
                {"index_name": "GSI_GUEST",          "partition_key": "guest_party_id", "sort_key": "created_at"},
                {"index_name": "GSI_HOTEL_STATUS",   "partition_key": "hotel_id",       "sort_key": "status"},
            ],
            attr_types={"created_at": "N"},
        ),
        # RSK-001: ATS skill registry + assignment store.
        # GSI1 (ByName) enables autocomplete prefix scan: GSI1PK="NAME_PREFIX#{c}" / GSI1SK=name_lc (STRING).
        # GSI1SK is a STRING sort key — do NOT add "N" to attr_types.
        TableDef(
            _resolve_table_name(S.ats_skills_table_name, "ats_skills"),
            "pk",
            "sk",
            gsi=[
                {
                    "index_name": "ByName",
                    "partition_key": "GSI1PK",
                    "sort_key": "GSI1SK",
                },
            ],
            attr_types={},
        ),
        # LSE-001 (open-property Lease entity). Two GSIs; numeric sort keys declared
        # in attr_types to avoid ValidationException when queried with integer values.
        TableDef(
            _resolve_table_name(S.leases_table_name, "leases"),
            "pk",
            "sk",
            gsi=[
                {
                    "index_name": "leases-all-index",
                    "partition_key": "GSI1PK",
                    "sort_key": "GSI1SK",
                },
                {
                    "index_name": "leases-by-status-index",
                    "partition_key": "GSI2PK",
                    "sort_key": "GSI2SK",
                },
            ],
            attr_types={"GSI1SK": "N", "GSI2SK": "N"},
        ),
        # QloApps hotel-PMS vertical (HTL-001 + HTL-005): hotel entity table.
        # META header row + ROOMTYPE#{room_type_id} + AMEN#{amenity_id} child rows.
        # GSI_OWNER: list a hotelier's hotels newest-first (PK=owner_sub, SK=created_at).
        # GSI_STATUS: admin listing by status (PK=status, SK=created_at).
        # GSI_HOTEL_ROOMTYPES: list a hotel's room types newest-first (PK=hotel_id, SK=created_at).
        # attr_types: created_at is N (integer Unix seconds from now_ts()).
        TableDef(
            _resolve_table_name(S.hotels_table_name, "hotels"),
            "hotel_id",
            "sk",
            gsi=[
                {"index_name": "GSI_OWNER",          "partition_key": "owner_sub",  "sort_key": "created_at"},
                {"index_name": "GSI_STATUS",         "partition_key": "status",     "sort_key": "created_at"},
                {"index_name": "GSI_HOTEL_ROOMTYPES","partition_key": "hotel_id",   "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # QloApps hotel-PMS vertical (HTL-006 + HTL-007): individual rooms table.
        # ROOM#{room_id} rows + HKTASK#{task_id} child rows on the hotel partition.
        # GSI_ROOMTYPE: list rooms of a given type newest-first (PK=room_type_id, SK=created_at).
        # GSI_HK_STATUS: query a hotel's rooms by housekeeping status (PK=hotel_id, SK=hk_status).
        # GSI_HK_TASK_STATUS: list a hotel's tasks by status (PK=hotel_id, SK=status).
        # GSI_HK_ASSIGNEE: list a staffer's assigned tasks newest-first (PK=assignee_sub, SK=created_at).
        # attr_types: created_at is N; housekeeping_status and status are S (no override needed).
        TableDef(
            _resolve_table_name(S.hotel_rooms_table_name, "hotel_rooms"),
            "hotel_id",
            "sk",
            gsi=[
                {"index_name": "GSI_ROOMTYPE",       "partition_key": "room_type_id", "sort_key": "created_at"},
                {"index_name": "GSI_HK_STATUS",      "partition_key": "hotel_id",     "sort_key": "housekeeping_status"},
                {"index_name": "GSI_HK_TASK_STATUS", "partition_key": "hotel_id",     "sort_key": "status"},
                {"index_name": "GSI_HK_ASSIGNEE",    "partition_key": "assignee_sub", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # Knowledge Base (KB-001) — crm_kb_articles single-table for all KB data
        TableDef(
            _resolve_table_name(S.kb_articles_table, "crm_kb_articles"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByCategory", "partition_key": "category",   "sort_key": "published_at"},
                {"index_name": "ByStatus",   "partition_key": "status",     "sort_key": "published_at"},
                {"index_name": "ByAuthor",   "partition_key": "author_sub", "sort_key": "created_at"},
                {"index_name": "ByTag",      "partition_key": "tag",        "sort_key": "created_at"},
            ],
            attr_types={"published_at": "N", "created_at": "N"},
        ),
        # TEN-001: Property management — tenant directory
        # GSI_OWNER: newest-first listing per landlord (sort key created_at is numeric)
        # GSI_PARTY: reverse-lookup from PTY party_id → tenant META row
        TableDef(
            _resolve_table_name(S.property_tenants_table_name, "property_tenants"),
            "PK",
            "SK",
            gsi=[
                {"index_name": "GSI_OWNER", "partition_key": "owner_id", "sort_key": "created_at"},
                {"index_name": "GSI_PARTY", "partition_key": "party_id", "sort_key": "SK"},
            ],
            attr_types={"created_at": "N"},
        ),
        # PIP-001: ATS Recruiting Pipeline junction table.
        # Stores pipeline entries (USER#{owner_sub} / PIPE#{job_id}#CAND#{cand_id}),
        # the status-config singleton (PIPELINE_STATUS_CONFIG / META), and
        # placement sub-rows (USER#{owner_sub} / PIPE#{job_id}#CAND#{cand_id}#PLACEMENT).
        # No numeric GSI sort keys in PIP-001..PIP-006; no attr_types needed.
        TableDef(
            _resolve_table_name(S.ats_pipeline_table_name, "ats_pipeline"),
            "pk",
            "sk",
        ),
        # PRD-002 (OFBiz Catalog Depth): dedicated product_depth table for virtual/variant
        # products, feature categories, price components, bundles, and associations.
        # All numeric GSI sort keys declared in attr_types per CLAUDE.md convention.
        TableDef(
            _resolve_table_name(S.product_depth_table_name, "product_depth"),
            "PK",
            "SK",
            gsi=[
                {"index_name": "ByParent",          "partition_key": "GSI_PARENT_PK", "sort_key": "GSI_PARENT_SK"},
                {"index_name": "ByFeatureCategory", "partition_key": "GSI_FTCAT_PK",  "sort_key": "GSI_FTCAT_SK"},
                {"index_name": "ByVirtualParent",   "partition_key": "GSI_VIRT_PK",   "sort_key": "GSI_VIRT_SK"},
                {"index_name": "ByAssocSource",     "partition_key": "GSI_ASSOC_PK",  "sort_key": "GSI_ASSOC_SK"},
                {"index_name": "ByItemPrice",       "partition_key": "GSI_PRICE_PK",  "sort_key": "GSI_PRICE_SK"},
            ],
            attr_types={
                "GSI_PARENT_SK": "N",   # category position (int)
                "GSI_FTCAT_SK":  "N",   # feature-value position (int)
                "GSI_VIRT_SK":   "N",   # variant created_at (int)
                "GSI_PRICE_SK":  "N",   # price effective_at (int)
            },
        ),
        # OFBiz GL Milestone 4 — chart of accounts (OFB-013).
        # gl_accounts: one row per account (PK=account_code, SK=META).
        # GSI_CLASS groups accounts by class for OFB-014 mapping.
        TableDef(
            _resolve_table_name(S.gl_accounts_table_name, "gl_accounts"),
            "account_code",
            "sk",
            gsi=[
                {"index_name": "GSI_CLASS", "partition_key": "account_class", "sort_key": "account_code"},
            ],
        ),
        # gl_journal: balanced double-entry journal entries (OFB-014).
        # PK=JE#GLOBAL, SK=JE#{id} (header) | JL#{id}#{seq} (lines).
        # ENTRIES_BY_DATE drives date-range queries; SOURCE_ENTRY_IDX idempotency.
        TableDef(
            _resolve_table_name(S.gl_journal_table_name, "gl_journal"),
            "PK",
            "SK",
            gsi=[
                {"index_name": "ENTRIES_BY_DATE", "partition_key": "ledger_date", "sort_key": "posted_at"},
                {"index_name": "SOURCE_ENTRY_IDX", "partition_key": "source_entry_id", "sort_key": "posted_at"},
            ],
            attr_types={"posted_at": "N"},
        ),
        # ar_ap_snapshots: point-in-time AR/AP aging snapshots (OFB-015).
        # PK="AR"|"AP", SK="SNAP#{ts}#{snap_id}"; GSI_DATE for time-range queries.
        TableDef(
            _resolve_table_name(S.ar_ap_snapshots_table_name, "ar_ap_snapshots"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI_DATE", "partition_key": "pk", "sort_key": "ts"},
            ],
            attr_types={"ts": "N"},
        ),
        # OFBiz GL Milestone 5 — pricing rules engine (OFB-019/020).
        # PricingRules: tiered/bulk/conditional rules + audit + redemption rows.
        # PK=pk, SK=sk; ByCreatorCreatedAt + ByActive GSIs.
        TableDef(
            _resolve_table_name(S.pricing_rules_table_name, "PricingRules"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByCreatorCreatedAt", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "ByActive", "partition_key": "active_pk", "sort_key": "created_at"},
            ],
            attr_types={"GSI1SK": "N", "created_at": "N"},
        ),
        # HTL-014: Hotel nightly rate plans — plan header (SK=META) + rule child
        # rows (SK=RULE#{kind}#{rule_id}) co-located on a hotel_id#room_type_id
        # partition.  GSI_HOTEL lists plans for a hotel; GSI_ROOM_TYPE fetches
        # the plan(s) for a room type.  created_at is the numeric GSI sort key on
        # both indexes — attr_types required (CLAUDE.md "DynamoDB numeric GSI sort
        # keys" gotcha; omitting it stores created_at as String → ValidationException).
        TableDef(
            _resolve_table_name(S.hotel_rate_plans_table_name, "hotel_rate_plans"),
            "hotel_id#room_type_id",
            "sk",
            gsi=[
                {"index_name": "GSI_HOTEL",     "partition_key": "hotel_id",     "sort_key": "created_at"},
                {"index_name": "GSI_ROOM_TYPE", "partition_key": "room_type_id", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # HTL-010..HTL-011 (QloApps hotel PMS): per-room-type per-date availability.
        # PK=availability_pk ("{hotel_id}#{room_type_id}"), SK="DATE#{YYYY-MM-DD}".
        # Hold meta rows use PK="HOLD#{hold_id}", SK="META".
        # GSI_HOTEL_DATE: hotel-wide calendar aggregation across all room types.
        # GSI_HOLD_EXPIRY: TTL sweep for expiring holds (expires_at is numeric).
        # attr_types: updated_at=N (mutation timestamp), expires_at=N (hold TTL).
        TableDef(
            _resolve_table_name(S.hotel_availability_table_name, "hotel_availability"),
            "availability_pk",
            "sk",
            gsi=[
                {"index_name": "GSI_HOTEL_DATE",  "partition_key": "hotel_id",      "sort_key": "date"},
                {"index_name": "GSI_HOLD_EXPIRY", "partition_key": "gsi_expiry_pk", "sort_key": "expires_at"},
            ],
            attr_types={"updated_at": "N", "expires_at": "N"},
        ),
        # STU-001: CRM Security Suite, Studio & Admin scaffolding
        TableDef(
            S.crm_acl_roles_table_name,
            "pk", "sk",
            gsi=[{"index_name": "by-assignee", "partition_key": "assignee_id", "sort_key": "assigned_at"}],
            attr_types={"assigned_at": "N"},
        ),
        TableDef(
            S.crm_security_groups_table_name,
            "pk", "sk",
            gsi=[{"index_name": "by-record", "partition_key": "record_ref", "sort_key": "created_at"}],
            attr_types={"created_at": "N"},
        ),
        TableDef(S.crm_studio_fields_table_name, "entity_type", "field_key"),
        TableDef(S.crm_studio_modules_table_name, "pk", "sk"),
        TableDef(S.crm_studio_layouts_table_name, "pk", "sk"),
        TableDef(S.crm_studio_dropdowns_table_name, "pk", "sk"),
        TableDef(
            S.crm_audit_trail_table_name,
            "pk", "sk",
            gsi=[{"index_name": "by-actor", "partition_key": "actor_sub", "sort_key": "changed_at"}],
            attr_types={"changed_at": "N"},
        ),
        TableDef(S.currencies_table_name, "pk", "sk"),
        TableDef(S.search_config_table_name, "pk", "sk"),
        TableDef(
            S.email_queue_table_name,
            "pk", "sk",
            gsi=[{"index_name": "by-status", "partition_key": "status", "sort_key": "queued_at"}],
            attr_types={"queued_at": "N"},
        ),
        # CRM Cases (CAS-001) — six new tables
        TableDef(
            _resolve_table_name(S.crm_cases_counter_table, "crm_cases_counters"),
            "counter_id",
            "scope",
        ),
        TableDef(
            _resolve_table_name(S.crm_cases_links_table, "crm_cases_links"),
            "ticket_id",
            "sk",
            gsi=[
                {"index_name": "ByRelated", "partition_key": "related_ticket_id", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        TableDef(
            _resolve_table_name(S.crm_cases_templates_table, "crm_cases_templates"),
            "template_id",
            "sk",
            gsi=[
                {"index_name": "ByOwner", "partition_key": "owner_sub", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        TableDef(
            _resolve_table_name(S.crm_cases_portal_sessions_table, "crm_cases_portal_sessions"),
            "token",
            "sk",
            gsi=[
                {"index_name": "ByEmail", "partition_key": "submitter_email", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        TableDef(
            _resolve_table_name(S.crm_cases_sla_config_table, "crm_cases_sla_config"),
            "config_key",
            "sk",
        ),
        TableDef(
            _resolve_table_name(S.crm_kb_articles_table, "crm_kb_articles"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByCategory", "partition_key": "category", "sort_key": "published_at"},
                {"index_name": "ByStatus", "partition_key": "status", "sort_key": "published_at"},
            ],
            attr_types={"published_at": "N"},
        ),
        # CAS-007: ticket watchers table
        TableDef(
            _resolve_table_name(S.crm_cases_watchers_table, "crm_cases_watchers"),
            "ticket_id",
            "sk",
            gsi=[
                {"index_name": "ByWatcher", "partition_key": "watcher_sub", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # CRM Workflow Rules (WFL-001)
        TableDef(
            _resolve_table_name(S.crm_workflow_rules_table_name, "crm_workflow_rules"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByModule", "partition_key": "GSI_MODULE_PK", "sort_key": "GSI_MODULE_SK"},
            ],
            attr_types={"GSI_MODULE_SK": "N"},
        ),
        # CRM Workflow Runs (WFL-001)
        TableDef(
            _resolve_table_name(S.crm_workflow_runs_table_name, "crm_workflow_runs"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByRecord", "partition_key": "GSI_RECORD_PK", "sort_key": "GSI_RECORD_SK"},
            ],
            attr_types={"GSI_RECORD_SK": "N"},
        ),
        # CRM Reports & Dashboards (RPT-001)
        # crm_reports: report definitions, RUN rows, and SCHEDULE rows (single-table).
        # GSI1: owner-reports-index  (GSI1PK=OWNER#{owner_sub}, GSI1SK=created_at N)
        # GSI2: rpt-schedules-due-index (GSI2PK=RPT_SCHEDULES#ACTIVE, GSI2SK=next_run_at N)
        TableDef(
            _resolve_table_name(S.crm_reports_table_name, "crm_reports"),
            "report_id",
            "sk",
            gsi=[
                {"index_name": "owner-reports-index",     "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "rpt-schedules-due-index", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
            ],
            attr_types={"GSI1SK": "N", "GSI2SK": "N"},
        ),
        # crm_dashboards: per-user dashboard layout (single item per user).
        TableDef(
            _resolve_table_name(S.crm_dashboards_table_name, "crm_dashboards"),
            "dashboard_id",
            "sk",
            gsi=[
                {"index_name": "owner-dashboards-index", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
            ],
            attr_types={"GSI1SK": "N"},
        ),
        # crm_saved_searches: named saved filter expressions.
        TableDef(
            _resolve_table_name(S.crm_saved_searches_table_name, "crm_saved_searches"),
            "saved_search_id",
            "sk",
            gsi=[
                {"index_name": "owner-searches-index", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
            ],
            attr_types={"GSI1SK": "N"},
        ),
        # CRM Leads (LED-001): single table for Lead + Prospect records.
        # GSI sort keys are integer Unix timestamps → must declare attr_types N.
        # LED-007 adds ByEmail GSI (GSI4) for O(1) email-based dedup.
        TableDef(
            _resolve_table_name(S.leads_table_name, "leads"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByOwner",  "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "ByStatus", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
                {"index_name": "BySource", "partition_key": "GSI3PK", "sort_key": "GSI3SK"},
                {"index_name": "ByEmail",  "partition_key": "GSI4PK", "sort_key": "GSI4SK"},
            ],
            attr_types={
                "GSI1SK": "N", "GSI2SK": "N", "GSI3SK": "N",
                "GSI4SK": "N",
            },
        ),
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
        # OAU-001: OAuth consumer-app registry (single-table: META + CODE# + GRANT# + OIDC_SIGNING_KEY rows)
        TableDef(
            _resolve_table_name(S.oauth_consumers_table_name, "oauth_consumers"),
            "client_id",
            "sk",
            gsi=[{
                "index_name": S.oauth_consumers_owner_index,
                "partition_key": "owner_sub",
                "sort_key": "created_at",
            }],
            attr_types={"created_at": "N"},
        ),
        TableDef(_resolve_table_name(S.alerts_table_name, "alerts"), "user_sub", "alert_id"),
        TableDef(_resolve_table_name(S.alert_prefs_table_name, "alert_prefs"), "user_sub"),
        TableDef(_resolve_table_name(S.push_devices_table_name, "push_devices"), "user_sub", "device_id"),
        # GAP-0202 / FIN-013: GSI_LEDGER_DATE lets the platform financial
        # dashboard query ledger entries by day instead of scanning the whole
        # billing table (which also holds payment methods + balance rows).
        TableDef(
            _resolve_table_name(S.billing_table_name, "billing"),
            "pk",
            "sk",
            gsi=[{
                "index_name": "GSI_LEDGER_DATE",
                "partition_key": "ledger_date",
                "sort_key": "sk",
            }],
            attr_types={"ledger_date": "S"},
        ),
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
        # GAP-0189 / FIN-003: per-stage cart reminder configuration
        TableDef(
            _resolve_table_name(S.cart_reminder_config_table_name, "cart_reminder_config"),
            "pk", "sk",
        ),
        # GAP-0348 / SHOP-001: ByItemId GSI lets adjust_stock + sibling endpoints
        # resolve an item from a bare item_id with an O(1) query instead of a
        # full-table scan (_find_item_by_id in app/routers/catalog.py). Catalog
        # item rows already carry item_id as a top-level attribute.
        TableDef(
            _resolve_table_name(S.catalog_table_name, "shopping_catalog"),
            "PK",
            "SK",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "ByItemId", "partition_key": "item_id"},
            ],
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
                # GAP-0282 (KYC-019): sparse index over admin availability records
                # (only items carrying both entity_type + admin_sub are projected),
                # so workload lookups Query instead of full-table Scanning.
                {"index_name": S.kyc_cases_entity_type_index_name, "partition_key": "entity_type", "sort_key": "admin_sub"},
                # GAP-0283 (KYC-019): sparse index over the top-level denormalized
                # ``assigned_admin_sub`` (written on assignment, removed on unclaim)
                # + ``gsi_status_pk``. Only assigned cases project, so per-admin
                # active-case counts run a targeted Select=COUNT Query per admin
                # instead of loading every active case into memory.
                {"index_name": S.kyc_cases_assigned_admin_index_name, "partition_key": "assigned_admin_sub", "sort_key": "gsi_status_pk"},
            ],
            attr_types={"gsi_pii_accessor_sk": "N", "entity_type": "S", "admin_sub": "S", "assigned_admin_sub": "S", "gsi_status_pk": "S"},
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
        # CRM Project Management (PRJ-001)
        # crm_pm_projects: PK=OWNER#{owner_sub}, SK=PROJECT#{project_id}
        #   GSI1: single-project lookup by project_id
        #   GSI2: status-filtered list sorted by created_at (N)
        #   GSI3: per-account project lookup sorted by created_at (N) (PRJ-011)
        TableDef(
            _resolve_table_name(S.crm_pm_projects_table_name, "crm_pm_projects"),
            "PK",
            "SK",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
                {"index_name": "GSI3", "partition_key": "GSI3PK", "sort_key": "GSI3SK"},
            ],
            attr_types={"GSI2SK": "N", "GSI3SK": "N"},
        ),
        # crm_pm_tasks: PK=PROJECT#{project_id}, SK=TASK#{task_order:06d}#{task_id}
        #   GSI1: single-task lookup by task_id
        #   GSI2: per-assignee workload sorted by end_date (N)
        TableDef(
            _resolve_table_name(S.crm_pm_tasks_table_name, "crm_pm_tasks"),
            "PK",
            "SK",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
            ],
            attr_types={"GSI2SK": "N"},
        ),
        # crm_pm_members: PK=PROJECT#{project_id}, SK=MEMBER#{user_sub}
        #   GSI1: per-user project membership list
        TableDef(
            _resolve_table_name(S.crm_pm_members_table_name, "crm_pm_members"),
            "PK",
            "SK",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
            ],
        ),
        # crm_pm_templates: PK=OWNER#{owner_sub}, SK=TEMPLATE#{template_id}
        #   GSI1: template lookup by template_id
        TableDef(
            _resolve_table_name(S.crm_pm_templates_table_name, "crm_pm_templates"),
            "PK",
            "SK",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
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
            "sk",
            gsi=[
                {"index_name": "GSI_USER", "partition_key": "user_id", "sort_key": "created_at"},
                {"index_name": "GSI_STATUS", "partition_key": "status", "sort_key": "created_at"},
                {"index_name": "GSI_ORDER_STATUS", "partition_key": "lifecycle_status", "sort_key": "updated_ts"},
                {"index_name": "GSI_SHIP_DATE", "partition_key": "ship_date_bucket", "sort_key": "ship_ts"},
            ],
            attr_types={"updated_ts": "N", "ship_ts": "N"},
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
        # Sales pipeline — Opportunities (OPP-001)
        TableDef(
            _resolve_table_name(S.sales_opportunities_table_name, "sales_opportunities"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI_BY_USER_CLOSE", "partition_key": "owner_sub", "sort_key": "close_date"},
                {"index_name": "GSI_BY_STAGE",      "partition_key": "stage",     "sort_key": "close_date"},
                {"index_name": "GSI_DIRECT",        "partition_key": "opp_id"},
            ],
            attr_types={"close_date": "N", "created_at": "N"},
        ),
        # Sales pipeline — Quotas (OPP-001)
        TableDef(
            _resolve_table_name(S.sales_quotas_table_name, "sales_quotas"),
            "pk",
            "sk",
        ),
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
                # TBT-002 — sparse ByBounty GSI: funded+unclaimed bounty board.
                # gsi_bounty_pk="BOUNTY#OPEN" / gsi_bounty_sk=created_at (numeric).
                {"index_name": S.tickets_bounty_index_name, "partition_key": "gsi_bounty_pk", "sort_key": "gsi_bounty_sk"},
                # CAS-003: priority filter index (gsi_priority_sk is a lexicographic string, not numeric)
                {"index_name": S.tickets_priority_index_name, "partition_key": "gsi_priority_pk", "sort_key": "gsi_priority_sk"},
                # CAS-005: contact/account link indexes
                {"index_name": S.tickets_contact_index_name, "partition_key": "gsi_contact_pk", "sort_key": "gsi_contact_sk"},
                {"index_name": S.tickets_account_index_name, "partition_key": "gsi_account_pk", "sort_key": "gsi_account_sk"},
            ],
            # TBT-002 — numeric sort key for the ByBounty GSI (CLAUDE.md gotcha).
            attr_types={"gsi_bounty_sk": "N"},
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
            gsi=[{"index_name": "MessageIdIndex", "partition_key": "message_id"}],
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
        # Video Comments (VOD-017 / GAP-0380) — durable, NO TTL (moved out of VideoViews)
        TableDef(
            os.environ.get("DDB_VIDEO_COMMENTS", "VideoComments"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByVideoCreatedAt", "partition_key": "video_id", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
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
        # Analytics Events (GAP-0333 / PLATFORM-019): raw event store that feeds
        # the rollup job. TTL on "ttl_epoch" is enabled in main() via
        # _enable_ttl_if_needed (default ddb_ttl_attr == "ttl_epoch").
        TableDef(
            _resolve_table_name(S.analytics_events_table_name, "AnalyticsEvents"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
            ],
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
        # ContentKeys (VOD-010 §4.2 / GAP-0374): DRM key revocation records + audit trail.
        # pk=key_id (the revocation record key); GSI ByAssetCreatedAt / ByTenantCreatedAt
        # let revocation/audit queries fetch all records for an asset or tenant.
        TableDef(
            _resolve_table_name(S.content_keys_table_name, "ContentKeys"),
            "key_id",
            gsi=[
                {"index_name": "ByAssetCreatedAt", "partition_key": "asset_id", "sort_key": "created_at"},
                {"index_name": "ByTenantCreatedAt", "partition_key": "tenant_id", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
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
                {"index_name": "ByCreator", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
            ],
            attr_types={"GSI1SK": "N", "GSI2SK": "N"},
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
                # GAP-0210: scheduled (recurring) audit exports — time-ordered
                # query for due schedules. GSI1SK (next_run_at) is numeric.
                {"index_name": "schedules-due-index", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
            ],
            attr_types={"created_at": "N", "GSI1SK": "N"},
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
                # GAP-0176: O(1) invite lookup by invite_id (replaces full table scan in _find_invite)
                {"index_name": "invite-id-index", "partition_key": "invite_id", "sort_key": "org_id"},
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
        # Messenger AI cache (MVA-002): translation/transcript caching.
        TableDef(
            _resolve_table_name(S.message_ai_cache_table_name, "message_ai_cache"),
            "cache_key",
            attr_types={"created_at": "N", "ttl": "N"},
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
                {"index_name": "ByGlobalStatus", "partition_key": "status", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N", "status": "S"},
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
                {"index_name": "ByGlobalStatus", "partition_key": "status", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N", "status": "S"},
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
        # Interactive Claude Code Sessions (ACS-001 / ADR-002)
        # PK pk=USER#{user_id}, SK sk=SESSION#{session_id}; ByWorker GSI keyed on
        # worker_id (S) + created_at (N) so list_sessions_for_worker can return
        # newest-first without a ValidationException (numeric sort key gotcha).
        TableDef(
            _resolve_table_name(S.agent_sessions_table_name, "agent_sessions"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByWorker", "partition_key": "worker_id", "sort_key": "created_at"},
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
        # Agent SSH QA (ADR-003 / AQA-003) — non-interactive SSH exec action
        # records (pk=WORKER#{worker_id}, sk=ACTION#{action_id}). The ByStatus
        # GSI lets the background runner claim pending actions (status=pending)
        # oldest-first; created_at is numeric so it must be declared as "N".
        TableDef(
            _resolve_table_name(S.agent_actions_table_name, "agent_actions"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByStatus", "partition_key": "status", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
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
                # GSI3=overdue scanner (STATUS#sent / due_date) — QUO-005.
                {"index_name": "GSI3", "partition_key": "GSI3PK", "sort_key": "GSI3SK"},
            ],
            attr_types={"GSI1SK": "N", "GSI2SK": "N", "GSI3SK": "N"},
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
        # GAP-0020 / FIN-008: W-9 / TIN collection (KMS-encrypted TIN storage).
        # Records: pk=USER#{user_sub} sk=TAX_INFO. All access by user PK; no GSI.
        TableDef(
            _resolve_table_name(S.tax_info_table_name, "tax_info"),
            "pk",
            "sk",
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
        # GAP-0217 (GEO-001): platform-level geo block list. Single record
        # pk="PLATFORM", sk="GEO_BLOCK" holds the runtime-mutable blocked-country
        # list so ROOT can update it without a backend restart (dev/prod parity).
        TableDef(
            _resolve_table_name(S.geo_rules_table_name, "geo_rules"),
            "pk",
            "sk",
        ),
        # LEX-006: standalone legal holds. PK=pk (HOLD#{hold_id}), SK=sk (META).
        # GSI ByUser lets is_user_on_hold() do an O(1) query keyed on the held
        # user_sub instead of scanning all holds. Sparse: user-index rows carry
        # gsi1pk="USER#{user_sub}" / gsi1sk="HOLD#{hold_id}".
        TableDef(
            _resolve_table_name(S.legal_holds_table_name, "legal_holds"),
            "pk",
            "sk",
            gsi=[{"index_name": "ByUser", "partition_key": "gsi1pk", "sort_key": "gsi1sk"}],
        ),
        # LEX-009/010: law-enforcement / subpoena scoped exports. PK=pk
        # (EXPORT#{legal_export_id}), SK=sk (META).
        TableDef(
            _resolve_table_name(S.legal_exports_table_name, "legal_exports"),
            "pk",
            "sk",
        ),
        # HNY-002: unified security/IDS/honeypot/honeytoken signal store.
        # PK=pk (EVENT#{event_id}), SK=sk (META). GSI ByDate lets the security
        # dashboard query a time window by event_date (S, e.g. "2026-06-09")
        # + ts (N, unix seconds) instead of scanning. ts MUST be declared "N"
        # or DynamoDB stores it as String and queries with integers raise
        # ValidationException (CLAUDE.md numeric-GSI gotcha).
        TableDef(
            _resolve_table_name(S.security_events_table_name, "security_events"),
            "pk",
            "sk",
            gsi=[{"index_name": "ByDate", "partition_key": "event_date", "sort_key": "ts"}],
            attr_types={"ts": "N"},
        ),
        # HNY-002: honeytoken (decoy credential / canary) store. PK=token_id.
        # GSI ByLookupHash resolves a presented decoy key by its lookup_hash
        # (api_key_hash of the secret) so the trip-wire can match without
        # storing decoys in the real api_keys table (attacker-indistinguishable
        # public shape, isolated store).
        TableDef(
            _resolve_table_name(S.honeytokens_table_name, "honeytokens"),
            "token_id",
            gsi=[{"index_name": "ByLookupHash", "partition_key": "lookup_hash"}],
        ),
        # OFBiz commerce/ERP Phase 1 — inventory & soft reservations (ADR-001, OFB-002).
        # inventory: first-class SKU stock record. PK=sku, SK=LOC#{location_id}
        # (single default "warehouse" now; multi-location deferred). GSI_AVAILABLE
        # buckets by status with numeric `available` sort key for low-stock filtering.
        TableDef(
            _resolve_table_name(S.inventory_table_name, "inventory"),
            "sku",
            "location_sk",
            gsi=[
                {"index_name": "GSI_AVAILABLE", "partition_key": "status", "sort_key": "available"},
            ],
            attr_types={"available": "N"},
        ),
        # reservations: reserve -> commit -> release lifecycle. PK=reservation_pk
        # (RES#{reservation_id}), SK=META. GSI_SKU lists reservations per SKU
        # (numeric created_at); GSI_EXPIRY drives the TTL-release loop over active
        # reservations (partition gsi_expiry_pk=SCHED#ACTIVE, numeric expires_at).
        TableDef(
            _resolve_table_name(S.reservations_table_name, "reservations"),
            "reservation_pk",
            "sk",
            gsi=[
                {"index_name": "GSI_SKU", "partition_key": "sku", "sort_key": "created_at"},
                {"index_name": "GSI_EXPIRY", "partition_key": "gsi_expiry_pk", "sort_key": "expires_at"},
            ],
            attr_types={"created_at": "N", "expires_at": "N"},
        ),
        # OFBiz commerce/ERP Milestone 3 — Returns / RMA (ADR-001, OFB-008..010).
        # returns: RMA header (SK=META) + per-line rows (SK=ITEM#{n}) keyed off the
        # existing orders/order_items. GSI_ORDER lists returns for an order; GSI_STATUS
        # drives the admin RMA queue. Both use a numeric created_at sort key.
        TableDef(
            _resolve_table_name(S.returns_table_name, "returns"),
            "return_id",
            "sk",
            gsi=[
                {"index_name": "GSI_ORDER", "partition_key": "order_id", "sort_key": "created_at"},
                {"index_name": "GSI_STATUS", "partition_key": "status", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # BRAND-001 / decision D6: platform-wide branding singleton (name, logo_url,
        # support_email). PK="PLATFORM", SK="BRANDING". No GSIs — singleton fetched
        # by exact key. updated_at is a plain item attribute (N), not a GSI key, so
        # no attr_types entry is needed.
        TableDef(_resolve_table_name(S.platform_settings_table_name, "platform_settings"), "pk", "sk"),
        # Party/CRM single table (PTY-002). Stores Party meta, role, relationship,
        # and contact-mech rows in one table. GSI_CREATED uses a numeric created_at
        # sort key for newest-first pagination; GSI1/2/3 are all-string.
        TableDef(
            _resolve_table_name(S.party_table_name, "party"),
            "PK",
            "SK",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
                {"index_name": "GSI3", "partition_key": "GSI3PK", "sort_key": "GSI3SK"},
                {"index_name": "GSI_CREATED", "partition_key": "type", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # CND-001: ATS Candidates table — single-table design with three GSIs.
        # GSI sort keys are numeric (created_at aliases) — attr_types required
        # to avoid ValidationException on integer range queries (CLAUDE.md gotcha).
        TableDef(
            _resolve_table_name(S.candidates_table_name, "candidates"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "ByOwner",  "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "ByStatus", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
                {"index_name": "BySource", "partition_key": "GSI3PK", "sort_key": "GSI3SK"},
            ],
            attr_types={
                "GSI1SK": "N",
                "GSI2SK": "N",
                "GSI3SK": "N",
            },
        ),
        # ATS — Job Orders (JOB-001)
        TableDef(
            _resolve_table_name(S.job_orders_table_name, "job_orders"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI_BY_STATUS",    "partition_key": "status",        "sort_key": "created_at"},
                {"index_name": "GSI_BY_RECRUITER", "partition_key": "recruiter_sub", "sort_key": "created_at"},
                {"index_name": "GSI_HOT",          "partition_key": "hot_flag",      "sort_key": "created_at"},
                {"index_name": "GSI_PUBLIC",       "partition_key": "public_flag",   "sort_key": "created_at"},
                {"index_name": "GSI_DIRECT",       "partition_key": "job_id"},
            ],
            attr_types={"created_at": "N", "updated_at": "N"},
        ),
        # Property management (open-property vertical, PROP-001..PROP-005).
        # Single table: META header rows + UNIT#{unit_id} child rows.
        # GSI_OWNER: list a landlord's properties newest-first (PROP-001).
        # GSI_STATUS: admin listing by active/archived state (PROP-001).
        # GSI_UNIT_OCCUPANCY: count units by occupancy bucket per property (PROP-002).
        TableDef(
            _resolve_table_name(S.properties_table_name, "properties"),
            "property_id",
            "sk",
            gsi=[
                {"index_name": "GSI_OWNER",          "partition_key": "owner_sub",         "sort_key": "created_at"},
                {"index_name": "GSI_STATUS",         "partition_key": "status",            "sort_key": "created_at"},
                {"index_name": "GSI_UNIT_OCCUPANCY", "partition_key": "property_id",       "sort_key": "occupancy_status"},
            ],
            attr_types={"created_at": "N"},
        ),
        # QloApps hotel-PMS vertical (HTL-002): reusable amenity dictionary table.
        # GSI_CATEGORY: list amenities by category for the FE picker.
        # attr_types: created_at is N.
        TableDef(
            _resolve_table_name(S.hotel_amenities_table_name, "hotel_amenities"),
            "amenity_id",
            "sk",
            gsi=[
                {"index_name": "GSI_CATEGORY", "partition_key": "category", "sort_key": "created_at"},
            ],
            attr_types={"created_at": "N"},
        ),
        # OpenBankProject ACC-001: single-table store for Banks + Accounts +
        # transaction metadata + co-owner reverse-index rows. GSI_ACCOUNT_BY_ID
        # resolves an account by id regardless of owner partition (cross-owner
        # co-access). created_at is the numeric GSI sort key → attr_types "N".
        TableDef(
            _resolve_table_name(S.banking_accounts_table_name, "banking_accounts"),
            "pk",
            "sk",
            gsi=[
                {
                    "index_name": "GSI_ACCOUNT_BY_ID",
                    "partition_key": "account_id",
                    "sort_key": "created_at",
                }
            ],
            attr_types={"created_at": "N"},
        ),
        # QUO-001: AOS Sales Quotes.
        # GSI1=admin cross-user list (QUOTES#ALL / created_at).
        # GSI2=per-user stage filter (USER#{sub}#STAGE#{stage} / created_at).
        TableDef(
            _resolve_table_name(S.aos_quotes_table_name, "aos_quotes"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
            ],
            attr_types={"GSI1SK": "N", "GSI2SK": "N"},
        ),
        # QUO-004: AOS CRM Contracts.
        # GSI1=admin cross-user list (CONTRACTS#ALL / created_at).
        # GSI2=per-user stage + expiry filter (USER#{sub}#STAGE#{stage} / end_date).
        TableDef(
            _resolve_table_name(S.aos_contracts_table_name, "aos_contracts"),
            "pk",
            "sk",
            gsi=[
                {"index_name": "contracts-all-index", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
                {"index_name": "contracts-by-stage-index", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
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
    # GAP-0333 / PLATFORM-019: analytics_events expires raw events via ttl_epoch.
    _enable_ttl_if_needed(ddb, _resolve_table_name(S.analytics_events_table_name, "AnalyticsEvents"))
    # GAP-0347 / SHOP-001: shopping_catalog carries per-item low-stock-alert
    # sentinel rows (ttl_epoch = now+3600) for once-per-hour alert dedup. Only
    # the sentinel rows write ttl_epoch; real catalog/item/review rows omit it
    # and are unaffected by TTL enablement.
    _enable_ttl_if_needed(ddb, _resolve_table_name(S.catalog_table_name, "shopping_catalog"))
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
    # ADS-005 / GAP-0045: Enable TTL on billing table for ad_feedback record expiry.
    # The TTL attribute is "expires_at" (Unix epoch seconds), written only on
    # AD_FEEDBACK# items. Other billing table item types do not write expires_at
    # and are unaffected by TTL enablement.
    _billing_table = _resolve_table_name(S.billing_table_name, "billing")
    try:
        client = ddb.meta.client
        _retry_transient_ddb_call(
            client.update_time_to_live,
            TableName=_billing_table,
            TimeToLiveSpecification={"Enabled": True, "AttributeName": "expires_at"},
        )
    except Exception:
        pass
    print(f"Ensured {len(created)} DynamoDB tables exist.")


if __name__ == "__main__":
    main()
