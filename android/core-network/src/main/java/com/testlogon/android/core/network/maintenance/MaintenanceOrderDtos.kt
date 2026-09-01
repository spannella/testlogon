package com.testlogon.android.core.network.maintenance

import com.squareup.moshi.Json

/**
 * Transport DTOs for the Maintenance Work Orders surface (WOV-001..WOV-005).
 *
 * Backend router: app/routers/maintenance_orders.py (prefix /ui, cookie/bearer session).
 * Master flag: MAINTENANCE_ORDERS_ENABLED (default false -> 404 on all endpoints) — the repository
 * degrades on 404.
 *
 * Mirrors frontend/src/api/endpoints/maintenanceOrders.ts (MaintenanceOrderOut / WoListOut /
 * MaintenanceOrderIn / MaintenanceOrderTransitionIn) and app/models.py WOV models.
 *
 * CODEGEN NOTE: core-network decodes via the reflective Moshi factory, so every wire key carries an
 * explicit @Json(name=...). Optional fields are nullable with defaults so a sparse row decodes. All
 * timestamps are Unix-second Longs (nullable where the backend allows null). `priority` / `wo_status`
 * are raw wire Strings mapped through the lenient domain enums in :app (no second enum adapter here).
 */

/** One maintenance work order (mirrors MaintenanceOrderOut). `work_order_id` is required. */
data class MaintenanceOrderDto(
    @Json(name = "work_order_id") val workOrderId: String,
    @Json(name = "property_id") val propertyId: String,
    @Json(name = "unit_id") val unitId: String? = null,
    @Json(name = "vendor_id") val vendorId: String? = null,
    @Json(name = "assignee_sub") val assigneeSub: String? = null,
    @Json(name = "title") val title: String,
    @Json(name = "description") val description: String? = null,
    @Json(name = "priority") val priority: String = "normal",
    @Json(name = "wo_status") val woStatus: String = "open",
    @Json(name = "scheduled_for") val scheduledFor: Long? = null,
    @Json(name = "cost_cents") val costCents: Long? = null,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
    @Json(name = "completed_at") val completedAt: Long? = null,
    @Json(name = "correlation_id") val correlationId: String? = null,
    @Json(name = "actor_sub") val actorSub: String? = null,
    @Json(name = "escrow_amount_cents") val escrowAmountCents: Long? = null,
    @Json(name = "escrow_status") val escrowStatus: String? = null,
)

/** The {items, count, cursor} list envelope (mirrors WoListOut). */
data class MaintenanceOrderListDto(
    @Json(name = "items") val items: List<MaintenanceOrderDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
    @Json(name = "cursor") val cursor: String? = null,
)

/** Create body for a property-scoped work order (mirrors MaintenanceOrderIn). */
data class CreateMaintenanceOrderRequest(
    @Json(name = "title") val title: String,
    @Json(name = "description") val description: String? = null,
    @Json(name = "priority") val priority: String? = null,
    @Json(name = "property_id") val propertyId: String,
    @Json(name = "unit_id") val unitId: String? = null,
    @Json(name = "scheduled_for") val scheduledFor: Long? = null,
    @Json(name = "correlation_id") val correlationId: String? = null,
    @Json(name = "amount_cents") val amountCents: Long? = null,
)

/** Status-transition body (mirrors MaintenanceOrderTransitionIn). `property_id` scopes authorization. */
data class TransitionMaintenanceOrderRequest(
    @Json(name = "property_id") val propertyId: String,
    @Json(name = "target_status") val targetStatus: String,
    @Json(name = "cost_cents") val costCents: Long? = null,
    @Json(name = "assignee_sub") val assigneeSub: String? = null,
    @Json(name = "vendor_id") val vendorId: String? = null,
)
