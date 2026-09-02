package com.testlogon.android.core.network.maintenance

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * Retrofit interface for the Maintenance Work Orders + Vendor directory endpoint surface (WOV).
 * Transport only.
 *
 * Paths have NO leading slash (relative to the shared Retrofit base URL, matching the rest of
 * core-network). All calls are suspend. Mutating verbs carry an explicit JSON Content-Type. Session
 * cookies / Authorization Bearer / X-CSRF-Token are attached globally by the core-network interceptors.
 * Mutations require admin/root server-side (they 403 otherwise); reads are any-authenticated.
 *
 * Mirrors frontend/src/api/endpoints/maintenanceOrders.ts. The full WOV surface is wired: work-order
 * list/detail/create/status, the board-columns layout, and the vendor directory CRUD (categories /
 * create / list / get / patch / status). The repository degrades on 404 (feature-flag off).
 */
interface MaintenanceOrdersApi {

    /** Static kanban board column layout (mirrors GET /ui/maintenance/work-orders/board-columns). */
    @GET("ui/maintenance/work-orders/board-columns")
    suspend fun getBoardColumns(): WoBoardColumnsDto

    /** System-wide work-order list, optionally filtered by status / assignee (cursor-paged). */
    @GET("ui/maintenance/work-orders")
    suspend fun listWorkOrders(
        @Query("wo_status") woStatus: String? = null,
        @Query("assignee_sub") assigneeSub: String? = null,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
    ): MaintenanceOrderListDto

    /** Property-scoped list. */
    @GET("ui/properties/{propertyId}/work-orders")
    suspend fun listPropertyWorkOrders(
        @Path("propertyId") propertyId: String,
        @Query("wo_status") woStatus: String? = null,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
    ): MaintenanceOrderListDto

    /** Read one work order (property-scoped). */
    @GET("ui/properties/{propertyId}/work-orders/{workOrderId}")
    suspend fun getWorkOrder(
        @Path("propertyId") propertyId: String,
        @Path("workOrderId") workOrderId: String,
    ): MaintenanceOrderDto

    /** Create a property-scoped work order. */
    @Headers("Content-Type: application/json")
    @POST("ui/properties/{propertyId}/work-orders")
    suspend fun createWorkOrder(
        @Path("propertyId") propertyId: String,
        @Body body: CreateMaintenanceOrderRequest,
    ): MaintenanceOrderDto

    /** Transition a work order's status (assigned / in_progress / completed / cancelled). */
    @Headers("Content-Type: application/json")
    @PATCH("ui/maintenance/work-orders/{workOrderId}")
    suspend fun transitionWorkOrder(
        @Path("workOrderId") workOrderId: String,
        @Body body: TransitionMaintenanceOrderRequest,
    ): MaintenanceOrderDto

    // ---- Vendor directory (WOV-004) ----

    /** The allowed vendor trade-categories (mirrors GET /ui/maintenance/vendors/categories). */
    @GET("ui/maintenance/vendors/categories")
    suspend fun listVendorCategories(): VendorCategoriesDto

    /** Create a vendor (admin/root). */
    @Headers("Content-Type: application/json")
    @POST("ui/maintenance/vendors")
    suspend fun createVendor(
        @Body body: VendorCreateRequest,
    ): VendorDto

    /** List vendors, optionally filtered by status / trade_category (cursor-paged). */
    @GET("ui/maintenance/vendors")
    suspend fun listVendors(
        @Query("status") status: String? = null,
        @Query("trade_category") tradeCategory: String? = null,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
    ): VendorListDto

    /** Read one vendor. */
    @GET("ui/maintenance/vendors/{vendorId}")
    suspend fun getVendor(
        @Path("vendorId") vendorId: String,
    ): VendorDto

    /** Patch a vendor's mutable fields (admin/root). */
    @Headers("Content-Type: application/json")
    @PATCH("ui/maintenance/vendors/{vendorId}")
    suspend fun updateVendor(
        @Path("vendorId") vendorId: String,
        @Body body: VendorPatchRequest,
    ): VendorDto

    /** Set a vendor's status active/inactive (admin/root). */
    @Headers("Content-Type: application/json")
    @POST("ui/maintenance/vendors/{vendorId}/status")
    suspend fun setVendorStatus(
        @Path("vendorId") vendorId: String,
        @Body body: VendorStatusRequest,
    ): VendorDto
}
