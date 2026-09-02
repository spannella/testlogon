package com.testlogon.android.feature.maintenance

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.maintenance.CreateMaintenanceOrderRequest
import com.testlogon.android.core.network.maintenance.MaintenanceOrdersApi
import com.testlogon.android.core.network.maintenance.TransitionMaintenanceOrderRequest
import com.testlogon.android.core.network.maintenance.VendorCreateRequest
import com.testlogon.android.core.network.maintenance.VendorPatchRequest
import com.testlogon.android.core.network.maintenance.VendorStatusRequest
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * WOV — data layer for the Maintenance Work Orders + Vendor directory surface.
 *
 * REUSES the core-network [MaintenanceOrdersApi] (raw DTOs) + shared [ApiErrorParser]; maps each DTO to
 * the feature domain BEFORE the typed [ApiResult] (mirrors SignatureRepositoryImpl). DEGRADE-ON-404: a
 * 404 (whole feature flag off) surfaces as an [ApiResult.Failure] with status 404, which the ViewModel
 * renders as a friendly unavailable state rather than an error.
 */
interface MaintenanceOrdersRepository {

    /** System-wide list, optionally filtered by status. */
    suspend fun list(
        status: WoStatus? = null,
        limit: Int? = null,
    ): ApiResult<List<MaintenanceOrder>>

    /** The static kanban board columns. */
    suspend fun boardColumns(): ApiResult<List<WoBoardColumn>>

    /** Create a property-scoped work order. */
    suspend fun create(
        propertyId: String,
        title: String,
        description: String? = null,
        priority: WoPriority? = null,
        unitId: String? = null,
        scheduledFor: Long? = null,
    ): ApiResult<MaintenanceOrder>

    /** Transition a work order to [target] (property scopes authorization). */
    suspend fun transition(
        workOrderId: String,
        propertyId: String,
        target: WoStatus,
        costCents: Long? = null,
    ): ApiResult<MaintenanceOrder>

    // ---- Vendor directory (WOV-004) ----

    /** The allowed vendor trade-category tokens. */
    suspend fun vendorCategories(): ApiResult<List<String>>

    /** List vendors, optionally filtered by status / trade-category. */
    suspend fun listVendors(
        status: VendorStatus? = null,
        tradeCategory: String? = null,
        limit: Int? = null,
    ): ApiResult<List<Vendor>>

    /** Read one vendor. */
    suspend fun getVendor(vendorId: String): ApiResult<Vendor>

    /** Create a vendor. */
    suspend fun createVendor(
        name: String,
        tradeCategory: String,
        email: String? = null,
        phone: String? = null,
    ): ApiResult<Vendor>

    /** Patch a vendor's mutable fields (only non-null fields are sent). */
    suspend fun updateVendor(
        vendorId: String,
        name: String? = null,
        tradeCategory: String? = null,
        email: String? = null,
        phone: String? = null,
    ): ApiResult<Vendor>

    /** Set a vendor's status (active/inactive). */
    suspend fun setVendorStatus(vendorId: String, status: VendorStatus): ApiResult<Vendor>
}

@Singleton
class MaintenanceOrdersRepositoryImpl @Inject constructor(
    private val api: MaintenanceOrdersApi,
    private val errorParser: ApiErrorParser,
) : MaintenanceOrdersRepository {

    override suspend fun list(status: WoStatus?, limit: Int?): ApiResult<List<MaintenanceOrder>> =
        withContext(Dispatchers.IO) {
            call {
                api.listWorkOrders(woStatus = status?.token, limit = limit)
                    .items.map { it.toDomain() }
            }
        }

    override suspend fun boardColumns(): ApiResult<List<WoBoardColumn>> =
        withContext(Dispatchers.IO) {
            call { api.getBoardColumns().columns.map { it.toDomain() } }
        }

    override suspend fun create(
        propertyId: String,
        title: String,
        description: String?,
        priority: WoPriority?,
        unitId: String?,
        scheduledFor: Long?,
    ): ApiResult<MaintenanceOrder> = withContext(Dispatchers.IO) {
        call {
            val body = CreateMaintenanceOrderRequest(
                title = title,
                description = description?.takeIf { it.isNotBlank() },
                priority = priority?.token,
                propertyId = propertyId,
                unitId = unitId?.takeIf { it.isNotBlank() },
                scheduledFor = scheduledFor,
            )
            api.createWorkOrder(propertyId, body).toDomain()
        }
    }

    override suspend fun transition(
        workOrderId: String,
        propertyId: String,
        target: WoStatus,
        costCents: Long?,
    ): ApiResult<MaintenanceOrder> = withContext(Dispatchers.IO) {
        call {
            val body = TransitionMaintenanceOrderRequest(
                propertyId = propertyId,
                targetStatus = target.token,
                costCents = costCents,
            )
            api.transitionWorkOrder(workOrderId, body).toDomain()
        }
    }

    override suspend fun vendorCategories(): ApiResult<List<String>> =
        withContext(Dispatchers.IO) {
            call { api.listVendorCategories().categories }
        }

    override suspend fun listVendors(
        status: VendorStatus?,
        tradeCategory: String?,
        limit: Int?,
    ): ApiResult<List<Vendor>> = withContext(Dispatchers.IO) {
        call {
            api.listVendors(
                status = status?.token,
                tradeCategory = tradeCategory?.takeIf { it.isNotBlank() },
                limit = limit,
            ).vendors.map { it.toDomain() }
        }
    }

    override suspend fun getVendor(vendorId: String): ApiResult<Vendor> =
        withContext(Dispatchers.IO) {
            call { api.getVendor(vendorId).toDomain() }
        }

    override suspend fun createVendor(
        name: String,
        tradeCategory: String,
        email: String?,
        phone: String?,
    ): ApiResult<Vendor> = withContext(Dispatchers.IO) {
        call {
            val body = VendorCreateRequest(
                name = name,
                tradeCategory = tradeCategory,
                email = email?.takeIf { it.isNotBlank() },
                phone = phone?.takeIf { it.isNotBlank() },
            )
            api.createVendor(body).toDomain()
        }
    }

    override suspend fun updateVendor(
        vendorId: String,
        name: String?,
        tradeCategory: String?,
        email: String?,
        phone: String?,
    ): ApiResult<Vendor> = withContext(Dispatchers.IO) {
        call {
            val body = VendorPatchRequest(
                name = name?.takeIf { it.isNotBlank() },
                tradeCategory = tradeCategory?.takeIf { it.isNotBlank() },
                email = email,
                phone = phone,
            )
            api.updateVendor(vendorId, body).toDomain()
        }
    }

    override suspend fun setVendorStatus(
        vendorId: String,
        status: VendorStatus,
    ): ApiResult<Vendor> = withContext(Dispatchers.IO) {
        call { api.setVendorStatus(vendorId, VendorStatusRequest(status.token)).toDomain() }
    }

    /** Folds a block into [ApiResult]; mirrors SignatureRepositoryImpl.call. */
    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: JsonEncodingException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
