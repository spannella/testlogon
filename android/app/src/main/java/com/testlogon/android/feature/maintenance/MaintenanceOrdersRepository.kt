package com.testlogon.android.feature.maintenance

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.maintenance.CreateMaintenanceOrderRequest
import com.testlogon.android.core.network.maintenance.MaintenanceOrdersApi
import com.testlogon.android.core.network.maintenance.TransitionMaintenanceOrderRequest
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * WOV — data layer for the Maintenance Work Orders MVP (list + create + status transition).
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
