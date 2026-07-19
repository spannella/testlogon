package com.testlogon.android.data.entitlements

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/** ECOMX-43 (B5) — a render-ready entitlement (digital library item). */
data class LibraryEntitlement(
    val entitlementId: String,
    val sku: String,
    val productType: String,
    val status: String,
    val orderId: String?,
    val label: String,
) {
    /** True when the buyer can currently open/access this item (active grant). */
    val isAccessible: Boolean get() = status.equals("active", ignoreCase = true)
}

/**
 * ECOMX-43 (B5) — the buyer's digital-library data layer over [OrderEntitlementsApi].
 * [libraryForOrder] filters the caller's entitlements to one order (the endpoint has no order_id filter).
 */
interface OrderEntitlementsRepository {
    /** All of the caller's entitlements (the full library). */
    suspend fun library(): ApiResult<List<LibraryEntitlement>>

    /** Just the entitlements granted by [orderId] (the OrderDetail "digital items" card). */
    suspend fun libraryForOrder(orderId: String): ApiResult<List<LibraryEntitlement>>
}

@Singleton
class OrderEntitlementsRepositoryImpl @Inject constructor(
    private val api: OrderEntitlementsApi,
) : OrderEntitlementsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun library(): ApiResult<List<LibraryEntitlement>> = withContext(io) {
        // ECOMX selldash-E3: the endpoint returns `{items:[...]}`; unwrap (null -> empty).
        call { api.listEntitlements().items.orEmpty() }.map { rows: List<EntitlementDto> ->
            rows.mapNotNull { dto -> dto.toDomain() }
        }
    }

    override suspend fun libraryForOrder(orderId: String): ApiResult<List<LibraryEntitlement>> =
        withContext(io) {
            call { api.listEntitlements().items.orEmpty() }.map { rows: List<EntitlementDto> ->
                rows.mapNotNull { dto -> dto.toDomain() }.filter { e -> e.orderId == orderId }
            }
        }

    private fun EntitlementDto.toDomain(): LibraryEntitlement? {
        val id = entitlementId ?: return null
        val skuVal = sku ?: id
        return LibraryEntitlement(
            entitlementId = id,
            sku = skuVal,
            productType = productType.orEmpty(),
            status = status.orEmpty(),
            orderId = orderId?.takeIf { it.isNotBlank() },
            label = skuVal,
        )
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(ApiError(status = e.code(), message = e.message().ifBlank { "Request failed" }))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = false)
    } catch (e: com.squareup.moshi.JsonDataException) {
        // ECOMX selldash-E3: a prod-divergent body must NOT crash the caller (OrderDetail treats
        // entitlements as best-effort). Degrade to an empty library instead of an uncaught throw.
        ApiResult.Failure(ApiError(status = 0, message = e.message ?: "Malformed response"))
    }
}
