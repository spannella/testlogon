package com.testlogon.android.data.sellerstore

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

// ─── Domain ──────────────────────────────────────────────────────────────────

/** One order row in the seller's orders-received list. */
data class SellerOrder(
    val orderId: String,
    val buyerId: String?,
    val status: String,
    val amountCents: Long,
    val currency: String,
    val lineItemCount: Int,
    val createdAt: String?,
)

/** One line item within an order. */
data class SellerOrderLine(
    val itemId: String,
    val name: String?,
    val sku: String?,
    val quantity: Int,
    val unitPriceCents: Long,
    val currency: String,
)

/** One status-history entry. */
data class SellerOrderHistory(
    val fromStatus: String?,
    val toStatus: String?,
    val actor: String?,
    val reason: String?,
    val ts: Long,
)

/** Full order lifecycle detail, including the fulfilment moves the server currently allows. */
data class SellerOrderDetail(
    val orderId: String,
    val status: String,
    val amountCents: Long,
    val currency: String,
    val createdAt: String?,
    val updatedAt: String?,
    val allowedTransitions: List<String>,
    val lineItems: List<SellerOrderLine>,
    val history: List<SellerOrderHistory>,
)

/** One page of orders plus the opaque next-page cursor. */
data class SellerOrderPage(
    val orders: List<SellerOrder>,
    val nextCursor: String?,
)

// ─── Repository ──────────────────────────────────────────────────────────────

/**
 * ECOM (seller store) — orders-received data layer over [SellerOrdersApi]. Lists orders by lifecycle
 * status, loads a single order's detail, and advances / cancels an order (fulfilment). Network-only;
 * never throws (CancellationException re-thrown).
 */
interface SellerOrdersRepository {

    suspend fun orders(status: String, cursor: String?): ApiResult<SellerOrderPage>

    suspend fun detail(orderId: String): ApiResult<SellerOrderDetail>

    /** Advances the order to [targetStatus] (one of the detail's allowedTransitions). */
    suspend fun transition(orderId: String, targetStatus: String, reason: String?): ApiResult<Unit>

    suspend fun cancel(orderId: String, reason: String?, refund: Boolean): ApiResult<Unit>
}

@Singleton
class SellerOrdersRepositoryImpl @Inject constructor(
    private val api: SellerOrdersApi,
    private val errorParser: ApiErrorParser,
) : SellerOrdersRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun orders(status: String, cursor: String?): ApiResult<SellerOrderPage> =
        withContext(io) {
            call { api.listOrders(status = status, cursor = cursor) }.map { it.toDomain() }
        }

    override suspend fun detail(orderId: String): ApiResult<SellerOrderDetail> =
        withContext(io) { call { api.lifecycle(orderId) }.map { it.toDomain() } }

    override suspend fun transition(orderId: String, targetStatus: String, reason: String?): ApiResult<Unit> =
        withContext(io) {
            call {
                api.transition(
                    orderId,
                    OrderTransitionRequestDto(targetStatus = targetStatus, reason = reason?.takeIf { it.isNotBlank() }),
                )
            }.map { }
        }

    override suspend fun cancel(orderId: String, reason: String?, refund: Boolean): ApiResult<Unit> =
        withContext(io) {
            call {
                api.cancel(orderId, OrderCancelDto(reason = reason?.takeIf { it.isNotBlank() }, refund = refund))
            }.map { }
        }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}

// ─── Mappers (DTO -> domain) ─────────────────────────────────────────────────

private fun OrderListItemDto.toDomain(): SellerOrder = SellerOrder(
    orderId = orderId,
    buyerId = userId,
    status = lifecycleStatus ?: status ?: "",
    amountCents = amountCents,
    currency = currency,
    lineItemCount = lineItemCount,
    createdAt = createdAt,
)

private fun OrderListOutDto.toDomain(): SellerOrderPage = SellerOrderPage(
    orders = orders.orEmpty().map { it.toDomain() },
    nextCursor = nextCursor,
)

private fun OrderLineItemDto.toDomain(): SellerOrderLine = SellerOrderLine(
    itemId = itemId,
    name = name,
    sku = sku,
    quantity = quantity,
    unitPriceCents = unitPriceCents,
    currency = currency,
)

private fun OrderStatusHistoryDto.toDomain(): SellerOrderHistory = SellerOrderHistory(
    fromStatus = fromStatus,
    toStatus = toStatus,
    actor = actor,
    reason = reason,
    ts = ts,
)

private fun OrderLifecycleDto.toDomain(): SellerOrderDetail = SellerOrderDetail(
    orderId = orderId,
    status = lifecycleStatus ?: status ?: "",
    amountCents = amountCents,
    currency = currency,
    createdAt = createdAt,
    updatedAt = updatedAt,
    allowedTransitions = allowedTransitions.orEmpty(),
    lineItems = lineItems.orEmpty().map { it.toDomain() },
    history = statusHistory.orEmpty().map { it.toDomain() },
)
