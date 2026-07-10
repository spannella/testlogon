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

/** The buyer's shipping address (G2) — what the seller mails to. */
data class SellerSaleAddress(
    val name: String?,
    val line1: String?,
    val line2: String?,
    val city: String?,
    val state: String?,
    val postalCode: String?,
    val country: String?,
) {
    val hasAny: Boolean
        get() = listOf(name, line1, line2, city, state, postalCode, country).any { !it.isNullOrBlank() }
}

/** One line item within the seller's own portion of the order (G4: real product name). */
data class SellerSaleLine(
    val itemId: String,
    val name: String?,
    val sku: String?,
    val quantity: Int,
    val unitPriceCents: Long,
    val lineTotalCents: Long,
    val currency: String,
)

/** One row in the seller's "Sales / Orders received" list (their own ship group). */
data class SellerSale(
    val shipGroupId: String,
    val orderId: String,
    val status: String,
    val buyerName: String?,
    val itemCount: Int,
    val subtotalCents: Long,
    val currency: String,
    val createdAt: Long,
)

/** Full sale detail: buyer + shipping address + this seller's real line items + fulfilment moves. */
data class SellerSaleDetail(
    val shipGroupId: String,
    val orderId: String,
    val status: String,
    val allowedTransitions: List<String>,
    val buyerName: String?,
    val buyerEmail: String?,
    val shipTo: SellerSaleAddress,
    val lineItems: List<SellerSaleLine>,
    val itemCount: Int,
    val subtotalCents: Long,
    val currency: String,
    val trackingNumber: String?,
    val carrier: String?,
    val createdAt: Long,
    val updatedAt: Long,
)

/** One page of sales plus the opaque next-page cursor. */
data class SellerSalePage(
    val sales: List<SellerSale>,
    val nextCursor: String?,
)

// ─── Repository ──────────────────────────────────────────────────────────────

/**
 * ECOM-SELLER (G1-G4) — seller-scoped sales data layer over [SellerSalesApi]. Lists the authenticated
 * seller's own ship groups, loads one sale's detail (buyer address + real line items), and advances the
 * ship group's lifecycle (fulfilment, e.g. mark-shipped). Network-only; never throws (Cancellation
 * re-thrown).
 */
interface SellerSalesRepository {

    suspend fun sales(cursor: String?): ApiResult<SellerSalePage>

    suspend fun detail(shipGroupId: String): ApiResult<SellerSaleDetail>

    /** Advances the ship group to [targetStatus] (one of the detail's allowedTransitions). */
    suspend fun transition(
        shipGroupId: String,
        targetStatus: String,
        reason: String?,
        trackingNumber: String?,
        carrier: String?,
    ): ApiResult<SellerSaleDetail>
}

@Singleton
class SellerSalesRepositoryImpl @Inject constructor(
    private val api: SellerSalesApi,
    private val errorParser: ApiErrorParser,
) : SellerSalesRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun sales(cursor: String?): ApiResult<SellerSalePage> =
        withContext(io) { call { api.listSales(cursor = cursor) }.map { it.toPage() } }

    override suspend fun detail(shipGroupId: String): ApiResult<SellerSaleDetail> =
        withContext(io) { call { api.sale(shipGroupId) }.map { it.toDetail() } }

    override suspend fun transition(
        shipGroupId: String,
        targetStatus: String,
        reason: String?,
        trackingNumber: String?,
        carrier: String?,
    ): ApiResult<SellerSaleDetail> = withContext(io) {
        call {
            api.transition(
                shipGroupId,
                SellerSaleTransitionRequestDto(
                    targetStatus = targetStatus,
                    reason = reason?.takeIf { it.isNotBlank() },
                    trackingNumber = trackingNumber?.takeIf { it.isNotBlank() },
                    carrier = carrier?.takeIf { it.isNotBlank() },
                ),
            )
        }.map { it.toDetail() }
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

private fun SellerSaleShipToDto?.toDomain(): SellerSaleAddress = SellerSaleAddress(
    name = this?.name,
    line1 = this?.line1,
    line2 = this?.line2,
    city = this?.city,
    state = this?.state,
    postalCode = this?.postalCode,
    country = this?.country,
)

private fun SellerSaleLineItemDto.toDomain(currency: String): SellerSaleLine = SellerSaleLine(
    itemId = itemId,
    name = name,
    sku = sku,
    quantity = quantity,
    unitPriceCents = unitPriceCents,
    lineTotalCents = if (lineTotalCents > 0) lineTotalCents else unitPriceCents * quantity,
    currency = currency,
)

private fun SellerSaleDto.toRow(): SellerSale = SellerSale(
    shipGroupId = shipGroupId,
    orderId = orderId,
    status = status,
    buyerName = buyerName,
    itemCount = itemCount,
    subtotalCents = subtotalCents,
    currency = currency,
    createdAt = createdAt,
)

private fun SellerSaleListOutDto.toPage(): SellerSalePage = SellerSalePage(
    sales = sales.orEmpty().map { it.toRow() },
    nextCursor = nextCursor,
)

private fun SellerSaleDto.toDetail(): SellerSaleDetail = SellerSaleDetail(
    shipGroupId = shipGroupId,
    orderId = orderId,
    status = status,
    allowedTransitions = allowedTransitions.orEmpty(),
    buyerName = buyerName,
    buyerEmail = buyerEmail,
    shipTo = shipTo.toDomain(),
    lineItems = lineItems.orEmpty().map { it.toDomain(currency) },
    itemCount = itemCount,
    subtotalCents = subtotalCents,
    currency = currency,
    trackingNumber = trackingNumber,
    carrier = carrier,
    createdAt = createdAt,
    updatedAt = updatedAt,
)
