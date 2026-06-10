package com.testlogon.android.data.checkout

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

/**
 * AND-213 — request to materialize a checkout session from the current cart. [idempotencyKey] is a
 * client-generated, stable-across-retries UUID; [totalCents]/[currency] seed the displayed total (the
 * response carries no monetary fields).
 */
data class CheckoutSessionRequest(
    val cartId: String?,
    val idempotencyKey: String,
    val totalCents: Long,
    val currency: String,
)

/**
 * AND-213 — checkout-session data layer over [CheckoutApi].
 *
 * createSession POSTs ui/checkout/session with source="cart" + cart_id and a best-effort
 * X-Idempotency-Key header, then maps the response into a [CheckoutSession]. Wraps every call in
 * [ApiResult]; CancellationException is re-thrown; HTTP errors fold to Failure and transport failures to
 * NetworkError. This non-idempotent POST is never auto-retried here.
 */
interface CheckoutRepository {
    suspend fun createSession(request: CheckoutSessionRequest): ApiResult<CheckoutSession>
}

@Singleton
class CheckoutRepositoryImpl @Inject constructor(
    private val api: CheckoutApi,
    private val errorParser: ApiErrorParser,
) : CheckoutRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun createSession(request: CheckoutSessionRequest): ApiResult<CheckoutSession> =
        withContext(io) {
            call {
                api.createSession(
                    idempotencyKey = request.idempotencyKey,
                    body = UnifiedCheckoutSessionInDto(source = SOURCE_CART, cartId = request.cartId),
                )
            }.map { it.toDomain(totalCents = request.totalCents, currency = request.currency) }
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

    companion object {
        /** UnifiedCheckoutSessionIn.source is required; "cart" materializes from the active cart. */
        const val SOURCE_CART = "cart"
    }
}
