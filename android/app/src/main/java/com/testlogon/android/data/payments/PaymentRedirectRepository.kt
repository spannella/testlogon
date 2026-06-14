package com.testlogon.android.data.payments

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.billing.BillingApi
import com.testlogon.android.data.billing.CheckoutSessionRequestDto
import com.testlogon.android.data.messaging.BillingAuthorizer
import com.testlogon.android.data.messaging.BillingResult
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-227/228/229 — creates a redirect/hosted payment session, GATED by the [BillingAuthorizer] stub,
 * plus the verified PayPal capture + CCBill authorize + US-bank verify calls.
 *
 * PAYMENTS FLAG (AND-031) — the load-bearing gate:
 *  - [createRedirectSession] FIRST asks [BillingAuthorizer.authorize]. The bound
 *    [com.testlogon.android.data.messaging.StubBillingAuthorizer] returns
 *    [BillingResult.NotConfigured], so the function returns [RedirectSessionResult.NotConfigured]
 *    WITHOUT creating a provider session, WITHOUT opening a charge URL, WITHOUT confirming a charge.
 *  - The [BillingResult.Authorized] branch — which would call the backend to create a real hosted /
 *    approval / flexform URL — is present but inert under the stub. When AND-031 binds a real
 *    authorizer, this branch goes live with no caller change.
 *
 * Non-idempotent POSTs are never auto-retried. CancellationException is re-thrown; HTTP errors fold to
 * Failure, transport failures to NetworkError. DTOs are mapped to domain before returning.
 */
interface PaymentRedirectRepository {

    /**
     * Attempts to create a redirect session for [provider]. Gated by [BillingAuthorizer]: under the
     * stub this yields [RedirectSessionResult.NotConfigured] and creates NOTHING live.
     */
    suspend fun createRedirectSession(
        provider: RedirectProvider,
        amountCents: Long,
        currency: String,
        description: String?,
        ccbillFlowType: String? = null,
        ccbillCheckoutSessionId: String? = null,
        ccbillReturnUrl: String? = null,
        ccbillState: String? = null,
    ): RedirectSessionResult

    /** AND-228 — capture a PayPal order after a SUCCESS return (verified endpoint). */
    suspend fun capturePayPalOrder(orderId: String, idempotencyKey: String): ApiResult<PayPalCaptureDto>

    /** AND-230 — verify the two microdeposit amounts for a pending US bank setup intent (verified). */
    suspend fun verifyMicrodeposits(
        setupIntentId: String,
        amounts: List<Int>,
    ): ApiResult<UsBankVerificationResult>
}

@Singleton
class PaymentRedirectRepositoryImpl @Inject constructor(
    private val api: PaymentRedirectApi,
    private val billingApi: BillingApi,
    private val authorizer: BillingAuthorizer,
    private val errorParser: ApiErrorParser,
) : PaymentRedirectRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun createRedirectSession(
        provider: RedirectProvider,
        amountCents: Long,
        currency: String,
        description: String?,
        ccbillFlowType: String?,
        ccbillCheckoutSessionId: String?,
        ccbillReturnUrl: String?,
        ccbillState: String?,
    ): RedirectSessionResult = withContext(io) {
        // GATE (AND-031): never create a live session unless a real authorizer authorizes it.
        when (val auth = authorizer.authorize(amountCents, currency, description)) {
            is BillingResult.NotConfigured -> RedirectSessionResult.NotConfigured
            is BillingResult.Cancelled -> RedirectSessionResult.Cancelled
            is BillingResult.Declined -> RedirectSessionResult.Failed(auth.reason, retryable = true)
            is BillingResult.Failed ->
                RedirectSessionResult.Failed(auth.cause.message ?: GENERIC_ERROR, retryable = true)
            // INERT under the stub. Live only when AND-031 binds a real authorizer.
            is BillingResult.Authorized ->
                createLiveSession(
                    provider, amountCents, currency, description,
                    ccbillFlowType, ccbillCheckoutSessionId, ccbillReturnUrl, ccbillState,
                )
        }
    }

    /**
     * The Authorized-branch live session creation. UNREACHABLE under the stub (which never returns
     * Authorized). Kept here so the full redirect plumbing exists and goes live with AND-031.
     */
    private suspend fun createLiveSession(
        provider: RedirectProvider,
        amountCents: Long,
        currency: String,
        description: String?,
        ccbillFlowType: String?,
        ccbillCheckoutSessionId: String?,
        ccbillReturnUrl: String?,
        ccbillState: String?,
    ): RedirectSessionResult = when (provider) {
        RedirectProvider.CHECKOUT, RedirectProvider.PAYPAL ->
            // AND-227: POST ui/billing/checkout_session -> {session_id, url} (hosted checkout / approval).
            // (PayPal create-order + approval_url is a BACKEND GAP, AND-228 §5; the hosted-checkout
            // redirect is the verified create path and is reused here for the Authorized branch.)
            when (
                val r = call {
                    billingApi.createCheckoutSession(
                        CheckoutSessionRequestDto(
                            amountCents = amountCents,
                            currency = currency,
                            description = description,
                        ),
                    )
                }
            ) {
                is ApiResult.Success -> RedirectSessionResult.Created(
                    RedirectSession(provider, r.data.sessionId, r.data.url),
                )
                is ApiResult.Failure -> RedirectSessionResult.Failed(r.error.message, retryable = true)
                is ApiResult.NetworkError -> RedirectSessionResult.Failed(OFFLINE, retryable = true)
            }

        RedirectProvider.CCBILL ->
            when (
                val r = call {
                    api.ccbillFrontendOauth(
                        CcbillOauthRequestDto(
                            flowType = ccbillFlowType ?: CCBILL_FLOW_PURCHASE,
                            checkoutSessionId = ccbillCheckoutSessionId,
                            state = ccbillState ?: UUID.randomUUID().toString(),
                            returnUrl = ccbillReturnUrl ?: PaymentReturnParser.RETURN_URL_BASE,
                        ),
                    )
                }
            ) {
                is ApiResult.Success -> RedirectSessionResult.Created(
                    RedirectSession(provider, r.data.correlationId ?: "", r.data.authorizationUrl),
                )
                is ApiResult.Failure -> RedirectSessionResult.Failed(r.error.message, retryable = true)
                is ApiResult.NetworkError -> RedirectSessionResult.Failed(OFFLINE, retryable = true)
            }
    }

    override suspend fun capturePayPalOrder(
        orderId: String,
        idempotencyKey: String,
    ): ApiResult<PayPalCaptureDto> = withContext(io) {
        call {
            api.capturePayPalOrder(CaptureOrderRequestDto(orderId = orderId, idempotencyKey = idempotencyKey))
        }.let { result ->
            when (result) {
                is ApiResult.Success -> ApiResult.Success(result.data.toPayPalCapture())
                is ApiResult.Failure -> result
                is ApiResult.NetworkError -> result
            }
        }
    }

    override suspend fun verifyMicrodeposits(
        setupIntentId: String,
        amounts: List<Int>,
    ): ApiResult<UsBankVerificationResult> = withContext(io) {
        call {
            api.verifyMicrodeposits(
                VerifyMicrodepositsRequestDto(setupIntentId = setupIntentId, amounts = amounts),
            )
        }.let { result ->
            when (result) {
                is ApiResult.Success ->
                    ApiResult.Success(result.data.toUsBankVerificationResult(setupIntentId))
                is ApiResult.Failure -> result
                is ApiResult.NetworkError -> result
            }
        }
    }

    private fun Map<String, Any?>.toPayPalCapture(): PayPalCaptureDto = PayPalCaptureDto(
        orderId = this["order_id"] as? String,
        captureId = this["capture_id"] as? String,
        status = this["status"] as? String,
    )

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
        const val CCBILL_FLOW_PURCHASE = "purchase"
        const val CCBILL_FLOW_ADD_PM = "add_payment_method"
        private const val OFFLINE = "You're offline"
        private const val GENERIC_ERROR = "Payment failed"
    }
}
