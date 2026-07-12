package com.testlogon.android.data.tip

import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.messaging.BillingAuthorizer
import com.testlogon.android.data.messaging.BillingResult
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/** AND-178 — what the user submitted plus any server-reported running post total. */
data class TipReceipt(
    val postId: String,
    /** The submitted amount (cents) echoed locally; the server returns no per-tip amount. */
    val amountCents: Int,
    /** Server-reported new running post total, when present. */
    val tipTotalCents: Int?,
)

/** AND-178 — outcome of a tip attempt (domain projection consumed by the ViewModel). */
sealed interface TipOutcome {
    data class Success(val receipt: TipReceipt) : TipOutcome

    /**
     * STOP-AND-FLAG (payments, AND-031): no billing provider is wired
     * ([com.testlogon.android.data.messaging.StubBillingAuthorizer] returns NotConfigured), so no
     * /posts/{id}/tip call was made and no charge was faked. The UI shows a "payments unavailable"
     * state. A real BillingAuthorizer binding enables the full flow with no ViewModel changes.
     */
    data object PaymentsUnavailable : TipOutcome
    data object Cancelled : TipOutcome
    data class Failure(val message: String, val retryable: Boolean) : TipOutcome
}

/** TIP-204 - outcome of a post tip-REACTION attempt (drives the money-reaction chip + snackbar). */
sealed interface TipReactOutcome {
    data class Success(
        val badge: com.testlogon.android.data.feed.TipReactionBadge,
        val tipTotalCents: Int?,
    ) : TipReactOutcome
    data object PaymentsUnavailable : TipReactOutcome
    data object Cancelled : TipReactOutcome
    data class Failure(val message: String) : TipReactOutcome
}

/**
 * AND-178 — tip a post: a money-moving, NON-optimistic mutation.
 *
 * REUSES the AND-139 [BillingAuthorizer] seam to obtain a payment_method_id before charging. The
 * shipped stub returns [BillingResult.NotConfigured] so this repo returns [TipOutcome.PaymentsUnavailable]
 * and never calls the tip endpoint or fakes a charge (STOP-AND-FLAG). When a real authorizer is bound,
 * the call path runs: authorize -> POST /posts/{id}/tip -> confirmed receipt. No optimistic UI; success
 * is gated on a 2xx. No Room caching (a tip is a fire-and-confirm action, not list state).
 */
interface TipRepository {
    suspend fun tip(postId: String, amountCents: Int): TipOutcome

    /**
     * TIP-204 - money-REACTION tip on a post (content_type post_react). Authorizes via the billing
     * seam like [tip], then POSTs the post tip-react; success carries a badge for the money-reaction chip.
     */
    suspend fun tipReact(postId: String, amountCents: Int, emoji: String): TipReactOutcome
    fun config(): TipConfig
}

/** AND-178 — preset amounts + bounds (client constants; no post tip-config endpoint exists, OQ-2). */
data class TipConfig(
    /** Preset amounts in cents (web parity: [100, 500, 1000]). */
    val presetsCents: List<Int> = listOf(100, 500, 1000),
    val minCents: Int = 1,
    val maxCents: Int = 50_000,
    val currency: String = "usd",
)

@Singleton
class TipRepositoryImpl @Inject constructor(
    private val api: TipApi,
    private val billing: BillingAuthorizer,
    private val errorParser: ApiErrorParser,
) : TipRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override fun config(): TipConfig = TipConfig()

    override suspend fun tip(postId: String, amountCents: Int): TipOutcome = withContext(io) {
        if (amountCents < MIN_CENTS) {
            return@withContext TipOutcome.Failure(MSG_INVALID_AMOUNT, retryable = false)
        }

        // Authorize via the billing seam (AND-139). Stub => NotConfigured (STOP-AND-FLAG).
        val billingResult = billing.authorize(amountMinorUnits = amountCents.toLong(), currency = CURRENCY_USD)
        val paymentMethodId: String? = when (billingResult) {
            is BillingResult.Authorized -> billingResult.paymentMethodId
            BillingResult.NotConfigured -> return@withContext TipOutcome.PaymentsUnavailable
            BillingResult.Cancelled -> return@withContext TipOutcome.Cancelled
            is BillingResult.Declined -> return@withContext TipOutcome.Failure(billingResult.reason, retryable = true)
            is BillingResult.Failed -> return@withContext TipOutcome.Failure(MSG_GENERIC, retryable = true)
        }

        try {
            val resp = api.tipPost(
                postId = postId,
                body = TipRequestDto(amountCents = amountCents, paymentMethodId = paymentMethodId),
            )
            TipOutcome.Success(
                TipReceipt(postId = postId, amountCents = amountCents, tipTotalCents = resp.tipTotalCents),
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            val error = errorParser.from(e)
            TipOutcome.Failure(error.message, retryable = error.status >= 500)
        } catch (e: IOException) {
            TipOutcome.Failure(MSG_OFFLINE, retryable = true)
        }
    }

    override suspend fun tipReact(postId: String, amountCents: Int, emoji: String): TipReactOutcome = withContext(io) {
        if (amountCents < MIN_CENTS) {
            return@withContext TipReactOutcome.Failure(MSG_INVALID_AMOUNT)
        }
        val billingResult = billing.authorize(amountMinorUnits = amountCents.toLong(), currency = CURRENCY_USD)
        val paymentMethodId: String? = when (billingResult) {
            is BillingResult.Authorized -> billingResult.paymentMethodId
            BillingResult.NotConfigured -> return@withContext TipReactOutcome.PaymentsUnavailable
            BillingResult.Cancelled -> return@withContext TipReactOutcome.Cancelled
            is BillingResult.Declined -> return@withContext TipReactOutcome.Failure(billingResult.reason)
            is BillingResult.Failed -> return@withContext TipReactOutcome.Failure(MSG_GENERIC)
        }
        try {
            val resp = api.tipReactPost(
                postId = postId,
                body = PostTipReactRequestDto(amountCents = amountCents, emoji = emoji, paymentMethodId = paymentMethodId),
            )
            TipReactOutcome.Success(
                badge = com.testlogon.android.data.feed.TipReactionBadge(
                    tipperId = null,
                    emoji = resp.emoji ?: emoji,
                    amountCents = amountCents,
                ),
                tipTotalCents = resp.tipTotalCents,
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            TipReactOutcome.Failure(errorParser.from(e).message)
        } catch (e: IOException) {
            TipReactOutcome.Failure(MSG_OFFLINE)
        }
    }

    private companion object {
        const val CURRENCY_USD = "USD"
        const val MIN_CENTS = 1
        const val MSG_INVALID_AMOUNT = "Enter a valid amount."
        const val MSG_OFFLINE = "You're offline. Try again."
        const val MSG_GENERIC = "Couldn't send tip. Try again."
    }
}
