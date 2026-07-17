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
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

/** TIPX-C2 - receipt for a direct creator (profile) tip. */
data class ProfileTipReceipt(
    val identifier: String,
    val amountCents: Int,
    /** Server-reported new running creator tip total, when present. */
    val tipTotalCents: Int?,
)

/** TIPX-C2 - outcome of a profile (creator) tip attempt (mirrors [TipOutcome]). */
sealed interface ProfileTipOutcome {
    data class Success(val receipt: ProfileTipReceipt) : ProfileTipOutcome
    data object PaymentsUnavailable : ProfileTipOutcome
    data object Cancelled : ProfileTipOutcome
    data class Failure(val message: String, val retryable: Boolean) : ProfileTipOutcome
}

/**
 * TIPX-C2 - tip a creator directly from their profile: a money-moving, NON-optimistic mutation that
 * REUSES the same [BillingAuthorizer] seam + the single charge_tip rail (content_type "profile").
 *
 * A STABLE per-attempt client_request_id is minted once per repository call so a transparent retry at
 * the same call site replays the server receipt (charged once). Success is gated on a 2xx.
 */
interface ProfileTipRepository {
    suspend fun tip(identifier: String, amountCents: Int): ProfileTipOutcome
    fun config(): TipConfig
}

@Singleton
class ProfileTipRepositoryImpl @Inject constructor(
    private val api: ProfileTipApi,
    private val billing: BillingAuthorizer,
    private val errorParser: ApiErrorParser,
) : ProfileTipRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override fun config(): TipConfig = TipConfig()

    override suspend fun tip(identifier: String, amountCents: Int): ProfileTipOutcome = withContext(io) {
        if (amountCents < MIN_CENTS) {
            return@withContext ProfileTipOutcome.Failure(MSG_INVALID_AMOUNT, retryable = false)
        }

        val billingResult = billing.authorize(amountMinorUnits = amountCents.toLong(), currency = CURRENCY_USD)
        val paymentMethodId: String? = when (billingResult) {
            is BillingResult.Authorized -> billingResult.paymentMethodId
            BillingResult.NotConfigured -> return@withContext ProfileTipOutcome.PaymentsUnavailable
            BillingResult.Cancelled -> return@withContext ProfileTipOutcome.Cancelled
            is BillingResult.Declined -> return@withContext ProfileTipOutcome.Failure(billingResult.reason, retryable = true)
            is BillingResult.Failed -> return@withContext ProfileTipOutcome.Failure(MSG_GENERIC, retryable = true)
        }

        // Stable idempotency key: a retry of THIS attempt replays the server receipt (charged once).
        val clientRequestId = UUID.randomUUID().toString()

        try {
            val resp = api.tipCreator(
                identifier = identifier,
                body = ProfileTipRequestDto(
                    amountCents = amountCents,
                    paymentMethodId = paymentMethodId,
                    clientRequestId = clientRequestId,
                ),
            )
            ProfileTipOutcome.Success(
                ProfileTipReceipt(
                    identifier = identifier,
                    amountCents = amountCents,
                    tipTotalCents = resp.tipTotalCents,
                ),
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            val error = errorParser.from(e)
            ProfileTipOutcome.Failure(error.message, retryable = error.status >= 500)
        } catch (e: IOException) {
            ProfileTipOutcome.Failure(MSG_OFFLINE, retryable = true)
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
