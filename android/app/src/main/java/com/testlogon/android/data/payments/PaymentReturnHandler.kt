package com.testlogon.android.data.payments

import javax.inject.Inject
import javax.inject.Singleton

/** AND-231 — injectable clock so TTL/idempotency logic is deterministically unit-testable. */
fun interface PaymentClock {
    fun nowEpochMs(): Long
}

@Singleton
class SystemPaymentClock @Inject constructor() : PaymentClock {
    override fun nowEpochMs(): Long = System.currentTimeMillis()
}

/**
 * AND-231 — the canonical, provider-agnostic return handler. Pure decision (parse + correlate +
 * classify); performs NO navigation side effects (the connector navigates).
 *
 * Returns null for:
 *  - non-billing URLs (so other deep-link handlers, e.g. magic link, get their turn — FR/AC-6);
 *  - a duplicate delivery of an already-consumed intent (idempotency, FR-8/AC-3).
 *
 * Correlation + classification (FR-4/FR-5/§4.4):
 *  - SUCCESS + matching, non-expired, first-delivery intent -> Confirm (hand off to server-side verify);
 *  - PENDING + matching intent -> Pending (poll/await);
 *  - CANCEL + matching intent -> Cancelled;
 *  - FAILURE / UNKNOWN -> Failed (recoverable);
 *  - no / mismatched / expired / already-consumed intent -> Stale (never confirms a purchase).
 */
@Singleton
class PaymentReturnHandler @Inject constructor(
    private val parser: PaymentReturnParser,
    private val store: PaymentIntentStore,
    private val clock: PaymentClock,
) {

    /**
     * Parses [url], correlates against the in-flight intent, and returns the routing decision, or null
     * when [url] is not a billing return or is a duplicate delivery. Also emits the parsed
     * [PaymentReturn] to [onParsed] (for provider dispatch) when it is a recognized billing return.
     */
    suspend fun handle(url: String, onParsed: (PaymentReturn) -> Unit = {}): PaymentReturnRoute? {
        val parsed = parser.parse(url) ?: return null
        onParsed(parsed)

        val inFlight = store.get()
        // No / mismatched in-flight intent -> Stale; never infer entitlement (§8).
        if (inFlight == null || (parsed.intentId != null && parsed.intentId != inFlight.intentId)) {
            return PaymentReturnRoute.Stale
        }
        val intentId = inFlight.intentId

        // Expired (> TTL) -> Stale.
        if (clock.nowEpochMs() - inFlight.createdAtEpochMs > PaymentIntentStore.TTL_MS) {
            store.clear()
            return PaymentReturnRoute.Stale
        }

        // Optional state binding (CCBill, AND-229): if the in-flight intent carried a state, the return
        // must echo the same value. A mismatch/missing state is treated as Stale (never success).
        if (inFlight.state != null && parsed.state != inFlight.state) {
            return PaymentReturnRoute.Stale
        }

        // Exactly-once (FR-8): the first delivery routes; later deliveries return null (no re-nav).
        if (!store.markConsumed(intentId)) return null

        return when (parsed.outcome) {
            PaymentOutcome.SUCCESS ->
                PaymentReturnRoute.Confirm(intentId, parsed.provider, parsed.providerRef)
            PaymentOutcome.PENDING -> PaymentReturnRoute.Pending(intentId, parsed.provider)
            PaymentOutcome.CANCEL -> PaymentReturnRoute.Cancelled(intentId, parsed.provider)
            PaymentOutcome.FAILURE, PaymentOutcome.UNKNOWN ->
                PaymentReturnRoute.Failed(intentId, parsed.provider, parsed.errorMessage)
        }
    }
}
