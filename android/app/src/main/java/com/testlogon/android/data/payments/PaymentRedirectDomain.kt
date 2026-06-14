package com.testlogon.android.data.payments

/**
 * AND-227/228/229 — framework-free domain models for the redirect/hosted-checkout payment cluster.
 *
 * PAYMENTS FLAG (AND-031): creating a LIVE redirect/hosted session (a real hosted-checkout URL, a real
 * PayPal approval URL, a real CCBill flexform URL) is a HUMAN-DECISION provider integration. All
 * session creation is routed through the existing [com.testlogon.android.data.messaging.BillingAuthorizer]
 * stub: under [BillingResult.NotConfigured] no provider session is created, no charge URL is opened,
 * and the flow surfaces "payments not configured". The Authorized branch (real session creation + Custom
 * Tab open) is present but inert under the stub.
 */

/** Which redirect provider a session targets. */
enum class RedirectProvider { CHECKOUT, PAYPAL, CCBILL }

/**
 * A created redirect session: an opaque session/order id (the correlation token seeded into the
 * in-flight intent store) plus the hosted URL to open in a Custom Tab.
 */
data class RedirectSession(
    val provider: RedirectProvider,
    val sessionId: String,
    val hostedUrl: String,
)

/** Outcome of attempting to create a redirect session, gated by the billing authorizer. */
sealed interface RedirectSessionResult {
    /** A real provider session was created (only reachable with a real authorizer — never the stub). */
    data class Created(val session: RedirectSession) : RedirectSessionResult

    /**
     * Payments are not configured (the FLAGGED stub path): no session created, no charge URL opened.
     * The flow MUST surface a payments-unavailable state.
     */
    data object NotConfigured : RedirectSessionResult

    /** The user dismissed the (would-be) payment sheet/picker. */
    data object Cancelled : RedirectSessionResult

    /** A non-decline failure (network / provider error / backend rejection). */
    data class Failed(val message: String, val retryable: Boolean = true) : RedirectSessionResult
}

// ---- US bank micro-deposit verification (AND-230) ----

/** The microdeposit verification state derived from the verify response status (total mapping). */
enum class UsBankVerificationState { VERIFIED, UNKNOWN }

/**
 * Result of POST verify-microdeposits. Keyed by [setupIntentId] (the verify request key). The verify
 * 200 body is only a `{status}` string map — there is NO is_default / attempts_remaining (AND-230 §4);
 * default/chargeability must come from a later payment-methods fetch.
 */
data class UsBankVerificationResult(
    val setupIntentId: String,
    val state: UsBankVerificationState,
)

/** "verified" -> VERIFIED; anything else (incl. absent) -> UNKNOWN. Never throws. */
internal fun String?.toUsBankVerificationState(): UsBankVerificationState =
    if (this?.equals("verified", ignoreCase = true) == true) {
        UsBankVerificationState.VERIFIED
    } else {
        UsBankVerificationState.UNKNOWN
    }

internal fun Map<String, String>.toUsBankVerificationResult(setupIntentId: String): UsBankVerificationResult =
    UsBankVerificationResult(
        setupIntentId = setupIntentId,
        state = this["status"].toUsBankVerificationState(),
    )
