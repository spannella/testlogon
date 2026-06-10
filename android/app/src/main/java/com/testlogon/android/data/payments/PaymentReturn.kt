package com.testlogon.android.data.payments

/**
 * AND-231 — provider-agnostic redirect/return models for the hosted-checkout payment cluster
 * (PayPal AND-228, CCBill AND-229, and any future redirect provider).
 *
 * The user leaves the app into a Chrome Custom Tab (AND-228/229), authorizes on the provider's hosted
 * page, and the browser bounces back into the app via a return deep link. This file owns the typed
 * result of parsing that return URL plus the routing classification.
 *
 * IMPORTANT (security, FR-5/§8): a SUCCESS return is NEVER proof of payment. It only triggers a
 * server-side confirm/poll (owned by the originating flow); entitlement is granted by the backend.
 */

/** Outcome of a redirect return, classified from the return URL (path segment first, then params). */
enum class PaymentOutcome { SUCCESS, CANCEL, PENDING, FAILURE, UNKNOWN }

/**
 * A registered redirect provider descriptor. Adding a provider is supplying one of these (FR-9) — the
 * parser is data-driven and never edited per-provider. [id] matches the `provider` query/path token
 * (e.g. "paypal", "ccbill"); [returnPathSegment] is the path token the provider returns under.
 */
data class PaymentProvider(val id: String, val returnPathSegment: String)

/**
 * The parsed, typed result of a return deep link. [intentId] / [state] are app-local correlation
 * tokens seeded from the backend `checkout_session_id` / `order_id` when the Custom Tab was launched
 * (there is no backend `intent_id`; see AND-231 §5). [rawUri] is retained for redacted logging only.
 */
data class PaymentReturn(
    val provider: String,
    val outcome: PaymentOutcome,
    val intentId: String?,
    val state: String?,
    val providerRef: String?,
    val errorCode: String?,
    val errorMessage: String?,
    val rawUri: String,
)

/**
 * The routing decision the handler produces from a [PaymentReturn] after correlation + idempotency.
 * Side-effect-free: navigation is performed by the caller/connector.
 */
sealed interface PaymentReturnRoute {
    /** Valid matching intent + SUCCESS — hand off to the originating flow's server-side confirm. */
    data class Confirm(val intentId: String, val provider: String, val providerRef: String?) :
        PaymentReturnRoute

    /** Provider reported a still-processing/deferred outcome — poll/await, do not fail. */
    data class Pending(val intentId: String, val provider: String) : PaymentReturnRoute

    /** Valid matching intent + CANCEL — return to the originating screen, no error. */
    data class Cancelled(val intentId: String?, val provider: String) : PaymentReturnRoute

    /** FAILURE / UNKNOWN — recoverable payment-error state with retry. */
    data class Failed(val intentId: String?, val provider: String, val message: String?) :
        PaymentReturnRoute

    /** No / mismatched / expired / already-consumed in-flight intent — never confirm a purchase. */
    data object Stale : PaymentReturnRoute
}
