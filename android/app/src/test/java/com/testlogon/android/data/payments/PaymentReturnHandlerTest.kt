package com.testlogon.android.data.payments

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-231 — handler decision tests (parse + correlate + classify) with a fake store + fixed clock.
 * Covers Confirm/Pending/Cancelled/Failed, Stale (no/mismatch/expired/state-mismatch), idempotency,
 * and non-billing -> null.
 */
class PaymentReturnHandlerTest {

    private val parser = PaymentReturnParser(
        providers = setOf(PaymentProvider("paypal", "paypal"), PaymentProvider("ccbill", "ccbill")),
    )
    private var now = 1_000_000L
    private val clock = PaymentClock { now }
    private val store = FakePaymentIntentStore()
    private val handler = PaymentReturnHandler(parser, store, clock)

    private fun successUri(intent: String = "cs_1") =
        "testlogon://payments/return?provider=paypal&intent=$intent&token=tok&status=success"

    @Test
    fun success_matchingIntent_routesConfirm_andEmitsParsed() = runTest {
        store.put(InFlightPayment("cs_1", "paypal", null, null, now))
        var emitted: PaymentReturn? = null
        val route = handler.handle(successUri()) { emitted = it }
        assertTrue(route is PaymentReturnRoute.Confirm)
        assertEquals("cs_1", (route as PaymentReturnRoute.Confirm).intentId)
        assertEquals("tok", route.providerRef)
        assertEquals("paypal", emitted?.provider)
    }

    @Test
    fun cancel_and_pending_and_failure_route() = runTest {
        store.put(InFlightPayment("cs_1", "paypal", null, null, now))
        assertTrue(
            handler.handle("testlogon://payments/return?provider=paypal&intent=cs_1&status=cancel")
                is PaymentReturnRoute.Cancelled,
        )
        store.put(InFlightPayment("cs_2", "paypal", null, null, now))
        assertTrue(
            handler.handle("testlogon://payments/return?provider=paypal&intent=cs_2&status=pending")
                is PaymentReturnRoute.Pending,
        )
        store.put(InFlightPayment("cs_3", "paypal", null, null, now))
        assertTrue(
            handler.handle("testlogon://payments/return?provider=paypal&intent=cs_3&status=failed")
                is PaymentReturnRoute.Failed,
        )
    }

    @Test
    fun noInFlightIntent_isStale() = runTest {
        assertEquals(PaymentReturnRoute.Stale, handler.handle(successUri()))
    }

    @Test
    fun mismatchedIntent_isStale() = runTest {
        store.put(InFlightPayment("other", "paypal", null, null, now))
        assertEquals(PaymentReturnRoute.Stale, handler.handle(successUri("cs_1")))
    }

    @Test
    fun expiredIntent_isStale() = runTest {
        store.put(InFlightPayment("cs_1", "paypal", null, null, now))
        now += PaymentIntentStore.TTL_MS + 1
        assertEquals(PaymentReturnRoute.Stale, handler.handle(successUri()))
    }

    @Test
    fun stateMismatch_isStale_neverConfirms() = runTest {
        store.put(InFlightPayment("cs_1", "ccbill", state = "S", null, now))
        val route = handler.handle(
            "testlogon://payments/return?provider=ccbill&intent=cs_1&state=WRONG&status=success",
        )
        assertEquals(PaymentReturnRoute.Stale, route)
    }

    @Test
    fun duplicateDelivery_secondReturnsNull_idempotent() = runTest {
        store.put(InFlightPayment("cs_1", "paypal", null, null, now))
        val first = handler.handle(successUri())
        assertTrue(first is PaymentReturnRoute.Confirm)
        val second = handler.handle(successUri())
        assertNull(second)
    }

    @Test
    fun nonBillingUri_returnsNull() = runTest {
        assertNull(handler.handle("https://example.com/magic-link-verify?token=abc"))
    }
}

/** Minimal in-memory PaymentIntentStore for handler tests. */
private class FakePaymentIntentStore : PaymentIntentStore {
    private var current: InFlightPayment? = null
    private val consumed = mutableSetOf<String>()

    override suspend fun put(payment: InFlightPayment) {
        current = payment
        consumed.remove(payment.intentId)
    }

    override suspend fun get(): InFlightPayment? = current
    override suspend fun clear() { current = null }
    override suspend fun markConsumed(intentId: String): Boolean = consumed.add(intentId)
}
