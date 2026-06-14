package com.testlogon.android.data.payments

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * AND-231 — pure return-URL parser tests (JVM; no Android framework). Covers success/cancel/pending/
 * failure classification, path-vs-param precedence, provider resolution (custom scheme + App Link),
 * query extraction, and foreign-URI null.
 */
class PaymentReturnParserTest {

    private val parser = PaymentReturnParser(
        providers = setOf(
            PaymentProvider("paypal", "paypal"),
            PaymentProvider("ccbill", "ccbill"),
        ),
    )

    @Test
    fun customScheme_success_parsesProviderIntentAndOutcome() {
        val r = parser.parse(
            "testlogon://payments/return?provider=paypal&intent=ck_9f3&token=EC-2X&status=success",
        )
        requireNotNull(r)
        assertEquals("paypal", r.provider)
        assertEquals(PaymentOutcome.SUCCESS, r.outcome)
        assertEquals("ck_9f3", r.intentId)
        assertEquals("EC-2X", r.providerRef)
    }

    @Test
    fun appLink_pathDrivenOutcome_perProvider() {
        val success = parser.parse(
            "https://app.testlogon.example/app/billing/return/ccbill/success?intent=cs_1&state=S",
        )
        requireNotNull(success)
        assertEquals("ccbill", success.provider)
        assertEquals(PaymentOutcome.SUCCESS, success.outcome)
        assertEquals("S", success.state)

        val cancel = parser.parse(
            "https://app.testlogon.example/app/billing/return/paypal/cancel?intent=cs_2",
        )
        assertEquals(PaymentOutcome.CANCEL, requireNotNull(cancel).outcome)

        val failure = parser.parse(
            "https://app.testlogon.example/app/billing/return/paypal/failure?intent=cs_3&error_description=card_declined",
        )
        requireNotNull(failure)
        assertEquals(PaymentOutcome.FAILURE, failure.outcome)
        assertEquals("card_declined", failure.errorMessage)
    }

    @Test
    fun pendingOutcome_isClassified() {
        val r = parser.parse("testlogon://payments/return?provider=paypal&intent=x&status=pending")
        assertEquals(PaymentOutcome.PENDING, requireNotNull(r).outcome)
    }

    @Test
    fun pathWinsOverConflictingStatusParam() {
        val r = parser.parse(
            "https://h.example/app/billing/return/paypal/success?intent=x&status=failed",
        )
        assertEquals(PaymentOutcome.SUCCESS, requireNotNull(r).outcome)
    }

    @Test
    fun unknownOutcome_whenNoDecisiveSignal() {
        val r = parser.parse("testlogon://payments/return?provider=paypal&intent=x")
        assertEquals(PaymentOutcome.UNKNOWN, requireNotNull(r).outcome)
    }

    @Test
    fun foreignOrMalformedUri_returnsNull() {
        assertNull(parser.parse("https://example.com/magic-link-verify?token=abc"))
        assertNull(parser.parse("testlogon://u/some-profile"))
        assertNull(parser.parse("not a uri at all"))
    }

    @Test
    fun unregisteredProvider_returnsNull() {
        assertNull(parser.parse("testlogon://payments/return?provider=stripe&status=success"))
    }
}
