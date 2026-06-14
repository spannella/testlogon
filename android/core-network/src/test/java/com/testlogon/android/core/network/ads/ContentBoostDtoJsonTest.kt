package com.testlogon.android.core.network.ads

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.network.json.BigDecimalAdapter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-364 - DTO-level Moshi tests for the content-boost transport (mirrors AND-363 AdsDtoJsonTest).
 *
 * The Moshi is built EXACTLY like the production NetworkModule.provideMoshi (BigDecimalAdapter + the
 * reflective KotlinJsonAdapterFactory; no boost enum adapter, status is a raw String) so decoding reflects
 * production. Focus: status is a free string (incl. an unrecognized value, which the DTO keeps verbatim),
 * *_cents decode to Long including a value greater than Int.MAX_VALUE (overflow proof), ends_at is an epoch
 * Long, optional fields default to null, required keys are enforced, and extra keys are tolerated. core-
 * network has no test dependency on core-testing, so the JSON is inline. KDoc avoids the comment terminator.
 */
class ContentBoostDtoJsonTest {

    private val moshi: Moshi = Moshi.Builder()
        .add(BigDecimalAdapter)
        .add(KotlinJsonAdapterFactory())
        .build()

    private fun outAdapter() = moshi.adapter(ContentBoostOut::class.java)

    private inline fun <reified T> roundTrip(value: T): T {
        val adapter = moshi.adapter(T::class.java)
        return requireNotNull(adapter.fromJson(adapter.toJson(value))) { "round-trip produced null" }
    }

    @Test
    fun out_roundTrips_preservingStatusCentsAndEpoch() {
        val decoded = roundTrip(
            ContentBoostOut(
                boostId = "bst_1",
                status = "active",
                contentType = "post",
                contentId = "post_9",
                budgetCents = 500L,
                spentCents = 100L,
                remainingCents = 400L,
                durationSeconds = 3600L,
                endsAt = 1700003600L,
                createdAt = 1700000000L,
            ),
        )
        assertEquals("bst_1", decoded.boostId)
        assertEquals("active", decoded.status)
        assertEquals(500L, decoded.budgetCents)
        assertEquals(1700003600L, decoded.endsAt)
    }

    @Test
    fun status_isFreeString_unknownTokenKeptVerbatim() {
        val json = """{"boost_id":"b","status":"awaiting_wizard_approval","budget_cents":100}"""
        val out = requireNotNull(outAdapter().fromJson(json))
        assertEquals("awaiting_wizard_approval", out.status)
    }

    @Test
    fun cents_decodeToLong_aboveIntMax_noOverflow() {
        val big = Int.MAX_VALUE.toLong() + 1_000_000L // overflows a 32-bit Int
        val json = """{"boost_id":"b","status":"active","budget_cents":$big,"spent_cents":$big}"""
        val out = requireNotNull(outAdapter().fromJson(json))
        assertEquals(big, out.budgetCents)
        assertEquals(big, out.spentCents)
        assertTrue(out.budgetCents > Int.MAX_VALUE.toLong())
    }

    @Test
    fun endsAt_decodesAsEpochLong() {
        val json = """{"boost_id":"b","status":"active","budget_cents":1,"ends_at":1700003600}"""
        val out = requireNotNull(outAdapter().fromJson(json))
        assertEquals(1700003600L, out.endsAt)
    }

    @Test
    fun sparseOut_decodesOptionalFieldsNull_andToleratesExtraKeys() {
        val json = """{"boost_id":"b","status":"pending","budget_cents":1000,"unknown":"ignored"}"""
        val out = requireNotNull(outAdapter().fromJson(json))
        assertEquals(1000L, out.budgetCents)
        assertNull(out.spentCents)
        assertNull(out.remainingCents)
        assertNull(out.durationSeconds)
        assertNull(out.endsAt)
        assertNull(out.createdAt)
    }

    @Test
    fun out_missingRequiredBoostId_throws() {
        assertThrows(JsonDataException::class.java) {
            outAdapter().fromJson("""{"status":"active","budget_cents":1}""")
        }
    }

    @Test
    fun out_missingRequiredStatus_throws() {
        assertThrows(JsonDataException::class.java) {
            outAdapter().fromJson("""{"boost_id":"b","budget_cents":1}""")
        }
    }

    @Test
    fun out_missingRequiredBudgetCents_throws() {
        assertThrows(JsonDataException::class.java) {
            outAdapter().fromJson("""{"boost_id":"b","status":"active"}""")
        }
    }

    @Test
    fun spend_decodesOptionalCentsLong() {
        val spend = requireNotNull(
            moshi.adapter(ContentBoostSpendOut::class.java)
                .fromJson("""{"boost_id":"b","spent_cents":250,"remaining_cents":250}"""),
        )
        assertEquals(250L, spend.spentCents)
        assertEquals(250L, spend.remainingCents)
    }

    @Test
    fun cancel_decodesRefundLong_optionalFields() {
        val cancel = requireNotNull(
            moshi.adapter(ContentBoostCancelOut::class.java)
                .fromJson("""{"boost_id":"b","status":"cancelled","refunded_cents":250}"""),
        )
        assertEquals("cancelled", cancel.status)
        assertEquals(250L, cancel.refundedCents)
    }

    @Test
    fun listResponse_prefersItems_thenBoosts() {
        val adapter = moshi.adapter(ContentBoostListResponse::class.java)
        val viaItems = requireNotNull(
            adapter.fromJson("""{"items":[{"boost_id":"a","status":"active","budget_cents":1}]}"""),
        )
        assertEquals(1, viaItems.all.size)
        val viaBoosts = requireNotNull(
            adapter.fromJson("""{"boosts":[{"boost_id":"b","status":"active","budget_cents":2}]}"""),
        )
        assertEquals("b", viaBoosts.all[0].boostId)
        val empty = requireNotNull(adapter.fromJson("""{}"""))
        assertTrue(empty.all.isEmpty())
    }
}
