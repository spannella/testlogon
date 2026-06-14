package com.testlogon.android.core.network.sponsorship

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.network.json.BigDecimalAdapter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-365 - DTO-level Moshi tests for the sponsorship transport (mirrors AND-363 AdsDtoJsonTest).
 *
 * The Moshi is built EXACTLY like the production NetworkModule.provideMoshi (BigDecimalAdapter + the
 * reflective KotlinJsonAdapterFactory) so decoding reflects production. status is decoded as a RAW String (the
 * typed enum + UNKNOWN fallback lives in core-model). Focus: round-trip, compensation_cents decodes to Long
 * including a value greater than Int.MAX_VALUE (overflow proof), created_at epoch Long, deadline as a STRING,
 * sparse-body defaults, required deal_id enforcement, extra-key tolerance, and an unrecognized status token
 * surviving as a raw String. core-network has no test dependency on core-testing, so the JSON is inline. KDoc
 * avoids the comment-terminator character pair.
 */
class SponsorshipDtoJsonTest {

    private val moshi: Moshi = Moshi.Builder()
        .add(BigDecimalAdapter)
        .add(KotlinJsonAdapterFactory())
        .build()

    private inline fun <reified T> roundTrip(value: T): T {
        val adapter = moshi.adapter(T::class.java)
        val json = adapter.toJson(value)
        return requireNotNull(adapter.fromJson(json)) { "round-trip produced null for $json" }
    }

    private fun listAdapter() = moshi.adapter<List<SponsorshipDealDto>>(
        Types.newParameterizedType(List::class.java, SponsorshipDealDto::class.java),
    )

    @Test
    fun deal_roundTrips_preservingCentsEpochAndDeadlineString() {
        val decoded = roundTrip(
            SponsorshipDealDto(
                dealId = "d1",
                advertiserSub = "adv_1",
                brief = "Promote our new app",
                status = "proposed",
                compensationCents = 250000L,
                deadline = "2026-07-01",
                createdAt = 1700000000L,
            ),
        )
        assertEquals("d1", decoded.dealId)
        assertEquals("adv_1", decoded.advertiserSub)
        assertEquals("proposed", decoded.status)
        assertEquals(250000L, decoded.compensationCents)
        assertEquals("2026-07-01", decoded.deadline)
        assertEquals(1700000000L, decoded.createdAt)
    }

    @Test
    fun compensationCents_decodeToLong_aboveIntMax_noOverflow() {
        val big = Int.MAX_VALUE.toLong() + 1_000_000L // overflows a 32-bit Int
        val json = """[{"deal_id":"d_big","compensation_cents":$big}]"""
        val deals = requireNotNull(listAdapter().fromJson(json))
        assertEquals(big, deals[0].compensationCents)
        assertTrue(deals[0].compensationCents!! > Int.MAX_VALUE.toLong())
    }

    @Test
    fun createdAt_decodesAsEpochLong() {
        val json = """[{"deal_id":"d1","created_at":1700000999}]"""
        val deals = requireNotNull(listAdapter().fromJson(json))
        assertEquals(1700000999L, deals[0].createdAt)
    }

    @Test
    fun deadline_decodesAsStringNotLong() {
        val json = """[{"deal_id":"d1","deadline":"2026-12-31T00:00:00Z"}]"""
        val deals = requireNotNull(listAdapter().fromJson(json))
        assertEquals("2026-12-31T00:00:00Z", deals[0].deadline)
    }

    @Test
    fun unrecognizedStatus_survivesAsRawString() {
        // The DTO keeps status raw; the core-model enum maps unknown tokens to UNKNOWN (tested there).
        val json = """[{"deal_id":"d1","status":"teleported"}]"""
        val deals = requireNotNull(listAdapter().fromJson(json))
        assertEquals("teleported", deals[0].status)
    }

    @Test
    fun sparseDeal_decodesViaDefaults_andToleratesExtraKeys() {
        val json = """[{"deal_id":"d1","unknown_field":"ignored","nested":{"x":1}}]"""
        val deals = requireNotNull(listAdapter().fromJson(json))
        assertEquals("d1", deals[0].dealId)
        assertNull(deals[0].advertiserSub)
        assertNull(deals[0].brief)
        assertNull(deals[0].status)
        assertNull(deals[0].compensationCents)
        assertNull(deals[0].deadline)
        assertNull(deals[0].createdAt)
    }

    @Test
    fun deal_missingRequiredDealId_throws() {
        assertThrows(JsonDataException::class.java) {
            listAdapter().fromJson("""[{"status":"proposed"}]""")
        }
    }

    @Test
    fun emptyArray_decodesEmptyList() {
        val deals = requireNotNull(listAdapter().fromJson("""[]"""))
        assertTrue(deals.isEmpty())
    }
}
