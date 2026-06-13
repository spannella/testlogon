package com.testlogon.android.core.network.syndicates

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.network.json.BigDecimalAdapter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * AND-356 - DTO-level Moshi tests for the AND-356 syndicate transport (mirrors AND-355 GroupDtoJsonTest).
 *
 * Focus: optional-field defaults (nulls), EXTRA-key tolerance, required-field enforcement, *_cents ints,
 * the weights_bps map, the INTEGER epoch created_at / ts, and the unknown-mode token passing through as a
 * raw String (the SplitMode.UNKNOWN fallback is asserted in core-model). The Moshi is built like
 * NetworkModule.provideMoshi. core-network has no test dependency on core-testing, so the JSON is inline.
 * KDoc avoids the comment-terminator character pair.
 */
class SyndicateDtoJsonTest {

    private val moshi: Moshi = Moshi.Builder()
        .add(BigDecimalAdapter)
        .add(KotlinJsonAdapterFactory())
        .build()

    private fun profileAdapter() = moshi.adapter(SyndicateProfileOut::class.java)
    private fun feedAdapter() = moshi.adapter(SyndicateFeedOut::class.java)
    private fun treasuryAdapter() = moshi.adapter(SyndicateTreasuryOut::class.java)
    private fun splitAdapter() = moshi.adapter(SplitConfigOut::class.java)

    @Test
    fun profile_decodes_withOptionalNullsAndExtraKeys() {
        val json = """{"id":"syn_1","name":"Aces","currency":"usd","unknown_top":1}"""
        val p = requireNotNull(profileAdapter().fromJson(json))
        assertEquals("syn_1", p.id)
        assertEquals("usd", p.currency)
        // optional fields default to null when absent
        assertNull(p.memberCount)
        assertNull(p.adminUserId)
        assertNull(p.isMember)
    }

    @Test
    fun profile_missingRequiredId_throws() {
        assertThrows(JsonDataException::class.java) {
            profileAdapter().fromJson("""{"name":"Aces"}""")
        }
    }

    @Test
    fun feed_decodesIntegerEpochCreatedAt_andCursor() {
        val json = """{"posts":[{"post_id":"p1","created_at":1780000000,"text":"hi"}],
                       "is_member":true,"next_cursor":"c2"}"""
        val feed = requireNotNull(feedAdapter().fromJson(json))
        assertEquals(1, feed.posts.size)
        assertEquals(1780000000L, feed.posts[0].createdAt)
        assertNull(feed.posts[0].imageUrl)
        assertEquals("c2", feed.nextCursor)
    }

    @Test
    fun treasury_decodes_centsInts_andLedgerEpochTs() {
        val json = """{"balance_cents":150000,"total_deposited_cents":200000,
                       "total_disbursed_cents":50000,"currency":"usd","ledger":[
                         {"direction":"debit","amount_cents":2500,"ts":1779999999}
                       ]}"""
        val t = requireNotNull(treasuryAdapter().fromJson(json))
        assertEquals(150000, t.balanceCents)
        assertEquals(2500, t.ledger[0].amountCents)
        assertEquals(1779999999L, t.ledger[0].ts)
        // optional ledger fields default null
        assertNull(t.ledger[0].reason)
        assertNull(t.ledger[0].counterpartyUserId)
        assertNull(t.nextCursor)
    }

    @Test
    fun treasury_missingRequiredBalance_throws() {
        assertThrows(JsonDataException::class.java) {
            treasuryAdapter().fromJson(
                """{"total_deposited_cents":1,"total_disbursed_cents":1}""",
            )
        }
    }

    @Test
    fun split_decodesWeightsMap_andUnknownModePassesThroughRaw() {
        val json = """{"mode":"tiered","platform_fee_bps":500,
                       "weights_bps":{"usr_a":6000,"usr_b":4000}}"""
        val s = requireNotNull(splitAdapter().fromJson(json))
        // an unrecognized mode is preserved raw on the DTO; SplitMode.from maps it to UNKNOWN in core-model
        assertEquals("tiered", s.mode)
        assertEquals(500, s.platformFeeBps)
        assertEquals(6000, s.weightsBps?.get("usr_a"))
        assertEquals(4000, s.weightsBps?.get("usr_b"))
    }

    @Test
    fun split_emptyWeights_defaultsNull_forEqualMode() {
        val json = """{"mode":"equal","platform_fee_bps":0}"""
        val s = requireNotNull(splitAdapter().fromJson(json))
        assertEquals("equal", s.mode)
        assertNull(s.weightsBps)
        assertNull(s.performanceMetric)
    }
}
