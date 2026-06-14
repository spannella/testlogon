package com.testlogon.android.data.referrals

import com.squareup.moshi.Moshi
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-264 — contract tests for [ReferralsApi] against MockWebServer (real Retrofit/Moshi).
 * Covers dashboard path/verb + mapping (cents, null defaults), empty-codes resilience, and the
 * create-code POST path/verb.
 */
class ReferralsApiContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun api(): ReferralsApi = backend.retrofit(moshi).create(ReferralsApi::class.java)

    @Test
    fun getDashboard_path_verb_andMapping() = runTest {
        backend.enqueue(Fixtures.okBody(DASHBOARD_FULL))
        val domain = api().getDashboard().toDomain()

        val recorded = backend.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/referrals/dashboard", recorded.requestUrl?.encodedPath)

        assertEquals(12, domain.stats.totalReferrals)
        assertEquals(5, domain.stats.confirmedReferrals)
        assertEquals(7, domain.stats.pendingReferrals)
        assertEquals(3000L, domain.stats.totalEarnedCents)
        assertEquals(1000L, domain.stats.pendingCommissionCents)
        assertEquals(2000L, domain.stats.paidCommissionCents)
        assertEquals(1500L, domain.stats.availableForWithdrawalCents)
        assertEquals(1, domain.codes.size)
        assertEquals("AB12CD34", domain.codes[0].code)
        assertTrue(domain.codes[0].active)
        assertEquals(5, domain.codes[0].referralCount)
    }

    @Test
    fun getDashboard_emptyBody_mapsToZeroStats_andIneligible() = runTest {
        backend.enqueue(Fixtures.okBody("{}"))
        val domain = api().getDashboard().toDomain()
        assertEquals(0, domain.stats.totalReferrals)
        assertEquals(0L, domain.stats.totalEarnedCents)
        assertTrue(domain.codes.isEmpty())
        assertTrue(domain.isIneligible)
    }

    @Test
    fun getDashboard_nullReferralCount_defaultsToZero() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"referral_codes":[{"code":"X1","active":true,"commission_tier":"standard","created_at":"2026-05-01"}]}""",
            ),
        )
        val domain = api().getDashboard().toDomain()
        assertEquals(0, domain.codes[0].referralCount)
    }

    @Test
    fun createCode_path_verb_andMapping() = runTest {
        backend.enqueue(Fixtures.okBody(CREATE_RESP, code = 201))
        val created = api().createCode().toDomain()

        val recorded = backend.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/referrals/code", recorded.requestUrl?.encodedPath)
        // Create takes no body.
        assertTrue(recorded.bodyJson().isEmpty())

        assertEquals("EF56GH78", created.code)
        assertTrue(created.active)
        assertEquals("standard", created.commissionTier)
    }

    private companion object {
        val DASHBOARD_FULL = """
            {
              "total_referrals": 12,
              "confirmed_referrals": 5,
              "pending_referrals": 7,
              "total_earned_cents": 3000,
              "pending_commission_cents": 1000,
              "paid_commission_cents": 2000,
              "available_for_withdrawal_cents": 1500,
              "referral_codes": [
                { "code": "AB12CD34", "active": true, "commission_tier": "standard", "referral_count": 5, "created_at": "2026-05-01T12:00:00Z" }
              ]
            }
        """.trimIndent()

        val CREATE_RESP = """
            { "code": "EF56GH78", "link": "https://app.testlogon.com/?ref=EF56GH78", "commission_tier": "standard", "created_at": "2026-06-06T00:00:00Z" }
        """.trimIndent()
    }
}
