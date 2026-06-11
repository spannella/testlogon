package com.testlogon.android.data.earnings

import com.squareup.moshi.Moshi
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-251 — contract tests for [EarningsApi] against MockWebServer (real Retrofit/Moshi).
 * Covers path/verb/query (null params omitted), summary mapping, defaults tolerance, weekly-date
 * degradation, quick-stats, and the empty-body resilience case.
 */
class EarningsApiContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun api(): EarningsApi = backend.retrofit(moshi).create(EarningsApi::class.java)

    @Test
    fun getSummary_path_verb_andNullParamsOmitted() = runTest {
        backend.enqueue(Fixtures.okBody(SUMMARY_FULL))
        api().getSummary(granularity = "day")

        val recorded = backend.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/earnings/summary", recorded.requestUrl?.encodedPath)
        assertEquals("day", recorded.requestUrl?.queryParameter("granularity"))
        // Null filters must NOT appear on the wire.
        assertNull(recorded.requestUrl?.queryParameter("from_date"))
        assertNull(recorded.requestUrl?.queryParameter("to_date"))
        assertNull(recorded.requestUrl?.queryParameter("from_ts"))
        assertNull(recorded.requestUrl?.queryParameter("to_ts"))
    }

    @Test
    fun getQuickStats_path_emptyQuery() = runTest {
        backend.enqueue(Fixtures.okBody(QUICK_STATS))
        api().getQuickStats()
        val recorded = backend.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/earnings/quick-stats", recorded.requestUrl?.encodedPath)
        assertTrue(recorded.requestUrl?.querySize == 0)
    }

    @Test
    fun getSummary_mapsAllFields_andPreservesSeriesOrder() = runTest {
        backend.enqueue(Fixtures.okBody(SUMMARY_FULL))
        val domain = api().getSummary().toDomain()

        assertEquals(1284350L, domain.total.cents)
        assertEquals("USD", domain.total.currency)
        assertEquals(412, domain.transactionCount)
        assertEquals(800000L, domain.breakdown.subscriptions)
        assertEquals(250000L, domain.breakdown.tips)
        assertEquals(150000L, domain.breakdown.unlocks)
        assertEquals(80350L, domain.breakdown.vodPurchases)
        assertEquals(4000L, domain.breakdown.other)
        assertEquals(2, domain.series.size)
        assertEquals("2026-05-01", domain.series[0].rawDate)
        // 2026-05-01 epoch day == LocalDate.parse("2026-05-01").toEpochDay()
        assertEquals(20574L, domain.series[0].dateEpochDay)
        assertEquals("2026-05-02", domain.series[1].rawDate)
        assertEquals(41000L, domain.series[0].totalCents)
    }

    @Test
    fun getSummary_defaultsTolerated_onMissingOptionalFields() = runTest {
        backend.enqueue(Fixtures.okBody("""{"time_series":[{"date":"2026-05-01"}]}"""))
        val domain = api().getSummary().toDomain()
        assertEquals(0L, domain.total.cents)
        assertEquals("USD", domain.total.currency)
        assertEquals(0L, domain.breakdown.tips)
        assertEquals(0, domain.transactionCount)
        assertEquals(0L, domain.series[0].totalCents)
    }

    @Test
    fun getSummary_emptyBody_mapsToAllZeroSummary() = runTest {
        backend.enqueue(Fixtures.okBody("{}"))
        val domain = api().getSummary().toDomain()
        assertEquals(0L, domain.total.cents)
        assertTrue(domain.series.isEmpty())
    }

    @Test
    fun getSummary_weeklyDateLabels_degradeToNullEpochDay() = runTest {
        backend.enqueue(
            Fixtures.okBody("""{"time_series":[{"date":"2026-W18","total":5},{"date":"2026-05","total":7}]}"""),
        )
        val domain = api().getSummary().toDomain()
        assertNull(domain.series[0].dateEpochDay)
        assertEquals("2026-W18", domain.series[0].rawDate)
        assertNull(domain.series[1].dateEpochDay)
        assertEquals("2026-05", domain.series[1].rawDate)
    }

    @Test
    fun getQuickStats_mapsAllMoneyFields() = runTest {
        backend.enqueue(Fixtures.okBody(QUICK_STATS))
        val s = api().getQuickStats().toDomain()
        assertEquals(12000L, s.today.cents)
        assertEquals(89000L, s.thisWeek.cents)
        assertEquals(412000L, s.thisMonth.cents)
        assertEquals(1284350L, s.allTime.cents)
        assertEquals(250000L, s.pendingPayout.cents)
        assertEquals("USD", s.allTime.currency)
    }

    private companion object {
        val SUMMARY_FULL = """
            {
              "total_cents": 1284350,
              "currency": "USD",
              "transaction_count": 412,
              "breakdown": { "subscriptions": 800000, "tips": 250000, "unlocks": 150000, "vod_purchases": 80350, "other": 4000 },
              "time_series": [
                { "date": "2026-05-01", "total": 41000, "tips": 9000, "subscriptions": 25000, "unlocks": 5000, "vod_purchases": 2000, "other": 0 },
                { "date": "2026-05-02", "total": 39000, "tips": 8000, "subscriptions": 24000, "unlocks": 5000, "vod_purchases": 2000, "other": 0 }
              ]
            }
        """.trimIndent()

        val QUICK_STATS = """
            {
              "today_cents": 12000,
              "this_week_cents": 89000,
              "this_month_cents": 412000,
              "all_time_cents": 1284350,
              "pending_payout_cents": 250000,
              "currency": "USD"
            }
        """.trimIndent()
    }
}
