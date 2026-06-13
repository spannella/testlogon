package com.testlogon.android.core.network.ads

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
 * AND-363 - DTO-level Moshi tests for the ads accounts transport (mirrors SigningDtoJsonTest /
 * OrgDtoJsonTest).
 *
 * The Moshi is built EXACTLY like the production NetworkModule.provideMoshi (BigDecimalAdapter + the two
 * ads enum adapters + the reflective KotlinJsonAdapterFactory, in the same order) so decoding reflects
 * production. Focus: round-trips, *_cents decode to Long including a value greater than Int.MAX_VALUE
 * (overflow proof), epoch Long timestamps, status UNKNOWN fallback, sparse-body defaults, required-key
 * enforcement, and extra-key tolerance. core-network has no test dependency on :core-testing, so the JSON
 * is inline. KDoc avoids the comment-terminator character pair.
 */
class AdsDtoJsonTest {

    private val moshi: Moshi = Moshi.Builder()
        .add(BigDecimalAdapter)
        .add(AdAccountStatusAdapter)
        .add(AdCampaignStatusAdapter)
        .add(KotlinJsonAdapterFactory())
        .build()

    private inline fun <reified T> roundTrip(value: T): T {
        val adapter = moshi.adapter(T::class.java)
        val json = adapter.toJson(value)
        return requireNotNull(adapter.fromJson(json)) { "round-trip produced null for $json" }
    }

    private fun accountListAdapter() = moshi.adapter<List<AdAccountDto>>(
        Types.newParameterizedType(List::class.java, AdAccountDto::class.java),
    )

    private fun campaignListAdapter() = moshi.adapter<List<AdCampaignDto>>(
        Types.newParameterizedType(List::class.java, AdCampaignDto::class.java),
    )

    private fun billingListAdapter() = moshi.adapter<List<AdBillingEntryDto>>(
        Types.newParameterizedType(List::class.java, AdBillingEntryDto::class.java),
    )

    // ---- Round-trips ----

    @Test
    fun account_roundTrips_preservingEnumCentsAndEpochs() {
        val decoded = roundTrip(
            AdAccountDto(
                accountId = "acc_1",
                name = "Acme Ads",
                status = AdAccountStatus.ACTIVE,
                balanceCents = 12345L,
                lifetimeSpendCents = 99999L,
                currency = "USD",
                createdAt = 1700000000L,
                updatedAt = 1700000100L,
            ),
        )
        assertEquals("acc_1", decoded.accountId)
        assertEquals(AdAccountStatus.ACTIVE, decoded.status)
        assertEquals(12345L, decoded.balanceCents)
        assertEquals(1700000000L, decoded.createdAt)
    }

    @Test
    fun campaign_roundTrips_withAllCentsAndStatus() {
        val decoded = roundTrip(
            AdCampaignDto(
                campaignId = "cmp_1",
                accountId = "acc_1",
                name = "Spring",
                status = AdCampaignStatus.PAUSED,
                budgetCents = 100000L,
                dailyBudgetCents = 5000L,
                spentTodayCents = 2500L,
                lifetimeSpentCents = 750000L,
                createdAt = 1700000000L,
                updatedAt = 1700000200L,
            ),
        )
        assertEquals("cmp_1", decoded.campaignId)
        assertEquals(AdCampaignStatus.PAUSED, decoded.status)
        assertEquals(100000L, decoded.budgetCents)
        assertEquals(750000L, decoded.lifetimeSpentCents)
    }

    @Test
    fun billingEntry_roundTrips() {
        val decoded = roundTrip(
            AdBillingEntryDto(
                entryId = "ent_1",
                amountCents = 2500L,
                type = "charge",
                description = "daily spend",
                createdAt = 1700000000L,
            ),
        )
        assertEquals("ent_1", decoded.entryId)
        assertEquals(2500L, decoded.amountCents)
        assertEquals("charge", decoded.type)
    }

    // ---- *_cents decode to Long, overflow proof (> Int.MAX_VALUE) ----

    @Test
    fun cents_decodeToLong_aboveIntMax_noOverflow() {
        val big = Int.MAX_VALUE.toLong() + 1_000_000L // 2,148,483,647 - overflows a 32-bit Int
        val json = """[{"account_id":"acc_big","balance_cents":$big,"lifetime_spend_cents":$big}]"""
        val accounts = requireNotNull(accountListAdapter().fromJson(json))
        assertEquals(big, accounts[0].balanceCents)
        assertEquals(big, accounts[0].lifetimeSpendCents)
        assertTrue(accounts[0].balanceCents > Int.MAX_VALUE.toLong())
    }

    @Test
    fun campaignCents_decodeToLong_aboveIntMax() {
        val big = 9_000_000_000L // far beyond Int range
        val json = """[{"campaign_id":"cmp_big","lifetime_spent_cents":$big}]"""
        val campaigns = requireNotNull(campaignListAdapter().fromJson(json))
        assertEquals(big, campaigns[0].lifetimeSpentCents)
    }

    // ---- epoch Long timestamps ----

    @Test
    fun timestamps_decodeAsEpochLong() {
        val json = """[{"account_id":"a","balance_cents":0,"lifetime_spend_cents":0,
            "created_at":1700000000,"updated_at":1700000999}]"""
        val accounts = requireNotNull(accountListAdapter().fromJson(json))
        assertEquals(1700000000L, accounts[0].createdAt)
        assertEquals(1700000999L, accounts[0].updatedAt)
    }

    // ---- status UNKNOWN fallback ----

    @Test
    fun unknownAccountStatus_decodesToUnknown() {
        val json = """[{"account_id":"a","status":"frozen_solid","balance_cents":0,
            "lifetime_spend_cents":0}]"""
        val accounts = requireNotNull(accountListAdapter().fromJson(json))
        assertEquals(AdAccountStatus.UNKNOWN, accounts[0].status)
    }

    @Test
    fun unknownCampaignStatus_decodesToUnknown() {
        val json = """[{"campaign_id":"c","status":"teleported"}]"""
        val campaigns = requireNotNull(campaignListAdapter().fromJson(json))
        assertEquals(AdCampaignStatus.UNKNOWN, campaigns[0].status)
    }

    @Test
    fun enumAdapters_serializeBackToWireToken() {
        assertEquals(
            "\"suspended\"",
            moshi.adapter(AdAccountStatus::class.java).toJson(AdAccountStatus.SUSPENDED),
        )
        assertEquals(
            "\"completed\"",
            moshi.adapter(AdCampaignStatus::class.java).toJson(AdCampaignStatus.COMPLETED),
        )
    }

    // ---- sparse-body defaults + extra-key tolerance ----

    @Test
    fun sparseAccount_decodesViaDefaults_andToleratesExtraKeys() {
        val json = """[{"account_id":"a","balance_cents":10,"lifetime_spend_cents":20,
            "unknown_field":"ignored","nested":{"x":1}}]"""
        val accounts = requireNotNull(accountListAdapter().fromJson(json))
        assertEquals(AdAccountStatus.UNKNOWN, accounts[0].status)
        assertNull(accounts[0].name)
        assertNull(accounts[0].createdAt)
        assertNull(accounts[0].currency)
    }

    @Test
    fun sparseCampaign_decodesAllOptionalCentsNull() {
        val campaigns = requireNotNull(campaignListAdapter().fromJson("""[{"campaign_id":"c"}]"""))
        assertEquals(AdCampaignStatus.UNKNOWN, campaigns[0].status)
        assertNull(campaigns[0].budgetCents)
        assertNull(campaigns[0].dailyBudgetCents)
        assertNull(campaigns[0].spentTodayCents)
        assertNull(campaigns[0].lifetimeSpentCents)
    }

    @Test
    fun sparseBilling_decodesOptionalEntryIdNull() {
        val entries = requireNotNull(billingListAdapter().fromJson("""[{"amount_cents":500}]"""))
        assertEquals(500L, entries[0].amountCents)
        assertNull(entries[0].entryId)
        assertNull(entries[0].type)
    }

    // ---- required-key enforcement ----

    @Test
    fun account_missingRequiredAccountId_throws() {
        assertThrows(JsonDataException::class.java) {
            accountListAdapter().fromJson("""[{"balance_cents":0,"lifetime_spend_cents":0}]""")
        }
    }

    @Test
    fun account_missingRequiredBalanceCents_throws() {
        assertThrows(JsonDataException::class.java) {
            accountListAdapter().fromJson("""[{"account_id":"a","lifetime_spend_cents":0}]""")
        }
    }

    @Test
    fun campaign_missingRequiredCampaignId_throws() {
        assertThrows(JsonDataException::class.java) {
            campaignListAdapter().fromJson("""[{"name":"no id"}]""")
        }
    }

    @Test
    fun billing_missingRequiredAmountCents_throws() {
        assertThrows(JsonDataException::class.java) {
            billingListAdapter().fromJson("""[{"entry_id":"e"}]""")
        }
    }

    // ---- AND-367: billing row entry_type / state / reason ----

    @Test
    fun billingEntry_decodesEntryTypeStateReason() {
        val entries = requireNotNull(
            billingListAdapter().fromJson(
                """[{"entry_type":"charge","amount_cents":2500,"state":"settled",
                    "reason":"daily spend","created_at":1700000000}]""",
            ),
        )
        assertEquals("charge", entries[0].entryType)
        assertEquals(2500L, entries[0].amountCents)
        assertEquals("settled", entries[0].state)
        assertEquals("daily spend", entries[0].reason)
        assertEquals(1700000000L, entries[0].createdAt)
    }

    // ---- AND-367: invoice DTO + campaign lines ----

    @Test
    fun invoice_roundTrips_withLinesAndCents() {
        val decoded = roundTrip(
            AdInvoiceDto(
                month = "2026-06",
                totalChargesCents = 750000L,
                totalDepositsCents = 100000L,
                entryCount = 3,
                campaigns = listOf(
                    AdInvoiceCampaignLineDto(
                        campaignId = "cmp_1",
                        impressions = 12000L,
                        clicks = 340L,
                        conversions = 12L,
                        totalCents = 500000L,
                    ),
                ),
            ),
        )
        assertEquals("2026-06", decoded.month)
        assertEquals(750000L, decoded.totalChargesCents)
        assertEquals(3, decoded.entryCount)
        assertEquals(1, decoded.campaigns.size)
        assertEquals("cmp_1", decoded.campaigns[0].campaignId)
        assertEquals(12000L, decoded.campaigns[0].impressions)
        assertEquals(500000L, decoded.campaigns[0].totalCents)
    }

    @Test
    fun invoice_sparse_decodesEmptyCampaigns_andNullTotals() {
        val adapter = moshi.adapter(AdInvoiceDto::class.java)
        val decoded = requireNotNull(adapter.fromJson("""{"month":"2026-06"}"""))
        assertEquals("2026-06", decoded.month)
        assertNull(decoded.totalChargesCents)
        assertNull(decoded.totalDepositsCents)
        assertNull(decoded.entryCount)
        assertTrue(decoded.campaigns.isEmpty())
    }

    @Test
    fun invoiceCents_decodeToLong_aboveIntMax() {
        val big = Int.MAX_VALUE.toLong() + 5_000_000L
        val adapter = moshi.adapter(AdInvoiceDto::class.java)
        val decoded = requireNotNull(
            adapter.fromJson("""{"month":"2026-06","total_charges_cents":$big}"""),
        )
        assertEquals(big, decoded.totalChargesCents)
        assertTrue(decoded.totalChargesCents!! > Int.MAX_VALUE.toLong())
    }

    // ---- AND-367: deposit in / out ----

    @Test
    fun depositIn_roundTrips() {
        val decoded = roundTrip(AdDepositIn(amountCents = 50000L, paymentMethodId = "pm_9"))
        assertEquals(50000L, decoded.amountCents)
        assertEquals("pm_9", decoded.paymentMethodId)
    }

    @Test
    fun depositIn_amountCents_decodesToLong_aboveIntMax() {
        val big = 9_500_000_000L
        val adapter = moshi.adapter(AdDepositIn::class.java)
        val decoded = requireNotNull(adapter.fromJson("""{"amount_cents":$big}"""))
        assertEquals(big, decoded.amountCents)
        assertNull(decoded.paymentMethodId)
    }

    @Test
    fun depositIn_missingRequiredAmountCents_throws() {
        assertThrows(JsonDataException::class.java) {
            moshi.adapter(AdDepositIn::class.java).fromJson("""{"payment_method_id":"pm_1"}""")
        }
    }

    @Test
    fun depositOut_decodesNewBalance_andToleratesSparse() {
        val adapter = moshi.adapter(AdDepositOut::class.java)
        val full = requireNotNull(adapter.fromJson("""{"new_balance_cents":155000,"status":"ok"}"""))
        assertEquals(155000L, full.newBalanceCents)
        assertEquals("ok", full.status)
        val sparse = requireNotNull(adapter.fromJson("""{}"""))
        assertNull(sparse.newBalanceCents)
        assertNull(sparse.status)
    }

    // ---- AND-368: analytics summary DTO ----

    private fun timeseriesListAdapter() = moshi.adapter<List<AdTimeSeriesPointDto>>(
        Types.newParameterizedType(List::class.java, AdTimeSeriesPointDto::class.java),
    )

    private fun breakdownListAdapter() = moshi.adapter<List<AdBreakdownEntryDto>>(
        Types.newParameterizedType(List::class.java, AdBreakdownEntryDto::class.java),
    )

    @Test
    fun analyticsSummary_decodesPctAsIs_centsLong_andOptionalFields() {
        val adapter = moshi.adapter(AdAnalyticsSummaryDto::class.java)
        val decoded = requireNotNull(
            adapter.fromJson(
                """{"impressions":120000,"clicks":3400,"spend_cents":250000,"ctr_pct":2.83,
                    "cpa_cents":7350,"effective_cpm_cents":2083,"completes":900,"skips":120,
                    "completion_rate_pct":88.2,"spend_change_pct":-3.4}""",
            ),
        )
        assertEquals(120000L, decoded.impressions)
        assertEquals(250000L, decoded.spendCents)
        // pct fields are already percentages - decoded verbatim (NOT multiplied by 100).
        assertEquals(2.83, decoded.ctrPct, 0.0001)
        assertEquals(88.2, decoded.completionRatePct!!, 0.0001)
        assertEquals(-3.4, decoded.spendChangePct!!, 0.0001)
        assertEquals(7350L, decoded.cpaCents)
        assertEquals(900L, decoded.completes)
    }

    @Test
    fun analyticsSummary_sparse_decodesOptionalNulls() {
        val adapter = moshi.adapter(AdAnalyticsSummaryDto::class.java)
        val decoded = requireNotNull(
            adapter.fromJson("""{"impressions":0,"clicks":0,"spend_cents":0,"ctr_pct":0.0}"""),
        )
        assertEquals(0L, decoded.impressions)
        assertNull(decoded.cpaCents)
        assertNull(decoded.effectiveCpmCents)
        assertNull(decoded.completionRatePct)
        assertNull(decoded.impressionsChangePct)
    }

    @Test
    fun analyticsSummary_spendCents_decodeToLong_aboveIntMax() {
        val big = Int.MAX_VALUE.toLong() + 3_000_000L
        val adapter = moshi.adapter(AdAnalyticsSummaryDto::class.java)
        val decoded = requireNotNull(
            adapter.fromJson(
                """{"impressions":1,"clicks":1,"spend_cents":$big,"ctr_pct":1.0}""",
            ),
        )
        assertEquals(big, decoded.spendCents)
        assertTrue(decoded.spendCents > Int.MAX_VALUE.toLong())
    }

    @Test
    fun analyticsSummary_missingRequiredCtrPct_throws() {
        assertThrows(JsonDataException::class.java) {
            moshi.adapter(AdAnalyticsSummaryDto::class.java)
                .fromJson("""{"impressions":1,"clicks":1,"spend_cents":1}""")
        }
    }

    // ---- AND-368: timeseries bare array (date OR ts) ----

    @Test
    fun timeseries_decodesBareArray_dateOrTs() {
        val points = requireNotNull(
            timeseriesListAdapter().fromJson(
                """[
                    {"date":"2026-06-08","impressions":1000,"clicks":30,"spend_cents":2500},
                    {"ts":1749513600,"impressions":1200,"clicks":36,"spend_cents":3000}
                ]""",
            ),
        )
        assertEquals(2, points.size)
        assertEquals("2026-06-08", points[0].date)
        assertNull(points[0].ts)
        assertEquals(1749513600L, points[1].ts)
        assertNull(points[1].date)
        assertEquals(3000L, points[1].spendCents)
    }

    @Test
    fun timeseries_missingRequiredSpendCents_throws() {
        assertThrows(JsonDataException::class.java) {
            timeseriesListAdapter().fromJson("""[{"date":"2026-06-08","impressions":1,"clicks":1}]""")
        }
    }

    // ---- AND-368: breakdown bare array (key OR dimension_value; optional ctr) ----

    @Test
    fun breakdown_decodesBareArray_keyOrDimensionValue() {
        val rows = requireNotNull(
            breakdownListAdapter().fromJson(
                """[
                    {"key":"cmp_1","impressions":80000,"clicks":2400,"spend_cents":180000,"ctr_pct":3.0},
                    {"dimension_value":"cmp_2","impressions":40000,"clicks":1000,"spend_cents":70000}
                ]""",
            ),
        )
        assertEquals(2, rows.size)
        assertEquals("cmp_1", rows[0].key)
        assertEquals(3.0, rows[0].ctrPct!!, 0.0001)
        assertEquals("cmp_2", rows[1].dimensionValue)
        assertNull(rows[1].key)
        assertNull(rows[1].ctrPct)
    }

    @Test
    fun breakdown_spendCents_decodeToLong_aboveIntMax() {
        val big = 8_000_000_000L
        val rows = requireNotNull(
            breakdownListAdapter().fromJson(
                """[{"key":"k","impressions":1,"clicks":1,"spend_cents":$big}]""",
            ),
        )
        assertEquals(big, rows[0].spendCents)
    }
}
