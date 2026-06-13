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
}
