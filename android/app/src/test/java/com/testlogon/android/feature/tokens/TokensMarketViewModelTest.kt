package com.testlogon.android.feature.tokens

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.ads.AdClickAttributionStore
import com.testlogon.android.data.ads.AdEvent
import com.testlogon.android.data.ads.CtaAction
import com.testlogon.android.data.ads.AdTrackRepository
import com.testlogon.android.data.feed.SponsoredInfo
import com.testlogon.android.data.shopads.ShopAdsRepository
import com.testlogon.android.data.shopads.SponsoredProduct
import com.testlogon.android.data.tokens.AuctionStatus
import com.testlogon.android.data.tokens.Token
import com.testlogon.android.data.tokens.TokenAck
import com.testlogon.android.data.tokens.TokenAuction
import com.testlogon.android.data.tokens.TokenCapTable
import com.testlogon.android.data.tokens.TokenRevenue
import com.testlogon.android.data.tokens.TokenStatus
import com.testlogon.android.data.tokens.TokenUpkeep
import com.testlogon.android.data.tokens.TokensRepository
import com.testlogon.android.data.tokens.UpkeepStatus
import com.testlogon.android.feature.ads.SlotEntry
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

private fun sampleToken(id: String, ticker: String) = Token(
    tokenId = id,
    name = "Token $ticker",
    ticker = ticker,
    totalSupply = 1_000_000L,
    revenueShareBps = 1_000,
    status = TokenStatus.LISTED,
)

private fun sampleSponsored(unitId: String) = SponsoredProduct(
    unitId = unitId,
    productId = "p_$unitId",
    categoryId = "c1",
    name = "Promoted $unitId",
    priceCents = 999L,
    currency = "USD",
    imageUrl = null,
    sponsorLabel = "AcmeCo",
    ctaText = "Shop now",
    tracking = SponsoredInfo(
        label = "AcmeCo",
        headline = "Promoted",
        ctaText = "Shop now",
        ctaUrl = "https://example.com/x",
        adClickId = "ac_$unitId",
        creativeId = "cr_$unitId",
        campaignId = "camp_$unitId",
        accountId = "acct_$unitId",
        surface = "shop_browse",
        slotType = "sponsored_post",
        creatorId = "platform",
        contentId = unitId,
    ),
)

/** Fake honoring the repo contract: reads return the configured [ApiResult]; mutations are unused. */
private class FakeTokensRepo(
    var marketResult: ApiResult<List<Token>> = ApiResult.Success(emptyList()),
    var issuedResult: ApiResult<List<Token>> = ApiResult.Success(emptyList()),
) : TokensRepository {
    override suspend fun issued(): ApiResult<List<Token>> = issuedResult
    override suspend fun market(): ApiResult<List<Token>> = marketResult
    override suspend fun openAuctions(): ApiResult<List<TokenAuction>> = ApiResult.Success(emptyList())
    override suspend fun token(id: String): ApiResult<Token?> = ApiResult.Success(null)
    override suspend fun capTable(id: String): ApiResult<TokenCapTable> =
        ApiResult.Success(TokenCapTable(id, 0, emptyList()))
    override suspend fun auction(id: String): ApiResult<TokenAuction?> = ApiResult.Success(null)
    override suspend fun revenue(id: String): ApiResult<TokenRevenue> =
        ApiResult.Success(TokenRevenue(id, 0, 0, 0, emptyList()))
    override suspend fun upkeep(id: String): ApiResult<TokenUpkeep> =
        ApiResult.Success(TokenUpkeep(id, "", 0, 0, 0, 0, UpkeepStatus.UNKNOWN))
    override suspend fun mint(name: String, ticker: String, totalSupply: Long, revenueShareBps: Int) =
        ApiResult.Success(sampleToken("x", ticker))
    override suspend fun list(id: String, offeredPctBps: Int, reservePrice: Long, closeTs: Long) =
        ApiResult.Success(TokenAuction("a", id, 0, 0, AuctionStatus.OPEN))
    override suspend fun placeBid(id: String, qty: Long, limitPrice: Long) = ApiResult.Success(TokenAck(true))
    override suspend fun clearAuction(id: String) =
        ApiResult.Success(TokenAuction("a", id, 0, 0, AuctionStatus.CLEARED))
    override suspend fun claimRevenue(id: String) = ApiResult.Success(TokenAck(true))
    override suspend fun payUpkeep(id: String) = ApiResult.Success(TokenAck(true))
}

/** FE-161 — fake shop-ads serve: returns [units] (degrades to empty like the real best-effort repo). */
private class FakeShopAdsRepo(
    var units: List<SponsoredProduct> = emptyList(),
) : ShopAdsRepository {
    override suspend fun serveShopSponsored(
        surface: String,
        query: String,
        categoryId: String,
        limit: Int,
    ): List<SponsoredProduct> = units.take(limit)

    override suspend fun boostListing(
        itemId: String,
        categoryId: String,
        budgetCents: Int,
        bidCpcCents: Int,
    ) = throw UnsupportedOperationException()
}

/** FE-161 — records the ad events fired so impression/click wiring can be asserted. */
private class RecordingAdTrackRepo : AdTrackRepository {
    val events = mutableListOf<Pair<AdEvent, SponsoredInfo>>()
    override suspend fun track(event: AdEvent, ad: SponsoredInfo): ApiResult<Unit> {
        events.add(event to ad)
        return ApiResult.Success(Unit)
    }
    override suspend fun clickCta(adClickId: String, action: CtaAction): ApiResult<Unit> =
        ApiResult.Success(Unit)
}

/**
 * ViewModel-level coverage for [TokensMarketViewModel]: the degrade-on-404 -> empty Content path, the
 * happy path with market + issued rows, a transport-failure -> retryable Error, and (FE-161) the
 * sponsored-slot interleave + impression/click tracking.
 */
class TokensMarketViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun vm(
        repo: FakeTokensRepo = FakeTokensRepo(),
        shop: FakeShopAdsRepo = FakeShopAdsRepo(),
        track: RecordingAdTrackRepo = RecordingAdTrackRepo(),
    ) = TokensMarketViewModel(repo, shop, track, AdClickAttributionStore())

    @Test
    fun degrade_bothEmpty_toEmptyContent() = runTest(mainRule.dispatcher) {
        val vm = vm()
        advanceUntilIdle()
        val s = vm.uiState.value
        assertEquals(TokensMarketUiState.Phase.Content, s.phase)
        assertTrue(s.market.isEmpty())
        assertTrue(s.issued.isEmpty())
        assertTrue(s.rows.isEmpty())
        assertTrue(s.sponsored.isEmpty())
        assertNull(s.errorMessage)
    }

    @Test
    fun happy_marketAndIssued_populated() = runTest(mainRule.dispatcher) {
        val repo = FakeTokensRepo(
            marketResult = ApiResult.Success(listOf(sampleToken("t1", "AAA"), sampleToken("t2", "BBB"))),
            issuedResult = ApiResult.Success(listOf(sampleToken("t3", "CCC"))),
        )
        val vm = vm(repo)
        advanceUntilIdle()
        val s = vm.uiState.value
        assertEquals(TokensMarketUiState.Phase.Content, s.phase)
        assertEquals(2, s.market.size)
        assertEquals(1, s.issued.size)
        assertEquals(2, s.rows.size)
        vm.selectTab(TokenListTab.ISSUED)
        assertEquals(1, vm.uiState.value.rows.size)
    }

    @Test
    fun transportFailure_toRetryableError() = runTest(mainRule.dispatcher) {
        val repo = FakeTokensRepo(marketResult = ApiResult.NetworkError(java.io.IOException(), isTimeout = false))
        val vm = vm(repo)
        advanceUntilIdle()
        val s = vm.uiState.value
        assertEquals(TokensMarketUiState.Phase.Error, s.phase)
        assertTrue(s.errorMessage != null)
    }

    @Test
    fun sponsored_interleaved_and_relabeled_to_token_discovery() = runTest(mainRule.dispatcher) {
        val market = (1..12).map { sampleToken("t$it", "T$it") }
        val repo = FakeTokensRepo(marketResult = ApiResult.Success(market))
        val shop = FakeShopAdsRepo(units = listOf(sampleSponsored("u1"), sampleSponsored("u2")))
        val vm = vm(repo, shop)
        advanceUntilIdle()
        val s = vm.uiState.value
        // Served units are re-labeled to the token-discovery track surface.
        assertEquals(2, s.sponsored.size)
        assertTrue(s.sponsored.all { it.tracking.surface == TokensMarketViewModel.SURFACE_TOKEN_DISCOVERY })
        // Interleaved: 12 organic tokens + 2 sponsored slots, none adjacent / trailing.
        val slots = s.marketSlots
        assertEquals(12, slots.count { it is SlotEntry.Organic<*> })
        assertEquals(2, slots.count { it is SlotEntry.Sponsored<*> })
        assertTrue(slots.last() is SlotEntry.Organic<*>)
    }

    @Test
    fun impression_and_click_fire_through_track_repo() = runTest(mainRule.dispatcher) {
        val track = RecordingAdTrackRepo()
        val vm = vm(track = track)
        advanceUntilIdle()
        val ad = sampleSponsored("u1")
        vm.onSponsoredImpression(ad)
        vm.onSponsoredImpression(ad) // deduped -> still one impression
        vm.onSponsoredClick(ad)
        advanceUntilIdle()
        assertEquals(1, track.events.count { it.first == AdEvent.IMPRESSION })
        assertEquals(1, track.events.count { it.first == AdEvent.CLICK })
    }
}
