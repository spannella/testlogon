package com.testlogon.android.feature.tokens

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiResult
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

/**
 * ViewModel-level coverage for [TokensMarketViewModel] (beyond the pure TokenMath tests): the
 * degrade-on-404 -> empty Content path (repo already folds 404 to empty Success) and the happy path
 * with a fake repo returning market + issued rows. A transport failure -> retryable Error is also
 * asserted so the "no connection" branch is exercised.
 */
class TokensMarketViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    @Test
    fun degrade_bothEmpty_toEmptyContent() = runTest(mainRule.dispatcher) {
        // 404 already folded to empty Success inside the repo -> honest empty Content, no crash.
        val vm = TokensMarketViewModel(FakeTokensRepo())
        advanceUntilIdle()
        val s = vm.uiState.value
        assertEquals(TokensMarketUiState.Phase.Content, s.phase)
        assertTrue(s.market.isEmpty())
        assertTrue(s.issued.isEmpty())
        assertTrue(s.rows.isEmpty())
        assertNull(s.errorMessage)
    }

    @Test
    fun happy_marketAndIssued_populated() = runTest(mainRule.dispatcher) {
        val repo = FakeTokensRepo(
            marketResult = ApiResult.Success(listOf(sampleToken("t1", "AAA"), sampleToken("t2", "BBB"))),
            issuedResult = ApiResult.Success(listOf(sampleToken("t3", "CCC"))),
        )
        val vm = TokensMarketViewModel(repo)
        advanceUntilIdle()
        val s = vm.uiState.value
        assertEquals(TokensMarketUiState.Phase.Content, s.phase)
        assertEquals(2, s.market.size)
        assertEquals(1, s.issued.size)
        // MARKET tab is the default -> rows mirror the market slice.
        assertEquals(2, s.rows.size)
        vm.selectTab(TokenListTab.ISSUED)
        assertEquals(1, vm.uiState.value.rows.size)
    }

    @Test
    fun transportFailure_toRetryableError() = runTest(mainRule.dispatcher) {
        val repo = FakeTokensRepo(marketResult = ApiResult.NetworkError(java.io.IOException(), isTimeout = false))
        val vm = TokensMarketViewModel(repo)
        advanceUntilIdle()
        val s = vm.uiState.value
        assertEquals(TokensMarketUiState.Phase.Error, s.phase)
        assertTrue(s.errorMessage != null)
    }
}
