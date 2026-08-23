package com.testlogon.android.feature.trading

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.strategies.InvestorPosition
import com.testlogon.android.data.strategies.StrategiesRepository
import com.testlogon.android.data.strategies.Strategy
import com.testlogon.android.data.strategies.StrategyAck
import com.testlogon.android.data.strategies.StrategyFees
import com.testlogon.android.data.strategies.StrategyHolding
import com.testlogon.android.data.strategies.StrategyNav
import com.testlogon.android.data.strategies.UpsertStrategyRequestDto
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

/**
 * Shared (non-private, feature.trading-package) fakes for the token + strategy repositories, usable
 * across the trading-surface ViewModel tests. Reads default to empty/null Successes (mirroring the
 * repos' degrade-on-404 folding); individual reads are overridable via the `var` fields.
 */

class FakeTokensRepository(
    var marketResult: ApiResult<List<Token>> = ApiResult.Success(emptyList()),
    var issuedResult: ApiResult<List<Token>> = ApiResult.Success(emptyList()),
    var tokenResult: ApiResult<Token?> = ApiResult.Success(null),
) : TokensRepository {
    override suspend fun issued(): ApiResult<List<Token>> = issuedResult
    override suspend fun market(): ApiResult<List<Token>> = marketResult
    override suspend fun openAuctions(): ApiResult<List<TokenAuction>> = ApiResult.Success(emptyList())
    override suspend fun token(id: String): ApiResult<Token?> = tokenResult
    override suspend fun capTable(id: String): ApiResult<TokenCapTable> = ApiResult.Success(TokenCapTable(id, 0, emptyList()))
    override suspend fun auction(id: String): ApiResult<TokenAuction?> = ApiResult.Success(null)
    override suspend fun revenue(id: String): ApiResult<TokenRevenue> = ApiResult.Success(TokenRevenue(id, 0, 0, 0, emptyList()))
    override suspend fun upkeep(id: String): ApiResult<TokenUpkeep> = ApiResult.Success(TokenUpkeep(id, "", 0, 0, 0, 0, UpkeepStatus.UNKNOWN))
    override suspend fun mint(name: String, ticker: String, totalSupply: Long, revenueShareBps: Int) = ApiResult.Success(sampleTokenFake("x", ticker))
    override suspend fun list(id: String, offeredPctBps: Int, reservePrice: Long, closeTs: Long) = ApiResult.Success(TokenAuction("a", id, 0, 0, AuctionStatus.OPEN))
    override suspend fun placeBid(id: String, qty: Long, limitPrice: Long) = ApiResult.Success(TokenAck(true))
    override suspend fun clearAuction(id: String) = ApiResult.Success(TokenAuction("a", id, 0, 0, AuctionStatus.CLEARED))
    override suspend fun claimRevenue(id: String) = ApiResult.Success(TokenAck(true))
    override suspend fun payUpkeep(id: String) = ApiResult.Success(TokenAck(true))
}

fun sampleTokenFake(id: String, ticker: String, clearingPrice: Long? = null) = Token(
    tokenId = id,
    name = "Token $ticker",
    ticker = ticker,
    totalSupply = 1_000_000L,
    revenueShareBps = 1_000,
    status = TokenStatus.LISTED,
    clearingPrice = clearingPrice,
)

class FakeStrategiesRepository(
    var mineResult: ApiResult<List<Strategy>> = ApiResult.Success(emptyList()),
    var marketResult: ApiResult<List<Strategy>> = ApiResult.Success(emptyList()),
    var strategyResult: ApiResult<Strategy?> = ApiResult.Success(null),
    var navResult: ApiResult<StrategyNav?> = ApiResult.Success(null),
    var positionResult: ApiResult<InvestorPosition?> = ApiResult.Success(null),
) : StrategiesRepository {
    var investResult: ApiResult<StrategyAck> = ApiResult.Success(StrategyAck(true))
    var redeemResult: ApiResult<StrategyAck> = ApiResult.Success(StrategyAck(true))
    override suspend fun mine(): ApiResult<List<Strategy>> = mineResult
    override suspend fun market(): ApiResult<List<Strategy>> = marketResult
    override suspend fun strategy(id: String): ApiResult<Strategy?> = strategyResult
    override suspend fun nav(id: String): ApiResult<StrategyNav?> = navResult
    override suspend fun holdings(id: String): ApiResult<List<StrategyHolding>> = ApiResult.Success(emptyList())
    override suspend fun position(id: String): ApiResult<InvestorPosition?> = positionResult
    override suspend fun fees(id: String): ApiResult<StrategyFees> = ApiResult.Success(StrategyFees(id, 0, 0, 0, emptyList()))
    override suspend fun create(body: UpsertStrategyRequestDto) = ApiResult.Success(sampleStrategyFake("x", "x"))
    override suspend fun update(id: String, body: UpsertStrategyRequestDto) = ApiResult.Success(sampleStrategyFake(id, "x"))
    override suspend fun publish(id: String) = ApiResult.Success(sampleStrategyFake(id, "x"))
    override suspend fun invest(id: String, amountCents: Long) = investResult
    override suspend fun redeem(id: String, units: Long) = redeemResult
}

fun sampleStrategyFake(id: String, name: String, aumCents: Long? = null, navPerUnit: Long? = null, inceptionReturnBps: Int? = null) =
    Strategy(strategyId = id, name = name, aumCents = aumCents, navPerUnit = navPerUnit, inceptionReturnBps = inceptionReturnBps)
