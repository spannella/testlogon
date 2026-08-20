package com.testlogon.android.data.tokens

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Data layer over [TokensApi] for the CREATOR REVENUE-SHARE TOKEN surface.
 *
 * The `me/tokens/(all)` endpoints do NOT exist on the backend yet, so every READ DEGRADES to an
 * empty-but-honest value on 404/HTTP-error (the UI shows an honest "pending backend" / empty state),
 * while a real transport failure ([ApiResult.NetworkError]) is surfaced so the UI can offer retry.
 * Every MUTATION passes failures through as [ApiResult.Failure]/[ApiResult.NetworkError] so a 404
 * (undeployed) surfaces as a clear error and never a silent success.
 */
interface TokensRepository {
    /** Tokens issued by the caller (degrades to empty). */
    suspend fun issued(): ApiResult<List<Token>>

    /** Listed tokens to browse — the market (degrades to empty). */
    suspend fun market(): ApiResult<List<Token>>

    /** A single token by id (degrades to null when absent/undeployed). */
    suspend fun token(id: String): ApiResult<Token?>

    /** Cap table (degrades to an empty table). */
    suspend fun capTable(id: String): ApiResult<TokenCapTable>

    /** The IPO auction (degrades to null when none / undeployed). */
    suspend fun auction(id: String): ApiResult<TokenAuction?>

    /** Revenue + my claimable (degrades to a zeroed, empty read). */
    suspend fun revenue(id: String): ApiResult<TokenRevenue>

    /** Book-upkeep state (degrades to a zeroed, empty read). */
    suspend fun upkeep(id: String): ApiResult<TokenUpkeep>

    // ---- Mutations (errors surface; never silent success) ----
    suspend fun mint(name: String, ticker: String, totalSupply: Long, revenueShareBps: Int): ApiResult<Token>
    suspend fun list(id: String, offeredPctBps: Int, reservePrice: Long, closeTs: Long): ApiResult<TokenAuction>
    suspend fun placeBid(id: String, qty: Long, limitPrice: Long): ApiResult<TokenAck>
    suspend fun clearAuction(id: String): ApiResult<TokenAuction>
    suspend fun claimRevenue(id: String): ApiResult<TokenAck>
    suspend fun payUpkeep(id: String): ApiResult<TokenAck>
}

@Singleton
class TokensRepositoryImpl @Inject constructor(
    private val api: TokensApi,
    private val errorParser: ApiErrorParser,
) : TokensRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun issued(): ApiResult<List<Token>> = withContext(io) {
        degradeToEmpty(emptyList()) { api.getIssued().toDomain() }
    }

    override suspend fun market(): ApiResult<List<Token>> = withContext(io) {
        degradeToEmpty(emptyList()) { api.getMarket().toDomain() }
    }

    override suspend fun token(id: String): ApiResult<Token?> = withContext(io) {
        degradeToEmpty(null) { api.getToken(id).toDomain() }
    }

    override suspend fun capTable(id: String): ApiResult<TokenCapTable> = withContext(io) {
        degradeToEmpty(TokenCapTable(id, 0, emptyList())) { api.getCapTable(id).toDomain(id) }
    }

    override suspend fun auction(id: String): ApiResult<TokenAuction?> = withContext(io) {
        degradeToEmpty(null) { api.getAuction(id).toDomain(id) }
    }

    override suspend fun revenue(id: String): ApiResult<TokenRevenue> = withContext(io) {
        degradeToEmpty(TokenRevenue(id, 0L, 0, 0L, emptyList())) { api.getRevenue(id).toDomain(id) }
    }

    override suspend fun upkeep(id: String): ApiResult<TokenUpkeep> = withContext(io) {
        degradeToEmpty(TokenUpkeep(id, "", 0L, 0L, 0L, 0L, UpkeepStatus.UNKNOWN)) {
            api.getUpkeep(id).toDomain(id)
        }
    }

    override suspend fun mint(
        name: String,
        ticker: String,
        totalSupply: Long,
        revenueShareBps: Int,
    ): ApiResult<Token> = withContext(io) {
        apiCall { api.mint(MintTokenRequestDto(name, ticker, totalSupply, revenueShareBps)).toDomain() }
    }

    override suspend fun list(
        id: String,
        offeredPctBps: Int,
        reservePrice: Long,
        closeTs: Long,
    ): ApiResult<TokenAuction> = withContext(io) {
        apiCall { api.list(id, ListTokenRequestDto(offeredPctBps, reservePrice, closeTs)).toDomain(id) }
    }

    override suspend fun placeBid(id: String, qty: Long, limitPrice: Long): ApiResult<TokenAck> =
        withContext(io) { apiCall { api.placeBid(id, PlaceBidRequestDto(qty, limitPrice)).toDomain() } }

    override suspend fun clearAuction(id: String): ApiResult<TokenAuction> =
        withContext(io) { apiCall { api.clearAuction(id).toDomain(id) } }

    override suspend fun claimRevenue(id: String): ApiResult<TokenAck> =
        withContext(io) { apiCall { api.claimRevenue(id).toDomain() } }

    override suspend fun payUpkeep(id: String): ApiResult<TokenAck> =
        withContext(io) { apiCall { api.payUpkeep(id).toDomain() } }

    /**
     * Read helper: run [block]; on an HTTP error (the endpoint doesn't exist yet -> 404) DEGRADE to
     * [empty]; only a transport [ApiResult.NetworkError] is surfaced (so the UI can offer retry).
     */
    private suspend fun <T> degradeToEmpty(empty: T, block: suspend () -> T): ApiResult<T> =
        when (val r = apiCall(block)) {
            is ApiResult.Success -> r
            is ApiResult.Failure -> ApiResult.Success(empty)
            is ApiResult.NetworkError -> r
        }

    private suspend fun <T> apiCall(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
