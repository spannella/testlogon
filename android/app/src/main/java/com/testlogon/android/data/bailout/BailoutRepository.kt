package com.testlogon.android.data.bailout

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
 * Data layer over [BailoutApi] for the MARGIN DISTRESS / PRE-EMPTIVE BAILOUT AUCTION surface.
 *
 * The endpoints do NOT exist on the backend yet, so every READ DEGRADES to an empty-but-honest value on
 * 404/HTTP-error (the UI shows an honest "pending backend" / empty state and NEVER fabricates distress),
 * while a real transport failure ([ApiResult.NetworkError]) is surfaced so the UI can offer retry.
 * Every MUTATION passes failures through as [ApiResult.Failure]/[ApiResult.NetworkError] so a 404
 * (undeployed) surfaces as a clear error and never a silent success.
 *
 * The auto-bailout preference read additionally degrades to a DEVICE-LOCAL copy ([BailoutPrefsStore])
 * when the server endpoint 404s, so the settings toggle always reflects the last chosen value.
 */
interface BailoutRepository {
    /** The caller's distressed-but-solvent positions (degrades to empty — never fabricated). */
    suspend fun distress(): ApiResult<List<DistressPosition>>

    /** Open bailout auctions to browse — the rescuer board (degrades to empty). */
    suspend fun bailouts(): ApiResult<List<BailoutAuction>>

    /** The bailout auction for one position (degrades to null when none / undeployed). */
    suspend fun positionBailout(symbolId: Int): ApiResult<BailoutAuction?>

    /** The auto-bailout preference (degrades to the device-local copy on 404). */
    suspend fun prefs(): ApiResult<BailoutPrefs>

    // ---- Mutations (errors surface; never silent success) ----
    suspend fun openBailout(symbolId: Int, maxShareBps: Int, closeTs: Long?): ApiResult<BailoutAuction>
    suspend fun placeBid(auctionId: String, capitalCents: Long, shareBps: Int): ApiResult<BailoutAck>
    suspend fun clear(auctionId: String): ApiResult<BailoutAuction>
    suspend fun putPrefs(autoEnabled: Boolean, defaultMaxShareBps: Int): ApiResult<BailoutPrefs>
}

@Singleton
class BailoutRepositoryImpl @Inject constructor(
    private val api: BailoutApi,
    private val prefsStore: BailoutPrefsStore,
    private val errorParser: ApiErrorParser,
) : BailoutRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun distress(): ApiResult<List<DistressPosition>> = withContext(io) {
        degradeToEmpty(emptyList()) { api.getDistress().toDomain() }
    }

    override suspend fun bailouts(): ApiResult<List<BailoutAuction>> = withContext(io) {
        degradeToEmpty(emptyList()) { api.getBailouts().toDomain() }
    }

    override suspend fun positionBailout(symbolId: Int): ApiResult<BailoutAuction?> = withContext(io) {
        degradeToEmpty(null) { api.getPositionBailout(symbolId).toDomain() }
    }

    override suspend fun prefs(): ApiResult<BailoutPrefs> = withContext(io) {
        // Degrade to the device-local copy on HTTP error (endpoint pending); mirror server reads locally.
        when (val r = apiCall { api.getPrefs().toDomain() }) {
            is ApiResult.Success -> { prefsStore.write(r.data); r }
            is ApiResult.Failure -> ApiResult.Success(prefsStore.read())
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun openBailout(
        symbolId: Int,
        maxShareBps: Int,
        closeTs: Long?,
    ): ApiResult<BailoutAuction> = withContext(io) {
        apiCall { api.openBailout(symbolId, OpenBailoutRequestDto(maxShareBps, closeTs)).toDomain() }
    }

    override suspend fun placeBid(
        auctionId: String,
        capitalCents: Long,
        shareBps: Int,
    ): ApiResult<BailoutAck> = withContext(io) {
        apiCall { api.placeBid(auctionId, BailoutBidRequestDto(capitalCents, shareBps)).toDomain() }
    }

    override suspend fun clear(auctionId: String): ApiResult<BailoutAuction> = withContext(io) {
        apiCall { api.clear(auctionId).toDomain(auctionId) }
    }

    override suspend fun putPrefs(
        autoEnabled: Boolean,
        defaultMaxShareBps: Int,
    ): ApiResult<BailoutPrefs> = withContext(io) {
        // Always persist locally so the toggle is durable even when the server endpoint 404s. If the PUT
        // itself 404s we still report success from the local write (labelled device-local in the UI).
        prefsStore.write(BailoutPrefs(autoEnabled, defaultMaxShareBps))
        when (val r = apiCall { api.putPrefs(BailoutPrefsDto(autoEnabled, defaultMaxShareBps)).toDomain() }) {
            is ApiResult.Success -> { prefsStore.write(r.data); r }
            is ApiResult.Failure -> ApiResult.Success(prefsStore.read())
            is ApiResult.NetworkError -> r
        }
    }

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
