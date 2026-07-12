package com.testlogon.android.data.watchparties

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
 * Watch-parties data layer over [WatchPartiesApi] (mirrors AlertsRepository conventions).
 *
 * All calls are wrapped in [ApiResult] (CancellationException re-thrown, HTTP -> Failure,
 * malformed body -> Failure, transport -> NetworkError). The list keeps a last-known-good in-memory
 * snapshot so a failed refresh can fall back to stale content; [clear] empties it (logout cleanup).
 * Mutations (create/join/leave) are not auto-retried. Realtime playback is intentionally absent.
 */
interface WatchPartiesRepository {

    suspend fun loadParties(): ApiResult<List<WatchParty>>

    suspend fun createParty(videoId: String, title: String?, maxParticipants: Int?): ApiResult<WatchParty>

    suspend fun getParty(partyId: String): ApiResult<WatchParty>

    suspend fun loadParticipants(partyId: String): ApiResult<List<WatchPartyParticipant>>

    suspend fun joinParty(partyId: String): ApiResult<Unit>

    suspend fun leaveParty(partyId: String): ApiResult<Unit>

    suspend fun resolveInvite(inviteCode: String): ApiResult<InviteResolution>

    fun cached(): List<WatchParty>?

    fun clear()
}

@Singleton
class WatchPartiesRepositoryImpl @Inject constructor(
    private val api: WatchPartiesApi,
    private val errorParser: ApiErrorParser,
) : WatchPartiesRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    @Volatile
    private var snapshot: List<WatchParty>? = null

    override suspend fun loadParties(): ApiResult<List<WatchParty>> = withContext(io) {
        call { api.listParties().map { it.toDomain() } }
            .also { if (it is ApiResult.Success) snapshot = it.data }
    }

    override suspend fun createParty(
        videoId: String,
        title: String?,
        maxParticipants: Int?,
    ): ApiResult<WatchParty> = withContext(io) {
        call {
            api.createParty(
                CreatePartyReqDto(
                    videoId = videoId,
                    title = title?.takeIf { it.isNotBlank() },
                    maxParticipants = maxParticipants,
                ),
            ).toDomain()
        }
    }

    override suspend fun getParty(partyId: String): ApiResult<WatchParty> = withContext(io) {
        call { api.getParty(partyId).toDomain() }
    }

    override suspend fun loadParticipants(partyId: String): ApiResult<List<WatchPartyParticipant>> =
        withContext(io) {
            call { api.listParticipants(partyId).map { it.toDomain() } }
        }

    override suspend fun joinParty(partyId: String): ApiResult<Unit> = withContext(io) {
        call { api.joinParty(partyId); Unit }
    }

    override suspend fun leaveParty(partyId: String): ApiResult<Unit> = withContext(io) {
        call { api.leaveParty(partyId); Unit }
    }

    override suspend fun resolveInvite(inviteCode: String): ApiResult<InviteResolution> = withContext(io) {
        call { api.resolveInvite(inviteCode).toDomain() }
    }

    override fun cached(): List<WatchParty>? = snapshot

    override fun clear() {
        snapshot = null
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: com.squareup.moshi.JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
