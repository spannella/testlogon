package com.testlogon.android.feature.guest

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.broadcast.BroadcastInput
import com.testlogon.android.data.broadcast.BroadcastInputType
import com.testlogon.android.data.broadcast.InputsApi
import com.testlogon.android.data.broadcast.toDomain
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Response
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-312 - data layer over [GuestApi] + the AND-310 [InputsApi].
 *
 * The host-facing guest list is the MERGE of two reads fanned out per refresh:
 *  1) GET guest-invites (the invite resource), and
 *  2) InputsApi.listInputs filtered to input_type == "guest" (the guest broadcast inputs),
 * joined by input_id into a [Guest] list whose display status is DERIVED (see [mergeGuests] /
 * [deriveGuestStatus]).
 *
 * CACHE: guests are cached IN-MEMORY in a per-session [MutableStateFlow] inside this @Singleton repo. The
 * spec's Room cache is intentionally DEFERRED (no Room table, no migration, no new dependency). [observeGuests]
 * exposes the in-memory snapshot; [refreshGuests] hits the network and updates it.
 *
 * Kept SEPARATE from BroadcastRepository / InputsRepository so the shared repository fakes are NOT touched -
 * this repo only CONSUMES [InputsApi] (an interface with no fakes to break). Each network call is wrapped in
 * [ApiResult] and the wire DTO is mapped to the domain BEFORE the typed result; never throws (Cancellation is
 * re-thrown). POSTs are never retried.
 *
 * MUTE: [setMuted] tracks the muted set CLIENT-SIDE (there is no wire echo); a successful mute POST updates
 * the in-memory muted set so the next merge reflects it.
 */
interface GuestRepository {

    /** Observe the in-memory guest snapshot for [sessionId] (offline-friendly last-known list). */
    fun observeGuests(sessionId: String): Flow<List<Guest>>

    /** Fan out GET guest-invites + listInputs(guest filter), MERGE into the list, update the cache. */
    suspend fun refreshGuests(sessionId: String): ApiResult<List<Guest>>

    /** Create a guest invite (201 GuestInviteOut). */
    suspend fun createInvite(
        sessionId: String,
        joinMode: String,
        label: String,
        expiryMinutes: Int,
    ): ApiResult<GuestInvite>

    /** Revoke invite [inviteId]. */
    suspend fun revokeInvite(sessionId: String, inviteId: String): ApiResult<Unit>

    /** Promote guest input [inputId] to the live program. */
    suspend fun promote(sessionId: String, inputId: String): ApiResult<Unit>

    /** Remove guest input [inputId] from the broadcast. */
    suspend fun remove(sessionId: String, inputId: String): ApiResult<Unit>

    /** Mute / unmute guest input [inputId] (the muted flag is tracked CLIENT-SIDE on success). */
    suspend fun setMuted(sessionId: String, inputId: String, muted: Boolean): ApiResult<Unit>

    /** Accept invite [inviteId] with a required [displayName] (the guest-side flow). */
    suspend fun acceptInvite(
        sessionId: String,
        inviteId: String,
        displayName: String,
    ): ApiResult<GuestAcceptResult>
}

@Singleton
class GuestRepositoryImpl @Inject constructor(
    private val api: GuestApi,
    private val inputsApi: InputsApi,
    private val errorParser: ApiErrorParser,
) : GuestRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    /** In-memory guest cache keyed by session id (NO Room - migration deliberately deferred per AND-312). */
    private val cache = MutableStateFlow<Map<String, List<Guest>>>(emptyMap())

    /** Client-tracked mute overlay: sessionId -> set of muted input ids (no wire echo). */
    private val muted = MutableStateFlow<Map<String, Set<String>>>(emptyMap())

    override fun observeGuests(sessionId: String): Flow<List<Guest>> =
        cache.map { it[sessionId].orEmpty() }.distinctUntilChanged()

    override suspend fun refreshGuests(sessionId: String): ApiResult<List<Guest>> = withContext(io) {
        val invitesResult = call { api.listInvites(sessionId) }
        if (invitesResult !is ApiResult.Success) return@withContext invitesResult.asFailureOf()

        val inputsResult = call { inputsApi.listInputs(sessionId) }
        if (inputsResult !is ApiResult.Success) return@withContext inputsResult.asFailureOf()

        val invites = invitesResult.data.invites.map { it.toInvite() }
        val guestInputs = inputsResult.data.toDomain()
            .filter { it.inputType.equals(BroadcastInputType.GUEST, ignoreCase = true) }
        val merged = mergeGuests(
            sessionId = sessionId,
            invites = invites,
            guestInputs = guestInputs,
            muted = mutedFor(sessionId),
        )
        cache.update { it + (sessionId to merged) }
        ApiResult.Success(merged)
    }

    override suspend fun createInvite(
        sessionId: String,
        joinMode: String,
        label: String,
        expiryMinutes: Int,
    ): ApiResult<GuestInvite> = withContext(io) {
        val body = CreateInviteRequest(joinMode = joinMode, label = label, expiryMinutes = expiryMinutes)
        call { api.createInvite(sessionId, body) }.map { it.toInvite() }
    }

    override suspend fun revokeInvite(sessionId: String, inviteId: String): ApiResult<Unit> =
        withContext(io) { callUnit { api.revokeInvite(sessionId, inviteId) } }

    override suspend fun promote(sessionId: String, inputId: String): ApiResult<Unit> =
        withContext(io) { callUnit { api.promote(sessionId, inputId) } }

    override suspend fun remove(sessionId: String, inputId: String): ApiResult<Unit> =
        withContext(io) { callUnit { api.remove(sessionId, inputId) } }

    override suspend fun setMuted(
        sessionId: String,
        inputId: String,
        muted: Boolean,
    ): ApiResult<Unit> = withContext(io) {
        val body = MuteRequest(muted = muted)
        val result = callUnit { api.setMuted(sessionId, inputId, body) }
        if (result is ApiResult.Success) {
            // Track the mute state CLIENT-SIDE (no wire echo); the next merge reflects it.
            this@GuestRepositoryImpl.muted.update { current ->
                val set = current[sessionId].orEmpty().toMutableSet()
                if (muted) set += inputId else set -= inputId
                current + (sessionId to set)
            }
        }
        result
    }

    override suspend fun acceptInvite(
        sessionId: String,
        inviteId: String,
        displayName: String,
    ): ApiResult<GuestAcceptResult> = withContext(io) {
        val body = AcceptInviteRequest(displayName = displayName)
        call { api.acceptInvite(sessionId, inviteId, body) }.map { it.toResult() }
    }

    private fun mutedFor(sessionId: String): Set<String> = muted.value[sessionId].orEmpty()

    /**
     * Folds a single call into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser]); transport
     * failures -> NetworkError; malformed JSON -> Failure(parse). The JsonEncodingException catch precedes
     * the IOException catch (it is an IOException subtype). Cancellation is re-thrown.
     */
    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: JsonEncodingException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }

    /**
     * Folds a [Response] returning call (the { ok } / empty 200 mutations) into [ApiResult] of Unit. A
     * non-2xx Response is mapped through [ApiErrorParser] from the synthesized [HttpException]; an empty 200
     * body is success.
     */
    private suspend fun callUnit(block: suspend () -> Response<*>): ApiResult<Unit> =
        when (val result = call { block() }) {
            is ApiResult.Success -> {
                val response = result.data
                if (response.isSuccessful) {
                    ApiResult.Success(Unit)
                } else {
                    ApiResult.Failure(errorParser.from(HttpException(response)))
                }
            }
            is ApiResult.Failure -> result
            is ApiResult.NetworkError -> result
        }

    /** Re-types a non-Success [ApiResult] of one payload as a non-Success [ApiResult] of another. */
    private fun ApiResult<*>.asFailureOf(): ApiResult<List<Guest>> = when (this) {
        is ApiResult.Failure -> this
        is ApiResult.NetworkError -> this
        is ApiResult.Success -> ApiResult.Success(emptyList())
    }
}
