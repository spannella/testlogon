package com.testlogon.android.data.broadcast

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.data.broadcast.BroadcastInputEntity
import com.testlogon.android.core.data.broadcast.BroadcastLayoutEntity
import com.testlogon.android.core.data.broadcast.InputsDao
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import java.time.Instant
import java.time.format.DateTimeParseException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-310 — data layer over [InputsApi] + the Room inputs/layout cache ([InputsDao]).
 *
 * SWR-flavoured: [observeInputs] / [observeLayout] expose the Room cache as a Flow (last-known data,
 * offline-friendly); [refresh] / [refreshLayout] hit the network and overwrite the cache. [setActive]
 * toggles via the activate/deactivate POSTs (empty body, { ok }) then RE-GETs the list to learn the
 * authoritative is_live (the toggle endpoints do NOT return the row). [setProgram] promotes an input to the
 * live program by POSTing the layout with the required mode + primary_input_id.
 *
 * Kept SEPARATE from [BroadcastRepository] so the shared repository fakes are not touched. Each network
 * call is wrapped in [ApiResult] and the wire DTO is mapped to the domain BEFORE the typed result; never
 * throws (CancellationException is re-thrown). POSTs are never retried.
 */
interface InputsRepository {

    /** Observe the cached inputs for [sessionId] (Room-backed; offline-friendly). */
    fun observeInputs(sessionId: String): Flow<List<BroadcastInput>>

    /** Observe the cached layout for [sessionId] (or null if none cached). */
    fun observeLayout(sessionId: String): Flow<BroadcastLayout?>

    /** GET the inputs list, atomically replacing the cache; returns the fresh domain list. */
    suspend fun refresh(sessionId: String): ApiResult<List<BroadcastInput>>

    /** GET the layout, upserting the cache; returns the fresh domain layout. */
    suspend fun refreshLayout(sessionId: String): ApiResult<BroadcastLayout>

    /**
     * Activate ([active] = true) or deactivate [inputId] on [sessionId]. The toggle endpoints return only
     * { ok }, so on success this RE-GETs the list (refresh) and returns the authoritative domain list.
     */
    suspend fun setActive(
        sessionId: String,
        inputId: String,
        active: Boolean,
    ): ApiResult<List<BroadcastInput>>

    /**
     * Promote [inputId] to the live program by POSTing the layout with [mode] + primary_input_id=[inputId].
     * Upserts the returned layout to the cache; returns the fresh domain layout.
     */
    suspend fun setProgram(
        sessionId: String,
        inputId: String,
        mode: String,
    ): ApiResult<BroadcastLayout>
}

@Singleton
class InputsRepositoryImpl @Inject constructor(
    private val api: InputsApi,
    private val dao: InputsDao,
    private val errorParser: ApiErrorParser,
) : InputsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override fun observeInputs(sessionId: String): Flow<List<BroadcastInput>> =
        dao.observeBySession(sessionId).map { rows -> rows.map { it.toDomain() } }

    override fun observeLayout(sessionId: String): Flow<BroadcastLayout?> =
        dao.observeLayout(sessionId).map { it?.toDomain() }

    override suspend fun refresh(sessionId: String): ApiResult<List<BroadcastInput>> =
        withContext(io) {
            when (val result = call { api.listInputs(sessionId) }.map { it.toDomain() }) {
                is ApiResult.Success -> {
                    dao.replaceForSession(sessionId, result.data.map { it.toEntity() })
                    result
                }
                is ApiResult.Failure -> result
                is ApiResult.NetworkError -> result
            }
        }

    override suspend fun refreshLayout(sessionId: String): ApiResult<BroadcastLayout> =
        withContext(io) {
            when (val result = call { api.getLayout(sessionId) }.map { it.toDomain() }) {
                is ApiResult.Success -> {
                    dao.upsertLayout(result.data.toEntity(sessionId))
                    result
                }
                is ApiResult.Failure -> result
                is ApiResult.NetworkError -> result
            }
        }

    override suspend fun setActive(
        sessionId: String,
        inputId: String,
        active: Boolean,
    ): ApiResult<List<BroadcastInput>> = withContext(io) {
        val toggle = call {
            if (active) api.activateInput(sessionId, inputId) else api.deactivateInput(sessionId, inputId)
        }
        when (toggle) {
            is ApiResult.Success -> refresh(sessionId)
            is ApiResult.Failure -> toggle
            is ApiResult.NetworkError -> toggle
        }
    }

    override suspend fun setProgram(
        sessionId: String,
        inputId: String,
        mode: String,
    ): ApiResult<BroadcastLayout> = withContext(io) {
        val body = LayoutSwitchRequestDto(mode = mode, primaryInputId = inputId)
        when (val result = call { api.switchLayout(sessionId, body) }.map { it.toDomain() }) {
            is ApiResult.Success -> {
                dao.upsertLayout(result.data.toEntity(sessionId))
                result
            }
            is ApiResult.Failure -> result
            is ApiResult.NetworkError -> result
        }
    }

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
}

// ─── entity <-> domain mappers (pure) ────────────────────────────────────────────────────────────────

internal fun BroadcastInputEntity.toDomain(): BroadcastInput = BroadcastInput(
    inputId = inputId,
    sessionId = sessionId,
    inputType = inputType,
    label = label,
    ingestUrl = null,
    streamKey = null,
    position = position,
    isLive = isLive,
    connectedAt = connectedAt,
    disconnectedAt = disconnectedAt,
    createdBy = createdBy,
    createdAt = createdAt.toInstantOrNull(),
    updatedAt = updatedAt.toInstantOrNull(),
)

internal fun BroadcastInput.toEntity(): BroadcastInputEntity = BroadcastInputEntity(
    sessionId = sessionId,
    inputId = inputId,
    inputType = inputType,
    label = label,
    isLive = isLive,
    position = position,
    connectedAt = connectedAt,
    disconnectedAt = disconnectedAt,
    createdBy = createdBy,
    createdAt = createdAt?.toString(),
    updatedAt = updatedAt?.toString(),
)

internal fun BroadcastLayoutEntity.toDomain(): BroadcastLayout = BroadcastLayout(
    mode = mode,
    primaryInputId = primaryInputId,
    inputIds = inputIds,
    positions = emptyList(),
)

internal fun BroadcastLayout.toEntity(sessionId: String): BroadcastLayoutEntity = BroadcastLayoutEntity(
    sessionId = sessionId,
    mode = mode,
    primaryInputId = primaryInputId,
    inputIds = inputIds,
)

private fun String?.toInstantOrNull(): Instant? {
    if (this.isNullOrBlank()) return null
    return try {
        Instant.parse(this)
    } catch (_: DateTimeParseException) {
        null
    }
}
