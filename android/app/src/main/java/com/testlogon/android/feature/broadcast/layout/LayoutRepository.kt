package com.testlogon.android.feature.broadcast.layout

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.data.broadcast.InputsDao
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.broadcast.BroadcastLayout
import com.testlogon.android.data.broadcast.InputsApi
import com.testlogon.android.data.broadcast.LayoutSwitchRequestDto
import com.testlogon.android.data.broadcast.toDomain
import com.testlogon.android.data.broadcast.toEntity
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-311 — THIN data layer for the layout-management surface.
 *
 * Reuses AND-310 wholesale: the [InputsApi] (getLayout / switchLayout), the Room broadcast_layout cache via
 * [InputsDao] (observeLayout / upsertLayout), the AND-310 DTO->domain [toDomain] mappers, and the
 * domain->entity [toEntity] mapper. NO new endpoint, NO new Room table, NO migration.
 *
 * Kept SEPARATE from
 * [com.testlogon.android.data.broadcast.InputsRepository] so the inputs fakes are NOT touched — both
 * repositories share the same API + DAO but expose distinct, narrow surfaces.
 *
 * SWR-flavoured: [observeLayout] exposes the Room cache as a Flow (last-known mode / primary / inputIds —
 * offline-friendly); [refresh] GETs and upserts; [setLayout] POSTs the new mode and upserts the refreshed
 * layout. Each network call is wrapped in [ApiResult] with the wire DTO mapped to the domain BEFORE the
 * typed result; never throws (CancellationException is re-thrown). The POST is never retried.
 *
 * POSITIONS NOTE (FR-4): the cached [BroadcastLayout] from Room carries EMPTY positions by design (AND-310
 * does not persist them and AND-311 adds NO migration). The live, full positions list comes only from the
 * in-memory [BroadcastLayout] returned by [refresh] / [setLayout]; the ViewModel holds it in state for the
 * read-only positions display. Room drives only the live-mode badge (mode / primary / inputIds suffice).
 */
interface LayoutRepository {

    /** Observe the cached layout for [sessionId] (Room-backed; offline-friendly; positions are empty). */
    fun observeLayout(sessionId: String): Flow<BroadcastLayout?>

    /** GET the layout, upserting the cache; returns the fresh domain layout (with in-memory positions). */
    suspend fun refresh(sessionId: String): ApiResult<BroadcastLayout>

    /**
     * Switch [sessionId]'s composition to [mode]. The web client (and this port) sends only the required
     * `mode`; [inputIds] / [primaryInputId] are optional re-orders left null so the server keeps its input
     * set. On success the refreshed layout is upserted to the cache; on failure the cache is left intact and
     * the error is surfaced.
     */
    suspend fun setLayout(
        sessionId: String,
        mode: String,
        inputIds: List<String>? = null,
        primaryInputId: String? = null,
    ): ApiResult<BroadcastLayout>
}

@Singleton
class LayoutRepositoryImpl @Inject constructor(
    private val api: InputsApi,
    private val dao: InputsDao,
    private val errorParser: ApiErrorParser,
) : LayoutRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override fun observeLayout(sessionId: String): Flow<BroadcastLayout?> =
        dao.observeLayout(sessionId).map { it?.toDomain() }

    override suspend fun refresh(sessionId: String): ApiResult<BroadcastLayout> =
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

    override suspend fun setLayout(
        sessionId: String,
        mode: String,
        inputIds: List<String>?,
        primaryInputId: String?,
    ): ApiResult<BroadcastLayout> = withContext(io) {
        val body = LayoutSwitchRequestDto(mode = mode, primaryInputId = primaryInputId, inputIds = inputIds)
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
     * the IOException catch (it is an IOException subtype). Cancellation is re-thrown. Mirrors AND-310's
     * InputsRepositoryImpl.call.
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
