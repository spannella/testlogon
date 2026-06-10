package com.testlogon.android.data.messaging

import com.testlogon.android.core.data.messaging.DraftDao
import com.testlogon.android.core.data.messaging.DraftEntity
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Retrofit
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-141 — per-conversation composer draft. Local-first: every save/clear completes on the Room
 * write; the network call is best-effort. Field is `text` (not `body`); timestamps are epoch ms.
 */
data class Draft(
    val conversationId: String,
    val text: String,
    val updatedAtEpochMs: Long,
    val version: Int = 1,
    /** Server `draft_id` once synced; null while local-only. */
    val remoteId: String? = null,
    /** True when a local change has not yet been pushed. */
    val pendingSync: Boolean = false,
)

/** AND-141 — offline-first draft store: observe + reconcile-on-open + save + clear. */
interface DraftRepository {

    /** Reactive draft for a conversation, backed by Room (the restore source of truth). */
    fun observeDraft(conversationId: String): Flow<Draft?>

    /** Reconciles local + server on screen open; returns the draft to restore (or null). */
    suspend fun loadAndReconcile(conversationId: String): ApiResult<Draft?>

    /** Persists locally (pendingSync=true) then best-effort POST/PATCH; never blocks the user. */
    suspend fun saveDraft(conversationId: String, text: String): ApiResult<Draft>

    /** Deletes locally then best-effort DELETE (skipped for local-only drafts). */
    suspend fun clearDraft(conversationId: String): ApiResult<Unit>

    /** Pushes any pendingSync rows (invoked on open / app foreground); failures are silent. */
    suspend fun flushPending()
}

@Singleton
class DraftRepositoryImpl @Inject constructor(
    private val api: DraftApi,
    private val draftDao: DraftDao,
    private val errorParser: ApiErrorParser,
) : DraftRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    /** Epoch-millis clock; overridable in tests for deterministic timestamps. */
    internal var clock: () -> Long = { System.currentTimeMillis() }

    override fun observeDraft(conversationId: String): Flow<Draft?> =
        draftDao.observe(conversationId).map { it?.toDomain() }

    override suspend fun loadAndReconcile(conversationId: String): ApiResult<Draft?> = withContext(io) {
        val local = draftDao.get(conversationId)?.toDomain()
        when (val r = apiCall { api.listDrafts(conversationId) }) {
            is ApiResult.Success -> {
                // The active draft is the most-recent server entry (newest updated_at).
                val serverDraft = r.data.items.maxByOrNull { it.updatedAt }?.toDomain()
                val winner = reconcile(local, serverDraft)
                when {
                    winner == null -> { draftDao.delete(conversationId); ApiResult.Success(null) }
                    winner === serverDraft -> {
                        // Server won: overwrite Room, mark synced.
                        draftDao.upsert(winner.copy(pendingSync = false).toEntity())
                        ApiResult.Success(winner.copy(pendingSync = false))
                    }
                    else -> {
                        // Local won (or local-only): keep it and push.
                        draftDao.upsert(winner.toEntity())
                        if (winner.text.isNotBlank()) pushDraft(conversationId, winner)
                        ApiResult.Success(draftDao.get(conversationId)?.toDomain() ?: winner)
                    }
                }
            }
            // GET failed: fall back to the local copy (never block the composer).
            else -> ApiResult.Success(local)
        }
    }

    override suspend fun saveDraft(conversationId: String, text: String): ApiResult<Draft> = withContext(io) {
        val trimmed = text.trim()
        // FR-3: an empty body deletes rather than persists.
        if (trimmed.isEmpty()) {
            clearDraft(conversationId)
            return@withContext ApiResult.Success(
                Draft(conversationId, "", clock(), pendingSync = false),
            )
        }
        val now = clock()
        val existing = draftDao.get(conversationId)
        val local = Draft(
            conversationId = conversationId,
            text = trimmed,
            updatedAtEpochMs = now,
            version = existing?.version ?: 1,
            remoteId = existing?.remoteId,
            pendingSync = true,
        )
        // Local-first: write Room before the network call so restore/persistence never depend on it.
        draftDao.upsert(local.toEntity())
        val synced = pushDraft(conversationId, local)
        ApiResult.Success(draftDao.get(conversationId)?.toDomain() ?: synced ?: local)
    }

    override suspend fun clearDraft(conversationId: String): ApiResult<Unit> = withContext(io) {
        val existing = draftDao.get(conversationId)
        draftDao.delete(conversationId)
        val remoteId = existing?.remoteId
        // Local-only drafts are removed without a server call (mirrors the web deleteDraft behaviour).
        if (remoteId != null) {
            when (val r = apiCall { api.deleteDraft(conversationId, remoteId) }) {
                is ApiResult.Failure ->
                    // 404 (already gone) is idempotent success; other failures are non-blocking.
                    if (r.error.status != HTTP_NOT_FOUND) return@withContext ApiResult.Success(Unit)
                else -> Unit
            }
        }
        ApiResult.Success(Unit)
    }

    override suspend fun flushPending() = withContext(io) {
        draftDao.pending().forEach { entity ->
            if (entity.text.isNotBlank()) pushDraft(entity.conversationId, entity.toDomain())
        }
    }

    /**
     * Best-effort upstream of a local draft: POST when no remoteId, PATCH when one exists. On
     * success records remoteId/version and clears pendingSync; on failure leaves pendingSync=true.
     */
    private suspend fun pushDraft(conversationId: String, local: Draft): Draft? {
        val body = DraftCreateDto(text = local.text, clientUpdatedAt = local.updatedAtEpochMs)
        val call = if (local.remoteId == null) {
            apiCall {
                api.createDraft(
                    conversationId,
                    idempotencyKey = "$conversationId:${local.updatedAtEpochMs}",
                    body = body,
                )
            }
        } else {
            apiCall {
                api.patchDraft(
                    conversationId,
                    local.remoteId,
                    DraftPatchDto(text = local.text, clientUpdatedAt = local.updatedAtEpochMs),
                )
            }
        }
        return when (call) {
            is ApiResult.Success -> {
                val synced = call.data.draft.toDomain().copy(pendingSync = false)
                draftDao.upsert(synced.toEntity())
                synced
            }
            else -> null // keep pendingSync=true; flushPending retries later
        }
    }

    /** FR-7 — keep the newer copy by updatedAt; ties go to local (the device is authoritative for typing). */
    private fun reconcile(local: Draft?, server: Draft?): Draft? = when {
        local == null && server == null -> null
        local == null -> server
        server == null -> local
        local.updatedAtEpochMs >= server.updatedAtEpochMs -> local.copy(remoteId = local.remoteId ?: server.remoteId)
        else -> server
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

    private companion object {
        const val HTTP_NOT_FOUND = 404
    }
}

// ---- mappers ----

internal fun DraftEntity.toDomain(): Draft = Draft(
    conversationId = conversationId,
    text = text,
    updatedAtEpochMs = updatedAtEpochMs,
    version = version,
    remoteId = remoteId,
    pendingSync = pendingSync,
)

internal fun Draft.toEntity(): DraftEntity = DraftEntity(
    conversationId = conversationId,
    text = text,
    updatedAtEpochMs = updatedAtEpochMs,
    version = version,
    remoteId = remoteId,
    pendingSync = pendingSync,
)

internal fun DraftDto.toDomain(): Draft = Draft(
    conversationId = conversationId,
    text = text,
    updatedAtEpochMs = updatedAt,
    version = version,
    remoteId = draftId,
    pendingSync = false,
)

/** AND-141 — provides the [DraftApi] + binds the [DraftRepository]. */
@Module
@InstallIn(SingletonComponent::class)
object DraftApiModule {

    @Provides
    @Singleton
    fun provideDraftApi(retrofit: Retrofit): DraftApi = retrofit.create(DraftApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class DraftDataModule {

    @Binds
    @Singleton
    abstract fun bindDraftRepository(impl: DraftRepositoryImpl): DraftRepository
}
