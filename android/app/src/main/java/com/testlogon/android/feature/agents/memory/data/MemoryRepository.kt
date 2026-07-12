package com.testlogon.android.feature.agents.memory.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.agents.AgentIdentityUpdateRequest
import com.testlogon.android.core.network.agents.MemoryApi
import com.testlogon.android.core.network.agents.MemoryEntryCreateRequest
import com.testlogon.android.core.network.agents.ProjectContextUpdateRequest
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Response
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AGENTS-BASICS (web-parity) - data layer for the per-worker MEMORY surface over [MemoryApi]. Folds transport
 * into [ApiResult] via [call]. GETs are idempotent; identity/project PUT + entry add/delete are mutations. Mirrors
 * the WORKERS repository fold. No cache / Room.
 */
interface MemoryRepository {
    suspend fun getIdentity(workerId: String): ApiResult<AgentIdentity>
    suspend fun updateIdentity(workerId: String, identityText: String, customInstructions: String): ApiResult<AgentIdentity>
    suspend fun getProject(workerId: String): ApiResult<ProjectContext>
    suspend fun updateProject(workerId: String, update: ProjectContextUpdateRequest): ApiResult<ProjectContext>
    suspend fun listEntries(workerId: String, category: String? = null): ApiResult<MemoryList>
    suspend fun addEntry(workerId: String, request: MemoryEntryCreateRequest): ApiResult<MemoryEntry>
    suspend fun deleteEntry(workerId: String, memoryId: String): ApiResult<Unit>
}

@Singleton
class DefaultMemoryRepository @Inject constructor(
    private val api: MemoryApi,
    private val errorParser: ApiErrorParser,
) : MemoryRepository {

    override suspend fun getIdentity(workerId: String): ApiResult<AgentIdentity> =
        withContext(Dispatchers.IO) { call { api.getIdentity(workerId).toDomain() } }

    override suspend fun updateIdentity(
        workerId: String,
        identityText: String,
        customInstructions: String,
    ): ApiResult<AgentIdentity> = withContext(Dispatchers.IO) {
        call {
            api.updateIdentity(
                workerId,
                AgentIdentityUpdateRequest(identityText = identityText, customInstructions = customInstructions),
            ).toDomain()
        }
    }

    override suspend fun getProject(workerId: String): ApiResult<ProjectContext> =
        withContext(Dispatchers.IO) { call { api.getProject(workerId).toDomain() } }

    override suspend fun updateProject(
        workerId: String,
        update: ProjectContextUpdateRequest,
    ): ApiResult<ProjectContext> =
        withContext(Dispatchers.IO) { call { api.updateProject(workerId, update).toDomain() } }

    override suspend fun listEntries(workerId: String, category: String?): ApiResult<MemoryList> =
        withContext(Dispatchers.IO) {
            call {
                val dto = api.listEntries(workerId, category)
                MemoryList(entries = dto.entries.map { it.toDomain() }, totalTokens = dto.totalTokens)
            }
        }

    override suspend fun addEntry(workerId: String, request: MemoryEntryCreateRequest): ApiResult<MemoryEntry> =
        withContext(Dispatchers.IO) { call { api.addEntry(workerId, request).toDomain() } }

    override suspend fun deleteEntry(workerId: String, memoryId: String): ApiResult<Unit> =
        withContext(Dispatchers.IO) { call { api.deleteEntry(workerId, memoryId).unitOrThrow() } }

    private fun Response<Unit>.unitOrThrow() {
        if (!isSuccessful) throw HttpException(this)
    }

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
