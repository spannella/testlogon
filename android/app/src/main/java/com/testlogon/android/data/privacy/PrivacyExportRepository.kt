package com.testlogon.android.data.privacy

import android.net.Uri
import com.testlogon.android.core.data.privacy.ExportRequestDao
import com.testlogon.android.core.data.privacy.ExportRequestEntity
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
import retrofit2.Response
import retrofit2.Retrofit
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-385 - data layer for the privacy / data-export surface.
 *
 * Single source of truth: [observeRequests] exposes the Room-cached export rows (newest-first); [refresh]
 * writes the GET /ui/privacy/requests result into that cache so the UI updates reactively (FR-2 / §6).
 * [requestExport] issues exactly ONE non-idempotent POST and upserts the returned status (FR-1). [download]
 * streams a completed artifact to Downloads (FR-4). A non-2xx becomes [ApiResult.Failure] via
 * [ApiErrorParser] (preserving the 422 body in ApiError.raw); a transport failure becomes
 * [ApiResult.NetworkError]; [CancellationException] is always re-thrown. The 401-refresh-once behavior is
 * delegated to the core-network auth interceptor (AND-027). No export file contents / download URLs / raw
 * request_ids are logged here (§8 / AC-8).
 */
interface PrivacyExportRepository {

    /** Cache-backed stream of export requests (newest first). */
    fun observeRequests(): Flow<List<ExportRequest>>

    /** Network -> cache sync of the export history. */
    suspend fun refresh(): ApiResult<List<ExportRequest>>

    /** Single, non-idempotent create. The returned status is upserted into the cache. */
    suspend fun requestExport(categories: Map<String, Boolean>): ApiResult<ExportRequest>

    /** Idempotent single-request status poll; upserts the cache. */
    suspend fun refreshOne(requestId: String): ApiResult<ExportRequest>

    /** Streams a completed artifact to Downloads; returns the saved file Uri. */
    suspend fun download(requestId: String): ApiResult<Uri>

    /** Wipes the cache on sign-out (PII hygiene). */
    suspend fun clearCache()
}

@Singleton
class DefaultPrivacyExportRepository @Inject constructor(
    private val api: PrivacyApi,
    private val dao: ExportRequestDao,
    private val downloader: ExportDownloader,
    private val errorParser: ApiErrorParser,
) : PrivacyExportRepository {

    // No @IoDispatcher qualifier exists in this project; settable so tests can inject a test dispatcher.
    var io: CoroutineDispatcher = Dispatchers.IO

    // Settable clock seam (epoch ms) for the syncedAt stamp; overridable in tests.
    var now: () -> Long = { System.currentTimeMillis() }

    override fun observeRequests(): Flow<List<ExportRequest>> =
        dao.observeAll().map { rows -> rows.map { it.toDomain() } }

    override suspend fun refresh(): ApiResult<List<ExportRequest>> = withContext(io) {
        when (val r = apiCall { api.listPrivacyRequests() }) {
            is ApiResult.Success -> {
                val exports = r.data.toExportDomain()
                dao.replaceAll(exports.map { it.toEntity(now()) })
                ApiResult.Success(exports)
            }
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun requestExport(categories: Map<String, Boolean>): ApiResult<ExportRequest> =
        withContext(io) {
            when (val r = apiCall { api.requestExport(ExportRequestBodyDto(categories)) }) {
                is ApiResult.Success -> {
                    val domain = r.data.toDomain()
                    dao.upsert(domain.toEntity(now()))
                    ApiResult.Success(domain)
                }
                is ApiResult.Failure -> r
                is ApiResult.NetworkError -> r
            }
        }

    override suspend fun refreshOne(requestId: String): ApiResult<ExportRequest> = withContext(io) {
        when (val r = apiCall { api.getExport(requestId) }) {
            is ApiResult.Success -> {
                val domain = r.data.toDomain()
                dao.upsert(domain.toEntity(now()))
                ApiResult.Success(domain)
            }
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun download(requestId: String): ApiResult<Uri> = withContext(io) {
        when (val outcome = downloader.download(requestId)) {
            is DownloadResult.Success -> ApiResult.Success(outcome.uri)
            is DownloadResult.Failure ->
                if (outcome.error.isNetwork) {
                    ApiResult.NetworkError(IOException(outcome.error.message), isTimeout = false)
                } else {
                    ApiResult.Failure(outcome.error)
                }
        }
    }

    override suspend fun clearCache() = withContext(io) { dao.clearAll() }

    /**
     * Unwraps a Retrofit [Response]: a non-2xx (or a null 2xx body) becomes [ApiResult.Failure] via
     * [ApiErrorParser]; an [IOException] becomes [ApiResult.NetworkError]. ZERO retries (the idempotent GETs
     * get bounded retry from the caller, not here).
     */
    private suspend fun <T> apiCall(block: suspend () -> Response<T>): ApiResult<T> = try {
        val response = block()
        val body = response.body()
        if (response.isSuccessful && body != null) {
            ApiResult.Success(body)
        } else {
            ApiResult.Failure(errorParser.from(HttpException(response)))
        }
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }

    private fun ExportRequest.toEntity(syncedAt: Long) = ExportRequestEntity(
        id = id,
        status = status.name,
        requestedAt = createdAtEpochMs,
        expiresAt = downloadExpiresAtEpochMs,
        sizeBytes = sizeBytes,
        downloadUrl = downloadUrl,
        syncedAt = syncedAt,
    )

    private fun ExportRequestEntity.toDomain() = ExportRequest(
        id = id,
        status = runCatching { ExportStatus.valueOf(status) }.getOrDefault(ExportStatus.UNKNOWN),
        createdAtEpochMs = requestedAt,
        downloadExpiresAtEpochMs = expiresAt,
        sizeBytes = sizeBytes,
        downloadUrl = downloadUrl,
    )
}

/** AND-385 - provides [PrivacyApi] on the shared authenticated Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object PrivacyApiModule {
    @Provides
    @Singleton
    fun providePrivacyApi(retrofit: Retrofit): PrivacyApi = retrofit.create(PrivacyApi::class.java)
}

/** AND-385 - binds the privacy-export repository + the MediaStore downloader. */
@Module
@InstallIn(SingletonComponent::class)
abstract class PrivacyDataModule {
    @Binds
    @Singleton
    abstract fun bindPrivacyExportRepository(impl: DefaultPrivacyExportRepository): PrivacyExportRepository

    @Binds
    @Singleton
    abstract fun bindExportDownloader(impl: DefaultExportDownloader): ExportDownloader
}
