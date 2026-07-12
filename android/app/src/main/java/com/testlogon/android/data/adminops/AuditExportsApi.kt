package com.testlogon.android.data.adminops

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Retrofit
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * B6 admin audit-exports - mirrors web /admin/audit-exports (AuditExportPage.tsx). Backend:
 * audit_export.py, prefix /ui/admin/audit-exports. ENTIRE surface is require_root -> our ADMIN account
 * gets 403 -> Forbidden state (ROOT-GATED). List + create are surfaced (create mirrors the web fields:
 * categories/format/from_date/to_date). Valid categories: auth, moderation, broadcast, admin, billing.
 */
interface AuditExportsApi {

    @GET("ui/admin/audit-exports")
    suspend fun list(): AuditExportListDto

    @POST("ui/admin/audit-exports")
    suspend fun create(@Body body: AuditExportCreateReq): AuditExportDto
}

val AUDIT_EXPORT_CATEGORIES: List<String> = listOf("auth", "moderation", "broadcast", "admin", "billing")
val AUDIT_EXPORT_FORMATS: List<String> = listOf("ndjson", "csv", "pdf")

@JsonClass(generateAdapter = true)
data class AuditExportDto(
    @Json(name = "export_id") val exportId: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "categories") val categories: List<String> = emptyList(),
    @Json(name = "format") val format: String = "",
    @Json(name = "from_date") val fromDate: Long = 0,
    @Json(name = "to_date") val toDate: Long = 0,
    @Json(name = "event_count") val eventCount: Int? = null,
    @Json(name = "file_size_bytes") val fileSizeBytes: Long? = null,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "completed_at") val completedAt: Long? = null,
    @Json(name = "error_message") val errorMessage: String? = null,
)

@JsonClass(generateAdapter = true)
data class AuditExportListDto(
    @Json(name = "exports") val exports: List<AuditExportDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class AuditExportCreateReq(
    @Json(name = "categories") val categories: List<String>,
    @Json(name = "format") val format: String,
    @Json(name = "from_date") val fromDate: Long,
    @Json(name = "to_date") val toDate: Long,
)

interface AuditExportsRepository {
    suspend fun list(): ApiResult<AuditExportListDto>
    suspend fun create(categories: List<String>, format: String, fromDate: Long, toDate: Long): ApiResult<AuditExportDto>
}

@Singleton
class DefaultAuditExportsRepository @Inject constructor(
    private val api: AuditExportsApi,
    private val errorParser: ApiErrorParser,
) : AuditExportsRepository {

    override suspend fun list(): ApiResult<AuditExportListDto> =
        withContext(Dispatchers.IO) { call { api.list() } }

    override suspend fun create(
        categories: List<String>,
        format: String,
        fromDate: Long,
        toDate: Long,
    ): ApiResult<AuditExportDto> = withContext(Dispatchers.IO) {
        call { api.create(AuditExportCreateReq(categories, format, fromDate, toDate)) }
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}

@Module
@InstallIn(SingletonComponent::class)
object AuditExportsApiModule {
    @Provides
    @Singleton
    fun provideAuditExportsApi(retrofit: Retrofit): AuditExportsApi =
        retrofit.create(AuditExportsApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class AuditExportsDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindAuditExportsRepository(impl: DefaultAuditExportsRepository): AuditExportsRepository
}
