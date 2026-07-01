package com.testlogon.android.data.adminappeals

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Retrofit
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * B5 admin appeals review queue - mirrors the web /admin/appeals page (AppealReviewQueuePage.tsx +
 * api/endpoints/appeals.ts). Backend: admin_appeals.py, prefix /v1/admin/appeals, gated by
 * require_admin_scope(CONTENT_MODERATION). The LIST carries full appeal detail; claim then decide
 * (upheld|modified|reversed) are the admin actions. Timestamps are epoch SECONDS.
 */
interface AppealAdminApi {

    @GET("v1/admin/appeals")
    suspend fun list(@Query("status") status: String?): AppealListDto

    @POST("v1/admin/appeals/{id}/claim")
    suspend fun claim(@Path("id") appealId: String): AppealClaimDto

    @POST("v1/admin/appeals/{id}/decide")
    suspend fun decide(
        @Path("id") appealId: String,
        @Body body: AppealDecideReq,
    ): AppealDecisionDto
}

@JsonClass(generateAdapter = true)
data class AppealDto(
    @Json(name = "appeal_id") val appealId: String,
    @Json(name = "user_id") val userId: String = "",
    @Json(name = "enforcement_id") val enforcementId: String = "",
    @Json(name = "enforcement_type") val enforcementType: String = "",
    @Json(name = "source_ticket_id") val sourceTicketId: String = "",
    @Json(name = "appeal_text") val appealText: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "updated_at") val updatedAt: Long = 0L,
    @Json(name = "decided_at") val decidedAt: Long? = null,
    @Json(name = "decision_note") val decisionNote: String? = null,
)

@JsonClass(generateAdapter = true)
data class AppealListDto(
    @Json(name = "items") val items: List<AppealDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class AppealClaimDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "appeal_id") val appealId: String = "",
    @Json(name = "assigned_admin_user_id") val assignedAdminUserId: String = "",
)

@JsonClass(generateAdapter = true)
data class AppealDecideReq(
    @Json(name = "decision") val decision: String,
    @Json(name = "decision_note") val decisionNote: String = "",
)

@JsonClass(generateAdapter = true)
data class AppealDecisionDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "appeal_id") val appealId: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "decision") val decision: String = "",
    @Json(name = "decided_at") val decidedAt: Long = 0L,
)

interface AppealAdminRepository {
    suspend fun list(status: String?): ApiResult<AppealListDto>
    suspend fun claim(appealId: String): ApiResult<AppealClaimDto>
    suspend fun decide(appealId: String, decision: String, note: String?): ApiResult<AppealDecisionDto>
}

@Singleton
class DefaultAppealAdminRepository @Inject constructor(
    private val api: AppealAdminApi,
    private val errorParser: ApiErrorParser,
) : AppealAdminRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun list(status: String?): ApiResult<AppealListDto> =
        withContext(io) { call { api.list(status) } }

    override suspend fun claim(appealId: String): ApiResult<AppealClaimDto> =
        withContext(io) { call { api.claim(appealId) } }

    override suspend fun decide(appealId: String, decision: String, note: String?): ApiResult<AppealDecisionDto> =
        withContext(io) {
            call { api.decide(appealId, AppealDecideReq(decision, note?.trim().orEmpty())) }
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
object AppealAdminApiModule {
    @Provides
    @Singleton
    fun provideAppealAdminApi(retrofit: Retrofit): AppealAdminApi =
        retrofit.create(AppealAdminApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class AppealAdminDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindAppealAdminRepository(impl: DefaultAppealAdminRepository): AppealAdminRepository
}
