package com.testlogon.android.data.admindmca

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
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * B5 admin DMCA dashboard - mirrors the web /admin/dmca page (DmcaDashboardPage.tsx + api/endpoints/dmca.ts).
 * Backend: admin_dmca.py, prefix /v1/admin/dmca, gated by require_admin_scope(CONTENT_MODERATION). The claims
 * LIST carries full claim detail; resolve is the admin action. (agent-config PUT is root-only, deferred.)
 * Timestamps are epoch SECONDS.
 */
interface DmcaAdminApi {

    @GET("v1/admin/dmca/claims")
    suspend fun listClaims(): DmcaClaimListDto

    @POST("v1/admin/dmca/claims/{id}/resolve")
    suspend fun resolve(
        @Path("id") claimId: String,
        @Body body: DmcaResolveReq,
    ): DmcaResolveDto
}

@JsonClass(generateAdapter = true)
data class DmcaClaimDto(
    @Json(name = "claim_id") val claimId: String,
    @Json(name = "status") val status: String = "",
    @Json(name = "claimant_name") val claimantName: String = "",
    @Json(name = "claimant_email") val claimantEmail: String = "",
    @Json(name = "content_url") val contentUrl: String = "",
    @Json(name = "content_type") val contentType: String = "",
    @Json(name = "content_id") val contentId: String = "",
    @Json(name = "target_user_id") val targetUserId: String = "",
    @Json(name = "original_work_description") val originalWorkDescription: String = "",
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "updated_at") val updatedAt: Long = 0L,
    @Json(name = "resolved_at") val resolvedAt: Long? = null,
    @Json(name = "resolution") val resolution: String? = null,
    @Json(name = "strike_number") val strikeNumber: Int = 0,
)

@JsonClass(generateAdapter = true)
data class DmcaClaimListDto(
    @Json(name = "items") val items: List<DmcaClaimDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class DmcaResolveReq(
    @Json(name = "resolution") val resolution: String,
    @Json(name = "resolution_notes") val resolutionNotes: String? = null,
)

@JsonClass(generateAdapter = true)
data class DmcaResolveDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "claim_id") val claimId: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "resolution") val resolution: String = "",
    @Json(name = "resolved_at") val resolvedAt: Long = 0L,
)

interface DmcaAdminRepository {
    suspend fun list(): ApiResult<DmcaClaimListDto>
    suspend fun resolve(claimId: String, resolution: String, notes: String?): ApiResult<DmcaResolveDto>
}

@Singleton
class DefaultDmcaAdminRepository @Inject constructor(
    private val api: DmcaAdminApi,
    private val errorParser: ApiErrorParser,
) : DmcaAdminRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun list(): ApiResult<DmcaClaimListDto> =
        withContext(io) { call { api.listClaims() } }

    override suspend fun resolve(claimId: String, resolution: String, notes: String?): ApiResult<DmcaResolveDto> =
        withContext(io) {
            call { api.resolve(claimId, DmcaResolveReq(resolution, notes?.trim()?.takeIf { it.isNotEmpty() })) }
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
object DmcaAdminApiModule {
    @Provides
    @Singleton
    fun provideDmcaAdminApi(retrofit: Retrofit): DmcaAdminApi =
        retrofit.create(DmcaAdminApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class DmcaAdminDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindDmcaAdminRepository(impl: DefaultDmcaAdminRepository): DmcaAdminRepository
}
