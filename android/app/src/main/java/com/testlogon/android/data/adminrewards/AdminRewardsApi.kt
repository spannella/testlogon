package com.testlogon.android.data.adminrewards

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.json.LenientInt
import com.testlogon.android.core.network.json.LenientLong
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
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.PUT
import retrofit2.http.POST
import retrofit2.http.Path
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Operator CRUD over the REDEEMABLE-REWARDS CATALOG that members see on the user Rewards surface. This is
 * the ADMIN counterpart to [com.testlogon.android.data.rewards.RewardsApi] (whose me/rewards/catalog is a
 * read-only member view). Paths are relative (no leading slash) so they resolve against the shared
 * authenticated Retrofit base URL; session cookie + CSRF are attached by the core-network interceptor chain.
 *
 * The LIST read DEGRADES on 404 (undeployed backend) to an honest empty/unavailable state in the repository,
 * while a backend 403 on any call surfaces as [ApiResult.Failure] so the ViewModel can show a role-gated
 * "not authorised" state (the SAME server-side gate the other admin queues use). The MUTATIONS (create /
 * update / delete / toggle) pass failures through as a CLEAR error and NEVER a silent success. Every DTO is
 * codegen-only Moshi with numerics made lenient ([LenientLong]/[LenientInt]) and every field defaulted, so a
 * partial or string-encoded-numeric shape still parses.
 */
interface AdminRewardsApi {

    /** GET admin/rewards/catalog -> {rewards:[...]}. Read degrades on 404 (network errors surface). */
    @GET("admin/rewards/catalog")
    suspend fun list(): AdminCatalogListDto

    /** POST admin/rewards/catalog {name,description,cost_points,value_cents,kind,active} -> item. Mutation: errors surface. */
    @Headers("Content-Type: application/json")
    @POST("admin/rewards/catalog")
    suspend fun create(@Body body: AdminCatalogItemReq): AdminCatalogItemDto

    /** PUT admin/rewards/catalog/{id} same body -> item. Mutation: errors surface. */
    @Headers("Content-Type: application/json")
    @PUT("admin/rewards/catalog/{id}")
    suspend fun update(@Path("id") id: String, @Body body: AdminCatalogItemReq): AdminCatalogItemDto

    /** DELETE admin/rewards/catalog/{id} -> {ok}. Mutation: errors surface. */
    @DELETE("admin/rewards/catalog/{id}")
    suspend fun delete(@Path("id") id: String): AdminCatalogDeleteDto
}

// ---- GET admin/rewards/catalog ----

@JsonClass(generateAdapter = true)
data class AdminCatalogListDto(
    @Json(name = "rewards") val rewards: List<AdminCatalogItemDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class AdminCatalogItemDto(
    @Json(name = "id") val id: String? = null,
    @Json(name = "name") val name: String? = null,
    @Json(name = "description") val description: String? = null,
    @LenientLong @Json(name = "cost_points") val costPoints: Long? = null,
    @LenientLong @Json(name = "value_cents") val valueCents: Long? = null,
    @Json(name = "kind") val kind: String? = null,
    @Json(name = "active") val active: Boolean? = null,
    @LenientInt @Json(name = "redeemed_count") val redeemedCount: Int? = null,
    @LenientLong @Json(name = "stock_limit") val stockLimit: Long? = null,
)

// ---- POST/PUT body ----

@JsonClass(generateAdapter = true)
data class AdminCatalogItemReq(
    @Json(name = "name") val name: String,
    @Json(name = "description") val description: String,
    @Json(name = "cost_points") val costPoints: Long,
    @Json(name = "value_cents") val valueCents: Long,
    @Json(name = "kind") val kind: String,
    @Json(name = "active") val active: Boolean,
    /** Optional inventory cap; null = UNLIMITED (omitted-as-null on the wire). */
    @Json(name = "stock_limit") val stockLimit: Long? = null,
)

// ---- DELETE ----

@JsonClass(generateAdapter = true)
data class AdminCatalogDeleteDto(
    @Json(name = "ok") val ok: Boolean = false,
)

// ---- Repository ----

interface AdminRewardsRepository {
    /** LIST read: 404/undeployed degrades to an honest empty list; 403 -> Failure; network -> NetworkError. */
    suspend fun list(): ApiResult<AdminCatalogListDto>
    suspend fun create(body: AdminCatalogItemReq): ApiResult<AdminCatalogItemDto>
    suspend fun update(id: String, body: AdminCatalogItemReq): ApiResult<AdminCatalogItemDto>
    suspend fun delete(id: String): ApiResult<AdminCatalogDeleteDto>
}

@Singleton
class DefaultAdminRewardsRepository @Inject constructor(
    private val api: AdminRewardsApi,
    private val errorParser: ApiErrorParser,
) : AdminRewardsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    /**
     * LIST read. A 404 (undeployed backend) degrades to an honest EMPTY catalog so the screen shows a
     * truthful empty state rather than an error. A 403 (not an operator) is passed through as Failure so
     * the ViewModel renders the role-gated "not authorised" state. Real transport failures surface.
     */
    override suspend fun list(): ApiResult<AdminCatalogListDto> = withContext(io) {
        try {
            ApiResult.Success(api.list())
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            if (e.code() == 404) ApiResult.Success(AdminCatalogListDto())
            else ApiResult.Failure(errorParser.from(e))
        } catch (e: com.squareup.moshi.JsonDataException) {
            ApiResult.Success(AdminCatalogListDto())
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
    }

    override suspend fun create(body: AdminCatalogItemReq): ApiResult<AdminCatalogItemDto> =
        withContext(io) { call { api.create(body) } }

    override suspend fun update(id: String, body: AdminCatalogItemReq): ApiResult<AdminCatalogItemDto> =
        withContext(io) { call { api.update(id, body) } }

    override suspend fun delete(id: String): ApiResult<AdminCatalogDeleteDto> =
        withContext(io) { call { api.delete(id) } }

    /** Mutation wrapper: HTTP-error -> Failure (clear error, incl. 403/404), transport -> NetworkError. */
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
object AdminRewardsApiModule {
    @Provides
    @Singleton
    fun provideAdminRewardsApi(retrofit: Retrofit): AdminRewardsApi =
        retrofit.create(AdminRewardsApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class AdminRewardsDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindAdminRewardsRepository(impl: DefaultAdminRewardsRepository): AdminRewardsRepository
}
