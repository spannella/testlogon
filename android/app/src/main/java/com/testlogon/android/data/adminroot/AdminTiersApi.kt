package com.testlogon.android.data.adminroot

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
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Web-parity: ADMIN subscription-tier MANAGER (mirrors web /admin/subscription-tiers ->
 * SubscriptionTierManagerPage.tsx). Backend admin_subscription_tiers.py, prefix
 * /ui/admin/subscription-tiers. All ops are require_admin_or_root (writes add a CSRF variant handled by
 * the CsrfInterceptor) -> our ADMIN account CAN drive this fully. Distinct from the USER SubscribeScreen
 * (feature/subscriptions). Provides list/create/edit/archive/unarchive/delete + analytics.
 */
interface AdminTiersApi {

    @GET("ui/admin/subscription-tiers")
    suspend fun list(@Query("include_archived") includeArchived: Boolean = true): List<AdminTierDto>

    @POST("ui/admin/subscription-tiers")
    suspend fun create(@Body body: AdminTierCreateReqDto): AdminTierDto

    @PATCH("ui/admin/subscription-tiers/{id}")
    suspend fun update(@Path("id") tierId: String, @Body body: AdminTierUpdateReqDto): AdminTierDto

    @POST("ui/admin/subscription-tiers/{id}/archive")
    suspend fun archive(@Path("id") tierId: String): AdminTierDto

    @POST("ui/admin/subscription-tiers/{id}/unarchive")
    suspend fun unarchive(@Path("id") tierId: String): AdminTierDto

    @DELETE("ui/admin/subscription-tiers/{id}")
    suspend fun delete(@Path("id") tierId: String): OkDto

    @GET("ui/admin/subscription-tiers/analytics")
    suspend fun analytics(): AdminTierAnalyticsDto
}

@JsonClass(generateAdapter = true)
data class AdminTierDto(
    @Json(name = "tier_id") val tierId: String = "",
    @Json(name = "name") val name: String = "",
    @Json(name = "price_cents") val priceCents: Int = 0,
    @Json(name = "billing_cycle") val billingCycle: String = "monthly",
    @Json(name = "description") val description: String = "",
    @Json(name = "benefits") val benefits: List<String> = emptyList(),
    @Json(name = "access_level") val accessLevel: String = "basic",
    @Json(name = "display_order") val displayOrder: Int = 0,
    @Json(name = "status") val status: String = "active",
    @Json(name = "subscriber_count") val subscriberCount: Int = 0,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
    @Json(name = "archived_at") val archivedAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class AdminTierCreateReqDto(
    @Json(name = "name") val name: String,
    @Json(name = "price_cents") val priceCents: Int,
    @Json(name = "billing_cycle") val billingCycle: String = "monthly",
    @Json(name = "description") val description: String = "",
    @Json(name = "benefits") val benefits: List<String> = emptyList(),
    @Json(name = "access_level") val accessLevel: String = "basic",
)

@JsonClass(generateAdapter = true)
data class AdminTierUpdateReqDto(
    @Json(name = "name") val name: String? = null,
    @Json(name = "price_cents") val priceCents: Int? = null,
    @Json(name = "billing_cycle") val billingCycle: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "benefits") val benefits: List<String>? = null,
    @Json(name = "access_level") val accessLevel: String? = null,
)

@JsonClass(generateAdapter = true)
data class AdminTierAnalyticsDto(
    @Json(name = "total_subscribers") val totalSubscribers: Int = 0,
    @Json(name = "total_revenue_cents") val totalRevenueCents: Long = 0,
)

/** The form the tier create/edit UI produces (validated at the edge by the backend). */
data class AdminTierForm(
    val name: String,
    val priceCents: Int,
    val billingCycle: String,
    val description: String,
    val benefits: List<String>,
    val accessLevel: String,
)

data class AdminTiersData(
    val tiers: List<AdminTierDto>,
    val analytics: AdminTierAnalyticsDto,
)

interface AdminTiersRepository {
    suspend fun load(): ApiResult<AdminTiersData>
    suspend fun create(form: AdminTierForm): ApiResult<AdminTierDto>
    suspend fun update(tierId: String, form: AdminTierForm): ApiResult<AdminTierDto>
    suspend fun archive(tierId: String): ApiResult<AdminTierDto>
    suspend fun unarchive(tierId: String): ApiResult<AdminTierDto>
    suspend fun delete(tierId: String): ApiResult<Unit>
}

@Singleton
class DefaultAdminTiersRepository @Inject constructor(
    private val api: AdminTiersApi,
    private val errorParser: ApiErrorParser,
) : AdminTiersRepository {

    override suspend fun load(): ApiResult<AdminTiersData> = call {
        val tiers = api.list()
        val analytics = runCatching { api.analytics() }.getOrDefault(AdminTierAnalyticsDto())
        AdminTiersData(tiers = tiers, analytics = analytics)
    }

    override suspend fun create(form: AdminTierForm): ApiResult<AdminTierDto> = call {
        api.create(
            AdminTierCreateReqDto(
                name = form.name,
                priceCents = form.priceCents,
                billingCycle = form.billingCycle,
                description = form.description,
                benefits = form.benefits,
                accessLevel = form.accessLevel,
            ),
        )
    }

    override suspend fun update(tierId: String, form: AdminTierForm): ApiResult<AdminTierDto> = call {
        api.update(
            tierId,
            AdminTierUpdateReqDto(
                name = form.name,
                priceCents = form.priceCents,
                billingCycle = form.billingCycle,
                description = form.description,
                benefits = form.benefits,
                accessLevel = form.accessLevel,
            ),
        )
    }

    override suspend fun archive(tierId: String): ApiResult<AdminTierDto> = call { api.archive(tierId) }

    override suspend fun unarchive(tierId: String): ApiResult<AdminTierDto> = call { api.unarchive(tierId) }

    override suspend fun delete(tierId: String): ApiResult<Unit> = call { api.delete(tierId); Unit }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = withContext(Dispatchers.IO) {
        try {
            ApiResult.Success(block())
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Failure(errorParser.from(e))
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
    }
}

@Module
@InstallIn(SingletonComponent::class)
object AdminTiersApiModule {
    @Provides
    @Singleton
    fun provideAdminTiersApi(retrofit: Retrofit): AdminTiersApi = retrofit.create(AdminTiersApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class AdminTiersDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindAdminTiersRepository(impl: DefaultAdminTiersRepository): AdminTiersRepository
}
