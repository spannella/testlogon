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
import retrofit2.http.GET
import retrofit2.http.Query
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * B6 admin risk dashboard - mirrors web /admin/risk (RiskDashboardPage.tsx). Backend: risk_scoring.py,
 * admin prefix /ui/admin/risk. Reads (distribution + high-risk) are require_admin_or_root (our admin CAN
 * drive). The rescore/override POSTs are also admin but are governance actions and are NOT surfaced in
 * this read dashboard. Risk items are loosely-typed server dicts -> lenient DTO with defaults.
 */
interface RiskApi {

    @GET("ui/admin/risk/distribution")
    suspend fun distribution(): RiskDistributionDto

    @GET("ui/admin/risk/high-risk")
    suspend fun highRisk(
        @Query("threshold") threshold: Int = 70,
        @Query("limit") limit: Int = 50,
    ): RiskHighRiskListDto
}

@JsonClass(generateAdapter = true)
data class RiskDistributionDto(
    @Json(name = "distribution") val distribution: Map<String, Int> = emptyMap(),
    @Json(name = "total_scored") val totalScored: Int = 0,
    @Json(name = "auto_approve_rate") val autoApproveRate: Double = 0.0,
    @Json(name = "auto_escalate_rate") val autoEscalateRate: Double = 0.0,
)

@JsonClass(generateAdapter = true)
data class RiskUserDto(
    @Json(name = "user_sub") val userSub: String = "",
    @Json(name = "total_score") val totalScore: Int = 0,
    @Json(name = "risk_tier") val riskTier: String = "",
    @Json(name = "model_version") val modelVersion: String = "",
    @Json(name = "created_at") val createdAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class RiskHighRiskListDto(
    @Json(name = "items") val items: List<RiskUserDto> = emptyList(),
)

data class RiskDashboardData(
    val distribution: RiskDistributionDto,
    val highRisk: List<RiskUserDto>,
)

interface RiskRepository {
    suspend fun load(): ApiResult<RiskDashboardData>
}

@Singleton
class DefaultRiskRepository @Inject constructor(
    private val api: RiskApi,
    private val errorParser: ApiErrorParser,
) : RiskRepository {

    override suspend fun load(): ApiResult<RiskDashboardData> = withContext(Dispatchers.IO) {
        try {
            val dist = api.distribution()
            val high = api.highRisk()
            ApiResult.Success(RiskDashboardData(dist, high.items))
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
object RiskApiModule {
    @Provides
    @Singleton
    fun provideRiskApi(retrofit: Retrofit): RiskApi = retrofit.create(RiskApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class RiskDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindRiskRepository(impl: DefaultRiskRepository): RiskRepository
}
