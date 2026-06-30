package com.testlogon.android.feature.ads.scheduling.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.ads.AdSchedulingApi
import com.testlogon.android.core.network.ads.BudgetPacingDto
import com.testlogon.android.core.network.ads.CampaignScheduleDto
import com.testlogon.android.core.network.ads.CampaignScheduleUpdateIn
import com.testlogon.android.core.network.ads.DaypartingDto
import com.testlogon.android.core.network.ads.ScheduleEligibilityDto
import com.testlogon.android.core.network.error.ApiErrorParser
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Data layer for the ad SCHEDULING (dayparting + flights) editor (web parity: /ads/scheduling). Wraps the
 * [AdSchedulingApi] raw DTOs in the typed [ApiResult] via [call] (mirrors AdsBillingRepository). The schedule
 * DTO is surfaced directly (the screen edits the dayparting grid in place). NO Room / persistence.
 */
interface AdSchedulingRepository {

    /** GET predefined dayparting templates (name -> {day -> [hours]}). */
    suspend fun getTemplates(): ApiResult<Map<String, Map<String, List<Int>>>>

    /** GET the campaign schedule. */
    suspend fun getSchedule(campaignId: String): ApiResult<CampaignScheduleDto>

    /** PATCH the dayparting + timezone (flights pass through unchanged when not set). */
    suspend fun updateSchedule(
        campaignId: String,
        dayparting: DaypartingDto?,
        campaignTimezone: String?,
    ): ApiResult<CampaignScheduleDto>

    /** GET the eligibility-now debug result. */
    suspend fun getEligibility(campaignId: String): ApiResult<ScheduleEligibilityDto>

    /** GET the dayparting-aware budget pacing. */
    suspend fun getPacing(campaignId: String): ApiResult<BudgetPacingDto>
}

@Singleton
class AdSchedulingRepositoryImpl @Inject constructor(
    private val api: AdSchedulingApi,
    private val errorParser: ApiErrorParser,
) : AdSchedulingRepository {

    override suspend fun getTemplates(): ApiResult<Map<String, Map<String, List<Int>>>> =
        withContext(Dispatchers.IO) { call { api.getTemplates().templates } }

    override suspend fun getSchedule(campaignId: String): ApiResult<CampaignScheduleDto> =
        withContext(Dispatchers.IO) { call { api.getSchedule(campaignId) } }

    override suspend fun updateSchedule(
        campaignId: String,
        dayparting: DaypartingDto?,
        campaignTimezone: String?,
    ): ApiResult<CampaignScheduleDto> = withContext(Dispatchers.IO) {
        call {
            api.updateSchedule(
                campaignId,
                CampaignScheduleUpdateIn(dayparting = dayparting, campaignTimezone = campaignTimezone),
            )
        }
    }

    override suspend fun getEligibility(campaignId: String): ApiResult<ScheduleEligibilityDto> =
        withContext(Dispatchers.IO) { call { api.getEligibility(campaignId) } }

    override suspend fun getPacing(campaignId: String): ApiResult<BudgetPacingDto> =
        withContext(Dispatchers.IO) { call { api.getPacing(campaignId) } }

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

@Module
@InstallIn(SingletonComponent::class)
abstract class AdSchedulingDataModule {

    @Binds
    @Singleton
    abstract fun bindAdSchedulingRepository(impl: AdSchedulingRepositoryImpl): AdSchedulingRepository
}
