package com.testlogon.android.data.kycadmin

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
import retrofit2.http.Path
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * B2 - KYC workload / assignment dashboard. Mirrors web /admin/kyc-workload (KycWorkloadPage.tsx +
 * api/endpoints/kycAssignment.ts). Backend kyc_case_assignment.py, prefix /v1/kyc/assignment, all
 * admin-or-root gated EXCEPT PATCH /sla-config/{tier} which is ROOT-only (renders Forbidden for our
 * admin account, reported as deferred - not surfaced here). Reads: workloads + my-queue +
 * sla/breaches + sla-config. Case actions: claim / unclaim / reassign / escalate / auto-assign.
 * Epoch SECONDS.
 */
interface KycWorkloadAdminApi {

    @GET("v1/kyc/assignment/workloads")
    suspend fun workloads(): KycWorkloadDashboardDto

    @GET("v1/kyc/assignment/my-queue")
    suspend fun myQueue(): KycMyAssignedDto

    @GET("v1/kyc/assignment/sla/breaches")
    suspend fun slaBreaches(): KycSlaBreachListDto

    @POST("v1/kyc/assignment/cases/{caseId}/claim")
    suspend fun claim(@Path("caseId") caseId: String)

    @POST("v1/kyc/assignment/cases/{caseId}/unclaim")
    suspend fun unclaim(@Path("caseId") caseId: String)

    @POST("v1/kyc/assignment/cases/{caseId}/escalate")
    suspend fun escalate(@Path("caseId") caseId: String)

    @POST("v1/kyc/assignment/cases/{caseId}/reassign")
    suspend fun reassign(@Path("caseId") caseId: String, @Body body: KycReassignReq)

    @POST("v1/kyc/assignment/cases/{caseId}/auto-assign")
    suspend fun autoAssign(@Path("caseId") caseId: String, @Body body: KycAutoAssignReq)
}

@JsonClass(generateAdapter = true)
data class KycSlaTierConfigDto(
    @Json(name = "target_hours") val targetHours: Double = 0.0,
    @Json(name = "warning_pct") val warningPct: Double = 0.0,
    @Json(name = "escalation_pct") val escalationPct: Double? = null,
)

@JsonClass(generateAdapter = true)
data class KycAdminAvailabilityDto(
    @Json(name = "admin_sub") val adminSub: String = "",
    @Json(name = "on_duty") val onDuty: Boolean = false,
    @Json(name = "current_case_count") val currentCaseCount: Int = 0,
    @Json(name = "avg_processing_hours") val avgProcessingHours: Double = 0.0,
    @Json(name = "expertise_tiers") val expertiseTiers: List<String> = emptyList(),
    @Json(name = "languages") val languages: List<String> = emptyList(),
    @Json(name = "seniority_level") val seniorityLevel: Int = 0,
    @Json(name = "max_cases") val maxCases: Int = 0,
    @Json(name = "last_assigned_at") val lastAssignedAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class KycWorkloadDashboardDto(
    @Json(name = "admins") val admins: List<KycAdminAvailabilityDto> = emptyList(),
    @Json(name = "sla_config") val slaConfig: Map<String, KycSlaTierConfigDto> = emptyMap(),
    @Json(name = "total_active_cases") val totalActiveCases: Int = 0,
    @Json(name = "total_on_duty_admins") val totalOnDutyAdmins: Int = 0,
)

@JsonClass(generateAdapter = true)
data class KycMyAssignedCaseDto(
    @Json(name = "kyc_case_id") val kycCaseId: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "tier") val tier: String = "",
    @Json(name = "assigned_at") val assignedAt: Long? = null,
    @Json(name = "sla_due_at") val slaDueAt: Long? = null,
    @Json(name = "overdue") val overdue: Boolean = false,
    @Json(name = "escalation_level") val escalationLevel: Int = 0,
)

@JsonClass(generateAdapter = true)
data class KycMyAssignedDto(
    @Json(name = "cases") val cases: List<KycMyAssignedCaseDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class KycSlaBreachDto(
    @Json(name = "kyc_case_id") val kycCaseId: String = "",
    @Json(name = "assigned_admin_sub") val assignedAdminSub: String? = null,
    @Json(name = "tier") val tier: String = "",
    @Json(name = "sla_due_at") val slaDueAt: Long = 0L,
    @Json(name = "hours_overdue") val hoursOverdue: Double = 0.0,
    @Json(name = "escalation_level") val escalationLevel: Int = 0,
)

@JsonClass(generateAdapter = true)
data class KycSlaBreachListDto(
    @Json(name = "breaches") val breaches: List<KycSlaBreachDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class KycReassignReq(
    @Json(name = "target_admin_sub") val targetAdminSub: String,
    @Json(name = "reason") val reason: String = "",
)

@JsonClass(generateAdapter = true)
data class KycAutoAssignReq(
    @Json(name = "applicant_language") val applicantLanguage: String = "en",
)

data class KycWorkloadData(
    val dashboard: KycWorkloadDashboardDto,
    val myQueue: List<KycMyAssignedCaseDto>,
    val breaches: List<KycSlaBreachDto>,
)

interface KycWorkloadAdminRepository {
    suspend fun load(): ApiResult<KycWorkloadData>
    suspend fun claim(caseId: String): ApiResult<Unit>
    suspend fun unclaim(caseId: String): ApiResult<Unit>
    suspend fun escalate(caseId: String): ApiResult<Unit>
    suspend fun reassign(caseId: String, targetAdminSub: String, reason: String): ApiResult<Unit>
    suspend fun autoAssign(caseId: String): ApiResult<Unit>
}

@Singleton
class DefaultKycWorkloadAdminRepository @Inject constructor(
    private val api: KycWorkloadAdminApi,
    private val errorParser: ApiErrorParser,
) : KycWorkloadAdminRepository {

    override suspend fun load(): ApiResult<KycWorkloadData> = io {
        val dash = api.workloads()
        val mine = api.myQueue()
        val breaches = api.slaBreaches()
        KycWorkloadData(dash, mine.cases, breaches.breaches)
    }

    override suspend fun claim(caseId: String): ApiResult<Unit> = io { api.claim(caseId) }
    override suspend fun unclaim(caseId: String): ApiResult<Unit> = io { api.unclaim(caseId) }
    override suspend fun escalate(caseId: String): ApiResult<Unit> = io { api.escalate(caseId) }
    override suspend fun reassign(caseId: String, targetAdminSub: String, reason: String): ApiResult<Unit> =
        io { api.reassign(caseId, KycReassignReq(targetAdminSub.trim(), reason.trim())) }
    override suspend fun autoAssign(caseId: String): ApiResult<Unit> =
        io { api.autoAssign(caseId, KycAutoAssignReq()) }

    private suspend fun <T> io(block: suspend () -> T): ApiResult<T> = withContext(Dispatchers.IO) {
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
object KycWorkloadAdminApiModule {
    @Provides
    @Singleton
    fun provideKycWorkloadAdminApi(retrofit: Retrofit): KycWorkloadAdminApi =
        retrofit.create(KycWorkloadAdminApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class KycWorkloadAdminDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindKycWorkloadAdminRepository(impl: DefaultKycWorkloadAdminRepository): KycWorkloadAdminRepository
}
