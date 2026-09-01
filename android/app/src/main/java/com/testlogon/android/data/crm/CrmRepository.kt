package com.testlogon.android.data.crm

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

// ── Aggregate results ───────────────────────────────────────────────────────

/** A leads page + a module-disabled flag (degrade-on-404). */
data class LeadsPage(
    val leads: List<Lead>,
    val cursor: String?,
    val moduleDisabled: Boolean = false,
)

/** The pipeline snapshot: stage config + opportunities, with a module-disabled flag (degrade-on-404/503). */
data class PipelineSnapshot(
    val stages: List<StageConfigItem>,
    val opportunities: List<Opportunity>,
    val moduleDisabled: Boolean = false,
)

// ───────────────────────────  LEADS  ────────────────────────────────

interface LeadsRepository {
    suspend fun list(status: String? = null): ApiResult<LeadsPage>
    suspend fun get(leadId: String): ApiResult<Lead>
    suspend fun create(body: LeadCreateInDto): ApiResult<Lead>
    suspend fun updateStatus(leadId: String, status: String): ApiResult<Lead>
    suspend fun convert(leadId: String, body: LeadConversionInDto): ApiResult<LeadConversionResult>
    suspend fun computeScore(leadId: String): ApiResult<Int>
    suspend fun listActivities(leadId: String): ApiResult<List<LeadActivity>>
    suspend fun logActivity(leadId: String, body: LeadLogActivityInDto): ApiResult<LeadActivity>
}

@Singleton
class LeadsRepositoryImpl @Inject constructor(
    private val api: LeadsApi,
    private val errorParser: ApiErrorParser,
) : LeadsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun list(status: String?): ApiResult<LeadsPage> = withContext(io) {
        when (val r = call { api.listLeads(status = status) }) {
            is ApiResult.Success -> ApiResult.Success(
                LeadsPage(r.data.leads.map { it.toDomain() }, r.data.cursor),
            )
            is ApiResult.Failure ->
                // Degrade-on-404: the Leads module is off -> render an empty, non-error state.
                if (r.error.status == 404) ApiResult.Success(LeadsPage(emptyList(), null, moduleDisabled = true))
                else r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun get(leadId: String): ApiResult<Lead> = withContext(io) {
        call { api.getLead(leadId).toDomain() }
    }

    override suspend fun create(body: LeadCreateInDto): ApiResult<Lead> = withContext(io) {
        call { api.createLead(body).toDomain() }
    }

    override suspend fun updateStatus(leadId: String, status: String): ApiResult<Lead> = withContext(io) {
        call { api.updateLead(leadId, LeadUpdateInDto(status = status)).toDomain() }
    }

    override suspend fun convert(
        leadId: String,
        body: LeadConversionInDto,
    ): ApiResult<LeadConversionResult> = withContext(io) {
        call { api.convertLead(leadId, body).toDomain() }
    }

    override suspend fun computeScore(leadId: String): ApiResult<Int> = withContext(io) {
        call { api.computeScore(leadId).score }
    }

    override suspend fun listActivities(leadId: String): ApiResult<List<LeadActivity>> = withContext(io) {
        when (val r = call { api.listActivities(leadId) }) {
            is ApiResult.Success -> ApiResult.Success(r.data.activities.map { it.toDomain() })
            is ApiResult.Failure -> if (r.error.status == 404) ApiResult.Success(emptyList()) else r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun logActivity(
        leadId: String,
        body: LeadLogActivityInDto,
    ): ApiResult<LeadActivity> = withContext(io) {
        call { api.logActivity(leadId, body).toDomain() }
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

// ───────────────────────────  SALES  ────────────────────────────────

interface SalesRepository {
    /** One combined pull for the pipeline board: feature status + stages + opportunities. */
    suspend fun pipeline(): ApiResult<PipelineSnapshot>
    suspend fun getOpportunity(oppId: String): ApiResult<Opportunity>
    suspend fun create(body: OpportunityCreateInDto): ApiResult<Opportunity>
    suspend fun moveStage(oppId: String, stage: String): ApiResult<Opportunity>
}

@Singleton
class SalesRepositoryImpl @Inject constructor(
    private val api: SalesApi,
    private val errorParser: ApiErrorParser,
) : SalesRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun pipeline(): ApiResult<PipelineSnapshot> = withContext(io) {
        // Opportunities is the primary call; feature-status + stages are best-effort.
        when (val opps = call { api.listOpportunities() }) {
            is ApiResult.Success -> {
                val stages = (call { api.listStages() } as? ApiResult.Success)?.data
                    ?.stages?.map { it.toDomain() }?.sortedBy { it.order }
                    ?: defaultStages()
                ApiResult.Success(
                    PipelineSnapshot(
                        stages = stages,
                        opportunities = opps.data.items.map { it.toDomain() },
                    ),
                )
            }
            is ApiResult.Failure ->
                // Degrade-on-404/503: the pipeline module is off -> empty, non-error state.
                if (opps.error.status == 404 || opps.error.status == 503) {
                    ApiResult.Success(PipelineSnapshot(defaultStages(), emptyList(), moduleDisabled = true))
                } else {
                    opps
                }
            is ApiResult.NetworkError -> opps
        }
    }

    override suspend fun getOpportunity(oppId: String): ApiResult<Opportunity> = withContext(io) {
        call { api.getOpportunity(oppId).toDomain() }
    }

    override suspend fun create(body: OpportunityCreateInDto): ApiResult<Opportunity> = withContext(io) {
        call { api.createOpportunity(body).toDomain() }
    }

    override suspend fun moveStage(oppId: String, stage: String): ApiResult<Opportunity> = withContext(io) {
        call {
            api.updateOpportunity(
                oppId,
                OpportunityUpdateInDto(
                    stage = stage,
                    probability = CrmSalesMath.defaultProbabilityFor(stage),
                ),
            ).toDomain()
        }
    }

    /** Client-side default stage list (mirrors the web OPPORTUNITY_STAGES) used if /stages degrades. */
    private fun defaultStages(): List<StageConfigItem> =
        CrmSalesMath.STAGE_ORDER.mapIndexed { idx, key ->
            StageConfigItem(
                stageKey = key,
                label = CrmSalesMath.stageLabel(key),
                probabilityDefault = CrmSalesMath.defaultProbabilityFor(key),
                order = idx,
                isWon = CrmSalesMath.isWonStage(key),
                isLost = CrmSalesMath.isLostStage(key),
            )
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

/** Small helper for callers that need the [ApiError] status without a `when`. */
internal fun ApiResult<*>.statusOrNull(): Int? = (this as? ApiResult.Failure)?.error?.status
