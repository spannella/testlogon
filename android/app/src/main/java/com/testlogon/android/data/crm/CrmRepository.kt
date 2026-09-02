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

/** A prospects page + a module-disabled flag (degrade-on-404). */
data class ProspectsPage(
    val prospects: List<Prospect>,
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
    suspend fun delete(leadId: String): ApiResult<Unit>
    suspend fun convert(leadId: String, body: LeadConversionInDto): ApiResult<LeadConversionResult>
    suspend fun assign(leadId: String, assigneeSub: String): ApiResult<Lead>
    suspend fun merge(primaryLeadId: String, secondaryLeadId: String): ApiResult<Lead>
    suspend fun duplicates(leadId: String): ApiResult<List<Lead>>
    suspend fun computeScore(leadId: String): ApiResult<Int>
    suspend fun scoreHistory(leadId: String): ApiResult<List<LeadScoreHistoryEntry>>
    suspend fun listActivities(leadId: String): ApiResult<List<LeadActivity>>
    suspend fun logActivity(leadId: String, body: LeadLogActivityInDto): ApiResult<LeadActivity>

    // Prospects (LED-007)
    suspend fun listProspects(includeSuppressed: Boolean = true): ApiResult<ProspectsPage>
    suspend fun createProspect(body: ProspectCreateInDto): ApiResult<Prospect>
    suspend fun updateProspect(prospectId: String, body: ProspectUpdateInDto): ApiResult<Prospect>
    suspend fun deleteProspect(prospectId: String): ApiResult<Unit>

    // Admin (LED-013) — server enforces 403 for non-admins.
    suspend fun getScoringRules(): ApiResult<LeadScoreRules>
    suspend fun updateScoringRules(rules: List<LeadScoreRule>, maxScore: Int): ApiResult<LeadScoreRules>
    suspend fun sourceSummary(): ApiResult<Map<String, Int>>
    suspend fun adminListAll(status: String? = null): ApiResult<LeadsPage>
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

    override suspend fun delete(leadId: String): ApiResult<Unit> = withContext(io) {
        call { api.deleteLead(leadId) }
    }

    override suspend fun convert(
        leadId: String,
        body: LeadConversionInDto,
    ): ApiResult<LeadConversionResult> = withContext(io) {
        call { api.convertLead(leadId, body).toDomain() }
    }

    override suspend fun assign(leadId: String, assigneeSub: String): ApiResult<Lead> = withContext(io) {
        call { api.assignLead(leadId, LeadAssignInDto(assigneeSub = assigneeSub)).toDomain() }
    }

    override suspend fun merge(primaryLeadId: String, secondaryLeadId: String): ApiResult<Lead> = withContext(io) {
        call { api.mergeLeads(primaryLeadId, LeadMergeInDto(secondaryLeadId = secondaryLeadId)).toDomain() }
    }

    override suspend fun duplicates(leadId: String): ApiResult<List<Lead>> = withContext(io) {
        when (val r = call { api.findDuplicates(leadId) }) {
            is ApiResult.Success -> ApiResult.Success(r.data.duplicates.map { it.toDomain() })
            is ApiResult.Failure -> if (r.error.status == 404) ApiResult.Success(emptyList()) else r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun computeScore(leadId: String): ApiResult<Int> = withContext(io) {
        call { api.computeScore(leadId).score }
    }

    override suspend fun scoreHistory(leadId: String): ApiResult<List<LeadScoreHistoryEntry>> = withContext(io) {
        when (val r = call { api.scoreHistory(leadId) }) {
            is ApiResult.Success -> ApiResult.Success(r.data.entries.map { it.toDomain() })
            is ApiResult.Failure -> if (r.error.status == 404) ApiResult.Success(emptyList()) else r
            is ApiResult.NetworkError -> r
        }
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

    // ── Prospects ────────────────────────────────────────────────────────────

    override suspend fun listProspects(includeSuppressed: Boolean): ApiResult<ProspectsPage> = withContext(io) {
        when (val r = call { api.listProspects(includeSuppressed = includeSuppressed) }) {
            is ApiResult.Success -> ApiResult.Success(
                ProspectsPage(r.data.prospects.map { it.toDomain() }, r.data.cursor),
            )
            is ApiResult.Failure ->
                if (r.error.status == 404) ApiResult.Success(ProspectsPage(emptyList(), null, moduleDisabled = true))
                else r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun createProspect(body: ProspectCreateInDto): ApiResult<Prospect> = withContext(io) {
        call { api.createProspect(body).toDomain() }
    }

    override suspend fun updateProspect(
        prospectId: String,
        body: ProspectUpdateInDto,
    ): ApiResult<Prospect> = withContext(io) {
        call { api.updateProspect(prospectId, body).toDomain() }
    }

    override suspend fun deleteProspect(prospectId: String): ApiResult<Unit> = withContext(io) {
        call { api.deleteProspect(prospectId) }
    }

    // ── Admin ────────────────────────────────────────────────────────────────

    override suspend fun getScoringRules(): ApiResult<LeadScoreRules> = withContext(io) {
        call { api.getScoringRules().toDomain() }
    }

    override suspend fun updateScoringRules(
        rules: List<LeadScoreRule>,
        maxScore: Int,
    ): ApiResult<LeadScoreRules> = withContext(io) {
        call {
            api.updateScoringRules(
                LeadScoreRulesInDto(rules = rules.map { it.toDto() }, maxScore = maxScore),
            ).toDomain()
        }
    }

    override suspend fun sourceSummary(): ApiResult<Map<String, Int>> = withContext(io) {
        call { api.sourceSummary().sources }
    }

    override suspend fun adminListAll(status: String?): ApiResult<LeadsPage> = withContext(io) {
        when (val r = call { api.adminListAllLeads(status = status) }) {
            is ApiResult.Success -> ApiResult.Success(
                LeadsPage(r.data.leads.map { it.toDomain() }, r.data.cursor),
            )
            is ApiResult.Failure ->
                if (r.error.status == 404) ApiResult.Success(LeadsPage(emptyList(), null, moduleDisabled = true))
                else r
            is ApiResult.NetworkError -> r
        }
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

/** A forecast worksheet + module/forbidden flags (degrade-on-404/403). */
data class ForecastResult(
    val worksheet: ForecastWorksheet?,
    val moduleDisabled: Boolean = false,
)

/** A pipeline report + module/forbidden flags (degrade-on-404/503/403). */
data class PipelineReportResult(
    val report: PipelineReport?,
    val moduleDisabled: Boolean = false,
    val forbidden: Boolean = false,
)

/** A user's quota list + module/forbidden flags (admin; degrade-on-404/503/403). */
data class QuotaListResult(
    val quotas: List<SalesQuota>,
    val cursor: String?,
    val moduleDisabled: Boolean = false,
    val forbidden: Boolean = false,
)

interface SalesRepository {
    /** One combined pull for the pipeline board: feature status + stages + opportunities. */
    suspend fun pipeline(): ApiResult<PipelineSnapshot>
    suspend fun getOpportunity(oppId: String, includeContacts: Boolean = false): ApiResult<Opportunity>
    suspend fun create(body: OpportunityCreateInDto): ApiResult<Opportunity>
    suspend fun moveStage(oppId: String, stage: String): ApiResult<Opportunity>
    suspend fun delete(oppId: String): ApiResult<Unit>

    // OPP-004: contact roles
    suspend fun listContactRoles(oppId: String): ApiResult<List<OppContactRole>>
    suspend fun addContactRole(oppId: String, contactRef: String, contactRole: String): ApiResult<OppContactRole>
    suspend fun removeContactRole(oppId: String, contactRef: String): ApiResult<Unit>

    // OPP-005: forecast worksheet (degrade-on-404)
    suspend fun getForecast(periodKey: String): ApiResult<ForecastResult>
    suspend fun upsertForecast(
        periodKey: String,
        committedCents: Long,
        bestCaseCents: Long,
        pipelineCents: Long,
        notes: String?,
    ): ApiResult<ForecastWorksheet>

    // OPP-006: pipeline report (per-rep + admin cross-user)
    suspend fun pipelineReport(fromTs: Long? = null, toTs: Long? = null): ApiResult<PipelineReportResult>
    suspend fun adminPipelineReport(fromTs: Long? = null, toTs: Long? = null): ApiResult<PipelineReportResult>

    // OPP-005: admin quota (server 403 for non-admins)
    suspend fun listUserQuotas(userSub: String): ApiResult<QuotaListResult>
    suspend fun setQuota(
        userSub: String,
        periodType: String,
        periodKey: String,
        targetAmountCents: Long,
    ): ApiResult<SalesQuota>
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

    override suspend fun getOpportunity(oppId: String, includeContacts: Boolean): ApiResult<Opportunity> =
        withContext(io) {
            call { api.getOpportunity(oppId, includeContacts.takeIf { it }).toDomain() }
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

    override suspend fun delete(oppId: String): ApiResult<Unit> = withContext(io) {
        call { api.deleteOpportunity(oppId) }
    }

    // ── Contact roles (OPP-004) ──────────────────────────────────────────────

    override suspend fun listContactRoles(oppId: String): ApiResult<List<OppContactRole>> = withContext(io) {
        when (val r = call { api.listContactRoles(oppId) }) {
            is ApiResult.Success -> ApiResult.Success(r.data.map { it.toDomain() })
            is ApiResult.Failure ->
                if (r.error.status == 404 || r.error.status == 503) ApiResult.Success(emptyList()) else r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun addContactRole(
        oppId: String,
        contactRef: String,
        contactRole: String,
    ): ApiResult<OppContactRole> = withContext(io) {
        call { api.addContactRole(oppId, OppContactRoleInDto(contactRef, contactRole)).toDomain() }
    }

    override suspend fun removeContactRole(oppId: String, contactRef: String): ApiResult<Unit> = withContext(io) {
        call { api.removeContactRole(oppId, contactRef) }
    }

    // ── Forecast worksheet (OPP-005) ─────────────────────────────────────────

    override suspend fun getForecast(periodKey: String): ApiResult<ForecastResult> = withContext(io) {
        when (val r = call { api.getForecast(periodKey) }) {
            is ApiResult.Success -> ApiResult.Success(ForecastResult(r.data.toDomain()))
            is ApiResult.Failure ->
                when (r.error.status) {
                    // 404 = no worksheet yet OR module off; 503 = module off. Degrade to an empty, editable worksheet.
                    404, 503 -> ApiResult.Success(ForecastResult(null, moduleDisabled = r.error.status == 503))
                    else -> r
                }
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun upsertForecast(
        periodKey: String,
        committedCents: Long,
        bestCaseCents: Long,
        pipelineCents: Long,
        notes: String?,
    ): ApiResult<ForecastWorksheet> = withContext(io) {
        call {
            api.upsertForecast(
                periodKey,
                ForecastWorksheetInDto(
                    committedCents = maxOf(0L, committedCents),
                    bestCaseCents = maxOf(0L, bestCaseCents),
                    pipelineCents = maxOf(0L, pipelineCents),
                    notes = notes?.ifBlank { null },
                ),
            ).toDomain()
        }
    }

    // ── Pipeline report (OPP-006) ────────────────────────────────────────────

    override suspend fun pipelineReport(fromTs: Long?, toTs: Long?): ApiResult<PipelineReportResult> =
        withContext(io) {
            when (val r = call { api.getPipelineReport(fromTs, toTs) }) {
                is ApiResult.Success -> ApiResult.Success(PipelineReportResult(r.data.toDomain()))
                is ApiResult.Failure ->
                    when (r.error.status) {
                        404, 503 -> ApiResult.Success(PipelineReportResult(null, moduleDisabled = true))
                        403 -> ApiResult.Success(PipelineReportResult(null, forbidden = true))
                        else -> r
                    }
                is ApiResult.NetworkError -> r
            }
        }

    override suspend fun adminPipelineReport(fromTs: Long?, toTs: Long?): ApiResult<PipelineReportResult> =
        withContext(io) {
            when (val r = call { api.getAdminPipelineReport(fromTs, toTs) }) {
                is ApiResult.Success -> ApiResult.Success(PipelineReportResult(r.data.toDomain()))
                is ApiResult.Failure ->
                    when (r.error.status) {
                        404, 503 -> ApiResult.Success(PipelineReportResult(null, moduleDisabled = true))
                        403 -> ApiResult.Success(PipelineReportResult(null, forbidden = true))
                        else -> r
                    }
                is ApiResult.NetworkError -> r
            }
        }

    // ── Admin quota (OPP-005) ────────────────────────────────────────────────

    override suspend fun listUserQuotas(userSub: String): ApiResult<QuotaListResult> = withContext(io) {
        when (val r = call { api.listUserQuotas(userSub) }) {
            is ApiResult.Success ->
                ApiResult.Success(QuotaListResult(r.data.items.map { it.toDomain() }, r.data.nextCursor))
            is ApiResult.Failure ->
                when (r.error.status) {
                    404, 503 -> ApiResult.Success(QuotaListResult(emptyList(), null, moduleDisabled = true))
                    403 -> ApiResult.Success(QuotaListResult(emptyList(), null, forbidden = true))
                    else -> r
                }
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun setQuota(
        userSub: String,
        periodType: String,
        periodKey: String,
        targetAmountCents: Long,
    ): ApiResult<SalesQuota> = withContext(io) {
        call {
            api.setQuota(
                SalesQuotaInDto(
                    userSub = userSub,
                    periodType = periodType,
                    periodKey = periodKey,
                    targetAmountCents = maxOf(0L, targetAmountCents),
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

