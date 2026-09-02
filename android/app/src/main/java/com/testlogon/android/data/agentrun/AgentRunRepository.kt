package com.testlogon.android.data.agentrun

import com.squareup.moshi.JsonDataException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.agentrun.AgentRunApi
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

/**
 * AGENT-RUN (web-parity) - data layer over [AgentRunApi] for the generic agent-run console. Routes each
 * [AgentRunType] to the correct per-type eligible/claim/execute/output/metrics endpoint, projects every
 * free-form response into a display model via [AgentRunMath], and wraps every call in [ApiResult]. A 403
 * surfaces as ApiResult.Failure(status=403) (the VM renders Forbidden - expected for the non-operator test
 * user); a 404 on OUTPUT is DEGRADE-ON-404 (surfaced as Success(null) so the console shows "no output yet"
 * rather than an error).
 */
interface AgentRunRepository {

    suspend fun eligibleTickets(type: AgentRunType, typeId: String, limit: Int): ApiResult<List<EligibleTicket>>

    suspend fun claim(type: AgentRunType, runId: String, ticketId: String): ApiResult<Unit>

    suspend fun execute(
        type: AgentRunType,
        typeId: String,
        runId: String,
        ticketId: String,
        pmOperation: PmOperation?,
    ): ApiResult<AgentRunOutput>

    /** GET the persisted output. DEGRADE-ON-404: a 404 becomes Success(null) (no output yet). */
    suspend fun output(type: AgentRunType, runId: String): ApiResult<AgentRunOutput?>

    suspend fun report(runId: String): ApiResult<RunReport?>

    suspend fun metrics(type: AgentRunType, typeId: String, periodDays: Int): ApiResult<RunMetrics>

    suspend fun decide(
        runId: String,
        approve: Boolean,
        notes: String?,
    ): ApiResult<DeploymentDecision>
}

@Singleton
class AgentRunRepositoryImpl @Inject constructor(
    private val api: AgentRunApi,
    private val errorParser: ApiErrorParser,
) : AgentRunRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun eligibleTickets(
        type: AgentRunType,
        typeId: String,
        limit: Int,
    ): ApiResult<List<EligibleTicket>> = withContext(io) {
        call {
            val raw = when (type) {
                AgentRunType.CODER -> api.coderEligibleTickets(typeId, limit)
                AgentRunType.QA -> api.qaEligibleTickets(typeId, limit)
                AgentRunType.DEVOPS -> api.devopsEligibleTickets(typeId, limit)
                AgentRunType.ARCHITECT -> api.architectEligibleTickets(typeId, limit)
                // PM is operation-driven and DOCS has no ticket queue: no eligible-tickets endpoint.
                AgentRunType.PM, AgentRunType.DOCS -> emptyMap()
            }
            AgentRunMath.parseEligibleTickets(raw)
        }
    }

    override suspend fun claim(
        type: AgentRunType,
        runId: String,
        ticketId: String,
    ): ApiResult<Unit> = withContext(io) {
        val body = mapOf("ticket_id" to ticketId)
        call {
            when (type) {
                AgentRunType.QA -> api.claimQaTicket(runId, body)
                // Coder claim route is the generic claim-ticket; the other types execute without a claim step.
                else -> api.claimCoderTicket(runId, body)
            }
            Unit
        }
    }

    override suspend fun execute(
        type: AgentRunType,
        typeId: String,
        runId: String,
        ticketId: String,
        pmOperation: PmOperation?,
    ): ApiResult<AgentRunOutput> = withContext(io) {
        call {
            val raw = when (type) {
                AgentRunType.CODER -> api.executeCoder(typeId, runId, mapOf("ticket_id" to ticketId))
                AgentRunType.QA -> api.executeQa(
                    typeId, runId, mapOf("ticket_id" to ticketId, "scenario" to "fail"),
                )
                AgentRunType.DEVOPS -> api.executeDevops(typeId, runId, mapOf("ticket_id" to ticketId))
                AgentRunType.ARCHITECT -> api.decomposeArchitect(typeId, runId, mapOf("ticket_id" to ticketId))
                AgentRunType.PM -> api.runPmOperation(
                    typeId,
                    runId,
                    mapOf(
                        "operation_type" to (pmOperation ?: PmOperation.IDEA_TRIAGE).wire,
                        "report_type" to "daily",
                    ),
                )
                AgentRunType.DOCS -> emptyMap()
            }
            AgentRunMath.parseOutput(type, raw)
        }
    }

    override suspend fun output(type: AgentRunType, runId: String): ApiResult<AgentRunOutput?> =
        withContext(io) {
            callDegradable {
                val raw = when (type) {
                    AgentRunType.CODER -> api.coderOutput(runId)
                    AgentRunType.QA -> api.qaOutput(runId)
                    AgentRunType.DEVOPS -> api.devopsOutput(runId)
                    AgentRunType.ARCHITECT -> api.architectOutput(runId)
                    AgentRunType.PM -> api.pmOutput(runId)
                    AgentRunType.DOCS -> emptyMap()
                }
                AgentRunMath.parseOutput(type, raw)
            }
        }

    override suspend fun report(runId: String): ApiResult<RunReport?> = withContext(io) {
        callDegradable {
            val raw = api.qaReport(runId)
            RunReport(
                runId = (raw["run_id"] as? String)?.takeIf { it.isNotBlank() } ?: runId,
                verdict = (raw["verdict"] as? String).orEmpty(),
                markdown = (raw["report_markdown"] as? String).orEmpty(),
            )
        }
    }

    override suspend fun metrics(
        type: AgentRunType,
        typeId: String,
        periodDays: Int,
    ): ApiResult<RunMetrics> = withContext(io) {
        call {
            val raw = when (type) {
                AgentRunType.CODER -> api.coderMetrics(typeId, periodDays)
                AgentRunType.QA -> api.qaMetrics(typeId, periodDays)
                AgentRunType.DEVOPS -> api.devopsMetrics(typeId, periodDays)
                AgentRunType.ARCHITECT -> api.architectMetrics(typeId, periodDays)
                AgentRunType.PM -> api.pmMetrics(typeId, periodDays)
                AgentRunType.DOCS -> emptyMap()
            }
            AgentRunMath.parseMetrics(raw)
        }
    }

    override suspend fun decide(
        runId: String,
        approve: Boolean,
        notes: String?,
    ): ApiResult<DeploymentDecision> = withContext(io) {
        val body = mapOf<String, Any?>("approved" to approve, "approver_notes" to notes)
        call {
            val raw = if (approve) api.approveDeployment(runId, body) else api.rejectDeployment(runId, body)
            AgentRunMath.parseDecision(runId, raw)
        }
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }

    /** Like [call] but a 404 becomes Success(null) (degrade-on-404 for absent run output/report). */
    private suspend fun <T> callDegradable(block: suspend () -> T): ApiResult<T?> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        if (e.code() == 404) ApiResult.Success(null) else ApiResult.Failure(errorParser.from(e))
    } catch (e: JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
