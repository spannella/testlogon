package com.testlogon.android.core.network.agentrun

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AGENT-RUN (web-parity) - Retrofit transport for the agent-run CONSOLE lifecycle across the six agent types
 * (mirrors frontend/src/api/endpoints/{coder,qa,devops,architect,pm}Agent.ts). Transport only; the :app
 * AgentRunRepository wraps every call into ApiResult and projects the free-form maps into display models.
 *
 * Like AgentConfigApi, every endpoint here is backend OPERATOR-gated (require_admin_or_root; the
 * approve/reject and execute mutations are require_admin_or_root under CSRF). The signed-in non-operator test
 * account gets 403 (surfaced as a Forbidden state). The shared authenticated OkHttp client attaches the
 * session cookie + X-CSRF-Token via the global interceptors, so no per-call header is needed.
 *
 * The per-type output SHAPES diverge (CoderOutputOut vs QaOutputOut vs DevOpsOutputOut ...), so - exactly as
 * AgentConfigApi does for config bodies - outputs / eligible-tickets / metrics are modeled as free-form
 * Map<String, Any?> and projected by AgentRunMath. The one uniformly-shaped response (deployment
 * approve/reject: { run_id, deployment_id, approval_status, approved_by, approved_at, notes }) is likewise a
 * map so no per-type DTO is needed.
 *
 * Contract (relative paths, NO leading slash; {typeId} is the agent-type id):
 *   GET  ui/agents/types/{typeId}/eligible-tickets?limit=            (coder)
 *   GET  ui/agents/types/{typeId}/qa-eligible-tickets?limit=         (qa)
 *   GET  ui/agents/types/{typeId}/devops-eligible-tickets?limit=     (devops)
 *   GET  ui/agents/types/{typeId}/architect-eligible-tickets?limit=  (architect)
 *   POST ui/agents/runs/{runId}/claim-ticket        { ticket_id }    (coder)
 *   POST ui/agents/runs/{runId}/claim-qa-ticket     { ticket_id }    (qa)
 *   POST ui/agents/types/{typeId}/runs/{runId}/execute       { ticket_id }              (coder)
 *   POST ui/agents/types/{typeId}/runs/{runId}/execute-qa    { ticket_id, scenario }    (qa)
 *   POST ui/agents/types/{typeId}/runs/{runId}/execute-devops{ ticket_id, ... }         (devops)
 *   POST ui/agents/types/{typeId}/runs/{runId}/decompose     { ticket_id }              (architect)
 *   POST ui/agents/types/{typeId}/runs/{runId}/pm-operation  { operation_type, ... }    (pm)
 *   GET  ui/agents/runs/{runId}/{coder|qa|devops|architect|pm}-output
 *   GET  ui/agents/runs/{runId}/qa-report
 *   POST ui/agents/runs/{runId}/approve-deployment  { approved, approver_notes }
 *   POST ui/agents/runs/{runId}/reject-deployment   { approved, approver_notes }
 *   GET  ui/agents/{coder|qa|architect}/metrics?type_id=&period_days=
 *   GET  ui/agents/{devops|pm}/metrics?type_id=&period_days=
 */
interface AgentRunApi {

    // ---- Eligible tickets (per-type route) ----
    @GET("ui/agents/types/{typeId}/eligible-tickets")
    suspend fun coderEligibleTickets(
        @Path("typeId") typeId: String,
        @Query("limit") limit: Int,
    ): Map<String, Any?>

    @GET("ui/agents/types/{typeId}/qa-eligible-tickets")
    suspend fun qaEligibleTickets(
        @Path("typeId") typeId: String,
        @Query("limit") limit: Int,
    ): Map<String, Any?>

    @GET("ui/agents/types/{typeId}/devops-eligible-tickets")
    suspend fun devopsEligibleTickets(
        @Path("typeId") typeId: String,
        @Query("limit") limit: Int,
    ): Map<String, Any?>

    @GET("ui/agents/types/{typeId}/architect-eligible-tickets")
    suspend fun architectEligibleTickets(
        @Path("typeId") typeId: String,
        @Query("limit") limit: Int,
    ): Map<String, Any?>

    // ---- Claim ----
    @Headers("Content-Type: application/json")
    @POST("ui/agents/runs/{runId}/claim-ticket")
    suspend fun claimCoderTicket(
        @Path("runId") runId: String,
        @Body body: Map<String, Any?>,
    ): Map<String, Any?>

    @Headers("Content-Type: application/json")
    @POST("ui/agents/runs/{runId}/claim-qa-ticket")
    suspend fun claimQaTicket(
        @Path("runId") runId: String,
        @Body body: Map<String, Any?>,
    ): Map<String, Any?>

    // ---- Execute ----
    @Headers("Content-Type: application/json")
    @POST("ui/agents/types/{typeId}/runs/{runId}/execute")
    suspend fun executeCoder(
        @Path("typeId") typeId: String,
        @Path("runId") runId: String,
        @Body body: Map<String, Any?>,
    ): Map<String, Any?>

    @Headers("Content-Type: application/json")
    @POST("ui/agents/types/{typeId}/runs/{runId}/execute-qa")
    suspend fun executeQa(
        @Path("typeId") typeId: String,
        @Path("runId") runId: String,
        @Body body: Map<String, Any?>,
    ): Map<String, Any?>

    @Headers("Content-Type: application/json")
    @POST("ui/agents/types/{typeId}/runs/{runId}/execute-devops")
    suspend fun executeDevops(
        @Path("typeId") typeId: String,
        @Path("runId") runId: String,
        @Body body: Map<String, Any?>,
    ): Map<String, Any?>

    @Headers("Content-Type: application/json")
    @POST("ui/agents/types/{typeId}/runs/{runId}/decompose")
    suspend fun decomposeArchitect(
        @Path("typeId") typeId: String,
        @Path("runId") runId: String,
        @Body body: Map<String, Any?>,
    ): Map<String, Any?>

    @Headers("Content-Type: application/json")
    @POST("ui/agents/types/{typeId}/runs/{runId}/pm-operation")
    suspend fun runPmOperation(
        @Path("typeId") typeId: String,
        @Path("runId") runId: String,
        @Body body: Map<String, Any?>,
    ): Map<String, Any?>

    // ---- Output (per-type route) ----
    @GET("ui/agents/runs/{runId}/coder-output")
    suspend fun coderOutput(@Path("runId") runId: String): Map<String, Any?>

    @GET("ui/agents/runs/{runId}/qa-output")
    suspend fun qaOutput(@Path("runId") runId: String): Map<String, Any?>

    @GET("ui/agents/runs/{runId}/devops-output")
    suspend fun devopsOutput(@Path("runId") runId: String): Map<String, Any?>

    @GET("ui/agents/runs/{runId}/architect-output")
    suspend fun architectOutput(@Path("runId") runId: String): Map<String, Any?>

    @GET("ui/agents/runs/{runId}/pm-output")
    suspend fun pmOutput(@Path("runId") runId: String): Map<String, Any?>

    // ---- QA markdown report ----
    @GET("ui/agents/runs/{runId}/qa-report")
    suspend fun qaReport(@Path("runId") runId: String): Map<String, Any?>

    // ---- DevOps deployment approve / reject ----
    @Headers("Content-Type: application/json")
    @POST("ui/agents/runs/{runId}/approve-deployment")
    suspend fun approveDeployment(
        @Path("runId") runId: String,
        @Body body: Map<String, Any?>,
    ): Map<String, Any?>

    @Headers("Content-Type: application/json")
    @POST("ui/agents/runs/{runId}/reject-deployment")
    suspend fun rejectDeployment(
        @Path("runId") runId: String,
        @Body body: Map<String, Any?>,
    ): Map<String, Any?>

    // ---- Metrics (per-type route) ----
    @GET("ui/agents/coder/metrics")
    suspend fun coderMetrics(
        @Query("type_id") typeId: String,
        @Query("period_days") periodDays: Int,
    ): Map<String, Any?>

    @GET("ui/agents/qa/metrics")
    suspend fun qaMetrics(
        @Query("type_id") typeId: String,
        @Query("period_days") periodDays: Int,
    ): Map<String, Any?>

    @GET("ui/agents/devops/metrics")
    suspend fun devopsMetrics(
        @Query("type_id") typeId: String,
        @Query("period_days") periodDays: Int,
    ): Map<String, Any?>

    @GET("ui/agents/architect/metrics")
    suspend fun architectMetrics(
        @Query("type_id") typeId: String,
        @Query("period_days") periodDays: Int,
    ): Map<String, Any?>

    @GET("ui/agents/pm/metrics")
    suspend fun pmMetrics(
        @Query("type_id") typeId: String,
        @Query("period_days") periodDays: Int,
    ): Map<String, Any?>
}
