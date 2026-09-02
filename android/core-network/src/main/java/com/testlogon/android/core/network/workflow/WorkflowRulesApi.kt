package com.testlogon.android.core.network.workflow

import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * Retrofit interface for the SuiteCRM Workflow (WFL) admin endpoint surface. Transport only. Paths have
 * NO leading slash (relative to the shared base URL). Session cookies / Authorization Bearer /
 * X-CSRF-Token are attached globally by the core-network interceptors, so mutating verbs need only the
 * explicit JSON Content-Type header. Reads are admin-gated server-side (403 for members); mutations
 * require admin/root + CSRF (403 otherwise). The whole router 404s when CRM_WORKFLOW_ENABLED is off, and
 * the repository degrades on 404/403.
 *
 * Mirrors frontend/src/api/endpoints/crmWorkflow.ts (full rule CRUD + run history + drip-sequence CRUD).
 */
interface WorkflowRulesApi {

    // ----- Rule CRUD -----

    @GET("ui/admin/crm/workflow/rules")
    suspend fun listRules(
        @Query("target_module") targetModule: String? = null,
        @Query("enabled_only") enabledOnly: Boolean? = null,
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
    ): WorkflowRuleListDto

    @GET("ui/admin/crm/workflow/rules/{ruleId}")
    suspend fun getRule(@Path("ruleId") ruleId: String): WorkflowRuleDto

    @Headers("Content-Type: application/json")
    @POST("ui/admin/crm/workflow/rules")
    suspend fun createRule(@Body body: WorkflowRuleCreateRequest): WorkflowRuleDto

    @Headers("Content-Type: application/json")
    @PATCH("ui/admin/crm/workflow/rules/{ruleId}")
    suspend fun updateRule(
        @Path("ruleId") ruleId: String,
        @Body body: WorkflowRuleUpdateRequest,
    ): WorkflowRuleDto

    @DELETE("ui/admin/crm/workflow/rules/{ruleId}")
    suspend fun deleteRule(@Path("ruleId") ruleId: String)

    @Headers("Content-Type: application/json")
    @POST("ui/admin/crm/workflow/rules/{ruleId}/enable")
    suspend fun enableRule(@Path("ruleId") ruleId: String): WorkflowRuleDto

    @Headers("Content-Type: application/json")
    @POST("ui/admin/crm/workflow/rules/{ruleId}/disable")
    suspend fun disableRule(@Path("ruleId") ruleId: String): WorkflowRuleDto

    // ----- Run history -----

    @GET("ui/admin/crm/workflow/rules/{ruleId}/runs")
    suspend fun listRuleRuns(
        @Path("ruleId") ruleId: String,
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
    ): WorkflowRunListDto

    // ----- Drip sequences -----

    @GET("ui/admin/crm/workflow/drip-sequences")
    suspend fun listDripSequences(
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
    ): DripSequenceListDto

    @Headers("Content-Type: application/json")
    @POST("ui/admin/crm/workflow/drip-sequences")
    suspend fun createDripSequence(@Body body: DripSequenceCreateRequest): DripSequenceDto

    @GET("ui/admin/crm/workflow/drip-sequences/{sequenceId}")
    suspend fun getDripSequence(@Path("sequenceId") sequenceId: String): DripSequenceDto

    @Headers("Content-Type: application/json")
    @PATCH("ui/admin/crm/workflow/drip-sequences/{sequenceId}")
    suspend fun updateDripSequence(
        @Path("sequenceId") sequenceId: String,
        @Body body: DripSequenceUpdateRequest,
    ): DripSequenceDto

    @DELETE("ui/admin/crm/workflow/drip-sequences/{sequenceId}")
    suspend fun deleteDripSequence(@Path("sequenceId") sequenceId: String)
}
