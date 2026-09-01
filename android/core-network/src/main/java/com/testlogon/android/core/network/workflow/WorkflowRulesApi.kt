package com.testlogon.android.core.network.workflow

import retrofit2.http.GET
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * Retrofit interface for the SuiteCRM Workflow (WFL) admin endpoint surface — READ subset. Transport
 * only. Paths have NO leading slash (relative to the shared base URL). Session cookies / Authorization
 * Bearer / X-CSRF-Token are attached globally. These reads are admin-gated server-side (403 for members)
 * and the whole router 404s when CRM_WORKFLOW_ENABLED is off.
 *
 * Mirrors frontend/src/api/endpoints/crmWorkflow.ts listWorkflowRules / getWorkflowRule.
 */
interface WorkflowRulesApi {

    @GET("ui/admin/crm/workflow/rules")
    suspend fun listRules(
        @Query("target_module") targetModule: String? = null,
        @Query("enabled_only") enabledOnly: Boolean? = null,
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
    ): WorkflowRuleListDto

    @GET("ui/admin/crm/workflow/rules/{ruleId}")
    suspend fun getRule(@Path("ruleId") ruleId: String): WorkflowRuleDto
}
