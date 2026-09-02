package com.testlogon.android.feature.workflow

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.workflow.DripSequenceCreateRequest
import com.testlogon.android.core.network.workflow.WorkflowRuleCreateRequest
import com.testlogon.android.core.network.workflow.WorkflowRuleUpdateRequest
import com.testlogon.android.core.network.workflow.WorkflowRulesApi
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * WFL — data layer for the SuiteCRM Workflow admin CRUD.
 *
 * REUSES the core-network [WorkflowRulesApi] + shared [ApiErrorParser]; maps DTOs to domain BEFORE the
 * typed [ApiResult]. DEGRADE-ON-404: the whole router 404s when CRM_WORKFLOW_ENABLED is off (or 403 for
 * non-admins); both surface as an [ApiResult.Failure] the ViewModel folds to a calm unavailable state.
 *
 * Full admin surface: list/read + create/update/delete/enable/disable + run history + drip-sequence
 * list/create. Mutations require admin/root + CSRF server-side (attached globally by the interceptors).
 */
interface WorkflowRulesRepository {

    /** List workflow rules (optionally enabled-only), mapped + count-summarized. */
    suspend fun listRules(enabledOnly: Boolean? = null, limit: Int? = null): ApiResult<List<WorkflowRule>>

    /** Read one rule's detail. */
    suspend fun getRule(ruleId: String): ApiResult<WorkflowRule>

    /** Create a workflow rule. */
    suspend fun createRule(body: WorkflowRuleCreateRequest): ApiResult<WorkflowRule>

    /** Patch a rule (partial update; only non-null fields are sent). */
    suspend fun updateRule(ruleId: String, body: WorkflowRuleUpdateRequest): ApiResult<WorkflowRule>

    /** Delete a rule. */
    suspend fun deleteRule(ruleId: String): ApiResult<Unit>

    /** Enable a rule (returns the updated rule). */
    suspend fun enableRule(ruleId: String): ApiResult<WorkflowRule>

    /** Disable a rule (returns the updated rule). */
    suspend fun disableRule(ruleId: String): ApiResult<WorkflowRule>

    /** List a rule's run history (most-recent first, cursor-paged server-side). */
    suspend fun listRuleRuns(ruleId: String, limit: Int? = null): ApiResult<List<WorkflowRun>>

    /** List drip sequences. */
    suspend fun listDripSequences(limit: Int? = null): ApiResult<List<DripSequence>>

    /** Create a drip sequence. */
    suspend fun createDripSequence(body: DripSequenceCreateRequest): ApiResult<DripSequence>
}

@Singleton
class WorkflowRulesRepositoryImpl @Inject constructor(
    private val api: WorkflowRulesApi,
    private val errorParser: ApiErrorParser,
) : WorkflowRulesRepository {

    override suspend fun listRules(
        enabledOnly: Boolean?,
        limit: Int?,
    ): ApiResult<List<WorkflowRule>> = withContext(Dispatchers.IO) {
        call { api.listRules(enabledOnly = enabledOnly, limit = limit).rules.map { it.toDomain() } }
    }

    override suspend fun getRule(ruleId: String): ApiResult<WorkflowRule> =
        withContext(Dispatchers.IO) { call { api.getRule(ruleId).toDomain() } }

    override suspend fun createRule(body: WorkflowRuleCreateRequest): ApiResult<WorkflowRule> =
        withContext(Dispatchers.IO) { call { api.createRule(body).toDomain() } }

    override suspend fun updateRule(
        ruleId: String,
        body: WorkflowRuleUpdateRequest,
    ): ApiResult<WorkflowRule> =
        withContext(Dispatchers.IO) { call { api.updateRule(ruleId, body).toDomain() } }

    override suspend fun deleteRule(ruleId: String): ApiResult<Unit> =
        withContext(Dispatchers.IO) { call { api.deleteRule(ruleId) } }

    override suspend fun enableRule(ruleId: String): ApiResult<WorkflowRule> =
        withContext(Dispatchers.IO) { call { api.enableRule(ruleId).toDomain() } }

    override suspend fun disableRule(ruleId: String): ApiResult<WorkflowRule> =
        withContext(Dispatchers.IO) { call { api.disableRule(ruleId).toDomain() } }

    override suspend fun listRuleRuns(ruleId: String, limit: Int?): ApiResult<List<WorkflowRun>> =
        withContext(Dispatchers.IO) {
            call { api.listRuleRuns(ruleId, limit = limit).runs.map { it.toDomain() } }
        }

    override suspend fun listDripSequences(limit: Int?): ApiResult<List<DripSequence>> =
        withContext(Dispatchers.IO) {
            call { api.listDripSequences(limit = limit).sequences.map { it.toDomain() } }
        }

    override suspend fun createDripSequence(
        body: DripSequenceCreateRequest,
    ): ApiResult<DripSequence> =
        withContext(Dispatchers.IO) { call { api.createDripSequence(body).toDomain() } }

    /** Folds a block into [ApiResult]; mirrors SignatureRepositoryImpl.call. */
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
