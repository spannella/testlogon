package com.testlogon.android.feature.workflow

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
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
 * WFL — data layer for the SuiteCRM Workflow admin list/read MVP.
 *
 * REUSES the core-network [WorkflowRulesApi] + shared [ApiErrorParser]; maps DTOs to domain BEFORE the
 * typed [ApiResult]. DEGRADE-ON-404: the whole router 404s when CRM_WORKFLOW_ENABLED is off (or 403 for
 * non-admins); both surface as an [ApiResult.Failure] the ViewModel folds to a calm unavailable state.
 *
 * READ ONLY: create/update/delete/enable/disable + drip sequences + run history are intentionally out of
 * scope for the MVP (mutations are admin-heavy and the web surfaces them separately).
 */
interface WorkflowRulesRepository {

    /** List workflow rules (optionally enabled-only), mapped + count-summarized. */
    suspend fun listRules(enabledOnly: Boolean? = null, limit: Int? = null): ApiResult<List<WorkflowRule>>

    /** Read one rule's detail. */
    suspend fun getRule(ruleId: String): ApiResult<WorkflowRule>
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
