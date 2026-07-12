package com.testlogon.android.feature.agents.docs.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.agents.CreateDocTemplateRequest
import com.testlogon.android.core.network.agents.DocsApi
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Response
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AGENTS-BASICS (web-parity) - data layer for the DOC-COVERAGE surface over [DocsApi]. Folds transport into
 * [ApiResult] via [call]. coverage/details/stale/templates are idempotent GETs; freshness-check + template
 * create/delete are mutations. Mirrors the WORKERS repository fold. No cache / Room.
 */
interface DocsRepository {
    suspend fun coverage(): ApiResult<DocCoverageSummary>
    suspend fun coverageDetails(docType: String? = null): ApiResult<List<DocCoverage>>
    suspend fun stale(limit: Int? = null): ApiResult<List<DocCoverage>>
    suspend fun freshnessCheck(): ApiResult<FreshnessCheck>
    suspend fun listTemplates(docType: String? = null): ApiResult<List<DocTemplate>>
    suspend fun createTemplate(request: CreateDocTemplateRequest): ApiResult<DocTemplate>
    suspend fun deleteTemplate(templateId: String): ApiResult<Unit>
}

@Singleton
class DefaultDocsRepository @Inject constructor(
    private val api: DocsApi,
    private val errorParser: ApiErrorParser,
) : DocsRepository {

    override suspend fun coverage(): ApiResult<DocCoverageSummary> =
        withContext(Dispatchers.IO) { call { api.coverage().toDomain() } }

    override suspend fun coverageDetails(docType: String?): ApiResult<List<DocCoverage>> =
        withContext(Dispatchers.IO) { call { api.coverageDetails(docType).docs.map { it.toDomain() } } }

    override suspend fun stale(limit: Int?): ApiResult<List<DocCoverage>> =
        withContext(Dispatchers.IO) { call { api.stale(limit).docs.map { it.toDomain() } } }

    override suspend fun freshnessCheck(): ApiResult<FreshnessCheck> =
        withContext(Dispatchers.IO) { call { api.freshnessCheck().toDomain() } }

    override suspend fun listTemplates(docType: String?): ApiResult<List<DocTemplate>> =
        withContext(Dispatchers.IO) { call { api.listTemplates(docType).templates.map { it.toDomain() } } }

    override suspend fun createTemplate(request: CreateDocTemplateRequest): ApiResult<DocTemplate> =
        withContext(Dispatchers.IO) { call { api.createTemplate(request).toDomain() } }

    override suspend fun deleteTemplate(templateId: String): ApiResult<Unit> =
        withContext(Dispatchers.IO) { call { api.deleteTemplate(templateId).unitOrThrow() } }

    private fun Response<Unit>.unitOrThrow() {
        if (!isSuccessful) throw HttpException(this)
    }

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
