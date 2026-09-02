package com.testlogon.android.data.admin.email

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.admin.AdminRoleProvider
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import java.net.URLEncoder
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Data layer over [AdminEmailApi] for the ADMIN-EMAIL surface (stats + suppressed + campaign templates).
 *
 * Gating: reuses the AND-403 [AdminRoleProvider] client pre-check ([isAdmin]); the backend
 * `require_admin_or_root` 403 remains the authority. Degrade-on-404: the campaign-template routes 404
 * when the CAMPAIGN_TEMPLATES flag is off, so template reads fold a 404 into an honest-EMPTY list;
 * mutations surface the failure so the user sees "not enabled". Every call is wrapped in [ApiResult].
 */
interface AdminEmailRepository {
    fun isAdmin(): Boolean

    suspend fun loadStats(days: Int = AdminEmailApi.DEFAULT_DAYS): ApiResult<EmailStats>
    suspend fun loadSuppressed(): ApiResult<List<SuppressedEmail>>
    suspend fun unsuppress(email: String): ApiResult<Unit>

    suspend fun loadTemplates(): ApiResult<List<CampaignTemplate>>
    suspend fun createTemplate(
        name: String,
        subject: String,
        body: String,
        mergeFields: List<String>,
    ): ApiResult<CampaignTemplate>
    suspend fun setTemplateActive(templateId: String, active: Boolean): ApiResult<CampaignTemplate>
    suspend fun deleteTemplate(templateId: String): ApiResult<Unit>
}

@Singleton
class AdminEmailRepositoryImpl @Inject constructor(
    private val api: AdminEmailApi,
    private val errorParser: ApiErrorParser,
    private val roleProvider: AdminRoleProvider,
) : AdminEmailRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override fun isAdmin(): Boolean = roleProvider.mayAttemptAdminReads()

    override suspend fun loadStats(days: Int): ApiResult<EmailStats> = withContext(io) {
        readOrDefault(EMPTY_STATS) { api.getStats(days).toDomain() }
    }

    override suspend fun loadSuppressed(): ApiResult<List<SuppressedEmail>> = withContext(io) {
        readOrDefault(emptyList()) {
            api.listSuppressed().items.mapNotNull { it.toDomain() }
        }
    }

    override suspend fun unsuppress(email: String): ApiResult<Unit> = withContext(io) {
        call {
            api.unsuppress(URLEncoder.encode(email, "UTF-8"))
            Unit
        }
    }

    override suspend fun loadTemplates(): ApiResult<List<CampaignTemplate>> = withContext(io) {
        readOrDefault(emptyList()) { api.listTemplates().map { it.toDomain() } }
    }

    override suspend fun createTemplate(
        name: String,
        subject: String,
        body: String,
        mergeFields: List<String>,
    ): ApiResult<CampaignTemplate> = withContext(io) {
        call {
            api.createTemplate(
                CampaignTemplateCreateDto(
                    name = name.trim(),
                    subject = subject.trim(),
                    body = body,
                    mergeFields = mergeFields,
                ),
            ).toDomain()
        }
    }

    override suspend fun setTemplateActive(
        templateId: String,
        active: Boolean,
    ): ApiResult<CampaignTemplate> = withContext(io) {
        call {
            api.updateTemplate(templateId, CampaignTemplateUpdateDto(active = active)).toDomain()
        }
    }

    override suspend fun deleteTemplate(templateId: String): ApiResult<Unit> = withContext(io) {
        call {
            api.deleteTemplate(templateId)
            Unit
        }
    }

    private suspend fun <T> readOrDefault(empty: T, block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        if (e.code() == HTTP_NOT_FOUND) ApiResult.Success(empty) else ApiResult.Failure(errorParser.from(e))
    } catch (e: com.squareup.moshi.JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: com.squareup.moshi.JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }

    private companion object {
        private const val HTTP_NOT_FOUND = 404
        private val EMPTY_STATS = EmailStats(0, 0, 0, 0, 0, 0, 0, 0.0, 0.0, 0.0, AdminEmailApi.DEFAULT_DAYS)
    }
}
