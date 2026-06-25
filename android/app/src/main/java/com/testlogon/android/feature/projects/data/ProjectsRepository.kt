package com.testlogon.android.feature.projects.data

import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.projects.DriveConnection
import com.testlogon.android.core.model.projects.Project
import com.testlogon.android.core.model.projects.ProviderCallbackParams
import com.testlogon.android.core.model.projects.ProviderStart
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.projects.ProjectProviders
import com.testlogon.android.core.network.projects.ProjectCreateIn
import com.testlogon.android.core.network.projects.ProjectsApi
import com.testlogon.android.core.network.projects.ProviderOAuthCallbackIn
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-374 - data layer for the PROJECTS surface, over the AND-374 [ProjectsApi].
 *
 * The LIST is Paging 3 ([projectsPager], cursor-keyed). The DETAIL read ([getProjectDetail]) maps the
 * { project, files[], cursor } envelope to the domain [Project] (files[] ignored - AND-336 scope). The Drive
 * provider flow is ACCOUNT-scoped (spec §16): [startGoogleDrive] returns the authorization URL + state;
 * [completeGoogleDrive] posts {code, state} and returns a [DriveConnection]; [isDriveConnected] reads the
 * provider-credentials GET (a 404 / failure -> not connected). The list/detail GETs are idempotent (the global
 * GET-only retry backoff applies); the start/callback POSTs are NON-idempotent (NO auto-retry - the caller
 * decides whether to re-send).
 *
 * ROOM CACHE DEFERRED: there is intentionally NO Room-backed cache and NO Room migration this wave (mirrors the
 * AND-372 tickets decision); the stale-while-offline snapshot is kept IN-MEMORY in the ViewModels.
 *
 * An interface (bound to [ProjectsRepositoryImpl] in the data module) keeps the VM test fake-able.
 */
interface ProjectsRepository {

    /** A cold [PagingData] stream of the caller's projects (cursor-keyed); re-collect to refresh. */
    fun projectsPager(): Flow<PagingData<Project>>

    /** GET one project's detail ({ project, files[], cursor }), mapped to the domain project. Idempotent. */
    suspend fun getProjectDetail(projectId: String): ApiResult<Project>

    /**
     * Batch-8 (#9) - POST a new project. On success returns the created [Project] (the caller is the owner);
     * a 4xx/422 surfaces as Failure carrying the status; transport failures -> NetworkError. NON-idempotent.
     */
    suspend fun createProject(
        name: String,
        description: String?,
        tags: List<String>,
    ): ApiResult<Project>

    /**
     * POST the account-scoped Drive OAuth START - returns the authorization URL + state. NON-idempotent (no
     * project id is sent; spec §16). The caller opens [ProviderStart.authorizationUrl] in a Custom Tab and
     * retains [ProviderStart.state] for the callback CSRF check.
     */
    suspend fun startGoogleDrive(): ApiResult<ProviderStart>

    /**
     * POST the account-scoped Drive OAuth CALLBACK with the captured {code, state}. Returns the resulting
     * [DriveConnection] (connected = true on success). NON-idempotent (no auto-retry). The caller is
     * responsible for validating the echoed state BEFORE invoking this.
     */
    suspend fun completeGoogleDrive(params: ProviderCallbackParams): ApiResult<DriveConnection>

    /**
     * GET the connected-provider credential to decide "is Drive connected". A success -> connected; a 404 (or
     * any other failure) -> [DriveConnection] with connected = false (NOT an error - "not connected" is a
     * normal state, not a failure to surface). A genuine transport failure is surfaced as
     * [ApiResult.NetworkError] so the detail screen can render an offline/stale affordance.
     */
    suspend fun isDriveConnected(): ApiResult<DriveConnection>

    companion object {
        const val PAGE_SIZE = 20
        const val PREFETCH_DISTANCE = 6
        const val HTTP_NOT_FOUND = 404
    }
}

@Singleton
class ProjectsRepositoryImpl @Inject constructor(
    private val api: ProjectsApi,
    private val errorParser: ApiErrorParser,
) : ProjectsRepository {

    override fun projectsPager(): Flow<PagingData<Project>> =
        Pager(
            config = pagingConfig(),
            pagingSourceFactory = { ProjectsPagingSource(api, ProjectsRepository.PAGE_SIZE) },
        ).flow

    override suspend fun getProjectDetail(projectId: String): ApiResult<Project> =
        withContext(Dispatchers.IO) {
            call { api.getProjectDetail(projectId).project.toDomain() }
        }

    override suspend fun createProject(
        name: String,
        description: String?,
        tags: List<String>,
    ): ApiResult<Project> = withContext(Dispatchers.IO) {
        call {
            api.createProject(
                ProjectCreateIn(
                    name = name,
                    description = description?.takeIf { it.isNotBlank() },
                    tags = tags,
                ),
            ).toDomain()
        }
    }

    override suspend fun startGoogleDrive(): ApiResult<ProviderStart> =
        withContext(Dispatchers.IO) {
            call { api.startGoogleDrive().toDomain() }
        }

    override suspend fun completeGoogleDrive(params: ProviderCallbackParams): ApiResult<DriveConnection> =
        withContext(Dispatchers.IO) {
            val code = params.code
            val state = params.state
            if (code.isNullOrBlank() || state.isNullOrBlank()) {
                // Defensive: a callback with no code/state never reaches here in the happy path (the VM
                // gates on it), but fold it to a connected=false rather than POSTing an invalid body.
                return@withContext ApiResult.Success(DriveConnection(connected = false))
            }
            call {
                api.completeGoogleDrive(ProviderOAuthCallbackIn(code = code, state = state)).toDriveConnection()
            }
        }

    override suspend fun isDriveConnected(): ApiResult<DriveConnection> =
        withContext(Dispatchers.IO) {
            when (val result = call { api.getProviderCredential(ProjectProviders.GOOGLE_DRIVE).toDriveConnection() }) {
                is ApiResult.Success -> result
                // A 404 (or any HTTP failure that is NOT a transport error) means "not connected" - a NORMAL
                // state, not an error to surface. A genuine transport failure stays a NetworkError so the
                // screen can show an offline/stale affordance.
                is ApiResult.Failure -> ApiResult.Success(DriveConnection(connected = false))
                is ApiResult.NetworkError -> result
            }
        }

    private fun pagingConfig() = PagingConfig(
        pageSize = ProjectsRepository.PAGE_SIZE,
        initialLoadSize = ProjectsRepository.PAGE_SIZE,
        prefetchDistance = ProjectsRepository.PREFETCH_DISTANCE,
        enablePlaceholders = false,
    )

    /**
     * Folds a block into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser], preserving the status, so a
     * 401 surfaces as Failure(status=401) for the VM's re-auth handoff and a 404 stays Failure(status=404) for
     * the not-connected mapping above); malformed JSON -> Failure; transport failures -> NetworkError.
     * JsonEncodingException precedes IOException (it is a subtype). Cancellation is re-thrown. Mirrors AND-372.
     */
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
