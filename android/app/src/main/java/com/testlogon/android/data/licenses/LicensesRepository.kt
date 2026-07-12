package com.testlogon.android.data.licenses

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

/**
 * Content-licensing data layer over [LicensesApi].
 *
 * Each section loads its own first page via the idempotent GETs and maps to a domain page; every call is
 * wrapped in [ApiResult] (CancellationException re-thrown, HTTP -> Failure, JSON -> Failure, transport ->
 * NetworkError). A last-known-good snapshot per section is held in memory so a failed refresh can fall
 * back to a stale view; [clear] empties them all (logout cleanup). Read-only: no mutating endpoints.
 */
interface LicensesRepository {

    suspend fun loadIssued(): ApiResult<IssuedLicensesPage>

    suspend fun loadRequests(): ApiResult<LicenseRequestsPage>

    suspend fun loadRevenue(): ApiResult<RevenuePage>

    fun cachedIssued(): IssuedLicensesPage?

    fun cachedRequests(): LicenseRequestsPage?

    fun cachedRevenue(): RevenuePage?

    fun clear()
}

@Singleton
class LicensesRepositoryImpl @Inject constructor(
    private val api: LicensesApi,
    private val errorParser: ApiErrorParser,
) : LicensesRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    @Volatile
    private var issuedSnapshot: IssuedLicensesPage? = null

    @Volatile
    private var requestsSnapshot: LicenseRequestsPage? = null

    @Volatile
    private var revenueSnapshot: RevenuePage? = null

    override suspend fun loadIssued(): ApiResult<IssuedLicensesPage> = withContext(io) {
        call { api.getIssuedLicenses(limit = PAGE_SIZE).toDomain() }
            .also { if (it is ApiResult.Success) issuedSnapshot = it.data }
    }

    override suspend fun loadRequests(): ApiResult<LicenseRequestsPage> = withContext(io) {
        call { api.getSentRequests(limit = PAGE_SIZE).toDomain() }
            .also { if (it is ApiResult.Success) requestsSnapshot = it.data }
    }

    override suspend fun loadRevenue(): ApiResult<RevenuePage> = withContext(io) {
        call { api.getEarnedRevenue(limit = PAGE_SIZE).toDomain() }
            .also { if (it is ApiResult.Success) revenueSnapshot = it.data }
    }

    override fun cachedIssued(): IssuedLicensesPage? = issuedSnapshot

    override fun cachedRequests(): LicenseRequestsPage? = requestsSnapshot

    override fun cachedRevenue(): RevenuePage? = revenueSnapshot

    override fun clear() {
        issuedSnapshot = null
        requestsSnapshot = null
        revenueSnapshot = null
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
        private const val PAGE_SIZE = 50
    }
}
