package com.testlogon.android.data.billing

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Retrofit
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-248 — read-only data layer over [AdminBillingConfigApi].
 *
 * Wraps the single GET in [ApiResult] (matching the other billing repositories): CancellationException is
 * re-thrown; HTTP errors fold to Failure (via [ApiErrorParser]); transport failures to NetworkError. The
 * DTO is mapped to domain before returning. There are NO mutations here (read-only is a security
 * property — AND-248 §8): no PATCH/POST is exposed.
 */
interface AdminBillingConfigRepository {

    /** The effective platform billing configuration. Idempotent GET (root-gated server-side). */
    suspend fun getBillingConfig(): ApiResult<AdminBillingConfig>

    /** Change history (ADMIN-drivable). */
    suspend fun getAudit(): ApiResult<List<BillingConfigAuditEntry>>

    /** Reset all keys to defaults (ROOT-only -> 403 for our admin account). */
    suspend fun resetAll(): ApiResult<AdminBillingConfig>
}

@Singleton
class AdminBillingConfigRepositoryImpl @Inject constructor(
    private val api: AdminBillingConfigApi,
    private val errorParser: ApiErrorParser,
) : AdminBillingConfigRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun getBillingConfig(): ApiResult<AdminBillingConfig> = withContext(io) {
        call { api.getAdminBillingConfig() }.map { it.toDomain() }
    }

    override suspend fun getAudit(): ApiResult<List<BillingConfigAuditEntry>> = withContext(io) {
        call { api.getBillingConfigAudit() }.map { log -> log.entries.map { it.toDomain() } }
    }

    override suspend fun resetAll(): ApiResult<AdminBillingConfig> = withContext(io) {
        call { api.resetBillingConfig(BillingConfigResetReqDto(keys = null)) }.map { it.toDomain() }
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}

/** AND-248 — provides the [AdminBillingConfigApi] on the shared (authenticated) Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object AdminBillingConfigApiModule {

    @Provides
    @Singleton
    fun provideAdminBillingConfigApi(retrofit: Retrofit): AdminBillingConfigApi =
        retrofit.create(AdminBillingConfigApi::class.java)
}

/** AND-248 — binds the read-only admin billing-config repository. */
@Module
@InstallIn(SingletonComponent::class)
abstract class AdminBillingConfigDataModule {

    @Binds
    @Singleton
    abstract fun bindAdminBillingConfigRepository(
        impl: AdminBillingConfigRepositoryImpl,
    ): AdminBillingConfigRepository
}
