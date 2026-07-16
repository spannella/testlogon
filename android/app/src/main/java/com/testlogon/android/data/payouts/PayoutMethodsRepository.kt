package com.testlogon.android.data.payouts

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Response
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * PAY-13 — data layer over [PayoutMethodsApi] for ROUTABLE payout methods (PAY-10..12 backend).
 *
 * Wraps every call in [ApiResult] (same convention as [PayoutsRepository]). Mutations are NEVER
 * auto-retried. SEC-004: [addMethod] sends the full bank number/routing on the wire for server-side
 * tokenization only; the domain [PayoutMethod] it returns carries just the last-4 + an opaque ref.
 */
interface PayoutMethodsRepository {

    /** List routable methods (status + default flag). Idempotent GET. */
    suspend fun listMethods(): ApiResult<List<PayoutMethod>>

    /** Add a routable destination (bank tokenized server-side / paypal email / connect id). Mutation. */
    suspend fun addMethod(input: AddPayoutMethodInput): ApiResult<PayoutMethod>

    /** PAY-12 — verify a method so it can be a payout destination. Mutation. */
    suspend fun verifyMethod(methodId: String): ApiResult<PayoutMethod>

    /** Set the default payout destination. Mutation. */
    suspend fun setDefault(methodId: String): ApiResult<PayoutMethod>

    /** Remove a method. Mutation. */
    suspend fun deleteMethod(methodId: String): ApiResult<Unit>

    /** PAY-11 — the creator's Connect account status (creates none). Idempotent GET. */
    suspend fun getConnect(): ApiResult<ConnectAccount>

    /** PAY-11 — create (or return) the creator's Connect account id. Mutation. */
    suspend fun createConnectAccount(): ApiResult<ConnectAccount>

    /** PAY-11 — a Connect onboarding link (real when keyed; mock self-completes). Mutation. */
    suspend fun createConnectOnboardingLink(): ApiResult<ConnectOnboarding>
}

@Singleton
class PayoutMethodsRepositoryImpl @Inject constructor(
    private val api: PayoutMethodsApi,
    private val errorParser: ApiErrorParser,
) : PayoutMethodsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun listMethods(): ApiResult<List<PayoutMethod>> = withContext(io) {
        call { api.listMethods() }.map { it.toDomain() }
    }

    override suspend fun addMethod(input: AddPayoutMethodInput): ApiResult<PayoutMethod> = withContext(io) {
        call { api.addMethod(input.toDto()) }.map { it.toDomain() }
    }

    override suspend fun verifyMethod(methodId: String): ApiResult<PayoutMethod> = withContext(io) {
        call { api.verifyMethod(methodId) }.map { it.toDomain() }
    }

    override suspend fun setDefault(methodId: String): ApiResult<PayoutMethod> = withContext(io) {
        call { api.setDefault(methodId) }.map { it.toDomain() }
    }

    override suspend fun deleteMethod(methodId: String): ApiResult<Unit> = withContext(io) {
        call {
            val resp: Response<Unit> = api.deleteMethod(methodId)
            if (!resp.isSuccessful) throw HttpException(resp)
            Unit
        }
    }

    override suspend fun getConnect(): ApiResult<ConnectAccount> = withContext(io) {
        call { api.getConnect() }.map { it.toDomain() }
    }

    override suspend fun createConnectAccount(): ApiResult<ConnectAccount> = withContext(io) {
        call { api.createConnectAccount() }.map { it.toDomain() }
    }

    override suspend fun createConnectOnboardingLink(): ApiResult<ConnectOnboarding> = withContext(io) {
        call { api.createConnectOnboardingLink() }.map { it.toDomain() }
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
