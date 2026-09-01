package com.testlogon.android.data.promo

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
 * AND-266 — promo-codes data layer over [PromoCodesApi].
 *
 * MVP is a single non-paged GET ui/promo-codes (the endpoint takes no cursor/limit). create() POSTs
 * PromoCodeCreateIn (plain CRUD, no charge); both create() and deactivate() are non-idempotent mutations
 * (not auto-retried). redeem() is the internal/post-payment client. The screen re-fetches the list after
 * a successful create/deactivate (web parity: invalidates the list query). Every call is wrapped in
 * [ApiResult] (CancellationException re-thrown, HTTP -> Failure, JsonDataException -> Failure, transport
 * -> NetworkError). DTOs map to domain before returning.
 */
interface PromoCodesRepository {

    suspend fun listCodes(): ApiResult<List<PromoCode>>

    suspend fun create(request: CreatePromoRequestDto): ApiResult<PromoCode>

    suspend fun deactivate(codeId: String): ApiResult<Unit>

    suspend fun redeem(request: RedeemPromoRequestDto): ApiResult<RedeemResult>

    /**
     * Validate a code for a checkout context. Returns Success(null) when the promo-codes surface is
     * not deployed on this backend (404 -> degrade-on-404): the checkout field simply hides itself.
     * Every other HTTP/parse/transport failure folds to Failure/NetworkError as usual.
     */
    suspend fun validate(request: ValidatePromoRequestDto): ApiResult<PromoValidation?>
}

@Singleton
class PromoCodesRepositoryImpl @Inject constructor(
    private val api: PromoCodesApi,
    private val errorParser: ApiErrorParser,
) : PromoCodesRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun listCodes(): ApiResult<List<PromoCode>> = withContext(io) {
        call { api.list().toDomain() }
    }

    override suspend fun create(request: CreatePromoRequestDto): ApiResult<PromoCode> = withContext(io) {
        call { api.create(request).toDomain() }
    }

    override suspend fun deactivate(codeId: String): ApiResult<Unit> = withContext(io) {
        call { api.deactivate(codeId); Unit }
    }

    override suspend fun redeem(request: RedeemPromoRequestDto): ApiResult<RedeemResult> = withContext(io) {
        call { api.redeem(request).toDomain() }
    }

    override suspend fun validate(request: ValidatePromoRequestDto): ApiResult<PromoValidation?> =
        withContext(io) {
            try {
                ApiResult.Success(api.validate(request).toDomain())
            } catch (e: CancellationException) {
                throw e
            } catch (e: HttpException) {
                // Degrade-on-404: promo-codes not enabled/deployed on this backend.
                if (e.code() == 404) ApiResult.Success(null)
                else ApiResult.Failure(errorParser.from(e))
            } catch (e: com.squareup.moshi.JsonDataException) {
                ApiResult.Failure(errorParser.fromThrowable(e))
            } catch (e: IOException) {
                ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
            }
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
}
