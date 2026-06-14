package com.testlogon.android.feature.donation.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.donation.DonateRequestDto
import com.testlogon.android.core.network.donation.DonationApi
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.feature.donation.model.DonationReceipt
import com.testlogon.android.feature.donation.model.DonationRequest
import com.testlogon.android.feature.donation.model.Fundraiser
import com.testlogon.android.feature.donation.model.toDomain
import com.testlogon.android.feature.donation.model.toReceiptFallback
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
 * AND-393 - data layer over the SESSION-FREE [DonationApi] (cookieless Retrofit from
 * core-network DonationNetworkModule). Each network call is wrapped in [ApiResult] and the wire DTO is
 * mapped to the domain BEFORE the typed result. Never throws (Cancellation is re-thrown).
 *
 * ANONYMOUS-CAPABLE: the underlying [DonationApi] runs on a cookieless client, so none of these calls
 * carry the caller's session - a signed-out donor reaches the public fundraiser/donate/receipt endpoints
 * without an authenticated session and GET /ui/me is never on this path (AC-2).
 *
 * SOFT-FALLBACK ([donate]): the donation 201 is the binding success; the receipt GET is a best-effort
 * SECOND call. If the receipt errors transiently the donation still succeeds with a minimal receipt built
 * from the 201 (§5/AC-2) - the donor never loses a completed donation to a flaky receipt endpoint.
 *
 * Repos live in :app (core-data lacks HttpException / ApiErrorParser); the call{} fold mirrors the
 * established AND-335 ShareRepository pattern.
 */
interface DonationRepository {

    /** GET the public fundraiser summary (session-free). */
    suspend fun getFundraiser(id: String): ApiResult<Fundraiser>

    /**
     * POST a donation, then fetch its receipt (soft-fallback to a minimal receipt on receipt failure).
     * The fundraiser context ([currency]/[groupName]/[fundraiserTitle]) backs the fallback receipt copy.
     */
    suspend fun donate(
        fundraiserId: String,
        request: DonationRequest,
        currency: String,
        groupName: String?,
        fundraiserTitle: String?,
    ): ApiResult<DonationReceipt>

    /**
     * Extracts the FastAPI 422 validation message whose `loc` tail equals [locTail] (e.g. "amount_cents"
     * or "donor_email"), so the ViewModel can surface a field-level error. Returns null when the error is
     * not a mappable 422 for that field. Lives on the repo because ApiErrorParser is an :app-side dep.
     */
    fun fieldError(error: ApiError, locTail: String): String?
}

@Singleton
class DonationRepositoryImpl @Inject constructor(
    private val api: DonationApi,
    private val errorParser: ApiErrorParser,
) : DonationRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun getFundraiser(id: String): ApiResult<Fundraiser> = withContext(io) {
        when (val result = call { unwrap(api.getFundraiser(id)) }) {
            is ApiResult.Success -> ApiResult.Success(result.data.toDomain())
            is ApiResult.Failure -> result
            is ApiResult.NetworkError -> result
        }
    }

    override suspend fun donate(
        fundraiserId: String,
        request: DonationRequest,
        currency: String,
        groupName: String?,
        fundraiserTitle: String?,
    ): ApiResult<DonationReceipt> = withContext(io) {
        val body = DonateRequestDto(
            amountCents = request.amountCents,
            donorName = request.donorName?.takeIf { it.isNotBlank() },
            donorEmail = request.donorEmail?.takeIf { it.isNotBlank() },
        )
        when (val donation = call { unwrap(api.donate(fundraiserId, body)) }) {
            is ApiResult.Failure -> donation
            is ApiResult.NetworkError -> donation
            is ApiResult.Success -> {
                // The donation succeeded. The receipt GET is a best-effort SECOND call; a transient
                // failure must NOT lose the completed donation, so fall back to a minimal receipt.
                val dto = donation.data
                val receipt = when (
                    val r = call { unwrap(api.getReceipt(fundraiserId, dto.donationId)) }
                ) {
                    is ApiResult.Success -> r.data.toDomain()
                    is ApiResult.Failure,
                    is ApiResult.NetworkError ->
                        dto.toReceiptFallback(currency, groupName, fundraiserTitle)
                }
                ApiResult.Success(receipt)
            }
        }
    }

    override fun fieldError(error: ApiError, locTail: String): String? =
        errorParser.fieldErrorForLocTail(error, locTail)

    /**
     * Reads a successful [Response] body; a non-2xx surfaces as [HttpException] (folded to Failure by
     * [call]); a 2xx with an unexpectedly empty body surfaces as a parse failure. Mirrors the established
     * Response<T> handling for the public surface.
     */
    private fun <T> unwrap(response: Response<T>): T {
        if (!response.isSuccessful) throw HttpException(response)
        return response.body() ?: throw JsonDataException("Empty body for ${response.raw().request.url}")
    }

    /**
     * Folds a single call into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser]); transport
     * failures -> NetworkError; malformed JSON -> Failure(parse). The JsonEncodingException catch precedes
     * the IOException catch (it is an IOException subtype). Cancellation is re-thrown.
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
