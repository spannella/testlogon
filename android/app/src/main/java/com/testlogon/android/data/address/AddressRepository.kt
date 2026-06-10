package com.testlogon.android.data.address

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
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
 * AND-214 — saved-address data layer over [AddressApi].
 *
 * Wraps every call in [ApiResult]; CancellationException is re-thrown; HTTP errors fold to Failure and
 * transport failures to NetworkError. The GET is idempotent; create + set-primary are non-idempotent
 * mutations and are never auto-retried here.
 *
 * Scope note (spec AND-214 sections 1/5/16): there is no shipping-quote / apply-to-checkout endpoint;
 * the only "apply" the backend supports is [setPrimary] (PUT ui/addresses/primary).
 */
interface AddressRepository {

    /** Loads the user's saved addresses (GET ui/addresses returns a bare AddressOut array). */
    suspend fun listAddresses(): ApiResult<List<Address>>

    /** Persists a new address (POST ui/addresses, 200 -> AddressOut). Never auto-retried. */
    suspend fun createAddress(draft: AddressDraft): ApiResult<Address>

    /**
     * Marks [addressId] as the primary mailing address (PUT ui/addresses/primary). This is the only
     * backend-supported "apply to order" today; the payment step reads the primary address.
     */
    suspend fun setPrimary(addressId: String): ApiResult<Address>
}

@Singleton
class AddressRepositoryImpl @Inject constructor(
    private val api: AddressApi,
    private val errorParser: ApiErrorParser,
) : AddressRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun listAddresses(): ApiResult<List<Address>> = withContext(io) {
        call { api.listAddresses() }.map { dtos -> dtos.map { it.toDomain() } }
    }

    override suspend fun createAddress(draft: AddressDraft): ApiResult<Address> = withContext(io) {
        call { api.createAddress(draft.toRequest()) }.map { it.toDomain() }
    }

    override suspend fun setPrimary(addressId: String): ApiResult<Address> = withContext(io) {
        call { api.setPrimaryAddress(AddressPrimaryReqDto(addressId = addressId)) }.map { it.toDomain() }
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
