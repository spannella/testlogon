package com.testlogon.android.data.ordertracking

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.tracking.CarrierTracking
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/** D4 - buyer order-tracking data layer over [OrderTrackingApi]. Read-only GET by ship-group id. */
interface OrderTrackingRepository {
    suspend fun tracking(shipGroupId: String): ApiResult<CarrierTracking>
}

@Singleton
class OrderTrackingRepositoryImpl @Inject constructor(
    private val api: OrderTrackingApi,
    private val errorParser: ApiErrorParser,
) : OrderTrackingRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun tracking(shipGroupId: String): ApiResult<CarrierTracking> = withContext(io) {
        try {
            ApiResult.Success(api.getOrderTracking(shipGroupId).toDomain())
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
}
