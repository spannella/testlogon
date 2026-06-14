package com.testlogon.android.data.broadcast.shelf

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
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
import retrofit2.Response
import retrofit2.Retrofit
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-283 — products shelf data layer. A single idempotent GET that maps the BroadcastShelfListOut
 * envelope's `items` to domain [ShelfProduct]s (ordered by display_order). No mutation here (the Buy
 * hand-off only navigates). No Room cache is added in this slice — the shelf is fetched lazily on open.
 */
interface ShelfRepository {
    suspend fun getSessionProducts(sessionId: String): ApiResult<List<ShelfProduct>>
}

@Singleton
class ShelfRepositoryImpl @Inject constructor(
    private val api: BroadcastShelfApi,
    private val errorParser: ApiErrorParser,
) : ShelfRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun getSessionProducts(sessionId: String): ApiResult<List<ShelfProduct>> =
        withContext(io) {
            when (val result = call { api.getSessionProducts(sessionId) }) {
                is ApiResult.Success -> ApiResult.Success(result.data?.toDomain() ?: emptyList())
                is ApiResult.Failure -> result
                is ApiResult.NetworkError -> result
            }
        }

    private suspend fun <T> call(block: suspend () -> Response<T>): ApiResult<T?> = try {
        val response = block()
        if (response.isSuccessful) {
            ApiResult.Success(response.body())
        } else {
            ApiResult.Failure(errorParser.from(HttpException(response)))
        }
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

/** AND-283 — provides [BroadcastShelfApi] + binds the repository. */
@Module
@InstallIn(SingletonComponent::class)
object BroadcastShelfApiModule {

    @Provides
    @Singleton
    fun provideBroadcastShelfApi(retrofit: Retrofit): BroadcastShelfApi =
        retrofit.create(BroadcastShelfApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class BroadcastShelfDataModule {

    @Binds
    @Singleton
    abstract fun bindShelfRepository(impl: ShelfRepositoryImpl): ShelfRepository
}
