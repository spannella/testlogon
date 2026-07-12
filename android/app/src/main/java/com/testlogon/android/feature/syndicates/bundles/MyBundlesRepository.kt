package com.testlogon.android.feature.syndicates.bundles

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.syndicates.SyndicateBundleApi
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Data layer for the "My Bundles" surface (web parity: /syndicates/my-bundles), over [SyndicateBundleApi].
 * list() maps the bare array to domain; cancel() POSTs the cancel and returns the new status. Each call
 * folds into [ApiResult] via [call]. Mirrors SyndicateRepositoryImpl.
 */
interface MyBundlesRepository {

    /** GET the caller's active bundle subscriptions, mapped. Idempotent GET. */
    suspend fun listMyBundles(): ApiResult<List<BundleSubscription>>

    /** POST a cancel for a bundle subscription; returns the resulting status string. */
    suspend fun cancelBundle(syndicateId: String, subscriptionId: String): ApiResult<String>
}

@Singleton
class DefaultMyBundlesRepository @Inject constructor(
    private val api: SyndicateBundleApi,
    private val errorParser: ApiErrorParser,
) : MyBundlesRepository {

    override suspend fun listMyBundles(): ApiResult<List<BundleSubscription>> =
        withContext(Dispatchers.IO) {
            call { api.listMyBundles().map { it.toDomain() } }
        }

    override suspend fun cancelBundle(
        syndicateId: String,
        subscriptionId: String,
    ): ApiResult<String> = withContext(Dispatchers.IO) {
        call { api.cancelBundleSubscription(syndicateId, subscriptionId).status ?: "cancelled" }
    }

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

/** Hilt wiring for the My Bundles feature. */
@Module
@InstallIn(SingletonComponent::class)
abstract class MyBundlesDataModule {

    @Binds
    @Singleton
    abstract fun bindMyBundlesRepository(impl: DefaultMyBundlesRepository): MyBundlesRepository
}
