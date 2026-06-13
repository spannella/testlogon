package com.testlogon.android.feature.delegates.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.data.delegates.DelegationStateStore
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.delegates.ManagedCreator
import com.testlogon.android.core.model.delegates.ManagingCreator
import com.testlogon.android.core.network.delegates.DelegatesApi
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-359 - data layer for the delegate / delegation surface (manage-as-creator mode).
 *
 * PLACEMENT: this repository lives in the app feature layer (like the AND-353 OrgsRepository), NOT in
 * core-data, because it needs Retrofit (HttpException) and the shared [ApiErrorParser], neither of which
 * is on core-data's compile classpath (adding them would be a new dependency, which this ticket forbids).
 * The PARALLEL local-state holder it drives ([DelegationStateStore]) DOES live in core-data so the
 * managing-creator flag is process-global.
 *
 * CRITICAL: enter / exit are PURE LOCAL mutations of the [DelegationStateStore] - they do NO network
 * round-trip (mirrors the web authStore.setManagingCreator). The ONLY network call is
 * [managedCreators] -> GET ui/delegates/managed. There is NO X-Manage-As header; path-scoping is the
 * [activeCreatorId] seam only.
 */
interface DelegationRepository {

    /**
     * The active manage-as-creator selection, re-exposed from the [DelegationStateStore] (process-global,
     * observable). Null when the principal acts as themselves.
     */
    val managingCreator: StateFlow<ManagingCreator?>

    /** GET the creators the caller MAY manage (mapped). Idempotent GET - the ONLY network call here. */
    suspend fun managedCreators(): ApiResult<List<ManagedCreator>>

    /**
     * ENTER (or switch) manage-as mode. PURE LOCAL: writes [managingCreator] and returns
     * Success(ManagingCreator) WITHOUT any network call (asserted in tests). [permissions] defaults empty.
     */
    suspend fun enter(
        creatorId: String,
        label: String?,
        permissions: List<String> = emptyList(),
    ): ApiResult<ManagingCreator>

    /** EXIT manage-as mode. PURE LOCAL: clears [managingCreator]; can not fail -> always Success(Unit). */
    suspend fun exit(): ApiResult<Unit>

    /**
     * The path-scoping SEAM: the active creator id, or null when acting as oneself. Downstream features
     * build ui/.../delegate/{creatorId}/... from this. This ticket owns ONLY this seam; it does NOT
     * rewrite every feature's traffic and adds NO header.
     */
    fun activeCreatorId(): String?
}

@Singleton
class DelegationRepositoryImpl @Inject constructor(
    private val delegatesApi: DelegatesApi,
    private val delegationStateStore: DelegationStateStore,
    private val errorParser: ApiErrorParser,
) : DelegationRepository {

    override val managingCreator: StateFlow<ManagingCreator?> = delegationStateStore.managingCreator

    override suspend fun managedCreators(): ApiResult<List<ManagedCreator>> =
        withContext(Dispatchers.IO) {
            call { delegatesApi.listManagedCreators().map { it.toDomain() } }
        }

    override suspend fun enter(
        creatorId: String,
        label: String?,
        permissions: List<String>,
    ): ApiResult<ManagingCreator> {
        // PURE LOCAL - NO network round-trip (mirrors web authStore.setManagingCreator).
        val managing = ManagingCreator(creatorId = creatorId, label = label, permissions = permissions)
        delegationStateStore.setManagingCreator(managing)
        return ApiResult.Success(managing)
    }

    override suspend fun exit(): ApiResult<Unit> {
        // PURE LOCAL - clearing the flag can not fail.
        delegationStateStore.clear()
        return ApiResult.Success(Unit)
    }

    override fun activeCreatorId(): String? = delegationStateStore.managingCreator.value?.creatorId

    /**
     * Folds a block into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser], preserving the
     * status); malformed JSON -> Failure(parse); transport failures -> NetworkError. The
     * JsonEncodingException catch precedes the IOException catch (it is an IOException subtype).
     * Cancellation is re-thrown. Mirrors AND-353 OrgsRepository.
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
