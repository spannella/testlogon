package com.testlogon.android.feature.syndicates.management

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.syndicates.BundlePlanCreateIn
import com.testlogon.android.core.network.syndicates.BundlePlanUpdateIn
import com.testlogon.android.core.network.syndicates.BundleSubscribeIn
import com.testlogon.android.core.network.syndicates.SyndicateInviteIn
import com.testlogon.android.core.network.syndicates.SyndicateInviteRespondIn
import com.testlogon.android.core.network.syndicates.SyndicateJoinRequestIn
import com.testlogon.android.core.network.syndicates.SyndicateManagementApi
import com.testlogon.android.core.network.syndicates.SyndicateTransferAdminIn
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
 * Data layer for the syndicate MANAGEMENT surface (invites / join-requests / bundle plans / subscribe /
 * transfer-admin / audit), over [SyndicateManagementApi]. Every call folds into [ApiResult] via [call],
 * mapping RAW DTOs to the feature domain. Mirrors MyBundlesRepository / SyndicateRepositoryImpl.
 *
 * Degrade-on-404: reads are honest-empty on failure at the ViewModel boundary; mutations surface the error.
 */
interface SyndicateManagementRepository {

    // Invites
    suspend fun listMyInvites(): ApiResult<List<SyndicateInvite>>
    suspend fun invite(syndicateId: String, userId: String): ApiResult<SyndicateInvite>
    suspend fun respondToInvite(syndicateId: String, accept: Boolean): ApiResult<String>

    // Join requests
    suspend fun requestToJoin(syndicateId: String, message: String): ApiResult<JoinRequest>
    suspend fun listRequests(syndicateId: String): ApiResult<List<JoinRequest>>
    suspend fun approveRequest(syndicateId: String, userId: String): ApiResult<Boolean>
    suspend fun rejectRequest(syndicateId: String, userId: String): ApiResult<Boolean>

    // Admin transfer / remove
    suspend fun transferAdmin(syndicateId: String, newAdminUserId: String): ApiResult<String>
    suspend fun removeMember(syndicateId: String, userId: String): ApiResult<Boolean>

    // Audit
    suspend fun getAudit(syndicateId: String, limit: Int = 50): ApiResult<List<SyndicateAuditEntry>>

    // Bundle plans
    suspend fun listPlans(syndicateId: String): ApiResult<List<BundlePlan>>
    suspend fun createPlan(
        syndicateId: String,
        name: String,
        description: String,
        priceCents: Int,
        interval: String,
    ): ApiResult<BundlePlan>
    suspend fun updatePlan(
        syndicateId: String,
        planId: String,
        name: String?,
        description: String?,
        priceCents: Int?,
    ): ApiResult<BundlePlan>
    suspend fun archivePlan(syndicateId: String, planId: String): ApiResult<String>
    suspend fun subscribeToPlan(
        syndicateId: String,
        planId: String,
        paymentMethodId: String?,
    ): ApiResult<SubscribeResult>
}

@Singleton
class DefaultSyndicateManagementRepository @Inject constructor(
    private val api: SyndicateManagementApi,
    private val errorParser: ApiErrorParser,
) : SyndicateManagementRepository {

    override suspend fun listMyInvites(): ApiResult<List<SyndicateInvite>> = io {
        call { api.listMyInvites().map { it.toDomain() } }
    }

    override suspend fun invite(syndicateId: String, userId: String): ApiResult<SyndicateInvite> = io {
        call { api.invite(syndicateId, SyndicateInviteIn(userId = userId)).toDomain() }
    }

    override suspend fun respondToInvite(syndicateId: String, accept: Boolean): ApiResult<String> = io {
        call {
            api.respondToInvite(syndicateId, SyndicateInviteRespondIn(accept = accept)).status
                ?: if (accept) "accepted" else "declined"
        }
    }

    override suspend fun requestToJoin(syndicateId: String, message: String): ApiResult<JoinRequest> = io {
        call { api.requestToJoin(syndicateId, SyndicateJoinRequestIn(message = message)).toDomain() }
    }

    override suspend fun listRequests(syndicateId: String): ApiResult<List<JoinRequest>> = io {
        call { api.listRequests(syndicateId).map { it.toDomain() } }
    }

    override suspend fun approveRequest(syndicateId: String, userId: String): ApiResult<Boolean> = io {
        call { api.approveRequest(syndicateId, userId).ok ?: true }
    }

    override suspend fun rejectRequest(syndicateId: String, userId: String): ApiResult<Boolean> = io {
        call { api.rejectRequest(syndicateId, userId).ok ?: true }
    }

    override suspend fun transferAdmin(syndicateId: String, newAdminUserId: String): ApiResult<String> = io {
        call {
            api.transferAdmin(syndicateId, SyndicateTransferAdminIn(newAdminUserId = newAdminUserId))
                .adminUserId ?: newAdminUserId
        }
    }

    override suspend fun removeMember(syndicateId: String, userId: String): ApiResult<Boolean> = io {
        call { api.removeMember(syndicateId, userId).ok ?: true }
    }

    override suspend fun getAudit(syndicateId: String, limit: Int): ApiResult<List<SyndicateAuditEntry>> = io {
        call { api.getAudit(syndicateId, limit).map { it.toDomain() } }
    }

    override suspend fun listPlans(syndicateId: String): ApiResult<List<BundlePlan>> = io {
        call { api.listPlans(syndicateId).map { it.toDomain() } }
    }

    override suspend fun createPlan(
        syndicateId: String,
        name: String,
        description: String,
        priceCents: Int,
        interval: String,
    ): ApiResult<BundlePlan> = io {
        call {
            api.createPlan(
                syndicateId,
                BundlePlanCreateIn(
                    name = name,
                    description = description,
                    priceCents = priceCents,
                    interval = interval,
                ),
            ).toDomain()
        }
    }

    override suspend fun updatePlan(
        syndicateId: String,
        planId: String,
        name: String?,
        description: String?,
        priceCents: Int?,
    ): ApiResult<BundlePlan> = io {
        call {
            api.updatePlan(
                syndicateId,
                planId,
                BundlePlanUpdateIn(name = name, description = description, priceCents = priceCents),
            ).toDomain()
        }
    }

    override suspend fun archivePlan(syndicateId: String, planId: String): ApiResult<String> = io {
        call { api.archivePlan(syndicateId, planId).toStatus() }
    }

    override suspend fun subscribeToPlan(
        syndicateId: String,
        planId: String,
        paymentMethodId: String?,
    ): ApiResult<SubscribeResult> = io {
        call {
            api.subscribeToPlan(
                syndicateId,
                planId,
                BundleSubscribeIn(paymentMethodId = paymentMethodId),
            ).toSubscribeResult()
        }
    }

    private suspend fun <T> io(block: suspend () -> ApiResult<T>): ApiResult<T> =
        withContext(Dispatchers.IO) { block() }

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

/** Hilt wiring for the syndicate-management feature. */
@Module
@InstallIn(SingletonComponent::class)
abstract class SyndicateManagementDataModule {

    @Binds
    @Singleton
    abstract fun bindSyndicateManagementRepository(
        impl: DefaultSyndicateManagementRepository,
    ): SyndicateManagementRepository
}
