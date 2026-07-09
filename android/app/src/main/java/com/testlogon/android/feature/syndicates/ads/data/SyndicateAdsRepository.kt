package com.testlogon.android.feature.syndicates.ads.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.ads.AdAccountRef
import com.testlogon.android.core.model.ads.AdAccountSummary
import com.testlogon.android.core.model.ads.SyndicateAdPlacementConfig
import com.testlogon.android.core.network.ads.AdAccountCreateIn
import com.testlogon.android.core.network.ads.SyndicateAdAccountDto
import com.testlogon.android.core.network.ads.SyndicateAdPlacementConfigDto
import com.testlogon.android.core.network.ads.SyndicateAdPlacementConfigIn
import com.testlogon.android.core.network.ads.SyndicateAdsApi
import com.testlogon.android.core.network.error.ApiErrorParser
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
 * ADV2-709/710/711 (F7) — data layer for SYNDICATE ad management over the [SyndicateAdsApi]. Creates + lists
 * a syndicate-owned ad account and reads/writes the per-syndicate placement split config. Campaign / creative
 * / deposit / analytics for the syndicate account REUSE the existing owner-scoped ads flow (AdsCreateRepository
 * / AdsBilling / AdAnalytics) once the created account id is set as the AdsStudioSelection — this repo only
 * covers the two syndicate-scoped surfaces those can't express.
 *
 * Each call maps the raw DTO to core-model BEFORE folding into the typed [ApiResult] (mirrors
 * AdsCreateRepository). The create + config-set writes are NON-idempotent, so neither this repo nor its VMs
 * auto-retry them. A 403 (a non-admin caller) surfaces as Failure(status=403) for the VM to message.
 */
interface SyndicateAdsRepository {

    /** ADV2-709 — create a syndicate-owned ad account (returns the new id + pending_review status). */
    suspend fun createAccount(
        syndicateId: String,
        companyName: String,
        billingEmail: String,
    ): ApiResult<AdAccountRef>

    /** ADV2-709 — list the syndicate's ad accounts (mapped to the shared [AdAccountSummary] rows). */
    suspend fun listAccounts(syndicateId: String): ApiResult<List<AdAccountSummary>>

    /** ADV2-710 — read the per-syndicate ad-placement split config. */
    suspend fun getPlacementConfig(syndicateId: String): ApiResult<SyndicateAdPlacementConfig>

    /** ADV2-710 — set the member's share (bps) of the 70% content-owner split; returns the updated config. */
    suspend fun setMemberShareBps(
        syndicateId: String,
        memberShareBps: Int,
    ): ApiResult<SyndicateAdPlacementConfig>
}

@Singleton
class SyndicateAdsRepositoryImpl @Inject constructor(
    private val api: SyndicateAdsApi,
    private val errorParser: ApiErrorParser,
) : SyndicateAdsRepository {

    override suspend fun createAccount(
        syndicateId: String,
        companyName: String,
        billingEmail: String,
    ): ApiResult<AdAccountRef> = withContext(Dispatchers.IO) {
        call { api.createSyndicateAdAccount(syndicateId, AdAccountCreateIn(companyName, billingEmail)).toRef() }
    }

    override suspend fun listAccounts(syndicateId: String): ApiResult<List<AdAccountSummary>> =
        withContext(Dispatchers.IO) {
            call { api.listSyndicateAdAccounts(syndicateId).map { it.toSummary() } }
        }

    override suspend fun getPlacementConfig(syndicateId: String): ApiResult<SyndicateAdPlacementConfig> =
        withContext(Dispatchers.IO) {
            call { api.getSyndicateAdPlacementConfig(syndicateId).toDomain(syndicateId) }
        }

    override suspend fun setMemberShareBps(
        syndicateId: String,
        memberShareBps: Int,
    ): ApiResult<SyndicateAdPlacementConfig> = withContext(Dispatchers.IO) {
        call {
            api.setSyndicateAdPlacementConfig(
                syndicateId, SyndicateAdPlacementConfigIn(memberShareBps),
            ).toDomain(syndicateId)
        }
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

/** ADV2-709 — create/list account DTO -> the shared advertiser domain types. */
private fun SyndicateAdAccountDto.toRef(): AdAccountRef =
    AdAccountRef(accountId = accountId, companyName = companyName, status = status)

private fun SyndicateAdAccountDto.toSummary(): AdAccountSummary = AdAccountSummary(
    accountId = accountId,
    companyName = companyName,
    status = status,
    balanceCents = balanceCents ?: 0L,
    lifetimeSpendCents = lifetimeSpendCents ?: 0L,
)

/** ADV2-710 — config DTO -> domain. treasury/default default sensibly when the server omits them. */
private fun SyndicateAdPlacementConfigDto.toDomain(syndicateId: String): SyndicateAdPlacementConfig {
    val member = memberShareBps
    return SyndicateAdPlacementConfig(
        syndicateId = this.syndicateId ?: syndicateId,
        memberShareBps = member,
        treasuryShareBps = treasuryShareBps ?: (10000 - member),
        defaultMemberShareBps = defaultMemberShareBps ?: 7000,
    )
}

/** ADV2-709 — Hilt wiring: binds the syndicate-ads repository seam to its default impl. */
@Module
@InstallIn(SingletonComponent::class)
abstract class SyndicateAdsDataModule {

    @Binds
    @Singleton
    abstract fun bindSyndicateAdsRepository(impl: SyndicateAdsRepositoryImpl): SyndicateAdsRepository
}
