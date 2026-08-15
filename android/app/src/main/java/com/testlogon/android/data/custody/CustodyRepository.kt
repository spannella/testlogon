package com.testlogon.android.data.custody

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Retrofit
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Data layer for the custody surface. Maps wire DTOs to null-safe domain models and folds transport
 * failures into [ApiResult] (HttpException -> Failure carrying the HTTP status, so the ViewModel can
 * branch on 403 = not-an-officer, 425 = timelock, 409 = under-approved; IOException -> NetworkError).
 * CancellationException is always re-thrown. Reads are safe to retry; the withdrawal POST is not
 * auto-retried.
 */
@Singleton
class CustodyRepository @Inject constructor(
    private val api: CustodyApi,
    private val errorParser: ApiErrorParser,
) {
    private val io: CoroutineDispatcher = Dispatchers.IO

    suspend fun loadAssets(): ApiResult<List<CustodyAsset>> = call {
        api.assets().map { it.toDomain() }
    }

    suspend fun depositAddress(asset: String, chain: String): ApiResult<CustodyDepositAddress> = call {
        api.depositAddress(asset, chain).toDomain(asset, chain)
    }

    suspend fun loadDeposits(): ApiResult<List<CustodyDeposit>> = call {
        api.deposits().map { it.toDomain() }
    }

    suspend fun submitWithdrawal(
        asset: String,
        chain: String,
        amount: String,
        destination: String,
        memo: String?,
    ): ApiResult<CustodyWithdrawalResult> = call {
        api.createWithdrawal(
            CustodyWithdrawalRequestDto(
                asset = asset,
                chain = chain,
                amount = amount,
                destination = destination,
                memo = memo?.takeIf { it.isNotBlank() },
            ),
        ).toDomain()
    }

    suspend fun loadWithdrawals(): ApiResult<List<CustodyWithdrawal>> = call {
        api.withdrawals().map { it.toDomain() }
    }

    suspend fun loadWithdrawal(id: String): ApiResult<CustodyWithdrawal> = call {
        api.withdrawal(id).toDomain()
    }

    suspend fun loadApprovals(): ApiResult<List<CustodyWithdrawal>> = call {
        api.approvals().map { it.toDomain() }
    }

    suspend fun approve(id: String, approver: String?): ApiResult<CustodyApproveResult> = call {
        api.approve(id, CustodyApproveRequestDto(approver = approver?.takeIf { it.isNotBlank() })).toDomain()
    }

    suspend fun release(id: String): ApiResult<CustodyReleaseResult> = call {
        api.release(id).toDomain()
    }

    suspend fun loadAudit(): ApiResult<CustodyAudit> = call {
        val a = api.audit()
        val entries = a.entries.orEmpty().map { it.toDomain() }
        CustodyAudit(entries = entries)
    }

    suspend fun verifyAudit(): ApiResult<CustodyAuditVerifyDto> = call {
        api.auditVerify()
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = withContext(io) {
        try {
            ApiResult.Success(block())
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Failure(errorParser.from(e))
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
    }
}

// ---- DTO -> domain mappers ----

private fun String?.orDash(): String = this?.takeIf { it.isNotBlank() } ?: "—"

private fun parseAmount(s: String?): Double = s?.trim()?.toDoubleOrNull() ?: 0.0

private fun CustodyAssetDto.toDomain(): CustodyAsset {
    val a = asset?.trim().orEmpty()
    return CustodyAsset(
        asset = a,
        chain = chain?.trim().orEmpty(),
        name = name?.takeIf { it.isNotBlank() } ?: (symbol ?: a),
        symbol = symbol?.takeIf { it.isNotBlank() } ?: a,
        decimals = decimals ?: 18,
        network = network?.takeIf { it.isNotBlank() } ?: (chain ?: ""),
        balanceText = balance?.trim()?.takeIf { it.isNotBlank() } ?: "0",
        balance = parseAmount(balance),
        addressAvailable = addressAvailable ?: false,
    )
}

private fun CustodyDepositAddressDto.toDomain(reqAsset: String, reqChain: String): CustodyDepositAddress =
    CustodyDepositAddress(
        asset = asset?.takeIf { it.isNotBlank() } ?: reqAsset,
        chain = chain?.takeIf { it.isNotBlank() } ?: reqChain,
        network = network?.takeIf { it.isNotBlank() } ?: (chain ?: reqChain),
        address = address?.trim().orEmpty(),
        memo = memo?.takeIf { it.isNotBlank() },
    )

private fun CustodyDepositDto.toDomain(): CustodyDeposit =
    CustodyDeposit(
        id = id?.takeIf { it.isNotBlank() } ?: "",
        asset = asset.orDash(),
        chain = chain.orDash(),
        amountText = amount?.trim()?.takeIf { it.isNotBlank() } ?: "0",
        status = status?.takeIf { it.isNotBlank() } ?: "pending",
        confirmations = confirmations ?: 0,
    )

private fun CustodyWithdrawalResultDto.toDomain(): CustodyWithdrawalResult =
    CustodyWithdrawalResult(
        id = id?.takeIf { it.isNotBlank() } ?: "",
        status = WithdrawalStatus.from(status),
        asset = asset.orDash(),
        chain = chain.orDash(),
        amountText = amount?.trim()?.takeIf { it.isNotBlank() } ?: "0",
        destination = destination.orDash(),
        signature = signature?.takeIf { it.isNotBlank() },
        digest = digest?.takeIf { it.isNotBlank() },
        approvalsRequired = approvalsRequired,
        approvals = approvals,
        reason = detail?.takeIf { it.isNotBlank() } ?: error?.takeIf { it.isNotBlank() },
        category = category?.takeIf { it.isNotBlank() },
    )

private fun CustodyWithdrawalDto.toDomain(): CustodyWithdrawal =
    CustodyWithdrawal(
        id = id?.takeIf { it.isNotBlank() } ?: "",
        asset = asset.orDash(),
        chain = (chain ?: chainRef).orDash(),
        network = network?.takeIf { it.isNotBlank() } ?: (chainRef ?: chain ?: ""),
        recipient = (recipient ?: destination).orDash(),
        amountText = amount?.trim()?.takeIf { it.isNotBlank() } ?: "0",
        status = WithdrawalStatus.from(status),
        approvals = approvals.orEmpty(),
        approvalsCount = approvalsCount ?: approvals?.size ?: 0,
        approvalsRequired = approvalsRequired ?: 0,
        signature = signature?.takeIf { it.isNotBlank() },
        digest = digest?.takeIf { it.isNotBlank() },
        reason = error?.takeIf { it.isNotBlank() },
        category = category?.takeIf { it.isNotBlank() },
        timelockUntilMs = timelockUntilMs,
        createdMs = createdMs,
    )

private fun CustodyApproveResultDto.toDomain(): CustodyApproveResult =
    CustodyApproveResult(
        withdrawalId = withdrawalId?.takeIf { it.isNotBlank() } ?: "",
        status = WithdrawalStatus.from(status),
        approvals = approvals.orEmpty(),
        approvalsRequired = approvalsRequired ?: 0,
    )

private fun CustodyReleaseResultDto.toDomain(): CustodyReleaseResult =
    CustodyReleaseResult(
        withdrawalId = withdrawalId?.takeIf { it.isNotBlank() } ?: "",
        status = WithdrawalStatus.from(status),
        signature = signature?.takeIf { it.isNotBlank() },
        digest = digest?.takeIf { it.isNotBlank() },
    )

private fun CustodyAuditEntryDto.toDomain(): CustodyAuditEntry =
    CustodyAuditEntry(
        seq = seq ?: 0L,
        action = action?.takeIf { it.isNotBlank() } ?: "—",
        detail = detail?.takeIf { it.isNotBlank() } ?: "",
        tsMs = tsMs ?: 0L,
        prev = prev.orEmpty(),
        hash = hash.orEmpty(),
    )

/** Provides the custody Retrofit API (mirrors the auth data module's provider style). */
@Module
@InstallIn(SingletonComponent::class)
object CustodyDataModule {

    @Provides
    @Singleton
    fun provideCustodyApi(retrofit: Retrofit): CustodyApi = retrofit.create(CustodyApi::class.java)
}
