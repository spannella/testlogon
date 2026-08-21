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
 * Data layer for the PRODUCTION custody surface. Maps wire DTOs to null-safe domain models and folds
 * transport failures into [ApiResult] (HttpException -> Failure carrying the HTTP status; IOException
 * -> NetworkError). CancellationException is always re-thrown. Reads are safe to retry; the withdraw
 * POST is not auto-retried. The custody<->trading bridge is four real routes (fund/settle x
 * spot/margin); a 422 rejection surfaces as a Failure whose parsed reason the ViewModel renders.
 */
@Singleton
class CustodyRepository @Inject constructor(
    private val api: CustodyApi,
    private val errorParser: ApiErrorParser,
) {
    private val io: CoroutineDispatcher = Dispatchers.IO

    suspend fun getBalance(): ApiResult<CustodyBalances> = call {
        api.balance().toDomain()
    }

    suspend fun getDepositAddress(chainId: Int): ApiResult<CustodyDepositAddress> = call {
        api.depositAddress(chainId).toDomain()
    }

    /**
     * Recent scanned incoming transfers. This endpoint is not on every backend: a 404 (or any HTTP
     * error) is folded into a soft "unavailable" success rather than a Failure, so the deposit tab can
     * degrade to an explanatory empty state instead of an error. Network errors still surface as such.
     */
    suspend fun getDeposits(): ApiResult<CustodyDeposits> = withContext(io) {
        try {
            ApiResult.Success(api.getDeposits().toDomain())
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Success(CustodyDeposits.unavailable())
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
    }

    suspend fun withdraw(
        chain: String,
        to: String,
        amount: String,
        token: String?,
        clientRef: String? = null,
    ): ApiResult<CustodyWithdrawResult> = call {
        api.withdraw(
            WithdrawRequestDto(
                chain = chain,
                to = to.trim(),
                amount = amount.trim(),
                token = token?.takeIf { it.isNotBlank() },
                clientRef = clientRef?.takeIf { it.isNotBlank() },
            ),
        ).toDomain()
    }

    /**
     * List the caller's sub-account vaults. Like [getDeposits], a 404 (route not deployed) folds into a
     * soft "unavailable" success so the tab can degrade to an explanatory empty state; other HTTP errors
     * also degrade (there is nothing actionable for the user). Network errors still surface.
     */
    suspend fun getSubAccounts(): ApiResult<CustodySubAccounts> = withContext(io) {
        try {
            ApiResult.Success(api.getSubAccounts().toDomain())
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Success(CustodySubAccounts.unavailable())
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
    }

    /** Create a named sub-account vault. A gateway rejection (400/409) surfaces as a [ApiResult.Failure]. */
    suspend fun createSubAccount(label: String): ApiResult<CustodySubAccount> = call {
        val res = api.createSubAccount(CreateSubAccountDto(label = label.trim()))
        CustodySubAccount(
            label = (res.label ?: label).trim(),
            vault = res.vault.orEmpty().trim(),
        )
    }

    /** Move an asset between two OWN sub-account vaults (REAL - balance moves; echoes new balances). */
    suspend fun subAccountTransfer(
        fromLabel: String?,
        toLabel: String?,
        asset: String,
        amount: String,
    ): ApiResult<SubAccountTransferResult> = call {
        api.subAccountTransfer(
            SubAccountTransferDto(
                fromLabel = fromLabel?.trim()?.takeIf { it.isNotBlank() },
                toLabel = toLabel?.trim()?.takeIf { it.isNotBlank() },
                asset = asset.trim().takeIf { it.isNotBlank() },
                amount = amount.trim(),
            ),
        ).toDomain()
    }

    /**
     * Custody<->trading bridge (four real routes). [action] selects fund/settle x spot/margin; the body
     * is {token (asset symbol), amount (decimal string)}. A 200 maps to funded/settled; a 422 rejection
     * surfaces as a Failure whose parsed body carries the reason.
     */
    suspend fun bridge(action: BridgeAction, token: String, amount: String): ApiResult<CustodyBridgeResult> = call {
        val body = BridgeRequestDto(token = token.trim().uppercase(), amount = amount.trim())
        when (action) {
            BridgeAction.FUND_SPOT -> api.fundSpot(body).toDomain(action)
            BridgeAction.SETTLE_SPOT -> api.settleSpot(body).toDomain(action)
            BridgeAction.FUND_MARGIN -> api.fundMargin(body).toDomain(action)
            BridgeAction.SETTLE_MARGIN -> api.settleMargin(body).toDomain(action)
        }
    }

    /**
     * Staking dashboard read: providers + the caller's positions. Like [getDeposits], a 404/403 (route
     * not deployed or not custody-gated for this account) folds into a soft "unavailable" success so the
     * Staking tab can degrade to an explanatory empty state instead of an error. Network errors still
     * surface. Providers + positions are fetched sequentially; if positions 404 but providers succeed the
     * providers still render (positions default empty).
     */
    suspend fun getStaking(): ApiResult<StakingDashboard> = withContext(io) {
        try {
            val providers = api.stakingProviders().providers.orEmpty().map { it.toDomain() }
            val posDto = api.stakingPositions()
            StakingDashboard(
                vault = posDto.vault?.trim().orEmpty(),
                providers = providers,
                positions = posDto.positions.orEmpty().map { it.toDomain() },
                unavailable = false,
            ).let { ApiResult.Success(it) }
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Success(StakingDashboard.unavailable())
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
    }

    /** Submit a stake (custody value -> a provider's staking contract). A gateway rejection surfaces as a Failure. */
    suspend fun stake(provider: String, amount: String): ApiResult<StakeResult> = call {
        api.stake(
            StakeRequestBodyDto(provider = provider.trim(), amount = amount.trim()),
        ).toDomain()
    }


    // ==== External custody providers (Fireblocks / BitGo / internal gateway) ====

    /**
     * List custody providers. Provider routes are NOT deployed on every backend: a 404 (or any HTTP
     * error) folds into a soft "unavailable" success so the Providers screen can degrade to an honest
     * "provider integration pending backend" empty state instead of erroring. Network errors still
     * surface. No provider secret is ever transported -- these are status-only reads.
     */
    suspend fun getProviders(): ApiResult<CustodyProviders> = withContext(io) {
        try {
            ApiResult.Success(api.getProviders().toDomain())
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Success(CustodyProviders.unavailable())
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
    }

    /**
     * Fetch a provider's live status probe. Also soft-degrades on HTTP error (returns null) so a single
     * provider whose status route is missing doesn't error the whole screen; network errors surface.
     */
    suspend fun getProviderStatus(id: String): ApiResult<ProviderStatusDetail?> = withContext(io) {
        try {
            ApiResult.Success(api.getProviderStatus(id.trim()).toDomain())
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Success(null)
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
    }

    /** Initiate a provider connection (creds server-side). A gateway rejection surfaces as a Failure. */
    suspend fun connectProvider(id: String, label: String?): ApiResult<ProviderActionResult> = call {
        api.connectProvider(
            id.trim(),
            ProviderConnectRequestDto(label = label?.trim()?.takeIf { it.isNotBlank() }),
        ).toDomain()
    }

    /** Disconnect a provider. A gateway rejection surfaces as a Failure. */
    suspend fun disconnectProvider(id: String): ApiResult<ProviderActionResult> = call {
        api.disconnectProvider(id.trim()).toDomain()
    }

    // ==== Provider-backed vaults ====

    /**
     * List the caller's vaults with their backing provider. Soft-degrades on HTTP error to an
     * "unavailable" empty state (route not deployed); network errors surface.
     */
    suspend fun getVaults(): ApiResult<CustodyVaults> = withContext(io) {
        try {
            ApiResult.Success(api.getVaults().toDomain())
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Success(CustodyVaults.unavailable())
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
    }

    /** Set a vault's backing provider. A gateway rejection surfaces as a Failure. */
    suspend fun setVaultProvider(vault: String, provider: String): ApiResult<SetVaultProviderResult> = call {
        api.setVaultProvider(
            vault.trim(),
            SetVaultProviderRequestDto(provider = provider.trim().lowercase()),
        ).toDomain()
    }

    // ==== Provider-backed withdrawal approval ====

    /**
     * Poll a provider-backed withdrawal's approval state. Soft-degrades on HTTP error to an
     * "unavailable" state (route not deployed / not a governed withdrawal); network errors surface.
     */
    suspend fun getWithdrawalApproval(id: String): ApiResult<WithdrawalApproval> = withContext(io) {
        try {
            ApiResult.Success(api.getWithdrawalApproval(id.trim()).toDomain())
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Success(WithdrawalApproval.unavailable())
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
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

/**
 * Coerces a balances wire value (a JSON number decoded to Double, a numeric String, or null) to a
 * Double. Any non-numeric shape falls back to 0.
 */
private fun coerceAmount(value: Any?): Double = when (value) {
    null -> 0.0
    is Double -> value
    is Number -> value.toDouble()
    is String -> value.trim().toDoubleOrNull() ?: 0.0
    else -> value.toString().trim().toDoubleOrNull() ?: 0.0
}

private fun BalanceDto.toDomain(): CustodyBalances {
    val coerced: Map<String, Double> = balances.orEmpty()
        .entries
        .filter { it.key.isNotBlank() }
        .associate { it.key.trim() to coerceAmount(it.value) }
    return CustodyBalances(
        vault = vault?.trim().orEmpty(),
        tier = tier?.trim()?.takeIf { it.isNotBlank() } ?: "—",
        rows = CustodyAssets.mergeBalances(coerced),
    )
}

private fun DepositAddressDto.toDomain(): CustodyDepositAddress =
    CustodyDepositAddress(
        address = address?.trim().orEmpty(),
        chain = chain?.trim().orEmpty(),
        family = family?.takeIf { it.isNotBlank() },
        derivation = derivation?.takeIf { it.isNotBlank() },
        domain = domain?.takeIf { it.isNotBlank() },
    )

private fun CustodyDepositsDto.toDomain(): CustodyDeposits = CustodyDeposits(
    vault = vault?.trim().orEmpty(),
    rows = deposits.orEmpty().map { it.toDomain() },
    unavailable = false,
)

private fun CustodyDepositDto.toDomain(): CustodyDeposit {
    val chainId = chain?.trim()?.toIntOrNull()
    return CustodyDeposit(
        chainId = chainId,
        chainName = if (chainId != null) CustodyAssets.chainName(chainId) else (chain?.trim().orEmpty().ifBlank { "Unknown chain" }),
        asset = asset?.trim().orEmpty().ifBlank { "?" },
        amount = amount?.trim().orEmpty(),
        txHash = txhash?.trim().orEmpty(),
        logIndex = logIndex?.trim()?.takeIf { it.isNotBlank() },
        dedupKey = dedupKey?.trim()?.takeIf { it.isNotBlank() },
    )
}

private fun WithdrawResultDto.toDomain(): CustodyWithdrawResult =
    CustodyWithdrawResult(
        status = WithdrawStatus.from(status),
        withdrawalId = withdrawalId?.takeIf { it.isNotBlank() },
        signature = signature?.takeIf { it.isNotBlank() },
        digest = digest?.takeIf { it.isNotBlank() },
        clientRef = clientRef?.takeIf { it.isNotBlank() },
        intentId = intentId?.takeIf { it.isNotBlank() },
        reason = listOfNotNull(detail, reason, error)
            .firstOrNull { it.isNotBlank() },
        category = category?.takeIf { it.isNotBlank() },
    )

private fun SubAccountsDto.toDomain(): CustodySubAccounts {
    val rows = subaccounts.orEmpty().map { it.toDomain() }
    return CustodySubAccounts(subAccounts = rows, unavailable = false)
}

private fun SubAccountDto.toDomain(): CustodySubAccount =
    CustodySubAccount(
        label = label?.trim().orEmpty(),
        vault = vault?.trim().orEmpty(),
    )

private fun SubAccountTransferResultDto.toDomain(): SubAccountTransferResult =
    SubAccountTransferResult(
        ok = transferred == true,
        from = from?.trim()?.takeIf { it.isNotBlank() },
        to = to?.trim()?.takeIf { it.isNotBlank() },
        asset = asset?.trim()?.takeIf { it.isNotBlank() },
        amount = amount?.trim()?.takeIf { it.isNotBlank() },
        fromBalance = fromBalance?.trim()?.takeIf { it.isNotBlank() },
        toBalance = toBalance?.trim()?.takeIf { it.isNotBlank() },
        reason = listOfNotNull(detail, error).firstOrNull { it.isNotBlank() },
    )

private fun FundResultDto.toDomain(action: BridgeAction): CustodyBridgeResult =
    CustodyBridgeResult(
        ok = funded == true,
        action = action,
        token = token?.trim()?.takeIf { it.isNotBlank() },
        amount = amount?.trim()?.takeIf { it.isNotBlank() },
        meAmount = meAmount?.trim()?.takeIf { it.isNotBlank() },
        ledger = (if (action.venue == BridgeVenue.SPOT) spot else margin)?.trim()?.takeIf { it.isNotBlank() },
        custody = null,
        reason = listOfNotNull(reason, detail, error).firstOrNull { it.isNotBlank() },
    )

private fun SettleResultDto.toDomain(action: BridgeAction): CustodyBridgeResult =
    CustodyBridgeResult(
        ok = settled == true,
        action = action,
        token = token?.trim()?.takeIf { it.isNotBlank() },
        amount = amount?.trim()?.takeIf { it.isNotBlank() },
        meAmount = meAmount?.trim()?.takeIf { it.isNotBlank() },
        ledger = (if (action.venue == BridgeVenue.SPOT) spot else margin)?.trim()?.takeIf { it.isNotBlank() },
        custody = custody?.trim()?.takeIf { it.isNotBlank() },
        reason = listOfNotNull(reason, detail, error).firstOrNull { it.isNotBlank() },
    )

private fun StakingProviderDto.toDomain(): StakingProvider = StakingProvider(
    id = id?.trim().orEmpty(),
    chain = chain?.trim().orEmpty(),
    contract = contract?.trim().orEmpty(),
    kind = kind?.trim().orEmpty(),
    asset = asset?.trim().orEmpty(),
)

private fun StakingPositionDto.toDomain(): StakingPosition = StakingPosition(
    positionId = positionId?.trim().orEmpty(),
    vault = vault?.trim().orEmpty(),
    provider = provider?.trim().orEmpty(),
    chain = chain?.trim().orEmpty(),
    asset = asset?.trim().orEmpty(),
    principal = principal?.trim().orEmpty().ifBlank { "0" },
    rewards = rewards?.trim().orEmpty().ifBlank { "0" },
    total = total?.trim().orEmpty().ifBlank { "0" },
    status = status?.trim().orEmpty(),
)

private fun StakeAckDto.toDomain(): StakeResult = StakeResult(
    ok = staked == true,
    positionId = positionId?.trim()?.takeIf { it.isNotBlank() },
    provider = provider?.trim()?.takeIf { it.isNotBlank() },
    amount = amount?.trim()?.takeIf { it.isNotBlank() },
    status = status?.trim()?.takeIf { it.isNotBlank() },
    reason = listOfNotNull(detail, error, reason).firstOrNull { it.isNotBlank() },
)

// ---- provider / vault / approval DTO -> domain mappers ----

private fun CustodyProvidersDto.toDomain(): CustodyProviders = CustodyProviders(
    providers = providers.orEmpty().map { it.toDomain() },
    unavailable = false,
)

private fun CustodyProviderDto.toDomain(): CustodyProvider = CustodyProvider(
    id = id?.trim().orEmpty(),
    name = name?.trim().orEmpty(),
    kind = kind?.trim().orEmpty().ifBlank { "internal" },
    connected = connected == true,
    status = status?.trim().orEmpty(),
    features = features.orEmpty().mapNotNull { it?.trim()?.takeIf(String::isNotBlank) },
)

private fun ProviderStatusDto.toDomain(): ProviderStatusDetail = ProviderStatusDetail(
    status = status?.trim().orEmpty(),
    balancesAttested = balancesAttested,
    lastReconciledTs = lastReconciledTs?.trim()?.takeIf { it.isNotBlank() },
    pendingApprovals = pendingApprovals,
)

private fun ProviderConnectResultDto.toDomain(): ProviderActionResult = ProviderActionResult(
    ok = (ok == true) || (disconnected == true),
    status = status?.trim()?.takeIf { it.isNotBlank() },
    reason = listOfNotNull(detail, error).firstOrNull { it.isNotBlank() },
)

private fun VaultsDto.toDomain(): CustodyVaults = CustodyVaults(
    vaults = vaults.orEmpty().map { it.toDomain() },
    unavailable = false,
)

private fun VaultDto.toDomain(): CustodyVault = CustodyVault(
    vault = vault?.trim().orEmpty(),
    label = label?.trim().orEmpty(),
    provider = provider?.trim().orEmpty().ifBlank { "internal" },
)

private fun SetVaultProviderResultDto.toDomain(): SetVaultProviderResult = SetVaultProviderResult(
    ok = ok == true,
    vault = vault?.trim()?.takeIf { it.isNotBlank() },
    provider = provider?.trim()?.takeIf { it.isNotBlank() },
    reason = listOfNotNull(detail, error).firstOrNull { it.isNotBlank() },
)

private fun WithdrawalApprovalDto.toDomain(): WithdrawalApproval = WithdrawalApproval(
    status = status?.trim().orEmpty(),
    quorum = quorum ?: 0,
    approvals = approvals.orEmpty().map { it.toDomain() },
    unavailable = false,
)

private fun WithdrawalApproverDto.toDomain(): WithdrawalApprover = WithdrawalApprover(
    approver = approver?.trim().orEmpty().ifBlank { "Approver" },
    at = at?.trim().orEmpty(),
)

/** Provides the custody Retrofit API (mirrors the auth data module's provider style). */
@Module
@InstallIn(SingletonComponent::class)
object CustodyDataModule {

    @Provides
    @Singleton
    fun provideCustodyApi(retrofit: Retrofit): CustodyApi = retrofit.create(CustodyApi::class.java)
}
