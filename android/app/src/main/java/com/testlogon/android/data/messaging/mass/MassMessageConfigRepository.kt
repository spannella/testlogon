package com.testlogon.android.data.messaging.mass

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.MessagingApi
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-160 — reads the mass-send capability flag (FR-8 gate).
 *
 * The authoritative client-side gate is `messaging_mass_send_enabled` from GET /messaging/config
 * (MessagingConfigOut). Reuses the EXISTING [MessagingApi.config] (no new endpoint, no FakeApi change)
 * but is a thin dedicated repo so the mass feature does not depend on the large MessagingRepository.
 * Authorization is always enforced server-side; this is UX-only gating.
 */
interface MassMessageConfigRepository {
    /** True when the mass-send feature is enabled for the user; defaults to false (fail-closed) on error. */
    suspend fun isMassSendEnabled(): Boolean
}

@Singleton
class MassMessageConfigRepositoryImpl @Inject constructor(
    private val api: MessagingApi,
) : MassMessageConfigRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun isMassSendEnabled(): Boolean = withContext(io) {
        when (val r = call { api.config().massSendEnabled }) {
            is ApiResult.Success -> r.data
            else -> false
        }
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: IOException) {
        ApiResult.NetworkError(e)
    } catch (e: Exception) {
        ApiResult.NetworkError(e)
    }
}
