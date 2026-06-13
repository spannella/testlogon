package com.testlogon.android.feature.delegates.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.delegates.DelegationContext
import com.testlogon.android.core.model.delegates.DelegatePermission
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException

/**
 * AND-360 - shared support for the delegate-PATH overlay repositories (feed / messaging / broadcast).
 *
 * Each delegate repository action follows the same pipeline:
 *  1. require an ACTIVE delegate context (else a clear "not in delegate mode" Failure);
 *  2. GATE on the required [DelegatePermission] - if absent, return PermissionDenied WITHOUT calling the
 *     API (the action is blocked before any network round-trip);
 *  3. call the delegate API with the active creatorId (attribution = the @Path segment);
 *  4. on an HTTP 403 (revoked / insufficient / disabled), trigger AUTO-EXIT: re-fetch the context and, if
 *     the delegation is gone, exit delegate mode back to self.
 *
 * The [DelegateGuard] wraps 1 + 2 + the call + the ApiResult folding; the 403 auto-exit is layered by the
 * repository via [DelegateAutoExit] so each repository can re-fetch + exit through the shared provider.
 */

/** AND-360 - sentinel ApiError codes the overlay raises locally (no server round-trip). */
internal object DelegateErrors {
    const val CODE_NOT_DELEGATE = "not_in_delegate_mode"
    const val CODE_PERMISSION_DENIED = "delegate_permission_denied"

    /** Not currently acting as a delegate - the action requires an active manage-as context. */
    val NotInDelegateMode = ApiError(
        status = ApiError.STATUS_PARSE,
        message = "You're not managing a creator right now.",
        code = CODE_NOT_DELEGATE,
    )

    /** The active delegate context lacks the permission this action requires (blocked WITHOUT calling). */
    fun permissionDenied(permission: DelegatePermission) = ApiError(
        status = 403,
        message = "You don't have permission to do that for this creator.",
        code = CODE_PERMISSION_DENIED,
        raw = permission.name,
    )
}

/**
 * AND-360 - the guard shared by every delegate repository. Holds the typed-context snapshot accessor + the
 * shared [ApiErrorParser] and folds a gated, path-scoped call into [ApiResult].
 */
internal class DelegateGuard(
    private val context: () -> DelegationContext?,
    private val errorParser: ApiErrorParser,
    private val autoExit: DelegateAutoExit,
) {

    /**
     * Runs [block] with the active creatorId AFTER asserting an active context and the [required]
     * permission. When [required] is absent the API is NOT called (PermissionDenied). On an HTTP 403 the
     * [autoExit] hook re-fetches the context and exits delegate mode if the delegation is gone.
     */
    suspend fun <T> gated(
        required: DelegatePermission,
        block: suspend (creatorId: String) -> T,
    ): ApiResult<T> {
        val ctx = context()
            ?: return ApiResult.Failure(DelegateErrors.NotInDelegateMode)
        if (required !in ctx.permissions) {
            // BLOCKED before any network round-trip.
            return ApiResult.Failure(DelegateErrors.permissionDenied(required))
        }
        val result = call { block(ctx.creatorId) }
        if (result is ApiResult.Failure && result.error.status == 403) {
            autoExit.onForbidden()
        }
        return result
    }

    /**
     * Folds a block into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser], preserving the
     * status); malformed JSON -> Failure(parse); transport failures -> NetworkError. Cancellation is
     * re-thrown. Mirrors the AND-359 DelegationRepository.call.
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

/**
 * AND-360 - the 403 SAFETY hook: on a forbidden delegate response, re-fetch the delegation context and, if
 * the delegation is gone (the creator is no longer in the managed list), AUTO-EXIT delegate mode back to
 * self. Backed by the [DelegationContextProvider] + the AND-359 enter/exit-on-the-repository.
 */
internal class DelegateAutoExit(
    private val contextProvider: DelegationContextProvider,
    private val delegationRepository: DelegationRepository,
) {

    /**
     * Re-fetch managedCreators; if the active creator is no longer present (revoked / disabled), exit
     * delegate mode. A network / fetch failure is treated conservatively as "still managing" (no exit) so
     * a transient blip does not eject the delegate.
     */
    suspend fun onForbidden() {
        val creatorId = delegationRepository.activeCreatorId() ?: return
        when (val managed = delegationRepository.managedCreators()) {
            is ApiResult.Success -> {
                val stillManaged = managed.data.any {
                    it.creatorId == creatorId && it.status == "active"
                }
                if (!stillManaged) delegationRepository.exit()
            }
            // Conservative: a transient fetch failure does NOT auto-exit (avoid ejecting on a blip).
            is ApiResult.Failure -> Unit
            is ApiResult.NetworkError -> Unit
        }
    }
}
