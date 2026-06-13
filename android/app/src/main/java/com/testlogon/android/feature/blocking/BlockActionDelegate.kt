package com.testlogon.android.feature.blocking

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.blocking.BlockAction
import com.testlogon.android.core.ui.safety.IrreversibleActionGuard
import com.testlogon.android.data.blocking.BlockingRepository
import javax.inject.Inject

/**
 * AND-388 - the reusable block / unblock interaction unit shared by the profile and messages
 * ViewModels and by [com.testlogon.android.feature.report.ReportViewModel]'s also-block path.
 *
 * AND-382 introduced the block/unblock interaction state inline in
 * [BlockInteractionViewModel]; this delegate relocates the destructive-action interaction into one
 * injectable, testable unit routed through the shared [IrreversibleActionGuard] so the guard is the
 * single choke point for every trust and safety action (spec sec.4.3, AC-2/AC-4). It is purely
 * additive: AND-382's [BlockingRepository] and its models are unchanged.
 *
 * The delegate owns no coroutines and performs no scheduling - the suspend forwarders run on the
 * caller's coroutine (the repository already confines its own I/O to Dispatchers.IO). Re-block /
 * re-unblock are benign at the repository (any 200 -> Success), so this delegate adds no extra
 * conflict handling.
 */
class BlockActionDelegate @Inject constructor(
    private val blockingRepository: BlockingRepository,
) {

    /**
     * The shared guard over the staged [BlockAction]. Profile / messages hosts mirror its [phase]
     * into their UiState; the also-block path issues a direct [block] without the confirm dialog
     * because it follows an already-confirmed report (spec FR-6).
     */
    val guard = IrreversibleActionGuard<BlockAction>()

    /** Stage a block for confirmation (opens the guard's Confirming phase). */
    fun requestBlock(userId: String, reason: String? = null) {
        guard.request(BlockAction.Block(userId, reason))
    }

    /** Stage an unblock for confirmation. */
    fun requestUnblock(userId: String) {
        guard.request(BlockAction.Unblock(userId))
    }

    /** Discard a staged action (Confirming -> Idle); no-op otherwise. */
    fun cancel() = guard.cancel()

    /**
     * Confirm and run the staged action through the guard, returning its result, or null if the
     * confirm was a no-op (not Confirming, or already Submitting - the double-submit guard, FR-4).
     * On a non-null run the guard moves to Submitted on success / Failed otherwise is left to the
     * caller via [onResult] so the host controls the [com.testlogon.android.core.ui.i18n.UiText].
     */
    suspend fun confirm(): ApiResult<Unit>? {
        val action = guard.confirm() ?: return null
        return runAction(action)
    }

    /** Directly block [userId] (no confirm dialog) - used by the post-report also-block path. */
    suspend fun block(userId: String): ApiResult<Unit> = blockingRepository.block(userId)

    /** Directly unblock [userId]. */
    suspend fun unblock(userId: String): ApiResult<Unit> = blockingRepository.unblock(userId)

    private suspend fun runAction(action: BlockAction): ApiResult<Unit> = when (action) {
        is BlockAction.Block -> blockingRepository.block(action.targetUserId)
        is BlockAction.Unblock -> blockingRepository.unblock(action.targetUserId)
    }
}
