package com.testlogon.android.feature.signing.packetlist

import com.testlogon.android.core.model.ApiError

/**
 * SUX-008 — PURE presentation logic for the signing INBOX. No I/O, no Android; JVM-testable.
 *
 * The inbox is assembled from up to four independent endpoint loads (awaiting / sent / completed / drafts).
 * Any subset may 404 (the whole feature is flag-gated server-side: SIGNATURE_PACKETS-off -> 404). The rules
 * here express the DEGRADE-ON-404 contract: a 404 (or any failure) on one bucket drops THAT bucket only; the
 * surface still renders from whatever buckets loaded. The screen shows [SigningInboxUiState.Empty] only when
 * every bucket loaded with zero rows, and [Error] only when every bucket failed (nothing to show).
 */

/** A single rendered inbox bucket: its kind + the rows that loaded for it. */
data class SigningInboxSection(
    val bucket: SigningInboxBucket,
    val items: List<SigningInboxItem>,
) {
    val count: Int get() = items.size
}

/** The UI envelope for the whole inbox surface. */
sealed interface SigningInboxUiState {

    /** Initial load (all four buckets in flight). */
    data object Loading : SigningInboxUiState

    /**
     * At least one bucket loaded. [sections] contains ONLY non-empty buckets, in canonical order
     * (awaiting first — it is the actionable one). [awaitingCount] powers a badge even when other
     * buckets dominate the list.
     */
    data class Content(
        val sections: List<SigningInboxSection>,
        val isRefreshing: Boolean = false,
    ) : SigningInboxUiState {
        val awaitingCount: Int
            get() = sections.firstOrNull { it.bucket == SigningInboxBucket.AWAITING }?.count ?: 0

        val totalCount: Int get() = sections.sumOf { it.count }
    }

    /** Every bucket loaded successfully but returned zero rows. */
    data object Empty : SigningInboxUiState

    /** Every bucket failed (nothing to render). Carries the first error for the retry affordance. */
    data class Error(val error: ApiError) : SigningInboxUiState
}

/**
 * The per-bucket load outcome the ViewModel feeds in. A [failure] of null means the bucket loaded (its
 * [items] are authoritative, possibly empty); a non-null [failure] means the bucket did not load (its
 * rows are unknown and it is dropped). A 404 is a failure like any other — see [isSuppressible404].
 */
data class BucketLoad(
    val bucket: SigningInboxBucket,
    val items: List<SigningInboxItem> = emptyList(),
    val failure: ApiError? = null,
) {
    val loaded: Boolean get() = failure == null

    /** True when this bucket's failure is a 404 — the flag-off / not-found signal we silently degrade on. */
    val isSuppressible404: Boolean get() = failure?.status == 404
}

/** Canonical render order: the actionable bucket first, drafts last. */
val CANONICAL_BUCKET_ORDER: List<SigningInboxBucket> = listOf(
    SigningInboxBucket.AWAITING,
    SigningInboxBucket.SENT,
    SigningInboxBucket.COMPLETED,
    SigningInboxBucket.DRAFTS,
)

/**
 * Folds the four (or fewer) [BucketLoad]s into a [SigningInboxUiState].
 *
 * Rules:
 *  - Buckets that LOADED with rows become sections (canonical order); empty loaded buckets are omitted.
 *  - If at least one bucket loaded and any rows exist -> [Content].
 *  - If every bucket loaded but ALL are empty -> [Empty].
 *  - If NO bucket loaded (all failed) -> [Error] with the first failure (404 preferred as least-alarming).
 *
 * [isRefreshing] is passed straight through to a resulting [Content].
 */
fun buildInboxState(
    loads: List<BucketLoad>,
    isRefreshing: Boolean = false,
): SigningInboxUiState {
    val loaded = loads.filter { it.loaded }
    if (loaded.isEmpty()) {
        // Every bucket failed. Prefer a 404 (flag-off / not-found) as the surfaced error so the retry
        // affordance reads as "nothing here" rather than a scary transport failure when appropriate.
        val firstError = loads.firstOrNull { it.isSuppressible404 }?.failure
            ?: loads.firstOrNull { it.failure != null }?.failure
        return firstError?.let { SigningInboxUiState.Error(it) } ?: SigningInboxUiState.Empty
    }

    val sections = CANONICAL_BUCKET_ORDER.mapNotNull { bucket ->
        val load = loaded.firstOrNull { it.bucket == bucket } ?: return@mapNotNull null
        if (load.items.isEmpty()) null else SigningInboxSection(bucket, load.items)
    }

    return if (sections.isEmpty()) {
        SigningInboxUiState.Empty
    } else {
        SigningInboxUiState.Content(sections = sections, isRefreshing = isRefreshing)
    }
}
