package com.testlogon.android.feature.blocking

import com.testlogon.android.data.blocking.BlockingRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine

/**
 * AND-382 - client-side content suppression helpers (spec sec.4.4 / sec.6 / AC-2).
 *
 * Feature list ViewModels combine their item flow with the repository's [BlockingRepository.blockedUserIds]
 * and drop items authored by a blocked user. Suppression is applied at the ViewModel layer so cached
 * Room / Paging data is filtered WITHOUT invalidating the cache; on unblock the next refresh restores
 * the items naturally because the blocked-id set shrinks.
 *
 * Pure + total: takes an author-id selector so it works for feed posts, conversation rows, comments, etc.
 */
fun <T> suppressBlocked(items: List<T>, blockedIds: Set<String>, authorId: (T) -> String): List<T> {
    if (blockedIds.isEmpty()) return items
    return items.filterNot { authorId(it) in blockedIds }
}

/**
 * Wire a content flow through block suppression. The result re-emits whenever either the items or the
 * blocked-id set changes, so a block hides authored content in the current session immediately.
 */
fun <T> Flow<List<T>>.suppressingBlocked(
    repository: BlockingRepository,
    authorId: (T) -> String,
): Flow<List<T>> = combine(repository.blockedUserIds) { items, blocked ->
    suppressBlocked(items, blocked, authorId)
}
