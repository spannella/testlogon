package com.testlogon.android.data.feed

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * #18 — app-singleton signal that the newsfeed changed and any feed surface should re-page from the head.
 *
 * Mirrors the established [com.testlogon.android.feature.files.data.FolderRefreshBus] pattern: a small
 * replay buffer covers the brief window between a write landing (a post published / edited) and the feed
 * screen collecting, so a refresh emitted just before the feed subscribes is not lost.
 *
 * Emitters: the compose screen on a successful publish (#18a) and the edit screen on a successful save
 * (#18b). Collector: [FeedViewModel], which invalidates its cached Pager so a newly published post is
 * prepended and an edited post is replaced IN PLACE in the main feed (not just in "My Posts").
 */
@Singleton
class FeedRefreshBus @Inject constructor() {

    private val _refreshes = MutableSharedFlow<Unit>(replay = 1, extraBufferCapacity = 8)

    /** Emits each time the feed should be re-paged from the head. */
    val refreshes: Flow<Unit> = _refreshes.asSharedFlow()

    /** Signal that the feed changed (a post was published or edited). */
    fun signal() {
        _refreshes.tryEmit(Unit)
    }
}
