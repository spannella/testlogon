package com.testlogon.android.feature.files.data

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-333 - app-singleton signal that a folder's listing has changed and should be re-paged.
 *
 * The upload coordinator emits the destination folder path after a successful confirm; the browse
 * [com.testlogon.android.feature.files.presentation.FilesViewModel] collects it and re-anchors its
 * Pager (the same first-page re-anchor used by pull-to-refresh) when the changed path is the folder
 * currently on screen. This keeps the AND-332 [FilesRepository] read interface UNCHANGED (no new
 * method, no fake updates) while still refreshing the listing after an upload lands.
 *
 * A small replay buffer covers the brief window between an upload landing and the screen collecting,
 * so a refresh emitted just before the browse screen subscribes is not lost.
 */
@Singleton
class FolderRefreshBus @Inject constructor() {

    private val _refreshes = MutableSharedFlow<String>(replay = 1, extraBufferCapacity = 8)

    /** Folder paths whose listing changed; collectors re-page when the path matches their own. */
    val refreshes: Flow<String> = _refreshes.asSharedFlow()

    /** Signals that [folderPath]'s listing changed (e.g. an upload confirmed into it). */
    fun signal(folderPath: String) {
        _refreshes.tryEmit(folderPath)
    }
}
