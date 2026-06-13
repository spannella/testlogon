package com.testlogon.android.feature.projects.ui.detail

import com.testlogon.android.core.model.projects.Project

/**
 * AND-374 - the exhaustive UI state for the PROJECT DETAIL screen (screen 2).
 *
 * Sealed so the screen renders mutually-exclusive surfaces; a new variant forces an exhaustive `when`.
 * [Loading] is the first-load spinner; [Content] carries the project + the Drive-connection flags plus an
 * in-memory [isStale] flag (last-good kept on a refresh failure - FR-6 stale banner, NOT persisted) and a
 * [connecting] flag (the Drive start/callback is in flight); [Error] carries a sanitized message for the retry
 * surface. The one-shot launch URL and transient messages are delivered as [ProjectDetailEffect]s (a Channel),
 * NOT as state, so they are not re-emitted on recomposition / config change.
 */
sealed interface ProjectDetailUiState {

    data object Loading : ProjectDetailUiState

    data class Content(
        val project: Project,
        val driveConnected: Boolean = false,
        val isStale: Boolean = false,
        val connecting: Boolean = false,
    ) : ProjectDetailUiState

    data class Error(val message: String) : ProjectDetailUiState
}

/**
 * AND-374 - one-shot effects for the project detail screen, delivered via a Channel (never re-delivered on
 * rotation). [LaunchAuth] opens the Drive authorization URL in a Custom Tab; [ShowMessage] surfaces a transient
 * snackbar (e.g. canceled / unverified); [NavigateToLogin] is the terminal-401 re-auth handoff.
 */
sealed interface ProjectDetailEffect {
    data class LaunchAuth(val url: String) : ProjectDetailEffect
    data class ShowMessage(val message: String) : ProjectDetailEffect
    data object NavigateToLogin : ProjectDetailEffect
}
