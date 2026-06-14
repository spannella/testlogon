package com.testlogon.android.feature.projects.provider

import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-374 - shared singleton that broadcasts a parsed [ProjectDriveReturn] from the Activity layer to the
 * ProjectDetailViewModel (mirrors the AND-273 GoogleCalendarReturnDispatcher / AND-231 PaymentReturnDispatcher).
 * replay=1 so a return that arrives just before the screen subscribes (cold-start race after the Custom Tab
 * excursion / process death) is still delivered.
 */
@Singleton
class ProjectDriveReturnDispatcher @Inject constructor() {

    private val _returns = MutableSharedFlow<ProjectDriveReturn>(replay = 1, extraBufferCapacity = 4)
    val returns: SharedFlow<ProjectDriveReturn> = _returns.asSharedFlow()

    fun emit(value: ProjectDriveReturn) {
        _returns.tryEmit(value)
    }
}

/**
 * AND-374 - thin handler the Activity calls on a VIEW intent's data URL: parse + emit. Returns true when the
 * URL was a recognized project Drive return (so the caller can stop other deep-link handling).
 */
@Singleton
class ProjectDriveReturnHandler @Inject constructor(
    private val parser: ProjectDriveReturnParser,
    private val dispatcher: ProjectDriveReturnDispatcher,
) {
    fun handle(url: String): Boolean {
        val parsed = parser.parse(url) ?: return false
        dispatcher.emit(parsed)
        return true
    }
}
