package com.testlogon.android.data.gcal

import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-273 — shared singleton that broadcasts a parsed [GoogleCalendarReturn] from the Activity layer to
 * the GoogleCalendarViewModel (mirrors the AND-231 PaymentReturnDispatcher). replay=1 so a return that
 * arrives just before the screen subscribes (cold-start race) is still delivered.
 */
@Singleton
class GoogleCalendarReturnDispatcher @Inject constructor() {

    private val _returns = MutableSharedFlow<GoogleCalendarReturn>(replay = 1, extraBufferCapacity = 4)
    val returns: SharedFlow<GoogleCalendarReturn> = _returns.asSharedFlow()

    fun emit(value: GoogleCalendarReturn) {
        _returns.tryEmit(value)
    }
}

/**
 * AND-273 — thin handler the Activity calls on a VIEW intent's data URL: parse + emit. Returns true when
 * the URL was a recognized Google-Calendar return (so the caller can stop other deep-link handling).
 */
@Singleton
class GoogleCalendarReturnHandler @Inject constructor(
    private val parser: GoogleCalendarReturnParser,
    private val dispatcher: GoogleCalendarReturnDispatcher,
) {
    fun handle(url: String): Boolean {
        val parsed = parser.parse(url) ?: return false
        dispatcher.emit(parsed)
        return true
    }
}
