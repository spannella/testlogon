package com.testlogon.android.feature.messaging.helpdesk

import com.testlogon.android.core.model.helpdesk.Availability
import com.testlogon.android.core.model.helpdesk.heartbeatStatus
import com.testlogon.android.data.messaging.helpdesk.availability.AvailabilityRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * AND-379 — in-memory [AvailabilityRepository] for ViewModel/gate JVM tests.
 *
 * [set] records the requested availability + the heartbeat status it would push (verifying the
 * immediate-push contract from a fake) and updates the StateFlow. Constructed ONLINE by default so
 * pre-existing claim tests proceed unchanged; AND-379 gate tests construct it AWAY.
 */
class FakeAvailabilityRepository(
    initial: Availability = Availability.ONLINE,
) : AvailabilityRepository {

    private val _availability = MutableStateFlow(initial)
    override val availability: StateFlow<Availability> = _availability.asStateFlow()

    val setCalls = mutableListOf<Availability>()
    val pushedStatuses = mutableListOf<String>()

    override suspend fun set(value: Availability) {
        setCalls += value
        pushedStatuses += value.heartbeatStatus()
        _availability.value = value
    }

    override suspend fun current(): Availability = _availability.value
}
