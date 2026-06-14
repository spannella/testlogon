package com.testlogon.android.data.profile

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.util.Collections
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Resolves a user id (an email / user_sub, as carried by feed posts and comments) to a human display
 * name via the public-profile endpoint, with a process-lifetime in-memory cache.
 *
 * Feed/comment payloads carry only `author_id`; this lets the UI show the person's name instead. The
 * resolution is reactive: [resolve] returns the cached name immediately, or null while a one-shot
 * background lookup runs — observers of [names] recompose and pick up the name once it arrives. Each id
 * is fetched at most once (in-flight de-duplication), and failures are simply left unresolved.
 */
@Singleton
class DisplayNameResolver @Inject constructor(
    private val profileRepository: ProfileRepository,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val inFlight = Collections.synchronizedSet(mutableSetOf<String>())

    private val _names = MutableStateFlow<Map<String, String>>(emptyMap())

    /** id -> display name, for every id resolved so far. Observe this to re-render when names arrive. */
    val names: StateFlow<Map<String, String>> = _names.asStateFlow()

    /** Cached display name for [id], or null while a background lookup is kicked off on first miss. */
    fun resolve(id: String): String? {
        if (id.isBlank()) return null
        _names.value[id]?.let { return it }
        if (inFlight.add(id)) {
            scope.launch {
                val name = (profileRepository.getPublicProfile(id) as? ProfileResult.Found)
                    ?.profile?.displayName?.takeIf { it.isNotBlank() }
                if (name != null) _names.update { it + (id to name) }
                inFlight.remove(id)
            }
        }
        return null
    }
}
