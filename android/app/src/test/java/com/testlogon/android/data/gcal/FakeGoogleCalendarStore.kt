package com.testlogon.android.data.gcal

/** AND-273 — pure-JVM in-memory [GoogleCalendarStore] for repository/VM tests. */
class FakeGoogleCalendarStore : GoogleCalendarStore {

    private var connection: CachedConnection? = null
    private var pending: PendingOauth? = null

    override suspend fun cachedConnection(): CachedConnection? = connection

    override suspend fun saveConnection(active: Boolean, accountEmail: String?) {
        connection = CachedConnection(active, accountEmail ?: connection?.accountEmail)
    }

    override suspend fun clearConnection() {
        connection = CachedConnection(false, null)
    }

    override suspend fun savePendingOauth(state: String, nonce: String) {
        pending = PendingOauth(state, nonce)
    }

    override suspend fun pendingOauth(): PendingOauth? = pending

    override suspend fun clearPendingOauth() {
        pending = null
    }
}
