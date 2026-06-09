package com.testlogon.android.core.data.cache

/**
 * AND-118 — narrow teardown seam the logout flow (AND-032) depends on, so feature/auth code does not
 * pull in the whole [CacheManager] surface (and so direct-construction tests can substitute [NOOP]).
 */
interface UserScopedCacheCleaner {
    /** Deletes every user-scoped cache row; global rows survive. Called on logout. */
    suspend fun clearAllUserScopedCache()

    companion object {
        /** No-op for tests / contexts where the Room cache is not wired. */
        val NOOP: UserScopedCacheCleaner = object : UserScopedCacheCleaner {
            override suspend fun clearAllUserScopedCache() = Unit
        }
    }
}
