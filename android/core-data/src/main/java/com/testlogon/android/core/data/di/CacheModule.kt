package com.testlogon.android.core.data.di

import com.testlogon.android.core.data.cache.CacheManager
import com.testlogon.android.core.data.cache.Clock
import com.testlogon.android.core.data.cache.SystemClock
import com.testlogon.android.core.data.cache.UserScopedCacheCleaner
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-118 — binds the time abstraction so freshness/TTL is mockable, and exposes the [CacheManager]
 * as the narrow [UserScopedCacheCleaner] seam the AND-032 logout flow depends on. `CacheManager` is
 * `@Inject`-constructed and `@Singleton`, so it needs no explicit provider.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class CacheModule {
    @Binds
    @Singleton
    abstract fun bindClock(impl: SystemClock): Clock

    @Binds
    @Singleton
    abstract fun bindUserScopedCacheCleaner(impl: CacheManager): UserScopedCacheCleaner
}
