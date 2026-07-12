package com.testlogon.android.feature.admessaging.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * ADV2-E5 (F5+F6) — Hilt wiring for the ad-messaging feature. Binds the repository seam to its impl, which
 * consumes the [com.testlogon.android.core.network.admessaging.AdMessagingApi] and the shared
 * ApiErrorParser. No new endpoint module, migration, or dependency is added.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class AdMessagingDataModule {

    @Binds
    @Singleton
    abstract fun bindAdMessagingRepository(impl: AdMessagingRepositoryImpl): AdMessagingRepository
}
