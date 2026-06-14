package com.testlogon.android.feature.delegates.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-359 - Hilt wiring for the delegate feature. Binds the [DelegationRepository] seam to its default
 * impl. The impl consumes AND-359's [com.testlogon.android.core.network.delegates.DelegatesApi], the
 * core-data [com.testlogon.android.core.data.delegates.DelegationStateStore] (the process-global
 * manage-as flag), and the shared [com.testlogon.android.core.network.error.ApiErrorParser]. NO new
 * endpoint module, migration, or dependency is added here. The DelegationStateStore is itself a
 * constructor-injectable @Singleton, so it needs no @Provides.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class DelegatesDataModule {

    @Binds
    @Singleton
    abstract fun bindDelegationRepository(impl: DelegationRepositoryImpl): DelegationRepository
}
