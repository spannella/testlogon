package com.testlogon.android.feature.delegationkeys.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/** Hilt wiring for the delegation-API keys feature - binds the repository seam to its default impl. */
@Module
@InstallIn(SingletonComponent::class)
abstract class DelegationKeyDataModule {

    @Binds
    @Singleton
    abstract fun bindDelegationKeyRepository(impl: DefaultDelegationKeyRepository): DelegationKeyRepository
}
