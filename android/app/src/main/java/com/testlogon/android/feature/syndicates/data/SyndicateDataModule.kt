package com.testlogon.android.feature.syndicates.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-356 - Hilt wiring for the syndicate-overview feature. Binds the repository seam to its default impl.
 * The impl consumes AND-356's [com.testlogon.android.core.network.syndicates.SyndicateApi], the shared
 * [com.testlogon.android.core.network.error.ApiErrorParser] and [AuthStateStore] (for the derived role
 * badge). NO new endpoint module, migration, or dependency is added here.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class SyndicateDataModule {

    @Binds
    @Singleton
    abstract fun bindSyndicateRepository(impl: SyndicateRepositoryImpl): SyndicateRepository
}
