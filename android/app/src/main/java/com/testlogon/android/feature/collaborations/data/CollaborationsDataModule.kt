package com.testlogon.android.feature.collaborations.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-358 - Hilt wiring for the collaborations feature. Binds the repository seam to its default impl. The
 * impl consumes AND-358's [com.testlogon.android.core.network.collaborations.CollaborationsApi] and the shared
 * [com.testlogon.android.core.network.error.ApiErrorParser]. NO new endpoint module, migration, or dependency
 * is added here. Mirrors the AND-356 SyndicateDataModule pattern.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class CollaborationsDataModule {

    @Binds
    @Singleton
    abstract fun bindCollaborationsRepository(impl: CollaborationsRepositoryImpl): CollaborationsRepository
}
