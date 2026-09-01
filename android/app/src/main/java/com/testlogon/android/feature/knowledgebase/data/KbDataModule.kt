package com.testlogon.android.feature.knowledgebase.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * KB-AND-1 - Hilt wiring for the READ-ONLY Knowledge Base feature. Binds the repository seam to its default
 * impl, which consumes the [com.testlogon.android.core.network.kb.KbApi] and the shared
 * [com.testlogon.android.core.network.error.ApiErrorParser]. NO new endpoint module, migration, or dependency
 * is added here. Mirrors the AND-372 TicketsDataModule pattern.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class KbDataModule {

    @Binds
    @Singleton
    abstract fun bindKbRepository(impl: KbRepositoryImpl): KbRepository
}
