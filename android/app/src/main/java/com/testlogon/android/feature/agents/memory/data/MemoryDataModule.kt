package com.testlogon.android.feature.agents.memory.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/** AGENTS-BASICS (web-parity) - Hilt wiring for the MEMORY feature. Binds the repository seam to its impl. */
@Module
@InstallIn(SingletonComponent::class)
abstract class MemoryDataModule {

    @Binds
    @Singleton
    abstract fun bindMemoryRepository(impl: DefaultMemoryRepository): MemoryRepository
}
