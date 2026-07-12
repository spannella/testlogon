package com.testlogon.android.feature.agents.prs.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/** AGENTS-BASICS (web-parity) - Hilt wiring for the agent-PR feature. Binds the repository seam to its impl. */
@Module
@InstallIn(SingletonComponent::class)
abstract class PrsDataModule {

    @Binds
    @Singleton
    abstract fun bindPrsRepository(impl: DefaultPrsRepository): PrsRepository
}
