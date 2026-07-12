package com.testlogon.android.feature.agents.docs.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/** AGENTS-BASICS (web-parity) - Hilt wiring for the DOC-COVERAGE feature. Binds the repository seam to its impl. */
@Module
@InstallIn(SingletonComponent::class)
abstract class DocsDataModule {

    @Binds
    @Singleton
    abstract fun bindDocsRepository(impl: DefaultDocsRepository): DocsRepository
}
