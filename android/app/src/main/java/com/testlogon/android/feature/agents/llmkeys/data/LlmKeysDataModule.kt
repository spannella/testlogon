package com.testlogon.android.feature.agents.llmkeys.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/** AGENTS-BASICS (web-parity) - Hilt wiring for the LLM keys feature. */
@Module
@InstallIn(SingletonComponent::class)
abstract class LlmKeysDataModule {

    @Binds
    @Singleton
    abstract fun bindLlmKeysRepository(impl: DefaultLlmKeysRepository): LlmKeysRepository
}
