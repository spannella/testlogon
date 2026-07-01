package com.testlogon.android.feature.agents.feedback.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/** AGENTS-BASICS (web-parity) - Hilt wiring for the FEEDBACK feature. Binds the repository seam to its impl. */
@Module
@InstallIn(SingletonComponent::class)
abstract class FeedbackDataModule {

    @Binds
    @Singleton
    abstract fun bindFeedbackRepository(impl: DefaultFeedbackRepository): FeedbackRepository
}
