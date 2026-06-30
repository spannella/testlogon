package com.testlogon.android.feature.questionnaire.builder.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * Hilt wiring for the questionnaire-builder feature. Binds the repository seam to its default impl, which
 * consumes the [com.testlogon.android.core.network.questionnaire.QuestionnaireBuilderApi] and the shared
 * [com.testlogon.android.core.network.error.ApiErrorParser]. No new endpoint module, migration, or
 * dependency is added here. Mirrors the apikeys ApiKeysDataModule pattern.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class QuestionnaireBuilderDataModule {

    @Binds
    @Singleton
    abstract fun bindQuestionnaireBuilderRepository(
        impl: DefaultQuestionnaireBuilderRepository,
    ): QuestionnaireBuilderRepository
}
