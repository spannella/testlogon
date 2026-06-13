package com.testlogon.android.feature.questionnaire.respond.di

import com.testlogon.android.feature.questionnaire.respond.data.RespondentSessionRepository
import com.testlogon.android.feature.questionnaire.respond.data.RespondentSessionRepositoryImpl
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-348 - Hilt wiring for the respondent session lifecycle. Binds the repository seam to its default
 * impl, which consumes AND-346's [com.testlogon.android.core.network.questionnaire.QuestionnaireApi]
 * (REUSED, no duplicate API), the AND-348 [com.testlogon.android.core.data.respond.SessionDraftDao],
 * the shared [com.squareup.moshi.Moshi] (for answer serialization), and the shared
 * [com.testlogon.android.core.network.error.ApiErrorParser] - all already provided by core-network /
 * core-data. NO new endpoint module, no new dependency. SUBMIT + PDF are OUT OF SCOPE (AND-349).
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class RespondentSessionModule {

    @Binds
    @Singleton
    abstract fun bindRespondentSessionRepository(
        impl: RespondentSessionRepositoryImpl,
    ): RespondentSessionRepository
}
