package com.testlogon.android.feature.questionnaire.respond.di

import com.testlogon.android.feature.questionnaire.respond.state.DefaultFieldValidator
import com.testlogon.android.feature.questionnaire.respond.state.DefaultVisibilityEvaluator
import com.testlogon.android.feature.questionnaire.respond.state.FieldValidator
import com.testlogon.android.feature.questionnaire.respond.state.FormVisibilityEvaluator
import com.testlogon.android.feature.questionnaire.respond.state.NoOpSubmitGateway
import com.testlogon.android.feature.questionnaire.respond.state.SubmitGateway
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-351 - Hilt wiring for the questionnaire FORM state machine seams so
 * [com.testlogon.android.feature.questionnaire.respond.vm.QuestionnaireFormViewModel] is
 * Hilt-constructable. The seams bind to their DEFAULT implementations, which REUSE existing code rather
 * than duplicate it:
 *
 * - [FieldValidator] -> [DefaultFieldValidator], delegating to AND-350 ClientValidator (FR-4).
 * - [FormVisibilityEvaluator] -> [DefaultVisibilityEvaluator], delegating to AND-350 VisibilityEvaluator
 *   (FR-5).
 * - [SubmitGateway] -> [NoOpSubmitGateway], a no-op stub; AND-349's real submit can REPLACE this binding
 *   (FR-7).
 *
 * The defaults are Kotlin objects (not @Inject classes), so this uses @Provides rather than @Binds.
 *
 * NOTE: KDoc here deliberately avoids the comment-terminator character pair.
 */
@Module
@InstallIn(SingletonComponent::class)
object QuestionnaireFormModule {

    @Provides
    @Singleton
    fun provideFieldValidator(): FieldValidator = DefaultFieldValidator

    @Provides
    @Singleton
    fun provideFormVisibilityEvaluator(): FormVisibilityEvaluator = DefaultVisibilityEvaluator

    @Provides
    @Singleton
    fun provideSubmitGateway(): SubmitGateway = NoOpSubmitGateway
}
