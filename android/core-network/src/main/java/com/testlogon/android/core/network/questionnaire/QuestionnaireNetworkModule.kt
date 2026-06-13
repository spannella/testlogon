package com.testlogon.android.core.network.questionnaire

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-346 - Hilt wiring for the questionnaire transport layer (epic E45).
 *
 * Provides [QuestionnaireApi] from the shared singleton [Retrofit] (reusing the production OkHttp /
 * Moshi / converter config; no new Retrofit, OkHttp or Moshi is built, and no new dependency is
 * introduced). The three custom questionnaire adapters (QuestionTypeAdapter / AnswerValueAdapter /
 * QuestionnaireFieldFactory) are registered on the shared Moshi in NetworkModule.provideMoshi (BEFORE
 * the reflective KotlinJsonAdapterFactory) so the polymorphic field schema + answer union + question
 * type decode correctly. Mirrors the AND-339 SigningNetworkModule pattern.
 */
@Module
@InstallIn(SingletonComponent::class)
object QuestionnaireNetworkModule {

    @Provides
    @Singleton
    fun provideQuestionnaireApi(retrofit: Retrofit): QuestionnaireApi =
        retrofit.create(QuestionnaireApi::class.java)
}
