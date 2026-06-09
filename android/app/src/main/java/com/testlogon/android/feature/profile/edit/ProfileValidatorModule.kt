package com.testlogon.android.feature.profile.edit

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/** AND-072 — provides the pure [ProfileValidator] to the edit ViewModel. */
@Module
@InstallIn(SingletonComponent::class)
object ProfileValidatorModule {

    @Provides
    @Singleton
    fun provideProfileValidator(): ProfileValidator = ProfileValidator()
}
