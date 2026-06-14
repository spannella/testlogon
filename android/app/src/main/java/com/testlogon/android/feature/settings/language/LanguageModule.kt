package com.testlogon.android.feature.settings.language

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/** AND-114 — binds the locale-application controller to its AppCompat-backed implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class LanguageModule {

    @Binds
    @Singleton
    abstract fun bindLocaleController(impl: AppCompatLocaleController): LocaleController
}
