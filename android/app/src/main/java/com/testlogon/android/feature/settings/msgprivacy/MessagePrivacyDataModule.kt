package com.testlogon.android.feature.settings.msgprivacy

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/** TIP-B4 — Hilt wiring for the message-privacy settings feature. */
@Module
@InstallIn(SingletonComponent::class)
abstract class MessagePrivacyDataModule {

    @Binds
    @Singleton
    abstract fun bindMessagePrivacyRepository(
        impl: DefaultMessagePrivacyRepository,
    ): MessagePrivacyRepository
}
