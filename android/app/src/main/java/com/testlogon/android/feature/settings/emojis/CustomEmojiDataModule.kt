package com.testlogon.android.feature.settings.emojis

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/** Hilt wiring for the custom-emoji settings feature. Binds the repository seam to its default impl. */
@Module
@InstallIn(SingletonComponent::class)
abstract class CustomEmojiDataModule {

    @Binds
    @Singleton
    abstract fun bindCustomEmojiRepository(impl: DefaultCustomEmojiRepository): CustomEmojiRepository
}
