package com.testlogon.android.data.messaging

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-120 — provides the [MessagingApi] on the shared Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object MessagingApiModule {

    @Provides
    @Singleton
    fun provideMessagingApi(retrofit: Retrofit): MessagingApi =
        retrofit.create(MessagingApi::class.java)
}

/** AND-120..124 — binds the messaging repository to its implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class MessagingDataModule {

    @Binds
    @Singleton
    abstract fun bindMessagingRepository(impl: MessagingRepositoryImpl): MessagingRepository

    /** AND-130 — binds the runtime image processor (faked in unit tests). */
    @Binds
    @Singleton
    abstract fun bindMessageImageProcessor(impl: DefaultMessageImageProcessor): MessageImageProcessor
}
