package com.testlogon.android.data.notifications

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-084 — provides the [NotificationsApi] on the shared Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object NotificationsApiModule {

    @Provides
    @Singleton
    fun provideNotificationsApi(retrofit: Retrofit): NotificationsApi =
        retrofit.create(NotificationsApi::class.java)
}

/** AND-084 — binds the notification repository to its implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class NotificationDataModule {

    @Binds
    @Singleton
    abstract fun bindNotificationRepository(impl: NotificationRepositoryImpl): NotificationRepository
}
