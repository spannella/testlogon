package com.testlogon.android.data.push

import android.content.Context
import androidx.work.WorkManager
import com.google.firebase.messaging.FirebaseMessaging
import com.testlogon.android.notifications.DefaultNotificationChannelInitializer
import com.testlogon.android.notifications.NotificationChannelInitializer
import com.testlogon.android.data.auth.PushLogoutHandler
import com.testlogon.android.notifications.NotificationDisplaySink
import com.testlogon.android.push.FirebaseMessagingTokenProvider
import com.testlogon.android.push.PushMessageSink
import com.testlogon.android.push.PushTokenProvider
import com.testlogon.android.push.PushTokenSink
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-105/106/107/109 — push DI wiring.
 *
 * Provides the FCM SDK handle, the Retrofit [PushApi], and WorkManager; binds the sinks to their
 * real implementations:
 *  - [PushTokenSink]   -> [FcmTokenRegistrar]   (AND-106/109: persist + register on rotation/login)
 *  - [PushMessageSink] -> [NotificationDisplaySink] (AND-107: parse + post on the right channel)
 * replacing AND-105's logging defaults. NOTE: [FirebaseMessaging.getInstance] THROWS when no default
 * FirebaseApp exists (no google-services.json), so this provider must never be resolved eagerly at
 * graph construction — its only consumer injects it as dagger.Lazy and resolves it lazily on a real
 * token fetch (see PushTokenProvider), which only runs once Firebase is configured.
 */
@Module
@InstallIn(SingletonComponent::class)
object PushProvidesModule {

    @Provides
    @Singleton
    fun provideFirebaseMessaging(): FirebaseMessaging = FirebaseMessaging.getInstance()

    @Provides
    @Singleton
    fun providePushApi(retrofit: Retrofit): PushApi = retrofit.create(PushApi::class.java)

    @Provides
    @Singleton
    fun provideWorkManager(@ApplicationContext context: Context): WorkManager =
        WorkManager.getInstance(context)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class PushBindsModule {

    @Binds
    @Singleton
    abstract fun bindPushRepository(impl: PushRepositoryImpl): PushRepository

    @Binds
    @Singleton
    abstract fun bindPushRegistrationStore(impl: DataStorePushRegistrationStore): PushRegistrationStore

    @Binds
    @Singleton
    abstract fun bindPushWorkScheduler(impl: WorkManagerPushScheduler): PushWorkScheduler

    @Binds
    @Singleton
    abstract fun bindPushTokenProvider(impl: FirebaseMessagingTokenProvider): PushTokenProvider

    @Binds
    @Singleton
    abstract fun bindNotificationChannelInitializer(
        impl: DefaultNotificationChannelInitializer,
    ): NotificationChannelInitializer

    // AND-106/109: the registrar is the real token sink (replaces AND-105's LoggingPushTokenSink).
    @Binds
    @Singleton
    abstract fun bindPushTokenSink(impl: FcmTokenRegistrar): PushTokenSink

    // AND-107: the display sink is the real message sink (replaces AND-105's LoggingPushMessageSink).
    @Binds
    @Singleton
    abstract fun bindPushMessageSink(impl: NotificationDisplaySink): PushMessageSink

    // AND-109: the real logout deregister handler inserted into the AND-032 logout flow.
    @Binds
    @Singleton
    abstract fun bindPushLogoutHandler(impl: PushLogoutHandlerImpl): PushLogoutHandler
}
