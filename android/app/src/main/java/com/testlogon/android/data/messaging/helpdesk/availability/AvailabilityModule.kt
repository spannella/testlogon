package com.testlogon.android.data.messaging.helpdesk.availability

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.preferencesDataStoreFile
import com.testlogon.android.data.messaging.presence.HeartbeatScheduler
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Qualifier
import javax.inject.Singleton

/** AND-379 — qualifier for the agent-availability DataStore (file `agent_availability_prefs`). */
@Qualifier
@Retention(AnnotationRetention.BINARY)
annotation class AvailabilityPrefs

/**
 * AND-379 — provides the availability DataStore and binds the repository + the heartbeat-push seam.
 *
 * The DataStore is built via [PreferenceDataStoreFactory] (rather than the `Context` extension) so the
 * exact same [AvailabilityRepositoryImpl] is constructible in JVM unit tests against a temp-file
 * DataStore (TC-AND-379-02/03/05). [PresenceHeartbeatPush] is bound to AND-145's [HeartbeatScheduler];
 * the scheduler reads availability back through `dagger.Lazy<AvailabilityRepository>`, so construction
 * order never forms a cycle.
 */
@Module
@InstallIn(SingletonComponent::class)
object AvailabilityModule {

    @Provides
    @Singleton
    @AvailabilityPrefs
    fun provideAvailabilityDataStore(
        @ApplicationContext context: Context,
    ): DataStore<Preferences> =
        PreferenceDataStoreFactory.create {
            context.preferencesDataStoreFile("agent_availability_prefs")
        }
}

/** AND-379 — binds the availability repository and the heartbeat-push seam. */
@Module
@InstallIn(SingletonComponent::class)
abstract class AvailabilityBindsModule {

    @Binds
    @Singleton
    abstract fun bindAvailabilityRepository(impl: AvailabilityRepositoryImpl): AvailabilityRepository

    @Binds
    @Singleton
    abstract fun bindPresenceHeartbeatPush(impl: HeartbeatScheduler): PresenceHeartbeatPush
}
