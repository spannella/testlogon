package com.testlogon.android.feature.health

import com.testlogon.android.core.model.BackendStatus
import com.testlogon.android.core.network.health.HealthProbe
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Thin seam over the core-network [HealthProbe] so the banner ViewModel can be unit-tested with a
 * fake status flow (the concrete probe needs Android `Context`/`ConnectivityManager`).
 */
interface BackendStatusMonitor {
    val status: Flow<BackendStatus>
}

@Singleton
class HealthProbeBackendStatusMonitor @Inject constructor(
    private val healthProbe: HealthProbe,
) : BackendStatusMonitor {
    override val status: Flow<BackendStatus> get() = healthProbe.status
}

@Module
@InstallIn(SingletonComponent::class)
object BackendStatusMonitorModule {
    @Provides
    @Singleton
    fun provideBackendStatusMonitor(impl: HealthProbeBackendStatusMonitor): BackendStatusMonitor = impl
}
