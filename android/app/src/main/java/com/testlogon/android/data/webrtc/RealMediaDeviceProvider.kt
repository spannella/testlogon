package com.testlogon.android.data.webrtc

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import org.webrtc.Camera2Enumerator
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Real (enumeration-only) [MediaDeviceProvider]: walks `org.webrtc.Camera2Enumerator` for cameras and
 * reports the standard earpiece/speaker audio outputs + the default microphone. Capture START is owned by
 * [RealPeerConnectionController]; this only populates the inventory that gates the camera-switch /
 * audio-route controls. Never opens a device.
 */
@Singleton
class RealMediaDeviceProvider @Inject constructor(
    @ApplicationContext private val context: Context,
) : MediaDeviceProvider {

    override suspend fun enumerate(): MediaDevices {
        val devices = mutableListOf<MediaDevice>()
        runCatching {
            val enumerator = Camera2Enumerator(context)
            enumerator.deviceNames.forEach { name ->
                val facing = when {
                    enumerator.isFrontFacing(name) -> CameraFacing.FRONT
                    enumerator.isBackFacing(name) -> CameraFacing.BACK
                    else -> CameraFacing.UNKNOWN
                }
                devices += MediaDevice(
                    id = name,
                    kind = MediaDeviceKind.CAMERA,
                    label = "Camera (${facing.name.lowercase()})",
                    facing = facing,
                )
            }
        }
        devices += MediaDevice(id = "mic_default", kind = MediaDeviceKind.MICROPHONE, label = "Microphone")
        devices += MediaDevice(
            id = "out_earpiece", kind = MediaDeviceKind.AUDIO_OUTPUT, label = "Earpiece",
            audioOutputKind = AudioOutputKind.EARPIECE,
        )
        devices += MediaDevice(
            id = "out_speaker", kind = MediaDeviceKind.AUDIO_OUTPUT, label = "Speaker",
            audioOutputKind = AudioOutputKind.SPEAKER,
        )
        return MediaDevices(devices)
    }
}
