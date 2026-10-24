package com.solar23040.bitaudio

import com.solar23040.bitaudio.transport.MeshRuntime

/**
 * Integration seam for the BLE mesh.
 *
 * Phase 2 replaces the offline instance with the real `:mesh` implementation.
 * The service and scan duty-cycler only talk to this interface, so wiring the
 * transport later does not require UI changes.
 */
class OfflineMeshRuntime : MeshRuntime {
    override val isAvailable: Boolean = false

    override fun start() = Unit

    override fun stop() = Unit

    override fun setScanning(enabled: Boolean) = Unit
}
