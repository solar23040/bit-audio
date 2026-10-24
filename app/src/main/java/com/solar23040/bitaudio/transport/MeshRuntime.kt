package com.solar23040.bitaudio.transport

/** App-facing lifecycle for the mesh transport. Implemented by the Phase 2 glue. */
interface MeshRuntime {
    /** False while the real BLE/mesh implementation is not wired in. */
    val isAvailable: Boolean

    fun start()

    fun stop()

    /** Scan duty-cycle hook; safe to call when BLE is not running. */
    fun setScanning(enabled: Boolean)
}
