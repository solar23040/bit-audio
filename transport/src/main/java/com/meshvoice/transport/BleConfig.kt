package com.meshvoice.transport

import android.bluetooth.le.ScanSettings
import com.meshvoice.transport.protocol.TransferSettings
import java.util.UUID

object BleUuids {
    /** Custom 128-bit service advertised by every node. */
    val SERVICE: UUID = UUID.fromString("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d")

    /** Central writes frames here (write-without-response). */
    val RX: UUID = UUID.fromString("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5e")

    /** Peripheral notifies frames (mostly acks) here. */
    val TX: UUID = UUID.fromString("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5f")

    /** Standard Client Characteristic Configuration Descriptor. */
    val CCCD: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
}

data class BleConfig(
    val serviceUuid: UUID = BleUuids.SERVICE,
    val rxCharacteristicUuid: UUID = BleUuids.RX,
    val txCharacteristicUuid: UUID = BleUuids.TX,
    val cccdUuid: UUID = BleUuids.CCCD,
    val transfer: TransferSettings = TransferSettings(),
    /** Android will grant less if the peer or controller cannot support it. */
    val mtuRequest: Int = 247,
    val scanMode: Int = ScanSettings.SCAN_MODE_LOW_LATENCY,
    val connectTimeoutMs: Long = 8_000,
    val maintenanceIntervalMs: Long = 100,
    /** Spacing between write-without-response calls; prevents controller buffer overflow. */
    val writeSpacingMs: Long = 8,
    val maxQueuedFrames: Int = 4_096,
    val maxPeers: Int = 64,
) {
    init {
        require(mtuRequest in 23..517) { "mtuRequest must be in 23..517" }
        require(connectTimeoutMs > 0)
        require(maintenanceIntervalMs > 0)
        require(writeSpacingMs >= 0)
        require(maxQueuedFrames > 0)
        require(maxPeers > 0)
    }
}
