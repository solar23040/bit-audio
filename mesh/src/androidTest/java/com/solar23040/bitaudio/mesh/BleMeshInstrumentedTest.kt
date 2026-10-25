package com.solar23040.bitaudio.mesh

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Ignore
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Placeholder for the on-device BLE acceptance test.
 *
 * The JVM suite covers flooding, crypto, frame limits, and store-and-forward on
 * `FakeNetwork`. This test needs two physical Android phones, BLE permissions,
 * and the `bit-audio` GATT service, so CI skips it until a device farm is
 * available.
 */
@RunWith(AndroidJUnit4::class)
class BleMeshInstrumentedTest {

    @Test
    @Ignore("Requires two BLE-capable devices; run manually on hardware")
    fun `two devices exchange a fifteen kilobyte clip`() {
        // Manual test outline:
        // 1. Start BleTransport on both devices with permissions granted.
        // 2. Publish 15 KB through MeshEngine on device A.
        // 3. Assert device B receives the same payload after selective acks.
        // 4. Kill B mid-transfer, restart, and assert store-and-forward completes.
    }
}
