package com.solar23040.bitaudio.mesh.node

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Ignore
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented BLE smoke test stub.
 *
 * CI has no emulator with a Bluetooth radio, and a real run needs two physical
 * phones with BLE permissions granted. The JVM suite covers the mesh codec and
 * the `FakeTransport` topology; manual radio testing uses this class on devices.
 */
@RunWith(AndroidJUnit4::class)
class BleMeshInstrumentedTest {

    @Ignore("Needs two physical BLE devices; CI runners have no BLE radio")
    @Test
    fun twoDevicesExchangeOneVoicePacket() {
        // Manual device test: start BleTransport on both phones, add the same
        // MeshChannel, publish a payload from one and assert onMessage fires on
        // the other within the transfer timeout.
    }
}
