package com.meshvoice.transport.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothStatusCodes
import android.content.Context
import android.os.Build
import android.util.Log
import com.meshvoice.transport.BleConfig
import com.meshvoice.transport.Peer
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.io.IOException

/**
 * Central side of one connection. Requests a large MTU, enables notifications on TX, then streams
 * frames through RX with write-without-response. Writes are paced by [BleConfig.writeSpacingMs].
 */
@SuppressLint("MissingPermission")
internal class GattClientConnection(
    private val context: Context,
    private val address: String,
    private val device: BluetoothDevice,
    private val config: BleConfig,
    private val scope: CoroutineScope,
    private val onFrame: (Peer, ByteArray) -> Unit,
    private val onError: (Throwable) -> Unit,
) {
    private val ready = CompletableDeferred<Int>()
    private val queue = Channel<ByteArray>(capacity = config.maxQueuedFrames)

    private var gatt: BluetoothGatt? = null
    private var rxCharacteristic: BluetoothGattCharacteristic? = null
    private var txCharacteristic: BluetoothGattCharacteristic? = null
    private var writerJob: Job? = null
    private var negotiatedMtu = DEFAULT_MTU

    @Volatile
    private var readyForWrites = false

    @Volatile
    private var closed = false

    val isReady: Boolean get() = readyForWrites && !closed
    val isUsable: Boolean get() = !closed

    fun connect() {
        if (closed) return
        val gatt = try {
            device.connectGatt(context, false, callback, BluetoothDevice.TRANSPORT_LE)
        } catch (t: Throwable) {
            fail(t)
            return
        }
        if (gatt == null) {
            fail(IOException("connectGatt returned null for $address"))
            return
        }
        this.gatt = gatt

        scope.launch {
            delay(config.connectTimeoutMs)
            if (!ready.isCompleted && !closed) {
                fail(IOException("connect timeout for $address"))
            }
        }
    }

    suspend fun awaitReady(timeoutMs: Long): Int? {
        return try {
            withTimeoutOrNull(timeoutMs) { ready.await() }
        } catch (t: CancellationException) {
            throw t
        } catch (t: Throwable) {
            null
        }
    }

    fun write(frame: ByteArray) {
        if (!isReady) return
        if (frame.size > negotiatedMtu - ATT_OVERHEAD) {
            onError(IllegalArgumentException("frame ${frame.size} exceeds MTU $negotiatedMtu"))
            return
        }
        queue.trySend(frame)
    }

    fun close() {
        shutdown(null)
    }

    private fun startWriter() {
        if (writerJob != null) return
        writerJob = scope.launch {
            try {
                for (frame in queue) {
                    if (!isReady) break
                    var attempts = 0
                    while (isActive && !writeFrame(frame) && attempts < WRITE_RETRIES) {
                        attempts += 1
                        delay(WRITE_RETRY_DELAY_MS)
                    }
                    delay(config.writeSpacingMs)
                }
            } catch (t: CancellationException) {
                throw t
            } catch (t: Throwable) {
                fail(t)
            }
        }
    }

    private fun writeFrame(frame: ByteArray): Boolean {
        val gatt = gatt ?: return false
        val rx = rxCharacteristic ?: return false
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                gatt.writeCharacteristic(
                    rx,
                    frame,
                    BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE,
                ) == BluetoothStatusCodes.SUCCESS
            } else {
                @Suppress("DEPRECATION")
                rx.writeType = BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE
                @Suppress("DEPRECATION")
                rx.value = frame
                @Suppress("DEPRECATION")
                gatt.writeCharacteristic(rx)
            }
        } catch (t: Throwable) {
            onError(t)
            false
        }
    }

    private fun deliver(value: ByteArray) {
        if (value.isEmpty() || value.size > config.transfer.maxFrameBytes) return
        try {
            onFrame(Peer(id = address, address = address), value.copyOf())
        } catch (t: Throwable) {
            onError(t)
        }
    }

    private fun fail(t: Throwable) {
        if (closed) return
        shutdown(t)
    }

    private fun shutdown(error: Throwable?) {
        if (closed) return
        closed = true
        readyForWrites = false
        if (!ready.isCompleted) {
            ready.completeExceptionally(error ?: IOException("connection $address closed"))
        }
        queue.close()
        writerJob?.cancel()
        writerJob = null
        closeGattQuietly()
        if (error != null) {
            Log.w(TAG, "connection $address closed", error)
            onError(error)
        }
    }

    private fun closeGattQuietly() {
        try {
            gatt?.disconnect()
        } catch (t: Throwable) {
            Log.d(TAG, "disconnect failed", t)
        }
        try {
            gatt?.close()
        } catch (t: Throwable) {
            Log.d(TAG, "gatt close failed", t)
        }
        gatt = null
    }

    private val callback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            when (newState) {
                BluetoothProfile.STATE_CONNECTED -> {
                    if (status != BluetoothGatt.GATT_SUCCESS) {
                        fail(IOException("GATT connect failed: $status"))
                        return
                    }
                    if (!gatt.requestMtu(config.mtuRequest)) {
                        if (!gatt.discoverServices()) {
                            fail(IOException("discoverServices failed"))
                        }
                    }
                }

                BluetoothProfile.STATE_DISCONNECTED -> {
                    shutdown(
                        if (status == BluetoothGatt.GATT_SUCCESS) {
                            null
                        } else {
                            IOException("GATT disconnected: $status")
                        },
                    )
                }
            }
        }

        override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
            if (status == BluetoothGatt.GATT_SUCCESS) {
                negotiatedMtu = maxOf(negotiatedMtu, mtu)
            } else {
                Log.w(TAG, "MTU request failed: $status; using $negotiatedMtu")
            }
            if (!gatt.discoverServices()) {
                fail(IOException("discoverServices failed"))
            }
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                fail(IOException("service discovery failed: $status"))
                return
            }
            val service = gatt.getService(config.serviceUuid)
            if (service == null) {
                fail(IllegalStateException("transport service not found on $address"))
                return
            }
            val rx = service.getCharacteristic(config.rxCharacteristicUuid)
            val tx = service.getCharacteristic(config.txCharacteristicUuid)
            if (rx == null || tx == null) {
                fail(IllegalStateException("transport characteristics not found on $address"))
                return
            }
            rxCharacteristic = rx
            txCharacteristic = tx

            if (!gatt.setCharacteristicNotification(tx, true)) {
                fail(IOException("could not enable local notifications"))
                return
            }
            val cccd = tx.getDescriptor(config.cccdUuid)
            if (cccd == null) {
                fail(IllegalStateException("CCCD missing on $address"))
                return
            }
            val started = try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    gatt.writeDescriptor(
                        cccd,
                        BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE,
                    ) == BluetoothStatusCodes.SUCCESS
                } else {
                    @Suppress("DEPRECATION")
                    cccd.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                    @Suppress("DEPRECATION")
                    gatt.writeDescriptor(cccd)
                }
            } catch (t: Throwable) {
                onError(t)
                false
            }
            if (!started) {
                fail(IOException("could not write notification descriptor"))
            }
        }

        override fun onDescriptorWrite(
            gatt: BluetoothGatt,
            descriptor: BluetoothGattDescriptor,
            status: Int,
        ) {
            if (descriptor.uuid != config.cccdUuid) return
            if (status != BluetoothGatt.GATT_SUCCESS) {
                fail(IOException("CCCD write failed: $status"))
                return
            }
            readyForWrites = true
            ready.complete(negotiatedMtu)
            startWriter()
        }

        @Suppress("DEPRECATION")
        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
        ) {
            if (characteristic.uuid != config.txCharacteristicUuid) return
            @Suppress("DEPRECATION")
            val value = characteristic.value ?: return
            deliver(value)
        }

        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray,
        ) {
            if (characteristic.uuid == config.txCharacteristicUuid) {
                deliver(value)
            }
        }
    }

    private companion object {
        const val TAG = "GattClient"
        const val DEFAULT_MTU = 23
        const val ATT_OVERHEAD = 3
        const val WRITE_RETRIES = 2
        const val WRITE_RETRY_DELAY_MS = 5L
    }
}
