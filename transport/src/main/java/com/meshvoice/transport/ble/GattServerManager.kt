package com.meshvoice.transport.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothStatusCodes
import android.content.Context
import android.os.Build
import android.util.Log
import com.meshvoice.transport.BleConfig
import com.meshvoice.transport.Peer
import java.util.concurrent.ConcurrentHashMap

/**
 * Peripheral side: every node advertises the service and accepts writes from nearby centrals.
 * Frames written to RX are delivered to [onFrame]; acks are sent back as notifications on TX.
 */
@SuppressLint("MissingPermission")
internal class GattServerManager(
    private val context: Context,
    private val config: BleConfig,
    private val onFrame: (Peer, ByteArray) -> Unit,
    private val onError: (Throwable) -> Unit,
) {
    private val manager =
        context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager

    private val lock = Any()
    private var server: BluetoothGattServer? = null
    private var txCharacteristic: BluetoothGattCharacteristic? = null
    private var started = false

    private val devices = ConcurrentHashMap<String, BluetoothDevice>()
    private val subscribed = ConcurrentHashMap<String, Boolean>()
    private val mtuByAddress = ConcurrentHashMap<String, Int>()

    fun start() {
        synchronized(lock) {
            if (started) return
            val manager = manager
            if (manager == null) {
                onError(IllegalStateException("Bluetooth unavailable; cannot open GATT server"))
                return
            }
            val adapter = manager.adapter
            if (adapter == null || !adapter.isEnabled) {
                onError(IllegalStateException("Bluetooth unavailable; cannot open GATT server"))
                return
            }
            val gattServer = try {
                manager.openGattServer(context, callback)
            } catch (t: Throwable) {
                onError(t)
                null
            } ?: run {
                onError(IllegalStateException("openGattServer returned null"))
                return
            }

            val service = buildService()
            val added = try {
                gattServer.addService(service)
            } catch (t: Throwable) {
                onError(t)
                false
            }
            if (!added) {
                gattServer.close()
                onError(IllegalStateException("could not add GATT service"))
                return
            }

            server = gattServer
            txCharacteristic = service.getCharacteristic(config.txCharacteristicUuid)
            started = true
        }
    }

    fun stop() {
        synchronized(lock) {
            started = false
            try {
                server?.clearServices()
            } catch (t: Throwable) {
                Log.w(TAG, "clearServices failed", t)
            }
            try {
                server?.close()
            } catch (t: Throwable) {
                Log.w(TAG, "GATT server close failed", t)
            }
            server = null
            txCharacteristic = null
            devices.clear()
            subscribed.clear()
            mtuByAddress.clear()
        }
    }

    /** Sends a notification if the central subscribed and the frame fits the negotiated MTU. */
    fun notify(address: String, frame: ByteArray): Boolean {
        if (subscribed[address] != true) return false
        val activeServer = server ?: return false
        val tx = txCharacteristic ?: return false
        val device = devices[address] ?: return false
        val mtu = mtuByAddress[address] ?: DEFAULT_MTU
        if (frame.size > mtu - ATT_OVERHEAD) return false

        return try {
            synchronized(lock) {
                if (!started) {
                    false
                } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    activeServer.notifyCharacteristicChanged(device, tx, false, frame) ==
                        BluetoothStatusCodes.SUCCESS
                } else {
                    @Suppress("DEPRECATION")
                    tx.value = frame
                    @Suppress("DEPRECATION")
                    activeServer.notifyCharacteristicChanged(device, tx, false)
                }
            }
        } catch (t: Throwable) {
            onError(t)
            false
        }
    }

    private fun buildService(): BluetoothGattService {
        val rx = BluetoothGattCharacteristic(
            config.rxCharacteristicUuid,
            BluetoothGattCharacteristic.PROPERTY_WRITE or
                BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
            BluetoothGattCharacteristic.PERMISSION_WRITE,
        )
        val tx = BluetoothGattCharacteristic(
            config.txCharacteristicUuid,
            BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_READ,
        )
        tx.addDescriptor(
            BluetoothGattDescriptor(
                config.cccdUuid,
                BluetoothGattDescriptor.PERMISSION_READ or
                    BluetoothGattDescriptor.PERMISSION_WRITE,
            ),
        )
        return BluetoothGattService(
            config.serviceUuid,
            BluetoothGattService.SERVICE_TYPE_PRIMARY,
        ).apply {
            addCharacteristic(rx)
            addCharacteristic(tx)
        }
    }

    private val callback = object : BluetoothGattServerCallback() {
        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            val address = device.address ?: return
            when (newState) {
                BluetoothProfile.STATE_CONNECTED -> {
                    devices[address] = device
                }
                BluetoothProfile.STATE_DISCONNECTED -> {
                    devices.remove(address)
                    subscribed.remove(address)
                    mtuByAddress.remove(address)
                }
            }
        }

        override fun onMtuChanged(device: BluetoothDevice, mtu: Int) {
            val address = device.address ?: return
            mtuByAddress[address] = mtu
        }

        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray,
        ) {
            val address = device.address ?: return
            var status = BluetoothGatt.GATT_SUCCESS
            if (characteristic.uuid == config.rxCharacteristicUuid &&
                !preparedWrite &&
                offset == 0 &&
                value.isNotEmpty() &&
                value.size <= config.transfer.maxFrameBytes
            ) {
                try {
                    onFrame(Peer(address), value.copyOf())
                } catch (t: Throwable) {
                    onError(t)
                    status = BluetoothGatt.GATT_FAILURE
                }
            }
            if (responseNeeded) {
                try {
                    server?.sendResponse(device, requestId, status, offset, null)
                } catch (t: Throwable) {
                    onError(t)
                }
            }
        }

        override fun onDescriptorWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            descriptor: BluetoothGattDescriptor,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray,
        ) {
            val address = device.address ?: return
            var status = BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED
            if (!preparedWrite && offset == 0 && descriptor.uuid == config.cccdUuid) {
                subscribed[address] = value.contentEquals(
                    BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE,
                )
                devices[address] = device
                status = BluetoothGatt.GATT_SUCCESS
            }
            if (responseNeeded) {
                try {
                    server?.sendResponse(device, requestId, status, offset, null)
                } catch (t: Throwable) {
                    onError(t)
                }
            }
        }

        override fun onDescriptorReadRequest(
            device: BluetoothDevice,
            requestId: Int,
            descriptor: BluetoothGattDescriptor,
            offset: Int,
        ) {
            if (descriptor.uuid != config.cccdUuid) return
            val value = if (subscribed[device.address] == true) {
                BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
            } else {
                BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE
            }
            try {
                server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, value)
            } catch (t: Throwable) {
                onError(t)
            }
        }

        override fun onCharacteristicReadRequest(
            device: BluetoothDevice,
            requestId: Int,
            offset: Int,
            characteristic: BluetoothGattCharacteristic,
        ) {
            try {
                server?.sendResponse(
                    device,
                    requestId,
                    BluetoothGatt.GATT_SUCCESS,
                    offset,
                    ByteArray(0),
                )
            } catch (t: Throwable) {
                onError(t)
            }
        }
    }

    private companion object {
        const val TAG = "GattServer"
        const val DEFAULT_MTU = 23
        const val ATT_OVERHEAD = 3
    }
}
