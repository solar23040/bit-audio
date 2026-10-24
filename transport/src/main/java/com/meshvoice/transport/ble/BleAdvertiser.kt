package com.meshvoice.transport.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothManager
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.content.Context
import android.os.ParcelUuid
import android.util.Log
import com.meshvoice.transport.BleConfig

@SuppressLint("MissingPermission")
internal class BleAdvertiser(
    context: Context,
    private val config: BleConfig,
    private val onError: (Throwable) -> Unit,
) {
    private val adapter =
        (context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)?.adapter

    private var advertising = false
    private var starting = false

    fun start() {
        if (advertising || starting) return
        val advertiser = try {
            adapter?.bluetoothLeAdvertiser
        } catch (t: Throwable) {
            onError(t)
            null
        } ?: run {
            onError(IllegalStateException("BLE advertiser unavailable (peripheral mode unsupported?)"))
            return
        }

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
            .setConnectable(true)
            .setTimeout(0)
            .build()
        val data = AdvertiseData.Builder()
            .addServiceUuid(ParcelUuid(config.serviceUuid))
            .setIncludeDeviceName(false)
            .setIncludeTxPowerLevel(false)
            .build()

        starting = true
        try {
            advertiser.startAdvertising(settings, data, callback)
        } catch (t: Throwable) {
            starting = false
            onError(t)
        }
    }

    fun stop() {
        if (!advertising && !starting) return
        advertising = false
        starting = false
        try {
            adapter?.bluetoothLeAdvertiser?.stopAdvertising(callback)
        } catch (t: Throwable) {
            Log.w(TAG, "stopAdvertising failed", t)
        }
    }

    private val callback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings) {
            starting = false
            advertising = true
        }

        override fun onStartFailure(errorCode: Int) {
            starting = false
            advertising = false
            onError(IllegalStateException("BLE advertise failed with code $errorCode"))
        }
    }

    private companion object {
        const val TAG = "BleAdvertiser"
    }
}
