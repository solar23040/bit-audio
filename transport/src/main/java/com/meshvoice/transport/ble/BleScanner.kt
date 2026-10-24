package com.meshvoice.transport.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothManager
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.ParcelUuid
import android.util.Log
import com.meshvoice.transport.BleConfig
import com.meshvoice.transport.Peer
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.ConcurrentHashMap

@SuppressLint("MissingPermission")
internal class BleScanner(
    context: Context,
    private val config: BleConfig,
    private val onError: (Throwable) -> Unit,
) {
    private val adapter =
        (context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)?.adapter

    private val known = ConcurrentHashMap<String, Peer>()
    private val _peers = MutableStateFlow<List<Peer>>(emptyList())
    val peers: StateFlow<List<Peer>> = _peers.asStateFlow()

    private var scanning = false

    fun start() {
        if (scanning) return
        val scanner = try {
            adapter?.bluetoothLeScanner
        } catch (t: Throwable) {
            onError(t)
            null
        } ?: run {
            onError(IllegalStateException("BLE scanner unavailable (Bluetooth off?)"))
            return
        }

        val filters = listOf(
            ScanFilter.Builder()
                .setServiceUuid(ParcelUuid(config.serviceUuid))
                .build(),
        )
        val settings = ScanSettings.Builder()
            .setScanMode(config.scanMode)
            .build()
        try {
            scanner.startScan(filters, settings, callback)
            scanning = true
        } catch (t: Throwable) {
            onError(t)
        }
    }

    fun stop() {
        if (!scanning) return
        scanning = false
        try {
            adapter?.bluetoothLeScanner?.stopScan(callback)
        } catch (t: Throwable) {
            Log.w(TAG, "stopScan failed", t)
        }
    }

    fun snapshot(): List<Peer> = _peers.value

    private val callback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            handle(result)
        }

        override fun onBatchScanResults(results: MutableList<ScanResult>) {
            results.forEach(::handle)
        }

        override fun onScanFailed(errorCode: Int) {
            scanning = false
            onError(IllegalStateException("BLE scan failed with code $errorCode"))
        }
    }

    private fun handle(result: ScanResult) {
        val device = result.device ?: return
        val address = try {
            device.address
        } catch (t: Throwable) {
            return
        } ?: return
        if (known.containsKey(address)) return

        if (known.size >= config.maxPeers) {
            known.keys.firstOrNull()?.let { known.remove(it) }
        }
        known[address] = Peer(
            id = address,
            address = address,
            rssi = result.rssi,
        )
        _peers.value = known.values.sortedBy { it.id }
    }

    private companion object {
        const val TAG = "BleScanner"
    }
}
