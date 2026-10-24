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
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
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
    private val _peers = MutableSharedFlow<Peer>(
        replay = config.maxPeers,
        extraBufferCapacity = 32,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    val peers: SharedFlow<Peer> = _peers.asSharedFlow()

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

    fun snapshot(): List<Peer> = known.values.toList()

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

        val advertisedName = try {
            result.scanRecord?.deviceName
        } catch (t: Throwable) {
            null
        }
        val systemName = try {
            device.name
        } catch (t: Throwable) {
            null
        }
        val peer = Peer(
            address = address,
            name = advertisedName ?: systemName,
            rssi = result.rssi,
        )
        val previous = known[address]
        if (previous == null) {
            if (known.size >= config.maxPeers) {
                known.keys.firstOrNull()?.let(known::remove)
            }
            known[address] = peer
            _peers.tryEmit(peer)
        } else {
            // Keep the discovery event stable; only fill in a name learned later.
            known[address] = peer.copy(name = previous.name ?: peer.name)
        }
    }

    private companion object {
        const val TAG = "BleScanner"
    }
}
