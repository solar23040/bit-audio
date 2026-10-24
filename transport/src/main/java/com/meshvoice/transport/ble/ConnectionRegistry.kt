package com.meshvoice.transport.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothManager
import android.content.Context
import com.meshvoice.transport.BleConfig
import com.meshvoice.transport.Peer
import kotlinx.coroutines.CoroutineScope
import java.util.concurrent.ConcurrentHashMap

/** Owns one GATT client connection per peer address, reconnecting lazily after a drop. */
@SuppressLint("MissingPermission")
internal class ConnectionRegistry(
    private val context: Context,
    private val scope: CoroutineScope,
    private val config: BleConfig,
    private val onFrame: (Peer, ByteArray) -> Unit,
    private val onError: (Throwable) -> Unit,
) {
    private val adapter =
        (context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)?.adapter
    private val connections = ConcurrentHashMap<String, GattClientConnection>()
    private val lock = Any()

    fun getOrConnect(peer: Peer): GattClientConnection? {
        synchronized(lock) {
            val existing = connections[peer.address]
            if (existing != null && existing.isUsable) return existing

            val device = try {
                adapter?.getRemoteDevice(peer.address)
            } catch (t: Throwable) {
                onError(t)
                null
            } ?: return null

            val connection = GattClientConnection(
                context = context,
                address = peer.address,
                device = device,
                config = config,
                scope = scope,
                onFrame = onFrame,
                onError = onError,
            )
            connections[peer.address] = connection
            connection.connect()
            return connection
        }
    }

    fun readyConnection(peer: Peer): GattClientConnection? =
        connections[peer.address]?.takeIf { it.isReady }

    fun closeAll() {
        synchronized(lock) {
            connections.values.forEach { it.close() }
            connections.clear()
        }
    }
}
