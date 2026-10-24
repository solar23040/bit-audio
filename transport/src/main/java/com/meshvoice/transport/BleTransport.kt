package com.meshvoice.transport

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.Context
import android.util.Log
import com.meshvoice.transport.ble.BleAdvertiser
import com.meshvoice.transport.ble.BleScanner
import com.meshvoice.transport.ble.ConnectionRegistry
import com.meshvoice.transport.ble.GattServerManager
import com.meshvoice.transport.protocol.TransferEngine
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.Closeable
import java.io.IOException
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean

/**
 * BLE implementation of [Transport].
 *
 * Every node advertises a GATT service and scans for the same service. A sender connects to the
 * receiver as a central, requests MTU 247, and streams chunks with write-without-response. The
 * receiver sends selective acks back as notifications.
 *
 * Call [start] after runtime permissions are granted, and [close] when the owning service stops.
 */
@SuppressLint("MissingPermission")
class BleTransport @JvmOverloads constructor(
    context: Context,
    private val config: BleConfig = BleConfig(),
    externalScope: CoroutineScope? = null,
    private val onError: ((Throwable) -> Unit)? = null,
) : Transport, Closeable {
    private val appContext = context.applicationContext
    private val scope: CoroutineScope =
        externalScope ?: CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val ownsScope = externalScope == null

    private val engine = TransferEngine(
        settings = config.transfer,
        onTransferFailed = { peer, transferId, reason ->
            report(IOException("transfer $transferId to ${peer.id} failed: $reason"))
        },
    )
    private val scanner = BleScanner(appContext, config, ::report)
    private val advertiser = BleAdvertiser(appContext, config, ::report)
    private val server = GattServerManager(appContext, config, ::handleFrame, ::report)
    private val connections =
        ConnectionRegistry(appContext, this.scope, config, ::handleFrame, ::report)

    private val started = AtomicBoolean(false)
    private var maintenanceJob: Job? = null
    private val receiveCallbacks = CopyOnWriteArrayList<(ReceivedFrame) -> Unit>()

    val isRunning: Boolean get() = started.get()

    fun start() {
        if (!started.compareAndSet(false, true)) return
        if (!BlePermissions.hasPermissions(appContext)) {
            started.set(false)
            report(TransportException("BLE runtime permissions are not granted"))
            return
        }
        val adapter = bluetoothAdapter()
        val enabled = try {
            adapter?.isEnabled == true
        } catch (t: Throwable) {
            report(t)
            false
        }
        if (adapter == null || !enabled) {
            started.set(false)
            report(TransportException("Bluetooth is unavailable or disabled"))
            return
        }

        server.start()
        advertiser.start()
        scanner.start()

        maintenanceJob = scope.launch {
            while (isActive) {
                delay(config.maintenanceIntervalMs)
                try {
                    maintenance()
                } catch (t: Throwable) {
                    report(t)
                }
            }
        }
        Log.i(TAG, "BLE transport started")
    }

    fun stop() {
        if (!started.compareAndSet(true, false)) return
        maintenanceJob?.cancel()
        maintenanceJob = null
        scanner.stop()
        advertiser.stop()
        connections.closeAll()
        server.stop()
        engine.clear()
        receiveCallbacks.clear()
        Log.i(TAG, "BLE transport stopped")
    }

    override suspend fun send(peer: Peer, bytes: ByteArray) {
        if (!started.get()) throw TransportException("transport is not started")
        if (bytes.size > config.transfer.maxPayloadBytes) {
            throw TransportException("payload is too large: ${bytes.size} bytes")
        }
        try {
            val connection = connections.getOrConnect(peer)
                ?: throw TransportException("cannot connect to ${peer.id}")
            val mtu = connection.awaitReady(config.connectTimeoutMs)
                ?: throw TransportException("connection to ${peer.id} not ready")
            val frameBytes = minOf(config.transfer.maxFrameBytes, mtu - ATT_OVERHEAD)
            val transfer = engine.startTransfer(peer, bytes.copyOf(), frameBytes)
            for (chunk in transfer.chunks) {
                connection.write(chunk)
            }
        } catch (t: CancellationException) {
            throw t
        } catch (t: TransportException) {
            throw t
        } catch (t: Throwable) {
            throw TransportException("send to ${peer.id} failed", t)
        }
    }

    override fun onReceive(callback: (ReceivedFrame) -> Unit): AutoCloseable {
        receiveCallbacks.add(callback)
        return AutoCloseable { receiveCallbacks.remove(callback) }
    }

    override fun peers(): Flow<List<Peer>> = scanner.peers

    override fun close() {
        stop()
        if (ownsScope) scope.cancel()
    }

    private fun maintenance() {
        for (retransmission in engine.poll()) {
            val connection = connections.readyConnection(retransmission.peer)
                ?: connections.getOrConnect(retransmission.peer)
            if (connection != null && connection.isReady) {
                for (chunk in retransmission.chunks) {
                    connection.write(chunk)
                }
                engine.markRetransmitted(retransmission.peer, retransmission.transferId)
            }
        }
    }

    private fun handleFrame(peer: Peer, frame: ByteArray) {
        try {
            val result = engine.receive(peer, frame)
            for (ack in result.acks) {
                sendAck(peer, ack)
            }
            if (result.deliveries.isNotEmpty() && receiveCallbacks.isNotEmpty()) {
                for (payload in result.deliveries) {
                    val received = ReceivedFrame(peer, payload)
                    scope.launch {
                        for (callback in receiveCallbacks) {
                            try {
                                callback(received)
                            } catch (t: Throwable) {
                                report(t)
                            }
                        }
                    }
                }
            }
        } catch (t: Throwable) {
            report(t)
        }
    }

    private fun sendAck(peer: Peer, ack: ByteArray) {
        val connection = connections.readyConnection(peer)
        if (connection != null) {
            connection.write(ack)
            return
        }
        val address = peer.address ?: peer.id
        if (!server.notify(address, ack)) {
            Log.d(TAG, "ack to $address dropped; sender will retransmit")
        }
    }

    private fun bluetoothAdapter(): BluetoothAdapter? =
        (appContext.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)?.adapter

    private fun report(t: Throwable) {
        Log.w(TAG, "BLE transport error", t)
        try {
            onError?.invoke(t)
        } catch (ignored: Throwable) {
            Log.w(TAG, "error callback threw", ignored)
        }
    }

    private companion object {
        const val TAG = "BleTransport"
        const val ATT_OVERHEAD = 3
    }
}
