package com.meshvoice.transport.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.Context
import android.util.Log
import com.meshvoice.transport.BleConfig
import com.meshvoice.transport.BlePermissions
import com.meshvoice.transport.Peer
import com.meshvoice.transport.Transport
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
            report(IOException("transfer $transferId to ${peer.address} failed: $reason"))
        },
    )
    private val scanner = BleScanner(appContext, config, ::report)
    private val advertiser = BleAdvertiser(appContext, config, ::report)
    private val server = GattServerManager(appContext, config, ::handleFrame, ::report)
    private val connections =
        ConnectionRegistry(appContext, this.scope, config, ::handleFrame, ::report)

    private val started = AtomicBoolean(false)
    private var maintenanceJob: Job? = null

    @Volatile
    private var receiveCallback: ((Peer, ByteArray) -> Unit)? = null

    val isRunning: Boolean get() = started.get()

    fun start() {
        if (!started.compareAndSet(false, true)) return
        if (!BlePermissions.hasPermissions(appContext)) {
            started.set(false)
            report(SecurityException("BLE runtime permissions are not granted"))
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
            report(IllegalStateException("Bluetooth is unavailable or disabled"))
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
        Log.i(TAG, "BLE transport stopped")
    }

    override fun send(peer: Peer, bytes: ByteArray) {
        if (!started.get()) {
            report(IllegalStateException("transport is not started"))
            return
        }
        if (bytes.size > config.transfer.maxPayloadBytes) {
            report(IllegalArgumentException("payload is too large: ${bytes.size} bytes"))
            return
        }
        val payload = bytes.copyOf()
        scope.launch {
            try {
                val connection = connections.getOrConnect(peer)
                    ?: throw IOException("cannot connect to ${peer.address}")
                val mtu = connection.awaitReady(config.connectTimeoutMs)
                    ?: throw IOException("connection to ${peer.address} not ready")
                val frameBytes = minOf(config.transfer.maxFrameBytes, mtu - ATT_OVERHEAD)
                val transfer = engine.startTransfer(peer, payload, frameBytes)
                for (chunk in transfer.chunks) {
                    connection.write(chunk)
                }
            } catch (t: CancellationException) {
                throw t
            } catch (t: Throwable) {
                report(t)
            }
        }
    }

    override fun onReceive(cb: (Peer, ByteArray) -> Unit) {
        receiveCallback = cb
    }

    override fun peers(): Flow<Peer> = scanner.peers

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
            if (result.deliveries.isNotEmpty()) {
                val callback = receiveCallback
                if (callback != null) {
                    for (payload in result.deliveries) {
                        scope.launch {
                            try {
                                callback(peer, payload)
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
        if (!server.notify(peer.address, ack)) {
            Log.d(TAG, "ack to ${peer.address} dropped; sender will retransmit")
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
