package com.solar23040.bitaudio.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import com.solar23040.bitaudio.BitAudioApplication
import com.solar23040.bitaudio.MainActivity
import com.solar23040.bitaudio.R
import com.solar23040.bitaudio.permissions.AppPermissions
import com.solar23040.bitaudio.transport.MeshRuntime
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay
import androidx.core.content.ContextCompat

/**
 * Keeps BLE/mesh work alive while the app is in the background.
 *
 * The runtime is [com.solar23040.bitaudio.BleMeshRuntime]; this service only
 * owns the foreground lifecycle and scan duty-cycle contract.
 */
class MeshForegroundService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private lateinit var runtime: MeshRuntime
    private var dutyCycleJob: kotlinx.coroutines.Job? = null

    override fun onCreate() {
        super.onCreate()
        runtime = (application as BitAudioApplication).graph.runtime
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf()
            return START_NOT_STICKY
        }

        // Android 14+ rejects a connectedDevice service without a BLE grant.
        if (!AppPermissions.hasBle(this)) {
            stopSelf()
            return START_NOT_STICKY
        }
        val foregroundStarted = runCatching {
            ServiceCompat.startForeground(
                this,
                NOTIFICATION_ID,
                buildNotification(),
                foregroundServiceType(),
            )
        }.isSuccess
        if (!foregroundStarted) {
            stopSelf()
            return START_NOT_STICKY
        }

        runCatching { runtime.start() }
        startDutyCycle()
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        dutyCycleJob?.cancel()
        dutyCycleJob = null
        runCatching { runtime.setScanning(false) }
        runCatching { runtime.stop() }
        scope.cancel()
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }

    private fun startDutyCycle() {
        dutyCycleJob?.cancel()
        val settings = (application as BitAudioApplication).graph.settings.current
        if (!settings.dutyCycleEnabled) {
            runtime.setScanning(true)
            return
        }
        dutyCycleJob = scope.launch {
            while (isActive) {
                runtime.setScanning(true)
                delay(settings.scanOnMs)
                runtime.setScanning(false)
                delay(settings.scanOffMs)
            }
        }
    }

    private fun buildNotification(): Notification {
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, MeshForegroundService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_mesh)
            .setContentTitle(getString(R.string.service_title))
            .setContentText(getString(R.string.service_text))
            .setContentIntent(openIntent)
            .setOngoing(true)
            .setSilent(true)
            .setShowWhen(false)
            .addAction(0, getString(R.string.service_stop), stopIntent)
            .build()
    }

    private fun createNotificationChannel() {
        val manager = getSystemService(NotificationManager::class.java) ?: return
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.service_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = getString(R.string.service_channel_description)
            setShowBadge(false)
        }
        manager.createNotificationChannel(channel)
    }

    private fun foregroundServiceType(): Int =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
        } else {
            0
        }

    companion object {
        private const val CHANNEL_ID = "mesh_service"
        private const val NOTIFICATION_ID = 1001
        private const val ACTION_STOP = "com.solar23040.bitaudio.STOP_MESH"

        fun start(context: Context) {
            if (!AppPermissions.hasBle(context)) return
            runCatching {
                ContextCompat.startForegroundService(
                    context,
                    Intent(context, MeshForegroundService::class.java),
                )
            }
        }

        fun stop(context: Context) {
            runCatching {
                context.startService(
                    Intent(context, MeshForegroundService::class.java).setAction(ACTION_STOP),
                )
            }
        }
    }
}
