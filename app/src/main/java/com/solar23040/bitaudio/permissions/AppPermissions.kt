package com.solar23040.bitaudio.permissions

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.content.ContextCompat

object AppPermissions {
    fun hasMic(context: Context): Boolean = granted(context, Manifest.permission.RECORD_AUDIO)

    fun hasCamera(context: Context): Boolean = granted(context, Manifest.permission.CAMERA)

    fun hasNotifications(context: Context): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
            granted(context, Manifest.permission.POST_NOTIFICATIONS)

    fun hasBle(context: Context): Boolean = requiredBlePermissions().all { granted(context, it) }

    fun requiredBlePermissions(): List<String> = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        listOf(
            Manifest.permission.BLUETOOTH_SCAN,
            Manifest.permission.BLUETOOTH_ADVERTISE,
            Manifest.permission.BLUETOOTH_CONNECT,
        )
    } else {
        listOf(
            Manifest.permission.BLUETOOTH,
            Manifest.permission.BLUETOOTH_ADMIN,
            Manifest.permission.ACCESS_FINE_LOCATION,
        )
    }

    /** Permissions shown in the in-app prompt. Camera is requested at scan time. */
    fun onboardingPermissions(context: Context): List<String> = buildList {
        if (!hasMic(context)) add(Manifest.permission.RECORD_AUDIO)
        requiredBlePermissions().filterNot { granted(context, it) }.forEach(::add)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            !hasNotifications(context)
        ) {
            add(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    private fun granted(context: Context, permission: String): Boolean =
        ContextCompat.checkSelfPermission(context, permission) == PackageManager.PERMISSION_GRANTED
}
