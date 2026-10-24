package com.solar23040.bitaudio.data

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

data class AppSettings(
    val displayName: String = "Me",
    val defaultTtl: Int = 5,
    val retentionHours: Int = 72,
    val dutyCycleEnabled: Boolean = true,
    val scanOnMs: Long = 10_000L,
    val scanOffMs: Long = 20_000L,
)

class SettingsRepository(context: Context) {
    private val prefs = context.getSharedPreferences(PREFS_FILE, Context.MODE_PRIVATE)
    private val _settings = MutableStateFlow(read())
    val settings: StateFlow<AppSettings> = _settings.asStateFlow()

    val current: AppSettings get() = _settings.value

    fun setDisplayName(value: String) {
        update(current.copy(displayName = value.trim().ifBlank { "Me" }.take(32)))
    }

    fun setDefaultTtl(value: Int) {
        update(current.copy(defaultTtl = value.coerceIn(1, 10)))
    }

    fun setRetentionHours(value: Int) {
        update(current.copy(retentionHours = value.coerceIn(1, 24 * 30)))
    }

    fun setDutyCycleEnabled(value: Boolean) {
        update(current.copy(dutyCycleEnabled = value))
    }

    private fun update(next: AppSettings) {
        _settings.value = next
        prefs.edit()
            .putString(KEY_NAME, next.displayName)
            .putInt(KEY_TTL, next.defaultTtl)
            .putInt(KEY_RETENTION, next.retentionHours)
            .putBoolean(KEY_DUTY_CYCLE, next.dutyCycleEnabled)
            .apply()
    }

    private fun read(): AppSettings = AppSettings(
        displayName = prefs.getString(KEY_NAME, null)?.trim()?.takeIf { it.isNotEmpty() } ?: "Me",
        defaultTtl = prefs.getInt(KEY_TTL, 5).coerceIn(1, 10),
        retentionHours = prefs.getInt(KEY_RETENTION, 72).coerceIn(1, 24 * 30),
        dutyCycleEnabled = prefs.getBoolean(KEY_DUTY_CYCLE, true),
    )

    private companion object {
        const val PREFS_FILE = "bit_audio_settings"
        const val KEY_NAME = "display_name"
        const val KEY_TTL = "default_ttl"
        const val KEY_RETENTION = "retention_hours"
        const val KEY_DUTY_CYCLE = "duty_cycle"
    }
}
